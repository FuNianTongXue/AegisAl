from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any
from uuid import uuid4

from app.storage import StateStore, now_iso, store


PAYMENT_METHODS = {
    "alipay": {"id": "alipay", "name": "支付宝"},
    "wechat": {"id": "wechat", "name": "微信支付"},
    "unionpay": {"id": "unionpay", "name": "银联"},
}

SUBSCRIPTION_PLANS: tuple[dict[str, Any], ...] = (
    {
        "id": "professional_monthly",
        "name": "专业版",
        "period_name": "月度",
        "billing_period": "month",
        "interval_months": 1,
        "price_cents": 2500,
        "original_price_cents": 2500,
        "currency": "CNY",
        "discount_percent": 0,
        "badge": "灵活订阅",
        "description": "按月使用，随时可取消自动续费",
        "features": ["完整代码扫描", "智能问答与报告", "漏洞情报与组件查询"],
        "recommended": False,
    },
    {
        "id": "professional_quarterly",
        "name": "专业版",
        "period_name": "季度",
        "billing_period": "quarter",
        "interval_months": 3,
        "price_cents": 6800,
        "original_price_cents": 7500,
        "currency": "CNY",
        "discount_percent": 9,
        "badge": "最受欢迎",
        "description": "性价比之选，适合持续安全分析",
        "features": ["完整代码扫描", "智能问答与报告", "漏洞情报与组件查询"],
        "recommended": True,
    },
    {
        "id": "professional_yearly",
        "name": "专业版",
        "period_name": "年度",
        "billing_period": "year",
        "interval_months": 12,
        "price_cents": 18800,
        "original_price_cents": 30000,
        "currency": "CNY",
        "discount_percent": 37,
        "badge": "长期优惠",
        "description": "最超值，适合团队与高频使用",
        "features": ["完整代码扫描", "智能问答与报告", "漏洞情报与组件查询"],
        "recommended": False,
    },
)


class SubscriptionServiceError(ValueError):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class SubscriptionService:
    def __init__(self, state_store: StateStore | None = None) -> None:
        self.store = state_store or store
        self._lock = RLock()
        self._plans = {plan["id"]: deepcopy(plan) for plan in SUBSCRIPTION_PLANS}

    def plans(self) -> dict[str, Any]:
        return {
            "plans": deepcopy(list(SUBSCRIPTION_PLANS)),
            "payment_methods": deepcopy(list(PAYMENT_METHODS.values())),
            "currency": "CNY",
        }

    def current(self, user_id: str) -> dict[str, Any]:
        clean_user_id = self._validate_user_id(user_id)
        with self._lock:
            state = self.store.read()
            billing = self._billing(state)
            subscription = billing["subscriptions"].get(clean_user_id)
            if subscription is None:
                return self._free_subscription(clean_user_id)
            changed = self._reconcile_expiration(subscription)
            if changed:
                self.store.write(state)
            return deepcopy(subscription)

    def usage(self, user_id: str) -> dict[str, Any]:
        clean_user_id = self._validate_user_id(user_id)
        with self._lock:
            state = self.store.read()
            billing = self._billing(state)
            usage = billing["usage"].get(clean_user_id)
            if usage is None:
                usage = self._default_usage(clean_user_id)
            return deepcopy(usage)

    def orders(self, user_id: str, limit: int = 50) -> dict[str, Any]:
        clean_user_id = self._validate_user_id(user_id)
        clean_limit = max(1, min(int(limit), 100))
        with self._lock:
            state = self.store.read()
            billing = self._billing(state)
            orders = [
                deepcopy(order)
                for order in billing["orders"].values()
                if order.get("user_id") == clean_user_id
            ]
        orders.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
        return {"orders": orders[:clean_limit], "total": len(orders)}

    def checkout(
        self,
        user_id: str,
        plan_id: str,
        payment_method: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        clean_user_id = self._validate_user_id(user_id)
        if plan_id not in self._plans:
            raise SubscriptionServiceError(404, "订阅方案不存在")
        if payment_method not in PAYMENT_METHODS:
            raise SubscriptionServiceError(422, "暂不支持该支付方式")

        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "user_id": clean_user_id,
                    "plan_id": plan_id,
                    "payment_method": payment_method,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        storage_key = hashlib.sha256(f"{clean_user_id}\0{idempotency_key}".encode("utf-8")).hexdigest()

        with self._lock:
            state = self.store.read()
            billing = self._billing(state)
            previous = billing["idempotency_keys"].get(storage_key)
            if previous:
                if previous.get("fingerprint") != fingerprint:
                    raise SubscriptionServiceError(409, "同一幂等键不能用于不同的订阅请求")
                order = billing["orders"].get(previous.get("order_id"))
                if order is None:
                    raise SubscriptionServiceError(409, "幂等订单状态异常，请使用新的幂等键重试")
                return self._checkout_result(order, reused=True)

            plan = self._plans[plan_id]
            created_at = now_iso()
            order_id = f"ord_{uuid4().hex}"
            order = {
                "id": order_id,
                "user_id": clean_user_id,
                "plan_id": plan_id,
                "plan_name": plan["name"],
                "period_name": plan["period_name"],
                "payment_method": payment_method,
                "amount_cents": plan["price_cents"],
                "currency": plan["currency"],
                "status": "integration_required",
                "provider_transaction_id": None,
                "payment_url": None,
                "created_at": created_at,
                "updated_at": created_at,
                "paid_at": None,
            }
            billing["orders"][order_id] = order
            billing["idempotency_keys"][storage_key] = {
                "fingerprint": fingerprint,
                "order_id": order_id,
                "created_at": created_at,
            }
            self.store.write(state)
            return self._checkout_result(order, reused=False)

    def cancel(self, user_id: str, reason: str | None = None) -> dict[str, Any]:
        clean_user_id = self._validate_user_id(user_id)
        with self._lock:
            state = self.store.read()
            billing = self._billing(state)
            subscription = billing["subscriptions"].get(clean_user_id)
            if subscription is None or subscription.get("status") != "active":
                raise SubscriptionServiceError(409, "当前没有可取消自动续费的有效订阅")
            subscription["auto_renew"] = False
            subscription["cancel_at_period_end"] = True
            subscription["canceled_at"] = now_iso()
            subscription["cancel_reason"] = (reason or "").strip()
            subscription["updated_at"] = now_iso()
            self.store.write(state)
            return deepcopy(subscription)

    def verify_webhook_signature(self, raw_body: bytes, signature: str | None) -> str:
        secret = os.getenv("SECFLOW_PAYMENT_WEBHOOK_SECRET", "").strip()
        if not secret:
            raise SubscriptionServiceError(503, "支付回调尚未配置")
        clean_signature = (signature or "").strip()
        if clean_signature.startswith("sha256="):
            clean_signature = clean_signature.removeprefix("sha256=")
        expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        if not clean_signature or not hmac.compare_digest(clean_signature.lower(), expected):
            raise SubscriptionServiceError(401, "支付回调签名无效")
        return hashlib.sha256(raw_body).hexdigest()

    def process_payment_event(self, event: dict[str, Any], payload_digest: str) -> dict[str, Any]:
        event_id = str(event.get("event_id", "")).strip()
        order_id = str(event.get("order_id", "")).strip()
        event_type = str(event.get("event_type", "")).strip()
        with self._lock:
            state = self.store.read()
            billing = self._billing(state)
            previous = billing["payment_events"].get(event_id)
            if previous:
                if previous.get("payload_digest") != payload_digest:
                    raise SubscriptionServiceError(409, "支付事件编号已被其他内容使用")
                return {"duplicate": True, "processed": False, "event": deepcopy(previous)}

            order = billing["orders"].get(order_id)
            if order is None:
                raise SubscriptionServiceError(404, "支付订单不存在")

            processed_at = now_iso()
            if event_type == "payment.succeeded":
                self._activate_subscription(billing, order, event, processed_at)
            elif event_type == "payment.failed":
                order["status"] = "failed"
                order["updated_at"] = processed_at
            elif event_type == "refund.succeeded":
                order["status"] = "refunded"
                order["updated_at"] = processed_at
                self._cancel_refunded_subscription(billing, order, processed_at)
            else:
                raise SubscriptionServiceError(422, "不支持的支付事件类型")

            event_record = {
                "event_id": event_id,
                "event_type": event_type,
                "order_id": order_id,
                "payload_digest": payload_digest,
                "processed_at": processed_at,
            }
            billing["payment_events"][event_id] = event_record
            self.store.write(state)
            return {
                "duplicate": False,
                "processed": True,
                "event": deepcopy(event_record),
                "order": deepcopy(order),
                "subscription": deepcopy(billing["subscriptions"].get(order["user_id"])),
            }

    def _activate_subscription(
        self,
        billing: dict[str, Any],
        order: dict[str, Any],
        event: dict[str, Any],
        processed_at: str,
    ) -> None:
        plan = self._plans.get(order["plan_id"])
        if plan is None:
            raise SubscriptionServiceError(409, "订单对应的订阅方案已失效")
        if order.get("status") == "refunded":
            raise SubscriptionServiceError(409, "退款订单不能重新激活订阅")

        now = datetime.now(timezone.utc).replace(microsecond=0)
        existing = billing["subscriptions"].get(order["user_id"])
        start = now
        if existing and existing.get("status") == "active" and existing.get("plan_id") == order["plan_id"]:
            existing_end = self._parse_datetime(existing.get("current_period_end"))
            if existing_end and existing_end > now:
                start = existing_end
        end = self._add_months(start, int(plan["interval_months"]))
        subscription = {
            "user_id": order["user_id"],
            "plan_id": order["plan_id"],
            "plan_name": plan["name"],
            "period_name": plan["period_name"],
            "status": "active",
            "auto_renew": True,
            "cancel_at_period_end": False,
            "current_period_start": start.isoformat(),
            "current_period_end": end.isoformat(),
            "payment_method": order["payment_method"],
            "latest_order_id": order["id"],
            "canceled_at": None,
            "cancel_reason": "",
            "updated_at": processed_at,
        }
        billing["subscriptions"][order["user_id"]] = subscription
        order["status"] = "paid"
        order["provider_transaction_id"] = event.get("provider_transaction_id") or None
        order["paid_at"] = event.get("occurred_at") or processed_at
        order["updated_at"] = processed_at

    @staticmethod
    def _cancel_refunded_subscription(
        billing: dict[str, Any], order: dict[str, Any], processed_at: str
    ) -> None:
        subscription = billing["subscriptions"].get(order["user_id"])
        if not subscription or subscription.get("latest_order_id") != order["id"]:
            return
        subscription["status"] = "canceled"
        subscription["auto_renew"] = False
        subscription["cancel_at_period_end"] = False
        subscription["current_period_end"] = processed_at
        subscription["canceled_at"] = processed_at
        subscription["updated_at"] = processed_at

    @staticmethod
    def _billing(state: dict[str, Any]) -> dict[str, Any]:
        billing = state.setdefault("billing", {})
        for key in ("subscriptions", "orders", "idempotency_keys", "payment_events", "usage"):
            billing.setdefault(key, {})
        return billing

    @staticmethod
    def _validate_user_id(user_id: str) -> str:
        clean = str(user_id).strip()
        if not clean or len(clean) > 120:
            raise SubscriptionServiceError(422, "用户标识无效")
        return clean

    @staticmethod
    def _free_subscription(user_id: str) -> dict[str, Any]:
        return {
            "user_id": user_id,
            "plan_id": "free",
            "plan_name": "免费版",
            "period_name": "",
            "status": "free",
            "auto_renew": False,
            "cancel_at_period_end": False,
            "current_period_start": None,
            "current_period_end": None,
            "payment_method": None,
            "latest_order_id": None,
            "canceled_at": None,
            "cancel_reason": "",
            "updated_at": "",
        }

    @staticmethod
    def _default_usage(user_id: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        period_start = now.replace(day=1, hour=0, minute=0, second=0)
        period_end = SubscriptionService._add_months(period_start, 1)
        return {
            "user_id": user_id,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "metrics": [
                {"id": "code_scans", "label": "代码扫描", "used": 0, "limit": 20, "unit": "次"},
                {"id": "ai_queries", "label": "智能问答", "used": 0, "limit": 100, "unit": "次"},
                {"id": "report_exports", "label": "报告导出", "used": 0, "limit": 20, "unit": "份"},
            ],
            "updated_at": now_iso(),
        }

    @staticmethod
    def _checkout_result(order: dict[str, Any], reused: bool) -> dict[str, Any]:
        return {
            "checkout_status": order["status"],
            "provider_configured": False,
            "payment_url": order.get("payment_url"),
            "reused": reused,
            "order": deepcopy(order),
            "message": "支付渠道接口尚未配置，订单已保存但不会激活订阅。",
        }

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _add_months(value: datetime, months: int) -> datetime:
        target_month = value.month - 1 + months
        year = value.year + target_month // 12
        month = target_month % 12 + 1
        day = min(value.day, calendar.monthrange(year, month)[1])
        return value.replace(year=year, month=month, day=day)

    def _reconcile_expiration(self, subscription: dict[str, Any]) -> bool:
        if subscription.get("status") != "active":
            return False
        period_end = self._parse_datetime(subscription.get("current_period_end"))
        if period_end is None or period_end > datetime.now(timezone.utc):
            return False
        subscription["status"] = "canceled" if subscription.get("cancel_at_period_end") else "expired"
        subscription["auto_renew"] = False
        subscription["updated_at"] = now_iso()
        return True


subscription_service = SubscriptionService()
