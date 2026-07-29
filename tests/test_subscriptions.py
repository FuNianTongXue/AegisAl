from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.storage import StateStore
from app.subscriptions import SubscriptionService


class SubscriptionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_store = StateStore(Path(self.temp_dir.name) / "state.json")
        self.service = SubscriptionService(self.state_store)
        self.client = TestClient(app)
        self.service_patch = patch("app.main.subscription_service", self.service)
        self.service_patch.start()

    def tearDown(self) -> None:
        self.service_patch.stop()
        self.temp_dir.cleanup()

    def test_plans_and_server_authoritative_checkout_price(self) -> None:
        plans_response = self.client.get("/api/subscriptions/plans")
        self.assertEqual(plans_response.status_code, 200)
        plans = plans_response.json()["data"]["plans"]
        self.assertEqual([plan["price_cents"] for plan in plans], [2500, 6800, 18800])
        self.assertEqual(
            [method["id"] for method in plans_response.json()["data"]["payment_methods"]],
            ["alipay", "wechat", "unionpay"],
        )

        checkout = self.client.post(
            "/api/subscriptions/checkout",
            json={
                "user_id": "user-a",
                "plan_id": "professional_monthly",
                "payment_method": "alipay",
                "idempotency_key": "checkout-key-0001",
                "price_cents": 1,
                "currency": "USD",
            },
        )
        self.assertEqual(checkout.status_code, 200)
        result = checkout.json()["data"]
        self.assertEqual(result["order"]["amount_cents"], 2500)
        self.assertEqual(result["order"]["currency"], "CNY")
        self.assertEqual(result["checkout_status"], "integration_required")
        self.assertFalse(result["provider_configured"])
        self.assertIsNone(result["payment_url"])

        response_text = checkout.text.lower()
        self.assertNotIn("webhook_secret", response_text)
        self.assertNotIn("payment_key", response_text)

    def test_checkout_idempotency_reuses_order_and_rejects_changed_request(self) -> None:
        payload = {
            "user_id": "user-a",
            "plan_id": "professional_quarterly",
            "payment_method": "wechat",
            "idempotency_key": "checkout-key-0002",
        }
        first = self.client.post("/api/subscriptions/checkout", json=payload)
        second = self.client.post("/api/subscriptions/checkout", json=payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["data"]["order"]["id"], second.json()["data"]["order"]["id"])
        self.assertTrue(second.json()["data"]["reused"])

        changed = dict(payload, plan_id="professional_yearly")
        conflict = self.client.post("/api/subscriptions/checkout", json=changed)
        self.assertEqual(conflict.status_code, 409)

    def test_webhook_requires_secret_and_rejects_invalid_signature(self) -> None:
        order = self._create_order("checkout-key-0003")
        raw = self._event_body(order["id"], "event-0003")
        with patch.dict(os.environ, {"SECFLOW_PAYMENT_WEBHOOK_SECRET": ""}):
            unconfigured = self.client.post(
                "/api/subscriptions/payment-events",
                content=raw,
                headers={"Content-Type": "application/json", "X-SecFlow-Signature": "invalid"},
            )
        self.assertEqual(unconfigured.status_code, 503)

        with patch.dict(os.environ, {"SECFLOW_PAYMENT_WEBHOOK_SECRET": "test-webhook-secret"}):
            invalid = self.client.post(
                "/api/subscriptions/payment-events",
                content=raw,
                headers={"Content-Type": "application/json", "X-SecFlow-Signature": "invalid"},
            )
        self.assertEqual(invalid.status_code, 401)

    def test_signed_payment_event_activates_once_and_cancel_keeps_period_end(self) -> None:
        order = self._create_order("checkout-key-0004", plan_id="professional_yearly")
        raw = self._event_body(order["id"], "event-0004")
        secret = "test-webhook-secret"
        signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()

        with patch.dict(os.environ, {"SECFLOW_PAYMENT_WEBHOOK_SECRET": secret}):
            paid = self.client.post(
                "/api/subscriptions/payment-events",
                content=raw,
                headers={"Content-Type": "application/json", "X-SecFlow-Signature": f"sha256={signature}"},
            )
            duplicate = self.client.post(
                "/api/subscriptions/payment-events",
                content=raw,
                headers={"Content-Type": "application/json", "X-SecFlow-Signature": signature},
            )

        self.assertEqual(paid.status_code, 200)
        self.assertTrue(paid.json()["data"]["processed"])
        self.assertEqual(paid.json()["data"]["order"]["amount_cents"], 18800)
        self.assertEqual(paid.json()["data"]["subscription"]["status"], "active")
        self.assertFalse(duplicate.json()["data"]["processed"])
        self.assertTrue(duplicate.json()["data"]["duplicate"])

        current = self.client.get("/api/subscriptions/current", params={"user_id": "user-a"}).json()["data"]
        period_end = current["current_period_end"]
        canceled = self.client.post(
            "/api/subscriptions/cancel",
            json={"user_id": "user-a", "reason": "暂时不续费"},
        )
        self.assertEqual(canceled.status_code, 200)
        self.assertEqual(canceled.json()["data"]["status"], "active")
        self.assertFalse(canceled.json()["data"]["auto_renew"])
        self.assertTrue(canceled.json()["data"]["cancel_at_period_end"])
        self.assertEqual(canceled.json()["data"]["current_period_end"], period_end)

    def test_reused_event_id_with_different_payload_is_rejected(self) -> None:
        order = self._create_order("checkout-key-0005")
        first_raw = self._event_body(order["id"], "event-0005")
        changed_raw = self._event_body(order["id"], "event-0005", transaction_id="provider-tx-changed")
        secret = "test-webhook-secret"

        with patch.dict(os.environ, {"SECFLOW_PAYMENT_WEBHOOK_SECRET": secret}):
            first = self._post_signed(first_raw, secret)
            changed = self._post_signed(changed_raw, secret)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(changed.status_code, 409)

    def test_usage_and_order_history_are_user_scoped(self) -> None:
        self._create_order("checkout-key-0006")
        self.client.post(
            "/api/subscriptions/checkout",
            json={
                "user_id": "user-b",
                "plan_id": "professional_monthly",
                "payment_method": "unionpay",
                "idempotency_key": "checkout-key-0007",
            },
        )
        orders = self.client.get("/api/subscriptions/orders", params={"user_id": "user-a"}).json()["data"]
        usage = self.client.get("/api/subscriptions/usage", params={"user_id": "user-a"}).json()["data"]
        self.assertEqual(orders["total"], 1)
        self.assertTrue(all(order["user_id"] == "user-a" for order in orders["orders"]))
        self.assertEqual([metric["id"] for metric in usage["metrics"]], ["code_scans", "ai_queries", "report_exports"])

    def _create_order(self, idempotency_key: str, plan_id: str = "professional_monthly") -> dict:
        response = self.client.post(
            "/api/subscriptions/checkout",
            json={
                "user_id": "user-a",
                "plan_id": plan_id,
                "payment_method": "alipay",
                "idempotency_key": idempotency_key,
            },
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["data"]["order"]

    @staticmethod
    def _event_body(order_id: str, event_id: str, transaction_id: str = "provider-tx-1") -> bytes:
        return json.dumps(
            {
                "event_id": event_id,
                "event_type": "payment.succeeded",
                "order_id": order_id,
                "provider_transaction_id": transaction_id,
                "occurred_at": "2026-07-23T10:00:00+00:00",
            },
            separators=(",", ":"),
        ).encode()

    def _post_signed(self, raw: bytes, secret: str):
        signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        return self.client.post(
            "/api/subscriptions/payment-events",
            content=raw,
            headers={"Content-Type": "application/json", "X-SecFlow-Signature": signature},
        )


if __name__ == "__main__":
    unittest.main()
