from __future__ import annotations

import sqlite3
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from app.storage import DATA_DIR, now_iso


def normalize_model_usage(data: Any) -> dict[str, int]:
    """Normalize token usage returned by OpenAI-compatible and Anthropic APIs."""

    payload = data if isinstance(data, dict) else {}
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    if not usage and isinstance(payload.get("response"), dict):
        nested = payload["response"]
        usage = nested.get("usage") if isinstance(nested.get("usage"), dict) else {}

    input_tokens = _first_non_negative_int(
        usage,
        "input_tokens",
        "prompt_tokens",
        "prompt_token_count",
    )
    output_tokens = _first_non_negative_int(
        usage,
        "output_tokens",
        "completion_tokens",
        "candidates_token_count",
    )
    total_tokens = _first_non_negative_int(
        usage,
        "total_tokens",
        "total_token_count",
    )
    if total_tokens <= 0:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


class ModelUsageStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DATA_DIR / "model-usage.sqlite3"

    def record(
        self,
        *,
        user_id: str,
        session_id: str,
        provider: str,
        model: str,
        source: str,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int,
        created_at: str | None = None,
    ) -> bool:
        normalized_total = max(0, int(total_tokens or 0))
        if normalized_total <= 0:
            return False
        with self._connect() as connection:
            connection.execute(
                """
                insert into model_usage_events (
                    user_id, session_id, provider, model, source,
                    input_tokens, output_tokens, total_tokens, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _clean_identifier(user_id, "default"),
                    _clean_identifier(session_id, ""),
                    _clean_identifier(provider, "unknown"),
                    _clean_identifier(model, "unknown"),
                    _clean_identifier(source, "assistant"),
                    max(0, int(input_tokens or 0)),
                    max(0, int(output_tokens or 0)),
                    normalized_total,
                    created_at or now_iso(),
                ),
            )
        return True

    def record_result(
        self,
        result: dict[str, Any],
        active_model: dict[str, Any],
        *,
        user_id: str,
        session_id: str,
        source: str,
    ) -> bool:
        if result.get("status") != "success":
            return False
        usage = normalize_model_usage(result.get("data"))
        return self.record(
            user_id=user_id,
            session_id=session_id,
            provider=str(active_model.get("provider") or "unknown"),
            model=str(active_model.get("model") or "unknown"),
            source=source,
            **usage,
        )

    def snapshot(
        self,
        user_id: str = "default",
        days: int = 30,
        *,
        history: Iterable[dict[str, Any]] = (),
        now: datetime | None = None,
    ) -> dict[str, Any]:
        range_days = 7 if int(days) == 7 else 30
        local_now = _aware_local(now or datetime.now().astimezone())
        local_timezone = local_now.tzinfo or timezone.utc
        start_date = local_now.date() - timedelta(days=range_days - 1)
        start_at = datetime.combine(start_date, time.min, tzinfo=local_timezone).astimezone(timezone.utc)
        day_values = [start_date + timedelta(days=index) for index in range(range_days)]
        daily: dict[str, dict[str, int]] = {
            value.isoformat(): {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "calls": 0,
                "messages": 0,
            }
            for value in day_values
        }

        rows = self._events_since(_clean_identifier(user_id, "default"), start_at.isoformat())
        model_totals: dict[tuple[str, str], int] = defaultdict(int)
        event_sessions: set[str] = set()
        for row in rows:
            created_at = _parse_datetime(row["created_at"])
            if created_at is None:
                continue
            day_key = created_at.astimezone(local_timezone).date().isoformat()
            if day_key not in daily:
                continue
            entry = daily[day_key]
            entry["input_tokens"] += int(row["input_tokens"] or 0)
            entry["output_tokens"] += int(row["output_tokens"] or 0)
            entry["total_tokens"] += int(row["total_tokens"] or 0)
            entry["calls"] += 1
            model_totals[(str(row["provider"]), str(row["model"]))] += int(row["total_tokens"] or 0)
            session_id = str(row["session_id"] or "").strip()
            if session_id:
                event_sessions.add(session_id)

        conversation_sessions: set[str] = set()
        for exchange in history:
            timestamp = _parse_datetime(exchange.get("timestamp"))
            if timestamp is None:
                continue
            day_key = timestamp.astimezone(local_timezone).date().isoformat()
            if day_key not in daily:
                continue
            daily[day_key]["messages"] += 2
            conversation_sessions.add(str(exchange.get("sessionId") or "default"))

        totals = {
            "input_tokens": sum(item["input_tokens"] for item in daily.values()),
            "output_tokens": sum(item["output_tokens"] for item in daily.values()),
            "total_tokens": sum(item["total_tokens"] for item in daily.values()),
            "call_count": sum(item["calls"] for item in daily.values()),
        }
        activity_dates = {
            day_key
            for day_key, item in daily.items()
            if item["calls"] > 0 or item["messages"] > 0
        }
        most_used = max(model_totals.items(), key=lambda item: item[1], default=None)
        most_used_model = {
            "provider": most_used[0][0] if most_used else "",
            "model": most_used[0][1] if most_used else "",
            "tokens": most_used[1] if most_used else 0,
            "share": round((most_used[1] / totals["total_tokens"] * 100), 1)
            if most_used and totals["total_tokens"]
            else 0,
        }
        daily_values = [{"date": day_key, **daily[day_key]} for day_key in daily]
        maximum_activity = max(
            (item["calls"] + item["messages"] for item in daily_values),
            default=0,
        )
        heatmap = []
        for item in daily_values:
            count = item["calls"] + item["messages"]
            level = 0 if count == 0 or maximum_activity == 0 else min(4, max(1, (count * 4 + maximum_activity - 1) // maximum_activity))
            heatmap.append({"date": item["date"], "count": count, "level": level})

        return {
            "range_days": range_days,
            "totals": totals,
            "conversation_count": len(conversation_sessions | event_sessions),
            "message_count": sum(item["messages"] for item in daily_values),
            "active_days": len(activity_dates),
            "current_streak": _current_streak(local_now.date(), activity_dates),
            "most_used_model": most_used_model,
            "daily": daily_values,
            "heatmap": heatmap,
            "updated_at": now_iso(),
        }

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("pragma journal_mode = wal")
        connection.execute("pragma busy_timeout = 10000")
        connection.execute(
            """
            create table if not exists model_usage_events (
                id integer primary key autoincrement,
                user_id text not null,
                session_id text not null default '',
                provider text not null,
                model text not null,
                source text not null,
                input_tokens integer not null default 0,
                output_tokens integer not null default 0,
                total_tokens integer not null,
                created_at text not null
            )
            """
        )
        connection.execute(
            "create index if not exists idx_model_usage_user_time on model_usage_events (user_id, created_at)"
        )
        return connection

    def _events_since(self, user_id: str, start_at: str) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return list(
                connection.execute(
                    """
                    select session_id, provider, model, input_tokens, output_tokens,
                           total_tokens, created_at
                    from model_usage_events
                    where user_id = ? and created_at >= ?
                    order by created_at asc, id asc
                    """,
                    (user_id, start_at),
                ).fetchall()
            )


def _first_non_negative_int(values: dict[str, Any], *keys: str) -> int:
    for key in keys:
        if key not in values:
            continue
        try:
            return max(0, int(values[key] or 0))
        except (TypeError, ValueError):
            continue
    return 0


def _clean_identifier(value: Any, fallback: str) -> str:
    return str(value or fallback).strip()[:240] or fallback


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _aware_local(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return value


def _current_streak(today: date, activity_dates: set[str]) -> int:
    streak = 0
    cursor = today
    while cursor.isoformat() in activity_dates:
        streak += 1
        cursor -= timedelta(days=1)
    return streak


model_usage_service = ModelUsageStore()
