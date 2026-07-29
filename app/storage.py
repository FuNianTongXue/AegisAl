from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.exceptions import InvalidTag

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text


DATA_DIR = Path(os.getenv("SECFLOW_DATA_DIR", "data"))
STATE_PATH = DATA_DIR / "state.json"
STATE_PURPOSE = "secflow-state"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_state() -> dict[str, Any]:
    return {
        "collectors": {
            "cve": {
                "id": "cve",
                "name": "固定情报接口 1",
                "enabled": True,
                "api_url": "",
                "api_key": "",
                "collection_name": "cve",
                "severity_filter": ["CRITICAL", "HIGH", "MEDIUM"],
                "dedupe_key": "cve_id",
                "max_results": 20,
                "sync_interval_minutes": 60,
                "last_test": None,
                "last_collect": None,
            },
            "github_advisory": {
                "id": "github_advisory",
                "name": "固定情报接口 2",
                "enabled": True,
                "api_url": "",
                "token": "",
                "collection_name": "github_advisory",
                "severity_filter": ["critical", "high", "medium"],
                "ecosystem": "",
                "dedupe_key": "ghsa_id",
                "max_results": 20,
                "sync_interval_minutes": 60,
                "last_test": None,
                "last_collect": None,
            },
        },
        "records": [
            {
                "id": "CVE-2021-44228",
                "title": "Apache Log4j remote code execution vulnerability",
                "severity": "CRITICAL",
                "source": "seed",
                "summary": "Log4Shell allows remote code execution through crafted JNDI lookup strings in vulnerable Log4j versions.",
                "references": [],
                "collection": "local",
                "updated_at": now_iso(),
            },
            {
                "id": "GHSA-jfh8-c2jp-5v3q",
                "title": "Example security advisory record",
                "severity": "high",
                "source": "seed",
                "summary": "A sample advisory record used to validate the local knowledge flow.",
                "references": [],
                "collection": "local",
                "updated_at": now_iso(),
            },
        ],
        "llm": {
            "provider": "custom",
            "catalog_provider": "sub2api",
            "model": "gpt-5.6-sol",
            "endpoint": "https://carpool.composiastack.com",
            "api_key": "",
            "enabled": False,
            "max_tokens": 1800,
            "temperature": 0.25,
            "top_p": 0.9,
            "timeout_ms": 60000,
            "wire_api": "responses",
            "reasoning_effort": "xhigh",
            "disable_response_storage": True,
            "updated_at": "",
        },
        "information": {
            "sources": {},
            "items": [],
            "updated_at": "",
            "last_refresh": "",
            "message": "等待首次在线更新。",
        },
        "settings": {
            "profile": {
                "display_name": "李明哲",
                "email": "limingzhe@example.com",
                "phone": "138 **** 6688",
                "department": "网络安全部",
                "role": "安全分析师",
                "employee_id": "SEC-20240315",
                "bio": "网络安全分析师，专注于威胁情报分析与漏洞研究。拥有 5 年以上安全行业经验，熟悉各类安全工具与攻防技术。",
                "avatar_file_name": "",
                "avatar_content_type": "",
                "avatar_updated_at": "",
                "updated_at": "",
            },
            "preferences": {
                "language": "zh-Hans",
                "dark_mode": False,
                "font_size": "default",
                "launch_at_login": False,
                "auto_check_updates": True,
                "updated_at": "",
            },
            "legal": {},
        },
        "billing": {
            "subscriptions": {},
            "orders": {},
            "idempotency_keys": {},
            "payment_events": {},
            "usage": {},
        },
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }


class StateStore:
    def __init__(self, path: Path = STATE_PATH) -> None:
        self.path = path
        self._lock = RLock()

    def read(self) -> dict[str, Any]:
        with self._lock:
            if not self.path.exists():
                state = default_state()
                self.write(state)
                return state
            try:
                raw = self.path.read_text(encoding="utf-8")
                state = decrypt_json_from_text(raw, STATE_PURPOSE)
                if not isinstance(state, dict):
                    raise ValueError("state payload is not an object")
                if not raw.lstrip().startswith('{"__secflow_encrypted__"'):
                    self.write(state)
                return state
            except (InvalidTag, json.JSONDecodeError, OSError, ValueError):
                state = default_state()
                self.write(state)
                return state

    def write(self, state: dict[str, Any]) -> None:
        with self._lock:
            state["updated_at"] = now_iso()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(encrypt_json_to_text(state, STATE_PURPOSE), encoding="utf-8")
            os.replace(tmp, self.path)

    def public_state(self) -> dict[str, Any]:
        state = deepcopy(self.read())
        for config in state.get("collectors", {}).values():
            if config.get("api_key"):
                config["api_key"] = mask_secret(config["api_key"])
            if config.get("token"):
                config["token"] = mask_secret(config["token"])
        llm = state.get("llm")
        if isinstance(llm, dict) and llm.get("api_key"):
            llm["api_key"] = mask_secret(llm["api_key"])
        return state


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}********{value[-4:]}"


store = StateStore()
