from __future__ import annotations

import json
import math
import os
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.exceptions import InvalidTag

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:  # pragma: no cover - Postgres is optional.
    psycopg = None
    dict_row = None

from app.storage import DATA_DIR, now_iso
from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text


MEMORY_PURPOSE = "secflow-memory"
ASSISTANT_PROJECT_ID = "assistant"
ASSISTANT_PROJECT_NAME = "智能问答"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class LongTermMemoryService:
    _topic_rules = {
        "CVE": re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I),
        "GHSA": re.compile(r"\bGHSA-[a-z0-9-]+\b", re.I),
        "供应链": re.compile(r"供应链|依赖|投毒|supply chain|dependency|sbom|sca", re.I),
        "代码审计": re.compile(r"代码审计|sast|semgrep|codeql|静态分析|code audit", re.I),
        "威胁建模": re.compile(r"威胁建模|stride|攻击面|安全评审|threat model", re.I),
        "合规": re.compile(r"合规|等保|审计|隐私|数据安全|policy|compliance", re.I),
        "AI 安全": re.compile(r"ai 安全|llm|prompt|提示词|越狱|模型|agent", re.I),
        "GitLab": re.compile(r"gitlab|merge request|pipeline|ci/cd|提交", re.I),
        "向量库": re.compile(r"向量|rag|milvus|chunk|embedding|知识库", re.I),
    }

    def __init__(self, state_path: Path | None = None) -> None:
        self.database_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DSN") or ""
        self.local_only = os.getenv("SECFLOW_MEMORY_LOCAL_ONLY", "true").strip().lower() not in {"0", "false", "no"}
        self.max_history = _env_int("SECFLOW_MEMORY_MAX_HISTORY", 300)
        self.recent_limit = _env_int("SECFLOW_MEMORY_RECENT_LIMIT", 6)
        self.retrieval_limit = _env_int("SECFLOW_MEMORY_RETRIEVAL_LIMIT", 5)
        self.context_chars = _env_int("SECFLOW_MEMORY_CONTEXT_CHARS", 3000)
        self.state_path = state_path or DATA_DIR / "memory.json"
        self._lock = RLock()
        self._postgres_ready: bool | None = None
        self._postgres_error = ""

    @property
    def backend(self) -> str:
        return "postgres" if self._use_postgres() else "local-json"

    def status(self, user_id: str = "default") -> dict[str, Any]:
        profile = self._get_profile(user_id)
        history = self.get_history(user_id, limit=self.max_history)
        return {
            "enabled": True,
            "backend": self.backend,
            "historyCount": len(history),
            "summaryChars": len(profile.get("summary", "")),
            "lastUpdated": profile.get("updatedAt", ""),
            "postgresAvailable": self._use_postgres(),
            "postgresError": self._postgres_error,
        }

    def get_history(self, user_id: str = "default", limit: int | None = None) -> list[dict[str, Any]]:
        limit = limit or self.max_history
        if self._use_postgres():
            try:
                return [self._row_to_entry(row) for row in self._pg_fetch_history(user_id, limit)]
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)
        state = self._read_json_state()
        history = state.setdefault("users", {}).get(user_id, [])
        return deepcopy(history[-limit:])

    def list_conversations(
        self,
        user_id: str = "default",
        limit: int = 30,
        archived: bool = False,
    ) -> list[dict[str, Any]]:
        history = self.get_history(user_id, limit=self.max_history)
        metadata = self._conversation_metadata(user_id)
        conversations: dict[str, dict[str, Any]] = {}
        for entry in history:
            session_id = str(entry.get("sessionId", "") or "default")
            conversation = conversations.get(session_id)
            if conversation is None:
                session_metadata = metadata.get(session_id, {})
                conversation = {
                    "id": session_id,
                    "title": str(entry.get("question", "") or "").strip() or "Untitled conversation",
                    "updated_at": str(entry.get("timestamp", "") or ""),
                    "turn_count": 0,
                    "project_id": ASSISTANT_PROJECT_ID,
                    "project_name": ASSISTANT_PROJECT_NAME,
                    "archived": bool(session_metadata.get("archived", False)),
                    "archived_at": str(session_metadata.get("archivedAt", "") or ""),
                }
                conversations[session_id] = conversation
            conversation["turn_count"] += 1
            timestamp = str(entry.get("timestamp", "") or "")
            if timestamp >= conversation["updated_at"]:
                conversation["updated_at"] = timestamp

        filtered = [item for item in conversations.values() if bool(item["archived"]) is archived]
        ordered = sorted(
            filtered,
            key=lambda item: (item["updated_at"], item["id"]),
            reverse=True,
        )
        return deepcopy(ordered[: max(1, min(limit, 100))])

    def get_conversation(self, user_id: str, session_id: str) -> dict[str, Any]:
        exchanges = [
            entry
            for entry in self.get_history(user_id, limit=self.max_history)
            if str(entry.get("sessionId", "") or "default") == session_id
        ]
        if not exchanges:
            raise KeyError(session_id)
        exchanges.sort(key=lambda item: (str(item.get("timestamp", "")), str(item.get("id", ""))))
        metadata = self._conversation_metadata(user_id).get(session_id, {})
        return {
            "id": session_id,
            "title": str(exchanges[0].get("question", "") or "").strip() or "Untitled conversation",
            "updated_at": str(exchanges[-1].get("timestamp", "") or ""),
            "turn_count": len(exchanges),
            "project_id": ASSISTANT_PROJECT_ID,
            "project_name": ASSISTANT_PROJECT_NAME,
            "archived": bool(metadata.get("archived", False)),
            "archived_at": str(metadata.get("archivedAt", "") or ""),
            "exchanges": [
                {
                    "id": str(entry.get("id", "")),
                    "question": str(entry.get("question", "") or ""),
                    "answer": str(entry.get("answer", "") or ""),
                    "mode": str(entry.get("mode", "") or ""),
                    "confidence": float(entry.get("confidence", 0) or 0),
                    "fields": deepcopy(entry.get("fields", {}) or {}),
                    "answer_payload": deepcopy(entry.get("answerPayload", {}) or {}),
                    "timestamp": str(entry.get("timestamp", "") or ""),
                }
                for entry in exchanges
            ],
        }

    def archive_conversation(self, user_id: str, session_id: str, archived: bool) -> dict[str, Any]:
        self.get_conversation(user_id, session_id)
        archived_at = now_iso() if archived else ""
        if self._use_postgres():
            try:
                with self._pg_connect() as conn:
                    conn.execute(
                        """
                        insert into secflow_knowledge_conversations
                            (user_id, session_id, archived, archived_at, updated_at)
                        values (%s, %s, %s, %s, now())
                        on conflict (user_id, session_id) do update set
                            archived = excluded.archived,
                            archived_at = excluded.archived_at,
                            updated_at = now()
                        """,
                        (user_id, session_id, archived, archived_at or None),
                    )
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)
                raise
        else:
            with self._lock:
                state = self._read_json_state()
                user_metadata = state.setdefault("conversationMetadata", {}).setdefault(user_id, {})
                user_metadata[session_id] = {
                    "archived": archived,
                    "archivedAt": archived_at,
                    "updatedAt": now_iso(),
                }
                self._write_json_state(state)
        detail = self.get_conversation(user_id, session_id)
        detail.pop("exchanges", None)
        return detail

    def delete_conversation(self, user_id: str, session_id: str) -> dict[str, Any]:
        detail = self.get_conversation(user_id, session_id)
        if self._use_postgres():
            try:
                with self._pg_connect() as conn:
                    conn.execute(
                        "delete from secflow_knowledge_conversation_exchanges where user_id = %s and session_id = %s",
                        (user_id, session_id),
                    )
                    conn.execute(
                        "delete from secflow_knowledge_conversations where user_id = %s and session_id = %s",
                        (user_id, session_id),
                    )
                self._replace_postgres_profile(user_id, self.get_history(user_id, limit=self.max_history))
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)
                raise
        else:
            with self._lock:
                state = self._read_json_state()
                users = state.setdefault("users", {})
                history = users.get(user_id, [])
                remaining = [
                    entry
                    for entry in history
                    if str(entry.get("sessionId", "") or "default") != session_id
                ]
                if remaining:
                    users[user_id] = remaining
                else:
                    users.pop(user_id, None)
                user_metadata = state.setdefault("conversationMetadata", {}).get(user_id, {})
                user_metadata.pop(session_id, None)
                if not user_metadata:
                    state["conversationMetadata"].pop(user_id, None)
                profile = self._profile_from_history(user_id, remaining)
                if remaining:
                    state.setdefault("profiles", {})[user_id] = profile
                else:
                    state.setdefault("profiles", {}).pop(user_id, None)
                self._write_json_state(state)
        return {
            "id": session_id,
            "title": detail["title"],
            "deleted": True,
            "deleted_turn_count": detail["turn_count"],
        }

    def build_context(self, user_id: str, question: str) -> dict[str, Any]:
        profile = self._get_profile(user_id)
        history = self.get_history(user_id, limit=self.max_history)
        has_query_tokens = bool(self._tokens(question))
        recent = history[-self.recent_limit :] if has_query_tokens else []
        relevant = self._retrieve_relevant(history, question, self.retrieval_limit) if has_query_tokens else []
        prompt_context = self._format_prompt_context(profile if has_query_tokens else {}, recent, relevant)
        return {
            "enabled": True,
            "backend": self.backend,
            "summary": profile.get("summary", ""),
            "recentHistory": recent,
            "retrievedMemories": relevant,
            "promptContext": prompt_context[: self.context_chars],
            "injectedMessages": self._history_messages(recent),
            "stats": {
                "historyCount": len(history),
                "recentCount": len(recent),
                "retrievedCount": len(relevant),
                "summaryChars": len(profile.get("summary", "")),
            },
        }

    def add_exchange(
        self,
        user_id: str,
        question: str,
        answer_data: dict[str, Any],
        session_id: str = "default",
    ) -> dict[str, Any]:
        entry = self._build_entry(user_id, session_id, question, answer_data)
        if self._use_postgres():
            try:
                stored = self._pg_add_exchange(entry)
                self._pg_update_profile(user_id, stored)
                return deepcopy(stored)
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)
        with self._lock:
            stored = self._json_add_exchange(entry)
            self._json_update_profile(user_id, stored)
            return deepcopy(stored)

    def update_interrupt_exchange(
        self,
        user_id: str,
        session_id: str,
        thread_id: str,
        answer_data: dict[str, Any],
    ) -> bool:
        """Replace the persisted answer for the message that owns a LangGraph thread."""

        clean_thread_id = str(thread_id or "").strip()
        if not clean_thread_id:
            return False
        if self._use_postgres():
            try:
                updated = self._pg_update_interrupt_exchange(
                    user_id,
                    session_id,
                    clean_thread_id,
                    answer_data,
                )
                if updated:
                    self._replace_postgres_profile(user_id, self.get_history(user_id, limit=self.max_history))
                return updated
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)

        with self._lock:
            state = self._read_json_state()
            history = state.setdefault("users", {}).get(user_id, [])
            target_index = next(
                (
                    index
                    for index in range(len(history) - 1, -1, -1)
                    if str(history[index].get("sessionId") or "default") == session_id
                    and str(
                        (((history[index].get("answerPayload") or {}).get("interrupt") or {}).get("thread_id"))
                        or ""
                    )
                    == clean_thread_id
                ),
                None,
            )
            if target_index is None:
                return False
            previous = history[target_index]
            replacement = self._build_entry(
                user_id,
                session_id,
                str(previous.get("question") or ""),
                answer_data,
            )
            replacement["id"] = str(previous.get("id") or "")
            history[target_index] = replacement
            state.setdefault("profiles", {})[user_id] = self._profile_from_history(user_id, history)
            state.setdefault("conversationMetadata", {}).setdefault(user_id, {})[session_id] = {
                "archived": False,
                "archivedAt": "",
                "updatedAt": replacement["timestamp"],
            }
            self._write_json_state(state)
            return True

    def clear_history(self, user_id: str = "default") -> dict[str, Any]:
        if self._use_postgres():
            try:
                with self._pg_connect() as conn:
                    conn.execute("delete from secflow_knowledge_conversation_exchanges where user_id = %s", (user_id,))
                    conn.execute("delete from secflow_knowledge_conversations where user_id = %s", (user_id,))
                    conn.execute("delete from secflow_knowledge_memory_profiles where user_id = %s", (user_id,))
                return {"status": "success", "message": f"已清除用户 {user_id} 的长期记忆。"}
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)
        state = self._read_json_state()
        state.setdefault("users", {}).pop(user_id, None)
        state.setdefault("conversationMetadata", {}).pop(user_id, None)
        state.setdefault("profiles", {}).pop(user_id, None)
        self._write_json_state(state)
        return {"status": "success", "message": f"已清除用户 {user_id} 的本地记忆。"}

    def _use_postgres(self) -> bool:
        if self.local_only:
            return False
        if not self.database_url or psycopg is None:
            return False
        if self._postgres_ready is False:
            return False
        if self._postgres_ready is True:
            return True
        try:
            self._ensure_postgres_schema()
            self._postgres_ready = True
            self._postgres_error = ""
            return True
        except Exception as exc:  # noqa: BLE001
            self._mark_postgres_failed(exc)
            return False

    def _mark_postgres_failed(self, exc: Exception) -> None:
        self._postgres_ready = False
        self._postgres_error = str(exc)[:500]

    def _pg_connect(self):
        assert psycopg is not None
        kwargs: dict[str, Any] = {"autocommit": True}
        if dict_row is not None:
            kwargs["row_factory"] = dict_row
        return psycopg.connect(self.database_url, **kwargs)

    def _ensure_postgres_schema(self) -> None:
        with self._pg_connect() as conn:
            conn.execute(
                """
                create table if not exists secflow_knowledge_conversation_exchanges (
                    id bigserial primary key,
                    user_id text not null,
                    session_id text not null default 'default',
                    question text not null,
                    answer text not null,
                    mode text not null default '',
                    confidence double precision not null default 0,
                    fields jsonb not null default '{}'::jsonb,
                    answer_payload jsonb not null default '{}'::jsonb,
                    sources jsonb not null default '[]'::jsonb,
                    topics jsonb not null default '[]'::jsonb,
                    importance double precision not null default 0,
                    compressed_summary text not null default '',
                    created_at timestamptz not null default now()
                )
                """
            )
            conn.execute(
                """
                alter table secflow_knowledge_conversation_exchanges
                add column if not exists answer_payload jsonb not null default '{}'::jsonb
                """
            )
            conn.execute(
                """
                create table if not exists secflow_knowledge_memory_profiles (
                    user_id text primary key,
                    summary text not null default '',
                    facts jsonb not null default '[]'::jsonb,
                    updated_at timestamptz not null default now()
                )
                """
            )
            conn.execute(
                """
                create table if not exists secflow_knowledge_conversations (
                    user_id text not null,
                    session_id text not null,
                    archived boolean not null default false,
                    archived_at timestamptz,
                    updated_at timestamptz not null default now(),
                    primary key (user_id, session_id)
                )
                """
            )
            conn.execute(
                """
                create index if not exists idx_secflow_knowledge_memory_user_time
                on secflow_knowledge_conversation_exchanges (user_id, created_at desc)
                """
            )
            conn.execute(
                """
                create index if not exists idx_secflow_knowledge_memory_user_importance
                on secflow_knowledge_conversation_exchanges (user_id, importance desc)
                """
            )

    def _pg_fetch_history(self, user_id: str, limit: int) -> list[dict[str, Any]]:
        with self._pg_connect() as conn:
            rows = conn.execute(
                """
                select id, user_id, session_id, question, answer, mode, confidence,
                       fields, answer_payload, sources, topics, importance, compressed_summary, created_at
                from secflow_knowledge_conversation_exchanges
                where user_id = %s
                order by created_at desc, id desc
                limit %s
                """,
                (user_id, limit),
            ).fetchall()
        return list(reversed([dict(row) for row in rows]))

    def _pg_add_exchange(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._pg_connect() as conn:
            row = conn.execute(
                """
                insert into secflow_knowledge_conversation_exchanges
                    (user_id, session_id, question, answer, mode, confidence,
                     fields, answer_payload, sources, topics, importance, compressed_summary)
                values (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)
                returning id, user_id, session_id, question, answer, mode, confidence,
                          fields, answer_payload, sources, topics, importance, compressed_summary, created_at
                """,
                (
                    entry["userId"],
                    entry["sessionId"],
                    entry["question"],
                    entry["answer"],
                    entry["mode"],
                    entry["confidence"],
                    json.dumps(entry["fields"], ensure_ascii=False),
                    json.dumps(entry["answerPayload"], ensure_ascii=False),
                    json.dumps(entry["sources"], ensure_ascii=False),
                    json.dumps(entry["topics"], ensure_ascii=False),
                    entry["importance"],
                    entry["compressedSummary"],
                ),
            ).fetchone()
            conn.execute(
                """
                insert into secflow_knowledge_conversations
                    (user_id, session_id, archived, archived_at, updated_at)
                values (%s, %s, false, null, now())
                on conflict (user_id, session_id) do update set
                    archived = false,
                    archived_at = null,
                    updated_at = now()
                """,
                (entry["userId"], entry["sessionId"]),
            )
        return self._row_to_entry(dict(row))

    def _pg_update_interrupt_exchange(
        self,
        user_id: str,
        session_id: str,
        thread_id: str,
        answer_data: dict[str, Any],
    ) -> bool:
        with self._pg_connect() as conn:
            row = conn.execute(
                """
                select id, question
                from secflow_knowledge_conversation_exchanges
                where user_id = %s and session_id = %s
                  and answer_payload #>> '{interrupt,thread_id}' = %s
                order by created_at desc, id desc
                limit 1
                """,
                (user_id, session_id, thread_id),
            ).fetchone()
            if not row:
                return False
            entry = self._build_entry(user_id, session_id, str(row["question"] or ""), answer_data)
            conn.execute(
                """
                update secflow_knowledge_conversation_exchanges
                set answer = %s, mode = %s, confidence = %s,
                    fields = %s::jsonb, answer_payload = %s::jsonb,
                    sources = %s::jsonb, topics = %s::jsonb,
                    importance = %s, compressed_summary = %s, created_at = now()
                where id = %s and user_id = %s and session_id = %s
                """,
                (
                    entry["answer"],
                    entry["mode"],
                    entry["confidence"],
                    json.dumps(entry["fields"], ensure_ascii=False),
                    json.dumps(entry["answerPayload"], ensure_ascii=False),
                    json.dumps(entry["sources"], ensure_ascii=False),
                    json.dumps(entry["topics"], ensure_ascii=False),
                    entry["importance"],
                    entry["compressedSummary"],
                    row["id"],
                    user_id,
                    session_id,
                ),
            )
            conn.execute(
                """
                update secflow_knowledge_conversations
                set archived = false, archived_at = null, updated_at = now()
                where user_id = %s and session_id = %s
                """,
                (user_id, session_id),
            )
        return True

    def _replace_postgres_profile(self, user_id: str, history: list[dict[str, Any]]) -> None:
        profile = self._profile_from_history(user_id, history)
        with self._pg_connect() as conn:
            if not history:
                conn.execute("delete from secflow_knowledge_memory_profiles where user_id = %s", (user_id,))
                return
            conn.execute(
                """
                insert into secflow_knowledge_memory_profiles (user_id, summary, facts, updated_at)
                values (%s, %s, %s::jsonb, now())
                on conflict (user_id) do update set
                    summary = excluded.summary,
                    facts = excluded.facts,
                    updated_at = now()
                """,
                (user_id, profile["summary"], json.dumps(profile["facts"], ensure_ascii=False)),
            )

    def _pg_update_profile(self, user_id: str, entry: dict[str, Any]) -> None:
        profile = self._get_profile(user_id)
        summary = self._compress_profile(profile.get("summary", ""), entry)
        facts = self._merge_facts(profile.get("facts", []), entry)
        with self._pg_connect() as conn:
            conn.execute(
                """
                insert into secflow_knowledge_memory_profiles (user_id, summary, facts, updated_at)
                values (%s, %s, %s::jsonb, now())
                on conflict (user_id) do update set
                    summary = excluded.summary,
                    facts = excluded.facts,
                    updated_at = now()
                """,
                (user_id, summary, json.dumps(facts, ensure_ascii=False)),
            )

    def _pg_get_profile(self, user_id: str) -> dict[str, Any] | None:
        with self._pg_connect() as conn:
            row = conn.execute(
                "select user_id, summary, facts, updated_at from secflow_knowledge_memory_profiles where user_id = %s",
                (user_id,),
            ).fetchone()
        if not row:
            return None
        data = dict(row)
        return {
            "userId": data.get("user_id", user_id),
            "summary": data.get("summary", ""),
            "facts": self._json_value(data.get("facts"), []),
            "updatedAt": self._time_text(data.get("updated_at")),
        }

    def _json_add_exchange(self, entry: dict[str, Any]) -> dict[str, Any]:
        state = self._read_json_state()
        users = state.setdefault("users", {})
        history = users.setdefault(entry["userId"], [])
        entry = deepcopy(entry)
        entry["id"] = f"msg-{len(history) + 1:04d}"
        history.append(entry)
        if len(history) > self.max_history:
            users[entry["userId"]] = history[-self.max_history :]
        state.setdefault("conversationMetadata", {}).setdefault(entry["userId"], {})[entry["sessionId"]] = {
            "archived": False,
            "archivedAt": "",
            "updatedAt": now_iso(),
        }
        self._write_json_state(state)
        return entry

    def _json_update_profile(self, user_id: str, entry: dict[str, Any]) -> None:
        state = self._read_json_state()
        profiles = state.setdefault("profiles", {})
        profile = profiles.setdefault(user_id, {"userId": user_id, "summary": "", "facts": [], "updatedAt": ""})
        profile["summary"] = self._compress_profile(profile.get("summary", ""), entry)
        profile["facts"] = self._merge_facts(profile.get("facts", []), entry)
        profile["updatedAt"] = now_iso()
        self._write_json_state(state)

    def _read_json_state(self) -> dict[str, Any]:
        with self._lock:
            if self.state_path.exists():
                try:
                    raw = self.state_path.read_text(encoding="utf-8")
                    state = decrypt_json_from_text(raw, MEMORY_PURPOSE)
                    if not isinstance(state, dict):
                        raise ValueError("memory payload is not an object")
                    state.setdefault("users", {})
                    state.setdefault("profiles", {})
                    state.setdefault("conversationMetadata", {})
                    if not raw.lstrip().startswith('{"__secflow_encrypted__"'):
                        self._write_json_state(state)
                    return state
                except (InvalidTag, json.JSONDecodeError, OSError, ValueError):
                    pass
            state: dict[str, Any] = {"users": {}, "profiles": {}, "conversationMetadata": {}}
            self._write_json_state(state)
            return state

    def _write_json_state(self, state: dict[str, Any]) -> None:
        with self._lock:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_name(f"{self.state_path.name}.tmp")
            tmp.write_text(encrypt_json_to_text(state, MEMORY_PURPOSE), encoding="utf-8")
            os.replace(tmp, self.state_path)

    def _get_profile(self, user_id: str) -> dict[str, Any]:
        if self._use_postgres():
            try:
                profile = self._pg_get_profile(user_id)
                if profile:
                    return profile
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)
        state = self._read_json_state()
        return deepcopy(state.setdefault("profiles", {}).get(user_id, {"userId": user_id, "summary": "", "facts": [], "updatedAt": ""}))

    def _conversation_metadata(self, user_id: str) -> dict[str, dict[str, Any]]:
        if self._use_postgres():
            try:
                with self._pg_connect() as conn:
                    rows = conn.execute(
                        """
                        select session_id, archived, archived_at, updated_at
                        from secflow_knowledge_conversations
                        where user_id = %s
                        """,
                        (user_id,),
                    ).fetchall()
                return {
                    str(row["session_id"]): {
                        "archived": bool(row.get("archived", False)),
                        "archivedAt": self._time_text(row.get("archived_at")) if row.get("archived_at") else "",
                        "updatedAt": self._time_text(row.get("updated_at")),
                    }
                    for row in rows
                }
            except Exception as exc:  # noqa: BLE001
                self._mark_postgres_failed(exc)
        state = self._read_json_state()
        value = state.setdefault("conversationMetadata", {}).get(user_id, {})
        return deepcopy(value) if isinstance(value, dict) else {}

    def _profile_from_history(self, user_id: str, history: list[dict[str, Any]]) -> dict[str, Any]:
        summary = ""
        facts: list[dict[str, Any]] = []
        for entry in history:
            summary = self._compress_profile(summary, entry)
            facts = self._merge_facts(facts, entry)
        return {
            "userId": user_id,
            "summary": summary,
            "facts": facts,
            "updatedAt": now_iso(),
        }

    def _build_entry(self, user_id: str, session_id: str, question: str, answer_data: dict[str, Any]) -> dict[str, Any]:
        answer = str(answer_data.get("summary", "") or answer_data.get("answer", "") or "")
        topics = self._extract_topics(f"{question}\n{answer}")
        fields = deepcopy(answer_data.get("fields", {}) or {})
        answer_payload = {
            key: deepcopy(answer_data[key])
            for key in (
                "mode",
                "summary",
                "fields",
                "vulnerability_card",
                "knowledge_graph",
                "evidence_sources",
                "chart_data",
                "artifacts",
                "report",
                "interrupt",
                "token_usage",
                "confidence",
                "trace",
                "generated_at",
            )
            if key in answer_data
        }
        sources: list[dict[str, Any]] = []
        confidence = float(answer_data.get("confidence", 0) or 0)
        mode = str(answer_data.get("mode", "") or "")
        importance = self._importance_score(question, answer, mode, confidence, topics, sources)
        return {
            "id": "",
            "userId": user_id or "default",
            "sessionId": session_id or "default",
            "question": question,
            "answer": answer,
            "mode": mode,
            "confidence": confidence,
            "fields": fields,
            "answerPayload": answer_payload,
            "sources": sources,
            "topics": topics,
            "importance": importance,
            "compressedSummary": self._summarize_exchange(question, answer, topics),
            "timestamp": now_iso(),
        }

    def _retrieve_relevant(self, history: list[dict[str, Any]], question: str, limit: int) -> list[dict[str, Any]]:
        query_tokens = set(self._tokens(question))
        if not query_tokens:
            return []
        scored: list[tuple[float, dict[str, Any]]] = []
        total = max(len(history), 1)
        for index, entry in enumerate(history):
            text = " ".join(
                [
                    str(entry.get("question", "")),
                    str(entry.get("answer", "")),
                    " ".join(entry.get("topics", []) or []),
                    str(entry.get("compressedSummary", "")),
                ]
            )
            tokens = set(self._tokens(text))
            overlap = len(query_tokens & tokens)
            if overlap <= 0:
                continue
            lexical = overlap / math.sqrt(max(len(tokens), 1))
            recency = (index + 1) / total
            score = lexical * 0.68 + float(entry.get("importance", 0) or 0) * 0.22 + recency * 0.10
            compact = self._compact_entry(entry)
            compact["relevance"] = round(score, 4)
            scored.append((score, compact))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [entry for _score, entry in scored[:limit]]

    def _format_prompt_context(
        self,
        profile: dict[str, Any],
        recent: list[dict[str, Any]],
        relevant: list[dict[str, Any]],
    ) -> str:
        sections: list[str] = []
        summary = str(profile.get("summary", "") or "").strip()
        if summary:
            sections.append(f"长期记忆摘要：\n{summary}")
        if relevant:
            lines = []
            for idx, entry in enumerate(relevant, 1):
                lines.append(
                    f"{idx}. {entry.get('compressedSummary') or entry.get('question', '')} "
                    f"重要性 {float(entry.get('importance', 0) or 0):.2f}"
                )
            sections.append("跨会话相关记忆：\n" + "\n".join(lines))
        if recent:
            lines = []
            for entry in recent[-4:]:
                lines.append(f"用户：{self._clip(entry.get('question', ''), 220)}")
                lines.append(f"助手：{self._clip(entry.get('answer', ''), 320)}")
            sections.append("最近对话：\n" + "\n".join(lines))
        return "\n\n".join(sections)

    def _history_messages(self, recent: list[dict[str, Any]]) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        for entry in recent[-3:]:
            question = self._clip(entry.get("question", ""), 260)
            answer = self._clip(entry.get("answer", ""), 420)
            if question:
                messages.append({"role": "user", "content": f"历史问题：{question}"})
            if answer:
                messages.append({"role": "assistant", "content": f"历史回答摘要：{answer}"})
        return messages

    def _compress_profile(self, current_summary: str, entry: dict[str, Any]) -> str:
        candidate = "\n".join(part for part in [current_summary.strip(), entry.get("compressedSummary", "")] if part)
        lines = [line.strip() for line in candidate.splitlines() if line.strip()]
        deduped: list[str] = []
        seen: set[str] = set()
        for line in reversed(lines):
            key = line[:120]
            if key in seen:
                continue
            seen.add(key)
            deduped.append(line)
            if len("\n".join(reversed(deduped))) >= 1800:
                break
        return "\n".join(reversed(deduped))[-1800:]

    def _merge_facts(self, current_facts: list[Any], entry: dict[str, Any]) -> list[dict[str, Any]]:
        facts = [fact for fact in current_facts if isinstance(fact, dict)]
        for topic in entry.get("topics", [])[:6]:
            facts.append({"topic": topic, "importance": entry.get("importance", 0), "seenAt": entry.get("timestamp", now_iso())})
        facts.sort(key=lambda item: float(item.get("importance", 0) or 0), reverse=True)
        unique: list[dict[str, Any]] = []
        seen: set[str] = set()
        for fact in facts:
            topic = str(fact.get("topic", ""))
            if not topic or topic in seen:
                continue
            seen.add(topic)
            unique.append(fact)
            if len(unique) >= 24:
                break
        return unique

    def _importance_score(
        self,
        question: str,
        answer: str,
        mode: str,
        confidence: float,
        topics: list[str],
        sources: list[dict[str, Any]],
    ) -> float:
        text = f"{question}\n{answer}".lower()
        score = 0.18 + min(max(confidence, 0.0), 1.0) * 0.22
        if mode in {"vulnerability_lookup", "vulnerability_year_lookup", "llm_rag", "security_knowledge"}:
            score += 0.14
        if any(topic in {"CVE", "GHSA", "供应链", "代码审计", "威胁建模"} for topic in topics):
            score += 0.18
        if re.search(r"记住|以后|偏好|我是|我的|负责|团队|部门|项目|资产|配置", text):
            score += 0.18
        if len(question) > 60:
            score += 0.06
        score += min(len(sources), 4) * 0.025
        return round(min(score, 1.0), 3)

    def _summarize_exchange(self, question: str, answer: str, topics: list[str]) -> str:
        topic_text = "、".join(topics[:4]) if topics else "通用安全"
        return f"[{topic_text}] 用户问：{self._clip(question, 180)}；助手答：{self._clip(answer, 260)}"

    def _extract_topics(self, text: str) -> list[str]:
        topics = [name for name, pattern in self._topic_rules.items() if pattern.search(text)]
        explicit = re.findall(r"\b(?:CVE-\d{4}-\d{4,8}|GHSA-[a-z0-9-]+|CWE-\d+)\b", text, flags=re.I)
        topics.extend(item.upper() for item in explicit[:6])
        unique: list[str] = []
        for topic in topics:
            if topic not in unique:
                unique.append(topic)
        return unique[:12]

    def _tokens(self, text: str) -> list[str]:
        lowered = str(text or "").lower()
        tokens = re.findall(r"cve-\d{4}-\d{4,8}|ghsa-[a-z0-9-]+|cwe-\d+|[a-z][a-z0-9_.+-]{1,}", lowered)
        tokens.extend(re.findall(r"[\u4e00-\u9fff]{2,}", lowered))
        chinese = "".join(re.findall(r"[\u4e00-\u9fff]", lowered))
        tokens.extend(chinese[index : index + 2] for index in range(max(0, len(chinese) - 1)))
        return [token for token in tokens if token.strip()]

    def _compact_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        compact = deepcopy(entry)
        compact["question"] = self._clip(compact.get("question", ""), 240)
        compact["answer"] = self._clip(compact.get("answer", ""), 360)
        compact["fields"] = {}
        compact["answerPayload"] = {}
        compact["sources"] = compact.get("sources", [])[:3]
        return compact

    def _row_to_entry(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": f"msg-{row.get('id')}",
            "userId": row.get("user_id", "default"),
            "sessionId": row.get("session_id", "default"),
            "question": row.get("question", ""),
            "answer": row.get("answer", ""),
            "mode": row.get("mode", ""),
            "confidence": float(row.get("confidence", 0) or 0),
            "fields": self._json_value(row.get("fields"), {}),
            "answerPayload": self._json_value(row.get("answer_payload"), {}),
            "sources": self._json_value(row.get("sources"), []),
            "topics": self._json_value(row.get("topics"), []),
            "importance": float(row.get("importance", 0) or 0),
            "compressedSummary": row.get("compressed_summary", ""),
            "timestamp": self._time_text(row.get("created_at")),
        }

    @staticmethod
    def _json_value(value: Any, default: Any) -> Any:
        if value is None:
            return deepcopy(default)
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return deepcopy(default)
        return deepcopy(value)

    @staticmethod
    def _time_text(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat(timespec="seconds")
        return str(value or now_iso())

    @staticmethod
    def _clip(value: Any, limit: int) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 1)].rstrip() + "..."


memory_service = LongTermMemoryService()
