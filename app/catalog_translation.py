from __future__ import annotations

import re
import time
from copy import deepcopy
from threading import Lock
from typing import Any

from app.agent.translation_policy import translation_audit_is_publishable
from app.storage import now_iso


CATALOG_TRANSLATION_VERSION = 3
CATALOG_TRANSLATION_LANGUAGE = "zh-Hans"
_ZH_TITLE_UNAVAILABLE = "中文标题暂不可用"
_ZH_SUMMARY_UNAVAILABLE = "中文翻译暂不可用，请稍后重试。"
_ZH_HANT_TITLE_UNAVAILABLE = "中文標題暫不可用"
_ZH_HANT_SUMMARY_UNAVAILABLE = "中文翻譯暫不可用，請稍後重試。"
_CJK = re.compile(r"[\u3400-\u9fff]")
_MACHINE_TITLE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,8}|GHSA-[A-Za-z0-9-]+|[A-Za-z0-9_.@/+:-]+)$",
    flags=re.IGNORECASE,
)
_TRANSLATION_RETRY_SECONDS = 30.0
_translation_backoff_until = 0.0
_translation_backoff_lock = Lock()


def translate_records_for_storage(
    records: list[dict[str, Any]],
    *,
    user_id: str = "default",
    session_id: str = "catalog-ingest",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Translate vulnerability display text once, before it is persisted.

    Original upstream text remains in ``*_original`` fields for audit and
    English output.  A translation outage never drops verified vulnerability
    facts: the record is stored with a ``pending`` marker and can be retried by
    a later upsert.
    """

    prepared = [_prepare_record(record) for record in records if isinstance(record, dict)]
    simplified_pending = [
        index for index, record in enumerate(prepared) if not record_translation_ready(record, "zh-Hans")
    ]
    traditional_pending = [
        index for index, record in enumerate(prepared) if not record_translation_ready(record, "zh-Hant")
    ]
    if not simplified_pending and not traditional_pending:
        return prepared, _aggregate_audit(prepared, invoked=False)

    retry_after = _translation_backoff_remaining()
    if retry_after > 0:
        return prepared, _aggregate_audit(
            prepared,
            invoked=False,
            tool_audit={
                "translation_status": "deferred",
                "retry_after_seconds": round(retry_after, 1),
                "warnings": ["离线翻译资源暂时不可用，后台目录任务稍后重试。"],
            },
        )

    tool_audit: dict[str, Any] = {}
    invoked = False
    if simplified_pending:
        translated_by_key, tool_audit = _translate_catalog_fields(
            prepared,
            simplified_pending,
            target_language="zh-Hans",
            title_field="title_original",
            summary_field="summary_original",
            user_id=user_id,
            session_id=session_id,
            content_scope="vulnerability_catalog_ingest_simplified",
        )
        invoked = True
        translated_at = now_iso()
        tool_status = str(tool_audit.get("translation_status") or "fallback")
        tool_publishable = _agent_audit_is_publishable(tool_audit, "zh-Hans")
        for index in simplified_pending:
            record = prepared[index]
            row = translated_by_key.get(str(record.get("id") or index), {})
            original_title = str(record.get("title_original") or "").strip()
            original_summary = str(record.get("summary_original") or "").strip()
            record["title_zh"] = _accepted_title(str(row.get("title") or "").strip(), original_title)
            record["summary_zh"] = _accepted_summary(str(row.get("summary") or "").strip(), original_summary)
            record["catalog_translation"] = {
                "version": CATALOG_TRANSLATION_VERSION,
                "target_language": CATALOG_TRANSLATION_LANGUAGE,
                "status": "passthrough" if tool_status == "passthrough" else "translated",
                "translated_at": translated_at,
                "source_title": original_title,
                "source_summary": original_summary,
                **tool_audit,
            }
            if (
                not tool_publishable
                or tool_status not in {"translated", "passthrough"}
                or not record_translation_ready(record)
            ):
                record["catalog_translation"]["status"] = "pending"
                record["catalog_translation"]["translated_at"] = ""

    traditional_pending = [
        index
        for index, record in enumerate(prepared)
        if record_translation_ready(record, "zh-Hans")
        and not record_translation_ready(record, "zh-Hant")
    ]
    traditional_audit: dict[str, Any] = {}
    if traditional_pending:
        traditional_by_key, traditional_audit = _translate_catalog_fields(
            prepared,
            traditional_pending,
            target_language="zh-Hant",
            title_field="title_zh",
            summary_field="summary_zh",
            user_id=user_id,
            session_id=session_id,
            content_scope="vulnerability_catalog_ingest_traditional",
        )
        invoked = True
        traditional_at = now_iso()
        traditional_tool_status = str(traditional_audit.get("translation_status") or "fallback")
        traditional_publishable = _agent_audit_is_publishable(traditional_audit, "zh-Hant")
        for index in traditional_pending:
            record = prepared[index]
            row = traditional_by_key.get(str(record.get("id") or index), {})
            source_title = str(record.get("title_zh") or "").strip()
            source_summary = str(record.get("summary_zh") or "").strip()
            record["title_zh_hant"] = _accepted_title(
                str(row.get("title") or "").strip(),
                source_title,
            )
            record["summary_zh_hant"] = _accepted_summary(
                str(row.get("summary") or "").strip(),
                source_summary,
            )
            audit_record = dict(record.get("catalog_translation") or {})
            audit_record.update(
                {
                    "version": CATALOG_TRANSLATION_VERSION,
                    "source_title": str(record.get("title_original") or ""),
                    "source_summary": str(record.get("summary_original") or ""),
                    "traditional_status": (
                        "passthrough" if traditional_tool_status == "passthrough" else "translated"
                    ),
                    "traditional_translated_at": traditional_at,
                    "traditional_translation": dict(traditional_audit),
                }
            )
            record["catalog_translation"] = audit_record
            if (
                not traditional_publishable
                or traditional_tool_status not in {"translated", "passthrough"}
                or not record_translation_ready(record, "zh-Hant")
            ):
                audit_record["traditional_status"] = "pending"
                audit_record["traditional_translated_at"] = ""

    audit = _aggregate_audit(prepared, invoked=invoked, tool_audit=tool_audit)
    audit["traditional_translation"] = traditional_audit
    all_languages_ready = not int(audit.get("pending_records") or 0) and not int(
        audit.get("traditional_pending_records") or 0
    )
    if all_languages_ready:
        _clear_translation_backoff()
    elif _offline_runtime_unavailable(tool_audit) or _offline_runtime_unavailable(traditional_audit):
        _open_translation_backoff()
    return prepared, audit


def _translate_catalog_fields(
    records: list[dict[str, Any]],
    indexes: list[int],
    *,
    target_language: str,
    title_field: str,
    summary_field: str,
    user_id: str,
    session_id: str,
    content_scope: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    payload = {
        "records": [
            {
                "record_key": str(records[index].get("id") or index),
                "title": str(records[index].get(title_field) or ""),
                "summary": str(records[index].get(summary_field) or ""),
            }
            for index in indexes
        ]
    }
    try:
        from app.agent.translation_agent import translation_agent

        result = translation_agent.translate_json(
            payload,
            target_language=target_language,
            user_id=user_id,
            session_id=session_id,
            content_scope=content_scope,
        )
        audit = dict(result.audit)
        publishable = (
            translation_audit_is_publishable(audit)
            and audit.get("target_language") == target_language
        )
        translated_rows = list(result.payload.get("records") or []) if publishable else []
        audit["publication_status"] = "published" if publishable else "blocked"
        audit["agent_status"] = str(audit.pop("status", "failed"))
        audit["mcp_runtime"] = dict(audit.get("runtime") or {})
    except Exception as exc:  # noqa: BLE001 - verified facts must remain storable.
        translated_rows = []
        audit = {
            "translation_status": "unavailable",
            "target_language": target_language,
            "warnings": [str(exc)[:300]],
        }
    return (
        {
            str(row.get("record_key") or ""): row
            for row in translated_rows
            if isinstance(row, dict)
        },
        audit,
    )


def record_translation_ready(record: dict[str, Any], language: str = CATALOG_TRANSLATION_LANGUAGE) -> bool:
    requested = str(language or "").strip()
    if requested == "en":
        return True
    if requested not in {CATALOG_TRANSLATION_LANGUAGE, "zh-Hant"}:
        return False
    original_summary = str(record.get("summary_original") or record.get("summary") or "").strip()
    summary_field = "summary_zh_hant" if requested == "zh-Hant" else "summary_zh"
    title_field = "title_zh_hant" if requested == "zh-Hant" else "title_zh"
    localized_summary = str(record.get(summary_field) or "").strip()
    if original_summary and not _CJK.search(localized_summary):
        return False
    original_title = str(record.get("title_original") or record.get("title") or "").strip()
    localized_title = str(record.get(title_field) or "").strip()
    if (
        original_title
        and not _MACHINE_TITLE.fullmatch(original_title)
        and not _CJK.search(localized_title)
    ):
        return False
    return _stored_translation_audit_is_publishable(record, requested)


def records_translation_ready(records: list[dict[str, Any]], language: str = CATALOG_TRANSLATION_LANGUAGE) -> bool:
    return bool(records) and all(record_translation_ready(record, language) for record in records)


def record_title_for_language(record: dict[str, Any], language: str) -> str:
    requested = str(language or "").strip()
    if requested in {CATALOG_TRANSLATION_LANGUAGE, "zh-Hant"}:
        field = "title_zh_hant" if requested == "zh-Hant" else "title_zh"
        localized = str(record.get(field) or "").strip() if record_translation_ready(record, requested) else ""
        if localized:
            return localized
        original = str(record.get("title_original") or record.get("title") or "").strip()
        if original and _MACHINE_TITLE.fullmatch(original):
            return original
        return _ZH_HANT_TITLE_UNAVAILABLE if requested == "zh-Hant" else _ZH_TITLE_UNAVAILABLE
    return str(record.get("title_original") or record.get("title") or "")


def record_summary_for_language(record: dict[str, Any], language: str) -> str:
    requested = str(language or "").strip()
    if requested in {CATALOG_TRANSLATION_LANGUAGE, "zh-Hant"}:
        field = "summary_zh_hant" if requested == "zh-Hant" else "summary_zh"
        localized = str(record.get(field) or "").strip() if record_translation_ready(record, requested) else ""
        if localized:
            return localized
        original = str(record.get("summary_original") or record.get("summary") or "").strip()
        if not original:
            return ""
        return _ZH_HANT_SUMMARY_UNAVAILABLE if requested == "zh-Hant" else _ZH_SUMMARY_UNAVAILABLE
    return str(record.get("summary_original") or record.get("summary") or "")


def _prepare_record(record: dict[str, Any]) -> dict[str, Any]:
    item = deepcopy(record)
    original_title = str(item.get("title_original") or item.get("title") or "").strip()
    original_summary = str(item.get("summary_original") or item.get("summary") or "").strip()
    item["title_original"] = original_title
    item["summary_original"] = original_summary

    audit = item.get("catalog_translation") if isinstance(item.get("catalog_translation"), dict) else {}
    if _source_text_changed(item, audit):
        item.pop("title_zh", None)
        item.pop("summary_zh", None)
        item.pop("title_zh_hant", None)
        item.pop("summary_zh_hant", None)
        audit = {}

    if audit and not record_translation_ready(item, "zh-Hans"):
        item.pop("title_zh", None)
        item.pop("summary_zh", None)
        item.pop("title_zh_hant", None)
        item.pop("summary_zh_hant", None)
        audit = {}
    elif audit and not record_translation_ready(item, "zh-Hant"):
        item.pop("title_zh_hant", None)
        item.pop("summary_zh_hant", None)
        audit = dict(audit)
        audit.pop("traditional_translation", None)
        audit["traditional_status"] = "pending"
        audit["traditional_translated_at"] = ""

    no_translation_needed = _no_translation_needed(original_title, original_summary)
    if not audit and no_translation_needed:
        item["title_zh"] = original_title
        item["summary_zh"] = ""
        item["title_zh_hant"] = original_title
        item["summary_zh_hant"] = ""
        audit = {
            "version": CATALOG_TRANSLATION_VERSION,
            "target_language": CATALOG_TRANSLATION_LANGUAGE,
            "status": "passthrough",
            "translated_at": now_iso(),
            "traditional_status": "passthrough",
            "traditional_translated_at": now_iso(),
            "storage_stage": "no-content-passthrough",
        }
    if audit:
        audit = dict(audit)
        audit["source_title"] = original_title
        audit["source_summary"] = original_summary
        item["catalog_translation"] = audit
    return item


def _source_text_changed(record: dict[str, Any], audit: dict[str, Any]) -> bool:
    if not audit:
        return False
    return str(audit.get("source_title") or "") != str(record.get("title_original") or "") or str(
        audit.get("source_summary") or ""
    ) != str(record.get("summary_original") or "")


def _no_translation_needed(title: str, summary: str) -> bool:
    return not summary and (not title or bool(_MACHINE_TITLE.fullmatch(title)))


def _agent_audit_is_publishable(audit: Any, target_language: str) -> bool:
    if not isinstance(audit, dict):
        return False
    agent_audit = dict(audit)
    if "agent_status" in agent_audit:
        agent_audit["status"] = agent_audit.get("agent_status")
    return (
        agent_audit.get("target_language") == target_language
        and translation_audit_is_publishable(agent_audit)
    )


def _stored_translation_audit_is_publishable(record: dict[str, Any], language: str) -> bool:
    audit = record.get("catalog_translation")
    if not isinstance(audit, dict):
        return False
    if type(audit.get("version")) is not int or audit["version"] < CATALOG_TRANSLATION_VERSION:
        return False

    original_title = str(record.get("title_original") or record.get("title") or "").strip()
    original_summary = str(record.get("summary_original") or record.get("summary") or "").strip()
    if str(audit.get("source_title") or "") != original_title:
        return False
    if str(audit.get("source_summary") or "") != original_summary:
        return False

    no_translation_needed = _no_translation_needed(original_title, original_summary)
    if no_translation_needed:
        return (
            audit.get("storage_stage") == "no-content-passthrough"
            and audit.get("status") == "passthrough"
            and (
                language == "zh-Hans"
                or audit.get("traditional_status") == "passthrough"
            )
        )

    if audit.get("status") not in {"translated", "passthrough"}:
        return False
    simplified_audit = (
        audit.get("translation_agent")
        if isinstance(audit.get("translation_agent"), dict)
        else audit
    )
    if not _agent_audit_is_publishable(simplified_audit, "zh-Hans"):
        return False
    if language == "zh-Hans":
        return True
    if audit.get("traditional_status") not in {"translated", "passthrough"}:
        return False
    return _agent_audit_is_publishable(audit.get("traditional_translation"), "zh-Hant")


def _accepted_title(translated: str, original: str) -> str:
    if _CJK.search(translated):
        return translated
    if original and _CJK.search(original):
        return ""
    # Product names and vulnerability identifiers are intentionally allowed to
    # remain unchanged; the descriptive summary is the readiness gate.
    if not original or _MACHINE_TITLE.fullmatch(original):
        return original
    return ""


def _accepted_summary(translated: str, original: str) -> str:
    if not original:
        return ""
    return translated if _CJK.search(translated) else ""


def _aggregate_audit(
    records: list[dict[str, Any]],
    *,
    invoked: bool,
    tool_audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ready = sum(record_translation_ready(record) for record in records)
    traditional_ready = sum(record_translation_ready(record, "zh-Hant") for record in records)
    return {
        **dict(tool_audit or {}),
        "target_language": CATALOG_TRANSLATION_LANGUAGE,
        "status": "completed" if ready == len(records) else "partial",
        "ready_records": ready,
        "pending_records": len(records) - ready,
        "traditional_ready_records": traditional_ready,
        "traditional_pending_records": len(records) - traditional_ready,
        "record_count": len(records),
        "invoked": invoked,
    }


def _offline_runtime_unavailable(tool_audit: dict[str, Any]) -> bool:
    return str(tool_audit.get("translation_status") or "") == "unavailable"


def _translation_backoff_remaining() -> float:
    with _translation_backoff_lock:
        return max(0.0, _translation_backoff_until - time.monotonic())


def _open_translation_backoff() -> None:
    global _translation_backoff_until
    with _translation_backoff_lock:
        _translation_backoff_until = max(
            _translation_backoff_until,
            time.monotonic() + _TRANSLATION_RETRY_SECONDS,
        )


def _clear_translation_backoff() -> None:
    global _translation_backoff_until
    with _translation_backoff_lock:
        _translation_backoff_until = 0.0


__all__ = [
    "CATALOG_TRANSLATION_LANGUAGE",
    "CATALOG_TRANSLATION_VERSION",
    "record_summary_for_language",
    "record_title_for_language",
    "record_translation_ready",
    "records_translation_ready",
    "translate_records_for_storage",
]
