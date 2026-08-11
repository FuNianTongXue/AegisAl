from __future__ import annotations

import os
import re
import time
from copy import deepcopy
from threading import Lock
from typing import Any

from app.storage import now_iso


CATALOG_TRANSLATION_VERSION = 1
CATALOG_TRANSLATION_LANGUAGE = "zh-Hans"
_CJK = re.compile(r"[\u3400-\u9fff]")
_MACHINE_TITLE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,8}|GHSA-[A-Za-z0-9-]+|[A-Za-z0-9_.@/+:-]+)$",
    flags=re.IGNORECASE,
)
_PROVIDER_FAILURE = re.compile(
    r"(?:\b(?:401|402|403|429)\b|payment required|insufficient (?:balance|credit)|"
    r"unauthorized|forbidden|rate.?limit|connection (?:refused|reset)|timed?\s*out)",
    flags=re.IGNORECASE,
)
try:
    _TRANSLATION_BACKOFF_SECONDS = max(
        30.0,
        float(os.getenv("SECFLOW_CATALOG_TRANSLATION_BACKOFF_SECONDS", "300") or 300),
    )
except ValueError:
    _TRANSLATION_BACKOFF_SECONDS = 300.0
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
    pending_indexes = [index for index, record in enumerate(prepared) if not record_translation_ready(record)]
    if not pending_indexes:
        return prepared, _aggregate_audit(prepared, invoked=False)

    retry_after = _translation_backoff_remaining()
    if retry_after > 0:
        return prepared, _aggregate_audit(
            prepared,
            invoked=False,
            tool_audit={
                "translation_status": "deferred",
                "retry_after_seconds": round(retry_after, 1),
                "warnings": ["翻译服务暂时退避，避免后台目录任务重复占用模型连接。"],
            },
        )

    payload = {
        "records": [
            {
                "record_key": str(prepared[index].get("id") or index),
                "title": str(prepared[index].get("title_original") or ""),
                "summary": str(prepared[index].get("summary_original") or ""),
            }
            for index in pending_indexes
        ]
    }
    tool_audit: dict[str, Any] = {}
    try:
        # Local import keeps catalog startup independent from the MCP runtime
        # until an untranslated record actually needs to be stored.
        from app.mcp.translation import translate_json_payload

        outcome = translate_json_payload(
            payload,
            target_language=CATALOG_TRANSLATION_LANGUAGE,
            user_id=user_id,
            session_id=session_id,
            content_scope="vulnerability_catalog_ingest",
        )
        translated_rows = list((outcome.payload or {}).get("records") or [])
        tool_audit = {
            "translation_status": outcome.translation_status,
            "candidate_fields": outcome.candidate_fields,
            "translated_fields": outcome.translated_fields,
            "batch_count": outcome.batch_count,
            "model_used": outcome.model_used,
            "input_sha256": outcome.input_sha256,
            "output_sha256": outcome.output_sha256,
            "warnings": list(outcome.errors or []),
        }
    except Exception as exc:  # noqa: BLE001 - verified facts must remain storable.
        translated_rows = []
        tool_audit = {"translation_status": "fallback", "warnings": [str(exc)[:300]]}

    translated_by_key = {
        str(row.get("record_key") or ""): row
        for row in translated_rows
        if isinstance(row, dict)
    }
    translated_at = now_iso()
    for index in pending_indexes:
        record = prepared[index]
        row = translated_by_key.get(str(record.get("id") or index), {})
        original_title = str(record.get("title_original") or "").strip()
        original_summary = str(record.get("summary_original") or "").strip()
        translated_title = str(row.get("title") or "").strip()
        translated_summary = str(row.get("summary") or "").strip()

        record["title_zh"] = _accepted_title(translated_title, original_title)
        record["summary_zh"] = _accepted_summary(translated_summary, original_summary)
        record["catalog_translation"] = {
            "version": CATALOG_TRANSLATION_VERSION,
            "target_language": CATALOG_TRANSLATION_LANGUAGE,
            "status": "translated",
            "translated_at": translated_at,
            "source_title": original_title,
            "source_summary": original_summary,
            **tool_audit,
        }
        ready = record_translation_ready(record)
        if not ready:
            record["catalog_translation"]["status"] = "pending"
            record["catalog_translation"]["translated_at"] = ""

    audit = _aggregate_audit(prepared, invoked=True, tool_audit=tool_audit)
    if int(audit.get("pending_records") or 0) == 0:
        _clear_translation_backoff()
    elif _is_provider_failure(tool_audit):
        _open_translation_backoff()
    return prepared, audit


def record_translation_ready(record: dict[str, Any], language: str = CATALOG_TRANSLATION_LANGUAGE) -> bool:
    if str(language or "").strip() != CATALOG_TRANSLATION_LANGUAGE:
        return False
    original_summary = str(record.get("summary_original") or record.get("summary") or "").strip()
    summary_zh = str(record.get("summary_zh") or "").strip()
    if original_summary and not _CJK.search(original_summary) and not _CJK.search(summary_zh):
        return False
    original_title = str(record.get("title_original") or record.get("title") or "").strip()
    title_zh = str(record.get("title_zh") or "").strip()
    if (
        not original_summary
        and original_title
        and not _CJK.search(original_title)
        and not _MACHINE_TITLE.fullmatch(original_title)
        and not _CJK.search(title_zh)
    ):
        return False
    audit = record.get("catalog_translation") if isinstance(record.get("catalog_translation"), dict) else {}
    return int(audit.get("version") or 0) >= CATALOG_TRANSLATION_VERSION and str(audit.get("status") or "") in {
        "translated",
        "passthrough",
    }


def records_translation_ready(records: list[dict[str, Any]], language: str = CATALOG_TRANSLATION_LANGUAGE) -> bool:
    return bool(records) and all(record_translation_ready(record, language) for record in records)


def record_title_for_language(record: dict[str, Any], language: str) -> str:
    if str(language or "").strip() == CATALOG_TRANSLATION_LANGUAGE:
        return str(record.get("title_zh") or record.get("title") or "")
    return str(record.get("title_original") or record.get("title") or "")


def record_summary_for_language(record: dict[str, Any], language: str) -> str:
    if str(language or "").strip() == CATALOG_TRANSLATION_LANGUAGE:
        return str(record.get("summary_zh") or record.get("summary") or "")
    return str(record.get("summary_original") or record.get("summary") or "")


def _prepare_record(record: dict[str, Any]) -> dict[str, Any]:
    item = deepcopy(record)
    original_title = str(item.get("title_original") or item.get("title") or "").strip()
    original_summary = str(item.get("summary_original") or item.get("summary") or "").strip()
    item["title_original"] = original_title
    item["summary_original"] = original_summary

    if _CJK.search(original_title):
        item["title_zh"] = original_title
    if _CJK.search(original_summary):
        item["summary_zh"] = original_summary

    audit = item.get("catalog_translation") if isinstance(item.get("catalog_translation"), dict) else {}
    if _source_text_changed(item, audit):
        item.pop("title_zh", None)
        item.pop("summary_zh", None)
        audit = {}
        if _CJK.search(original_title):
            item["title_zh"] = original_title
        if _CJK.search(original_summary):
            item["summary_zh"] = original_summary

    title_is_ready = (
        bool(_CJK.search(original_title))
        or not original_title
        or bool(_MACHINE_TITLE.fullmatch(original_title))
        or bool(original_summary)
    )
    if not audit and (not original_summary or _CJK.search(original_summary)) and title_is_ready:
        audit = {
            "version": CATALOG_TRANSLATION_VERSION,
            "target_language": CATALOG_TRANSLATION_LANGUAGE,
            "status": "passthrough",
            "translated_at": now_iso(),
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


def _accepted_title(translated: str, original: str) -> str:
    if _CJK.search(translated) or (original and _CJK.search(original)):
        return translated or original
    # Product names and vulnerability identifiers are intentionally allowed to
    # remain unchanged; the descriptive summary is the readiness gate.
    if not original or _MACHINE_TITLE.fullmatch(original):
        return original
    return translated or original


def _accepted_summary(translated: str, original: str) -> str:
    if not original:
        return ""
    if _CJK.search(original):
        return original
    return translated if _CJK.search(translated) else ""


def _aggregate_audit(
    records: list[dict[str, Any]],
    *,
    invoked: bool,
    tool_audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ready = sum(record_translation_ready(record) for record in records)
    return {
        "target_language": CATALOG_TRANSLATION_LANGUAGE,
        "status": "completed" if ready == len(records) else "partial",
        "ready_records": ready,
        "pending_records": len(records) - ready,
        "record_count": len(records),
        "invoked": invoked,
        **dict(tool_audit or {}),
    }


def _is_provider_failure(tool_audit: dict[str, Any]) -> bool:
    warnings = " ".join(str(item) for item in tool_audit.get("warnings") or [])
    return bool(_PROVIDER_FAILURE.search(warnings))


def _translation_backoff_remaining() -> float:
    with _translation_backoff_lock:
        return max(0.0, _translation_backoff_until - time.monotonic())


def _open_translation_backoff() -> None:
    global _translation_backoff_until
    with _translation_backoff_lock:
        _translation_backoff_until = max(
            _translation_backoff_until,
            time.monotonic() + _TRANSLATION_BACKOFF_SECONDS,
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
