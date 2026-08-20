from __future__ import annotations

import hashlib
import hmac
import json
import re
from copy import deepcopy
from typing import Any

from app.privacy import sanitize_public_text
from app.secure_storage import sign_local_payload, verify_local_payload_signature


_UNAVAILABLE_MESSAGES = {
    "zh-Hans": "离线译文暂不可用，请稍后重试。",
    "zh-Hant": "離線譯文暫不可用，請稍後重試。",
    "en": "The offline translation is currently unavailable. Please try again later.",
    "ko": "오프라인 번역을 현재 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.",
    "ja": "オフライン翻訳は現在利用できません。しばらくしてからもう一度お試しください。",
    "es": "La traducción sin conexión no está disponible en este momento. Inténtelo de nuevo más tarde.",
    "fr": "La traduction hors ligne est actuellement indisponible. Veuillez réessayer plus tard.",
    "de": "Die Offline-Übersetzung ist derzeit nicht verfügbar. Bitte versuchen Sie es später erneut.",
    "it": "La traduzione offline non è al momento disponibile. Riprova più tardi.",
    "ru": "Офлайн-перевод сейчас недоступен. Повторите попытку позже.",
}
_STORED_TRANSLATION_SCHEMA = "secflow.stored-translation/v1"
_STORED_TRANSLATION_PURPOSE = "stored-translation-publication-v1"
_CONTROL_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,159}")
_HEX_SHA256 = re.compile(r"[a-fA-F0-9]{64}")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,95}")
_FILE_NAME = re.compile(r"[^/\\\x00-\x1f\x7f]{1,255}")
_ISO_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")
_INTERRUPT_KINDS = {
    "report_generation_confirmation",
    "report_download_confirmation",
    "component_excel_generation_confirmation",
    "component_excel_download_confirmation",
    "sbom_vulnerability_match_confirmation",
    "sbom_excel_generation_confirmation",
    "sbom_excel_download_confirmation",
}
_INTERRUPT_ACTIONS = {
    "generate",
    "download_report",
    "download_report_all_formats",
    "download_all",
    "generate_component_catalog_excel",
    "download_component_catalog_excel",
    "match_sbom_vulnerabilities",
    "generate_sbom_excel",
    "download_sbom_excel",
}
_REPORT_FORMATS = {"md", "html", "docx", "xlsx", "pdf"}
_ARTIFACT_KINDS = {"report", "component", "sbom", "markdown", "archive", "artifact"}
_ARTIFACT_STATUSES = {"completed", "ready", "published", "available"}
_TRANSLATION_STATUSES = {
    "translated",
    "passthrough",
    "fallback",
    "unavailable",
    "unsupported",
    "invalid",
}


def translation_audit_is_publishable(audit: Any) -> bool:
    if not isinstance(audit, dict):
        return False
    unresolved_fields = audit.get("unresolved_fields")
    if type(unresolved_fields) is not int:
        return False
    return (
        audit.get("status") == "completed"
        and audit.get("translation_status") in {"translated", "passthrough"}
        and unresolved_fields == 0
        and audit.get("offline_contract_valid") is True
        and audit.get("runtime_contract_valid") is True
        and audit.get("transport") == "stdio"
        and audit.get("network_used") is False
        and type(audit.get("provider_calls")) is int
        and audit.get("provider_calls") == 0
        and type(audit.get("billable_tokens")) is int
        and audit.get("billable_tokens") == 0
        and type(audit.get("token_usage")) is int
        and audit.get("token_usage") == 0
    )


def catalog_translation_status_is_complete(status: Any, target_language: Any) -> bool:
    if not isinstance(status, dict):
        return False
    record_count = status.get("record_count")
    ready_records = status.get("ready_records")
    pending_records = status.get("pending_records")
    if (
        type(record_count) is not int
        or record_count < 0
        or type(ready_records) is not int
        or type(pending_records) is not int
    ):
        return False
    return (
        status.get("status") == "completed"
        and _normalize_language(status.get("target_language")) == _normalize_language(target_language)
        and status.get("storage_stage") == "before-persist"
        and ready_records == record_count
        and pending_records == 0
    )


def public_catalog_records_are_ready(records: Any, target_language: Any) -> bool:
    if not isinstance(records, list):
        return False
    language = _normalize_language(target_language)
    expected_status = "original" if language == "en" else "translated"
    for record in records:
        if not isinstance(record, dict):
            return False
        if record.get("translation_status") != expected_status:
            return False
        if _normalize_language(record.get("content_language")) != language:
            return False
    return True


def issue_stored_translation_attestation(
    answer: dict[str, Any],
    *,
    target_language: Any,
    record_count: int,
    source: str,
) -> dict[str, Any]:
    """Mint a Host-only proof that binds a stored translation to its public payload."""

    if type(record_count) is not int or record_count < 0:
        raise ValueError("stored translation record_count must be a non-negative integer")
    language = _normalize_language(target_language)
    payload_sha256 = _public_payload_sha256(answer)
    unsigned = {
        "schema_version": _STORED_TRANSLATION_SCHEMA,
        "issuer": "secflow-host",
        "source": str(source or "local-catalog"),
        "status": "completed",
        "translation_status": "stored",
        "target_language": language,
        "storage_stage": "before-persist",
        "transport": "local-catalog",
        "record_count": record_count,
        "ready_records": record_count,
        "pending_records": 0,
        "unresolved_fields": 0,
        "offline": True,
        "network_used": False,
        "requires_api_key": False,
        "model_used": False,
        "provider_calls": 0,
        "billable_tokens": 0,
        "token_usage": 0,
        "payload_sha256": payload_sha256,
        "proof_algorithm": "HMAC-SHA256",
    }
    return {
        **unsigned,
        "proof": sign_local_payload(unsigned, _STORED_TRANSLATION_PURPOSE),
    }


def stored_translation_attestation_is_publishable(
    answer: Any,
    target_language: Any,
) -> bool:
    if not isinstance(answer, dict):
        return False
    audit = answer.get("translation")
    if not isinstance(audit, dict):
        return False
    record_count = audit.get("record_count")
    ready_records = audit.get("ready_records")
    pending_records = audit.get("pending_records")
    zero_fields = ("provider_calls", "billable_tokens", "token_usage", "unresolved_fields")
    if (
        audit.get("schema_version") != _STORED_TRANSLATION_SCHEMA
        or audit.get("issuer") != "secflow-host"
        or audit.get("status") != "completed"
        or audit.get("translation_status") != "stored"
        or audit.get("storage_stage") != "before-persist"
        or audit.get("transport") != "local-catalog"
        or audit.get("proof_algorithm") != "HMAC-SHA256"
        or _normalize_language(audit.get("target_language")) != _normalize_language(target_language)
        or type(record_count) is not int
        or record_count < 0
        or type(ready_records) is not int
        or ready_records != record_count
        or type(pending_records) is not int
        or pending_records != 0
        or audit.get("offline") is not True
        or audit.get("network_used") is not False
        or audit.get("requires_api_key") is not False
        or audit.get("model_used") is not False
        or any(type(audit.get(field)) is not int or audit.get(field) != 0 for field in zero_fields)
    ):
        return False
    payload_sha256 = audit.get("payload_sha256")
    if type(payload_sha256) is not str or not hmac.compare_digest(
        payload_sha256,
        _public_payload_sha256(answer),
    ):
        return False
    proof = audit.get("proof")
    unsigned = {key: deepcopy(value) for key, value in audit.items() if key != "proof"}
    return verify_local_payload_signature(unsigned, _STORED_TRANSLATION_PURPOSE, proof)


def _public_payload_sha256(answer: dict[str, Any]) -> str:
    payload = {key: deepcopy(value) for key, value in answer.items() if key != "translation"}
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_language(value: Any) -> str:
    text = str(value or "zh-Hans").strip().lower().replace("_", "-")
    aliases = {
        "zh": "zh-Hans",
        "zh-cn": "zh-Hans",
        "zh-sg": "zh-Hans",
        "zh-hans": "zh-Hans",
        "zh-tw": "zh-Hant",
        "zh-hk": "zh-Hant",
        "zh-hant": "zh-Hant",
        "en-us": "en",
        "en-gb": "en",
    }
    return aliases.get(text, text or "zh-Hans")


def translation_unavailable_message(target_language: Any) -> str:
    text = str(target_language or "").strip().lower().replace("_", "-")
    aliases = {
        "zh": "zh-Hans", "zh-cn": "zh-Hans", "zh-sg": "zh-Hans", "zh-hans": "zh-Hans",
        "zh-tw": "zh-Hant", "zh-hk": "zh-Hant", "zh-hant": "zh-Hant",
        "en-us": "en", "ko-kr": "ko", "ja-jp": "ja", "es-es": "es",
        "fr-fr": "fr", "de-de": "de", "it-it": "it", "ru-ru": "ru",
    }
    return _UNAVAILABLE_MESSAGES.get(aliases.get(text, text), _UNAVAILABLE_MESSAGES["en"])


def failed_translation_audit(target_language: Any, error: Any) -> dict[str, Any]:
    return {
        "server": "SecFlow Translation MCP",
        "tool": "translate_json_payload",
        "status": "failed",
        "translation_status": "unavailable",
        "target_language": str(target_language or "zh-Hans"),
        "unresolved_fields": 0,
        "publication_status": "blocked",
        "error": sanitize_public_text(error).strip() or "Translation MCP unavailable",
    }


def fail_closed_translation_payload(
    source: Any,
    *,
    target_language: Any,
    audit: Any,
) -> dict[str, Any]:
    original = source if isinstance(source, dict) else {}
    message = translation_unavailable_message(target_language)
    safe_audit = _safe_translation_audit(audit, target_language)
    payload: dict[str, Any] = {
        "mode": _safe_mode(original.get("mode")),
        "summary": message,
        "answer": message,
        "fields": {},
        "records": [],
        "vulnerability_card": {},
        "component_detail": {},
        "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
        "chart_data": {},
        "evidence_sources": [],
        "artifacts": _safe_artifacts(original.get("artifacts")),
        "confidence": 0.0,
        "trace": [],
        "translation": safe_audit,
    }
    generated_at = original.get("generated_at")
    if type(generated_at) is str and _ISO_TIMESTAMP.fullmatch(generated_at):
        payload["generated_at"] = generated_at
    elapsed_ms = original.get("elapsed_ms")
    if type(elapsed_ms) is int and 0 <= elapsed_ms <= 86_400_000:
        payload["elapsed_ms"] = elapsed_ms
    if "interrupt" in original:
        payload["interrupt"] = _safe_interrupt(original.get("interrupt"), message)
    return payload


def _safe_artifacts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    artifacts: list[dict[str, Any]] = []
    for item in value[:100]:
        if not isinstance(item, dict):
            continue
        artifact: dict[str, Any] = {}
        for field in ("id", "artifact_id"):
            identifier = _safe_identifier(item.get(field))
            if identifier:
                artifact[field] = identifier
        media_type = item.get("media_type")
        if type(media_type) is str and _MEDIA_TYPE.fullmatch(media_type.lower()):
            artifact["media_type"] = media_type.lower()
        file_name = item.get("file_name")
        if type(file_name) is str and _FILE_NAME.fullmatch(file_name):
            artifact["file_name"] = file_name
        kind = item.get("kind")
        if type(kind) is str and kind in _ARTIFACT_KINDS:
            artifact["kind"] = kind
        artifact_format = item.get("format")
        if type(artifact_format) is str and artifact_format in _REPORT_FORMATS:
            artifact["format"] = artifact_format
        status = item.get("status")
        if type(status) is str and status in _ARTIFACT_STATUSES:
            artifact["status"] = status
        for field in ("size", "size_bytes", "byte_size"):
            amount = item.get(field)
            if type(amount) is int and 0 <= amount <= 128 * 1024 * 1024:
                artifact[field] = amount
        for field in ("sha256", "checksum"):
            digest = item.get(field)
            if type(digest) is str and _HEX_SHA256.fullmatch(digest):
                artifact[field] = digest.lower()
        if artifact.get("id") or artifact.get("artifact_id"):
            artifacts.append(artifact)
    return artifacts


def _safe_interrupt(value: Any, message: str) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    thread_id = _safe_identifier(value.get("thread_id"))
    if type(kind) is not str or kind not in _INTERRUPT_KINDS or not thread_id:
        return None
    interrupt: dict[str, Any] = {"kind": kind, "thread_id": thread_id}
    for field in ("interrupt_id", "user_id", "session_id"):
        identifier = _safe_identifier(value.get(field))
        if identifier:
            interrupt[field] = identifier
    action = value.get("action")
    if type(action) is str and action in _INTERRUPT_ACTIONS:
        interrupt["action"] = action
    for field in ("report_ids", "artifact_ids"):
        identifiers = _safe_identifier_list(value.get(field), limit=100)
        if identifiers:
            interrupt[field] = identifiers
    formats = value.get("formats")
    if isinstance(formats, list):
        safe_formats = [item for item in formats[:5] if type(item) is str and item in _REPORT_FORMATS]
        if safe_formats:
            interrupt["formats"] = list(dict.fromkeys(safe_formats))
    allow_selection = value.get("allow_format_selection")
    if type(allow_selection) is bool:
        interrupt["allow_format_selection"] = allow_selection
    destination_hint = value.get("destination_hint")
    if type(destination_hint) is str and destination_hint in {"desktop", "select"}:
        interrupt["destination_hint"] = destination_hint
    interrupt.update({"message": message, "question": message, "detail": ""})
    return interrupt


def _safe_translation_audit(value: Any, target_language: Any) -> dict[str, Any]:
    audit = value if isinstance(value, dict) else {}
    status = audit.get("status")
    translation_status = audit.get("translation_status")
    safe: dict[str, Any] = {
        "server": "SecFlow Translation MCP",
        "tool": "translate_json_payload",
        "status": status if type(status) is str and status in {"failed", "partial"} else "failed",
        "translation_status": (
            translation_status
            if type(translation_status) is str and translation_status in _TRANSLATION_STATUSES
            else "unavailable"
        ),
        "target_language": _normalize_language(target_language),
        "publication_status": "blocked",
    }
    if audit.get("transport") == "stdio":
        safe["transport"] = "stdio"
    for field in (
        "offline",
        "network_used",
        "requires_api_key",
        "model_used",
        "offline_model_used",
        "resource_verified",
        "offline_contract_valid",
        "runtime_contract_valid",
    ):
        if type(audit.get(field)) is bool:
            safe[field] = audit[field]
    for field in (
        "candidate_fields",
        "translated_fields",
        "unresolved_fields",
        "batch_count",
        "provider_calls",
        "billable_tokens",
        "token_usage",
    ):
        amount = audit.get(field)
        if type(amount) is int and 0 <= amount <= 10_000_000:
            safe[field] = amount
    safe.setdefault("unresolved_fields", 0)
    for field in ("input_sha256", "output_sha256", "model_sha256"):
        digest = audit.get(field)
        if type(digest) is str and _HEX_SHA256.fullmatch(digest):
            safe[field] = digest.lower()
    return safe


def _safe_mode(value: Any) -> str:
    if type(value) is str and re.fullmatch(r"[a-z][a-z0-9_:-]{0,63}", value):
        return value
    return "translation_unavailable"


def _safe_identifier(value: Any) -> str:
    if type(value) is str and _CONTROL_IDENTIFIER.fullmatch(value):
        return value
    return ""


def _safe_identifier_list(value: Any, *, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(
        dict.fromkeys(
            identifier
            for item in value[:limit]
            if (identifier := _safe_identifier(item))
        )
    )


__all__ = [
    "catalog_translation_status_is_complete",
    "fail_closed_translation_payload",
    "failed_translation_audit",
    "issue_stored_translation_attestation",
    "public_catalog_records_are_ready",
    "stored_translation_attestation_is_publishable",
    "translation_audit_is_publishable",
    "translation_unavailable_message",
]
