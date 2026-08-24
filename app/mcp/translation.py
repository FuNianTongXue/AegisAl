from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from app.mcp.offline_translation import (
    OfflineTranslationUnavailable,
    UnsupportedTranslationLanguage,
    normalize_target_language,
    offline_translation_engine,
)
from app.privacy import sanitize_public_text


_TRANSLATABLE_KEYS = {
    "answer", "analysis", "conclusion", "content", "description", "detail",
    "caption", "fix_advice", "impact", "label", "message", "mitigation", "question",
    "reason", "recommendation", "remediation", "solution", "summary",
    "summary_zh", "text", "title",
}
_PROTECTED_KEYS = {
    "$schema", "action", "api_key", "artifact_id", "checksum", "code",
    "completed_at", "content_base64", "created_at", "cve", "cve_id", "digest",
    "ecosystem", "email", "file", "file_name", "fixed_code", "fixed_snippet",
    "fixed_version", "format", "generated_at", "ghsa", "hash", "href", "id",
    "identifier", "image_base64", "input_sha256", "interrupt_id", "kind",
    "language", "media_type", "mode", "model", "name", "operation_thread_id",
    "output_sha256", "package", "path", "payload_sha256", "provider",
    "record_key", "reference", "reference_links", "renderer", "rule_id",
    "schema_version", "server", "session_id", "sha256", "snippet", "source",
    "source_kind", "source_url", "status", "task_id", "thread_id", "tool",
    "transport", "uri", "url", "user_id", "version", "vulnerable_snippet",
    "workspace_path",
    "代码片段", "修复后代码", "风险代码",
}
_PROTECTED_ANCESTORS = {
    "agent_task", "artifacts", "audit", "chart_data", "code_blocks", "diagnostics",
    "diagrams", "events", "knowledge_graph", "orchestration", "report_mcps", "skill",
    "snippet_lines", "task", "trace", "translation",
}
_DISPLAY_MACHINE_KEYS = {
    "artifact", "artifact_id", "file", "file_name", "id", "path", "project",
    "project_name", "report_id", "task_id", "thread_id", "workspace", "workspace_name",
    "workspace_path", "任务编号", "任务id", "报告编号", "文件", "文件名", "工作区",
    "工作区路径", "项目", "项目名称",
}
_CONTROL_MACHINE_ANCESTORS = {
    "agent_task", "artifact", "artifacts", "interrupt", "orchestration", "report",
    "task", "trace",
}
_CONTROL_MACHINE_KEYS = {
    "artifact_id", "file_name", "id", "interrupt_id", "operation_thread_id", "path",
    "report_id", "task_id", "thread_id", "workspace_name", "workspace_path",
}
_TABLE_CONTAINER_KEYS = frozenset({"cards", "table", "tables"})
_TABLE_ROW_KEYS = frozenset({"data", "rows"})
_TABLE_COLUMN_LABEL_KEYS = frozenset({"label", "name", "title"})
_TABLE_DISPLAY_ENUM_KEYS = frozenset(
    {"action", "kind", "mode", "priority", "risk_state", "severity", "state", "status"}
)
_TABLE_CONTEXTUAL_NAME_ANCESTORS = frozenset(
    {"artifact", "component", "package", "project", "workspace"}
)
_TABLE_MACHINE_CELL_KEYS = frozenset(
    (
        _PROTECTED_KEYS
        | _DISPLAY_MACHINE_KEYS
        | {
            "bom_ref", "commit", "commit_hash", "component", "component_coordinate",
            "component_id", "component_name", "coordinate", "coordinates", "cpe",
            "group", "group_id", "package_name", "package_url", "purl", "sha", "sha1",
        }
    )
    - {"action", "kind", "mode", "name", "status"}
)
_MACHINE_VALUE = re.compile(
    r"^(?:https?://\S+|urn:uuid:[A-Fa-f0-9-]{36}|[A-Fa-f0-9]{7,64}|"
    r"CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|"
    r"v?\d+(?:\.\d+){1,4}(?:[-+][A-Za-z0-9.-]+)?|/[A-Za-z0-9._/\\-]+|"
    r"[a-z][a-z0-9]*(?:[_:-][a-z0-9]+)+)$",
    flags=re.IGNORECASE,
)
_TABLE_MACHINE_VALUE = re.compile(
    r"^(?:"
    r"(?:pkg|cpe):\S+|"
    r"(?:[A-Za-z0-9._+-]+:){1,4}[A-Za-z0-9._+@/-]+|"
    r"(?:@?[A-Za-z0-9._-]+/)+[A-Za-z0-9._@-]+(?:[:@][A-Za-z0-9._:+-]+)|"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|"
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?|"
    r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|"
    r"(?:true|false|null|none|n/?a)"
    r")$",
    flags=re.IGNORECASE,
)
_TABLE_DISPLAY_ENUM_VALUE = re.compile(
    r"^[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)+$"
)
_QUOTED_PATH_PATTERN = r'''["'](?:[A-Za-z]:[\\/]|/)[^"'\r\n]+["']'''
_WINDOWS_PATH_PATTERN = (
    r"(?<![\w])(?:[A-Za-z]:[\\/])(?:[^\\/\r\n:*?\"<>|]+[\\/])+"
    r"[^\\/\r\n:*?\"<>|]*?\.[A-Za-z0-9_-]{1,16}(?=$|[\s,;，；。)\]}])"
)
_PLAIN_FILE_PATTERN = r"(?<![\w.-])[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,4}(?![\w.-])"
_PACKAGE_COORDINATE_PATTERN = (
    r"(?<![\w.-])(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+:"
    r"[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.+-]+)?(?![\w.-])"
)
_URL_QUERY_FRAGMENT_PATTERN = (
    r"\?[A-Za-z0-9_.%~-]+=[A-Za-z0-9_.%~:@/+,-]+"
    r"(?:&[A-Za-z0-9_.%~-]+=[A-Za-z0-9_.%~:@/+,-]+)*"
)
_CONTEXTUAL_IDENTIFIER_PATTERN = (
    r"(?<=\bargument )[A-Za-z_](?:[A-Za-z0-9_.:-]*[A-Za-z0-9_])?|"
    r"(?<=\bparameter )[A-Za-z_](?:[A-Za-z0-9_.:-]*[A-Za-z0-9_])?|"
    r"(?<=\bfunction )[A-Za-z_][A-Za-z0-9_]*(?:_[A-Za-z0-9_]+)+"
)
_TECHNOLOGY_ENTITY_PATTERN = (
    r"(?i:\b(?:python|java|javascript|typescript|rust|solidity|kotlin|swift|php|ruby|scala|"
    r"gradle|maven|npm|pip|cargo|docker|kubernetes|agent|mcp|stdio|langgraph|sbom|sast|"
    r"code\s+scan|streamable\s+http)\b)|(?-i:\bGo\b)"
)
_PRODUCT_TOKEN_PATTERN = (
    r"[A-Z](?:[A-Za-z0-9_.+-]{1,}[A-Za-z0-9_+])"
    r"(?:\s+(?:[A-Z]{2,}(?:[A-Z0-9.-]*[A-Z0-9])?|"
    r"[A-Z][a-z](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)){0,7}"
)
_CONTEXTUAL_PRODUCT_PATTERN = "(?:" + "|".join(
    rf"(?i:(?<=\b{prefix} ))(?-i:{_PRODUCT_TOKEN_PATTERN})"
    for prefix in ("in", "on", "for", "from", "affects", "impacting", "product", "component")
) + ")"
_PRODUCT_IDENTIFIER_PATTERN = (
    r"(?-i:\b(?:[A-Z]?[a-z]+(?:[A-Z][A-Za-z0-9]*)+|"
    r"(?=[A-Za-z0-9-]*[A-Z]{2})(?=[A-Za-z0-9-]*[a-z])[A-Za-z][A-Za-z0-9-]{2,}|"
    r"(?=[A-Za-z0-9-]*\d)(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z][A-Za-z0-9-]{2,}|"
    r"[A-Z]{2,}[A-Z0-9-]*)\b)"
)
_LEADING_VERSIONED_PRODUCT_PATTERN = (
    r"(?-i:\b[A-Z][a-z][A-Za-z0-9_.+-]{2,}(?=\s+(?:before|after|prior\s+to|earlier\s+than|later\s+than)\b))"
)
_LEADING_DESCRIBED_PRODUCT_PATTERN = (
    r"(?-i:\b[A-Z][A-Za-z0-9_.+-]{2,}(?:\s+[A-Z][A-Za-z0-9_.+-]{2,}){0,3}"
    r"(?=\s+(?i:vulnerable|affected|allows|contains|has)\b))"
)
_ENGLISH_PROSE_WORDS = frozenset(
    {
        "affect", "affected", "affects", "allows", "arbitrary", "attacker", "attackers",
        "are", "before", "buffer", "can", "caused", "causes", "code", "command", "could",
        "denial", "disclosure", "execute", "execution", "exploit", "fixed", "found", "had",
        "has", "have", "impact", "information", "injection", "integer", "is", "issue", "keep",
        "may", "memory", "might", "must", "overflow", "package", "permits", "pollution",
        "prototype", "read", "remains", "remote", "service", "should", "that", "the", "these",
        "this", "those", "traversal", "unexpected", "vulnerability", "vulnerabilities",
        "vulnerable", "was", "were", "would", "write", "behavior",
    }
)
_SECURITY_MEANING_ANCHORS = (
    (
        r"(?i)execute\s+arbitrary\s+code|arbitrary\s+code\s+execution",
        ("执行任意代码", "任意代码执行", "執行任意程式碼", "任意程式碼執行", "任意代碼執行"),
    ),
    (r"(?i)remote\s+code\s+execution", ("远程代码执行", "遠程代碼執行", "遠端程式碼執行")),
    (r"(?i)buffer\s+overflow", ("缓冲区溢出", "缓冲溢出", "緩衝區溢位")),
    (r"(?i)integer\s+overflow", ("整数溢出", "整數溢位")),
    (r"(?i)denial\s+of\s+service", ("拒绝服务", "拒絕服務", "服務阻斷")),
    (r"(?i)information\s+disclosure", ("信息泄露", "信息披露", "資訊洩露", "資訊揭露")),
    (r"(?i)prototype\s+pollution", ("原型污染",)),
    (r"(?i)out-of-bounds\s+read", ("越界读取", "越界讀取")),
    (r"(?i)command\s+injection", ("命令注入",)),
    (r"(?i)sql\s+injection", ("SQL 注入", "SQL注入")),
    (r"(?i)lookup\s+injection", ("查找注入", "查詢注入")),
    (r"(?i)\bvulnerable\b", ("存在漏洞", "易受攻击", "存在漏洞")),
)
_SECURITY_GLOSSARY = (
    (r"(?i)execute\s+arbitrary\s+code", "执行任意代码", "執行任意程式碼"),
    (r"(?i)arbitrary\s+code\s+execution", "任意代码执行", "任意程式碼執行"),
    (r"(?i)remote\s+code\s+execution", "远程代码执行", "遠端程式碼執行"),
    (r"(?i)buffer\s+overflow", "缓冲区溢出", "緩衝區溢位"),
    (r"(?i)integer\s+overflow", "整数溢出", "整數溢位"),
    (r"(?i)denial\s+of\s+service", "拒绝服务", "拒絕服務"),
    (r"(?i)information\s+disclosure", "信息泄露", "資訊洩露"),
    (r"(?i)prototype\s+pollution", "原型污染", "原型污染"),
    (r"(?i)out-of-bounds\s+read", "越界读取", "越界讀取"),
    (r"(?i)command\s+injection", "命令注入", "命令注入"),
    (r"(?i)sql\s+injection", "SQL 注入", "SQL 注入"),
    (r"(?i)lookup\s+injection", "查找注入", "查詢注入"),
    (r"(?i)\bvulnerable\b", "存在漏洞的", "存在漏洞的"),
)
_VERIFIED_PRODUCT_ENTITY_SEGMENT = re.compile(
    rf"{_CONTEXTUAL_PRODUCT_PATTERN}|{_PRODUCT_IDENTIFIER_PATTERN}|"
    rf"{_LEADING_VERSIONED_PRODUCT_PATTERN}|{_LEADING_DESCRIBED_PRODUCT_PATTERN}",
    flags=re.IGNORECASE,
)
_STANDALONE_PRODUCT_ENTITY = re.compile(r"\b[A-Z][a-z][A-Za-z0-9_.+-]{2,}\b")
_PRODUCT_ENTITY_SEGMENT = re.compile(
    rf"{_CONTEXTUAL_PRODUCT_PATTERN}|{_PRODUCT_IDENTIFIER_PATTERN}|"
    rf"{_LEADING_VERSIONED_PRODUCT_PATTERN}|{_LEADING_DESCRIBED_PRODUCT_PATTERN}|"
    rf"(?-i:{_STANDALONE_PRODUCT_ENTITY.pattern})",
    flags=re.IGNORECASE,
)
_PRESERVED_SEGMENT = re.compile(
    rf"```[\s\S]*?```|`[^`\n]+`|{_QUOTED_PATH_PATTERN}|{_WINDOWS_PATH_PATTERN}|"
    rf"{_PACKAGE_COORDINATE_PATTERN}|{_URL_QUERY_FRAGMENT_PATTERN}|"
    rf"{_CONTEXTUAL_IDENTIFIER_PATTERN}|{_PLAIN_FILE_PATTERN}|{_TECHNOLOGY_ENTITY_PATTERN}|"
    rf"{_CONTEXTUAL_PRODUCT_PATTERN}|"
    rf"{_PRODUCT_IDENTIFIER_PATTERN}|https?://[^\s,，；;）)]*[^\s,，；;）).]|CVE-\d{{4}}-\d+|GHSA-[A-Za-z0-9-]+|"
    r"\b[A-Fa-f0-9]{7,64}\b|(?<![\w.-])v?\d+(?:\.\d+){1,4}(?:(?:[-+._]?[A-Za-z][A-Za-z0-9_-]*)(?:\.\d+)*)?|"
    r"(?<![\w.-])(?:[A-Za-z]:[\\/]|/)?@?(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_@-]+(?:\.[A-Za-z0-9_@-]+)*(?::\d+)?",
    flags=re.IGNORECASE,
)
_TECHNICAL_SEGMENT = re.compile(
    rf"```[\s\S]*?```|`[^`\n]+`|{_QUOTED_PATH_PATTERN}|{_WINDOWS_PATH_PATTERN}|"
    rf"{_PACKAGE_COORDINATE_PATTERN}|{_URL_QUERY_FRAGMENT_PATTERN}|"
    rf"{_CONTEXTUAL_IDENTIFIER_PATTERN}|{_PLAIN_FILE_PATTERN}|{_TECHNOLOGY_ENTITY_PATTERN}|"
    rf"https?://[^\s,，；;）)]*[^\s,，；;）).]|CVE-\d{{4}}-\d+|GHSA-[A-Za-z0-9-]+|"
    r"\b[A-Fa-f0-9]{7,64}\b|(?<![\w.-])v?\d+(?:\.\d+){1,4}(?:(?:[-+._]?[A-Za-z][A-Za-z0-9_-]*)(?:\.\d+)*)?|"
    r"(?<![\w.-])(?:[A-Za-z]:[\\/]|/)?@?(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_@-]+(?:\.[A-Za-z0-9_@-]+)*(?::\d+)?|"
    r"\b[A-Za-z_][A-Za-z0-9_.:-]*\([^\n)]{0,100}\)|"
    r"\b(?:strcpy|strncpy|memcpy|memmove|sprintf|eval|exec|system)\b",
)
_CJK_CHAR = re.compile(r"[\u3400-\u9fff]")
_LATIN_PROSE = re.compile(r"\b[A-Za-z]{2,}\b")
_SAFE_TECHNICAL_ACRONYM = re.compile(
    r"\b(?:API|AST|CFG|CVE|CVSS|CSRF|CWE|DFG|GHSA|HTML|HTTP|HTTPS|JNDI|JSON|"
    r"LDAP|LLM|MCP|RCE|SARIF|SAST|SBOM|SQL|SSE|SSRF|UI|XML|XSS|YAML|"
    r"source|sink|critical|high|medium|low)\b",
    flags=re.IGNORECASE,
)
_MIXED_LOCALIZED_TECHNICAL_TOKEN = re.compile(
    r"\b[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+\b"
)
_MACHINE_PATH = re.compile(r"^(?:@?[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(?::\d+)?$")
_FENCED_BLOCK = re.compile(r"```[\s\S]*?```")
_CACHE_ENGINE_ID = "ctranslate2:opus-mt-en-zh-1.9"
_TRANSLATION_CACHE_LIMIT = 2_000
_BATCH_MAX_ITEMS = 8
_BATCH_MAX_BYTES = 4_000
_LONG_TEXT_CHARS = 4_000
_LONG_TEXT_CHUNK_CHARS = 2_200
_PRODUCT_ENTITY_MARKER_DIGITS = "甲乙丙丁戊己庚辛壬癸"


class TranslationOutput(BaseModel):
    schema_version: int = 2
    renderer: Literal["secflow-json-translation"] = "secflow-json-translation"
    target_language: str
    payload: dict[str, Any]
    translation_status: Literal[
        "translated", "passthrough", "fallback", "unsupported", "unavailable"
    ]
    candidate_fields: int
    translated_fields: int
    unresolved_fields: int = 0
    batch_count: int
    model_used: bool = False
    offline_model_used: bool = False
    offline: bool = True
    network_used: bool = False
    requires_api_key: bool = False
    provider_calls: int = 0
    billable_tokens: int = 0
    token_usage: int = 0
    engine: str = "CTranslate2"
    engine_version: str = ""
    tokenizer: str = "SentencePiece"
    tokenizer_version: str = ""
    model_id: str = "opus-mt-en-zh-1.9"
    model_sha256: str = ""
    resource_verified: bool = False
    input_sha256: str
    output_sha256: str
    errors: list[str]


@dataclass(frozen=True)
class _Candidate:
    identifier: str
    path: tuple[Any, ...]
    text: str
    protected_literals: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _VerifiedOfflineProvenance:
    engine: str
    engine_version: str
    tokenizer: str
    tokenizer_version: str
    model_id: str
    model_sha256: str
    resource_verified: Literal[True] = True

    def audit_fields(self) -> dict[str, Any]:
        return {
            "offline_model_used": True,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "tokenizer": self.tokenizer,
            "tokenizer_version": self.tokenizer_version,
            "model_id": self.model_id,
            "model_sha256": self.model_sha256,
            "resource_verified": True,
        }


@dataclass(frozen=True, slots=True)
class _TranslationCacheEntry:
    translated: str
    provenance: _VerifiedOfflineProvenance | None = None


@dataclass(frozen=True, slots=True)
class _TranslationWorkResult:
    changed: int
    engine_calls: int
    provenances: frozenset[_VerifiedOfflineProvenance] = frozenset()


_translation_cache: OrderedDict[
    tuple[str, str, str], _TranslationCacheEntry
] = OrderedDict()
_translation_cache_lock = RLock()


translation_mcp = FastMCP(
    "AegisAl Translation MCP",
    instructions=(
        "Translate customer-visible structured JSON with AegisAl's verified offline language pack. "
        "Never use a configured chat model, API key, provider endpoint, or network transport. "
        "Preserve machine-readable security evidence exactly."
    ),
)


@translation_mcp.tool(
    name="translate_json_payload",
    description=(
        "Translate visible JSON values with the bundled offline engine while preserving code, "
        "identifiers, product names, versions, paths, URLs, and hashes."
    ),
    structured_output=True,
)
def translate_json_payload(
    payload: dict[str, Any],
    target_language: str = "zh-Hans",
    user_id: str = "default",
    session_id: str = "default",
    content_scope: str = "assistant_response",
    retry_untranslated_fields: bool = True,
) -> TranslationOutput:
    # Kept in the stable input schema for audit correlation. No identity value
    # participates in engine or credential resolution.
    del user_id, session_id, content_scope
    clean = _json_value(payload)
    input_sha256 = _payload_sha256(clean)
    try:
        target = normalize_translation_language(target_language)
    except UnsupportedTranslationLanguage as exc:
        return _output(
            target_language=str(target_language or ""), payload=clean, status="unsupported",
            candidate_fields=0, translated_fields=0, batch_count=0,
            input_sha256=input_sha256, errors=[_public_translation_error(exc)],
        )

    translatable_root = clean.get("payload") if clean.get("$schema") == "secflow.scan-results/v1" else clean
    candidates = _collect_candidates(translatable_root)
    if target == "en":
        cjk_candidates = [candidate for candidate in candidates if _CJK_CHAR.search(candidate.text)]
        return _output(
            target_language=target,
            payload=clean,
            status="unsupported" if cjk_candidates else "passthrough",
            candidate_fields=len(candidates),
            translated_fields=0,
            unresolved_fields=len(cjk_candidates),
            batch_count=0,
            input_sha256=input_sha256,
            errors=(
                ["The bundled English target is passthrough-only; Chinese source text is not translated to English."]
                if cjk_candidates else []
            ),
        )

    # String-only column definitions lose their field identity after the label
    # is translated. Lock object-row tables to explicit keys before translating
    # their labels so renderers never have to infer keys from JSON member order.
    _bind_object_row_table_columns(translatable_root)
    candidates = _collect_candidates(translatable_root)

    errors: list[str] = []
    translated_fields = 0
    batch_count = 0
    verified_provenances: set[_VerifiedOfflineProvenance] = set()
    unavailable = False
    if candidates:
        for batch in _candidate_batches(candidates):
            batch_count += 1
            try:
                work = _translate_batch(translatable_root, batch, target=target)
                translated_fields += work.changed
                verified_provenances.update(work.provenances)
            except OfflineTranslationUnavailable as exc:
                unavailable = True
                errors.append(_public_translation_error(exc))
                break
            except Exception as exc:  # noqa: BLE001 - verified facts remain unchanged.
                errors.append(_public_translation_error(exc))

        if retry_untranslated_fields and not unavailable:
            for candidate in _untranslated_candidates(candidates, translatable_root, target):
                try:
                    work = _translate_single(translatable_root, candidate, target=target)
                    translated_fields += work.changed
                    batch_count += work.engine_calls
                    verified_provenances.update(work.provenances)
                except OfflineTranslationUnavailable as exc:
                    unavailable = True
                    errors.append(_public_translation_error(exc))
                    break
                except Exception as exc:  # noqa: BLE001 - verified facts remain unchanged.
                    errors.append(_public_translation_error(exc))

    unresolved_fields = len(_untranslated_candidates(candidates, translatable_root, target))
    if unresolved_fields and not unavailable:
        errors.append(
            f"{unresolved_fields} field(s) failed evidence preservation or target-language validation"
        )

    if clean.get("$schema") == "secflow.scan-results/v1":
        from app.reports import refresh_scan_result_json

        clean = refresh_scan_result_json(clean, language=target)

    if unavailable:
        status: Literal["translated", "passthrough", "fallback", "unsupported", "unavailable"] = "unavailable"
    elif unresolved_fields:
        status = "fallback"
    elif translated_fields:
        status = "translated"
    elif unresolved_fields == 0:
        status = "passthrough"
    elif errors:
        status = "fallback"
    else:
        status = "fallback"
    return _output(
        target_language=target, payload=clean, status=status,
        candidate_fields=len(candidates), translated_fields=translated_fields,
        unresolved_fields=unresolved_fields, batch_count=batch_count,
        input_sha256=input_sha256, errors=errors,
        verified_provenances=frozenset(verified_provenances),
    )


def _output(
    *, target_language: str, payload: dict[str, Any],
    status: Literal["translated", "passthrough", "fallback", "unsupported", "unavailable"],
    candidate_fields: int, translated_fields: int, batch_count: int,
    input_sha256: str, errors: list[str], unresolved_fields: int = 0,
    verified_provenances: frozenset[_VerifiedOfflineProvenance] = frozenset(),
) -> TranslationOutput:
    audit = offline_translation_engine.info.audit_fields()
    if len(verified_provenances) == 1:
        audit.update(next(iter(verified_provenances)).audit_fields())
    else:
        audit.update(
            {
                "offline_model_used": False,
                "engine_version": "",
                "tokenizer_version": "",
                "model_sha256": "",
                "resource_verified": False,
            }
        )
    return TranslationOutput(
        target_language=target_language,
        payload=payload,
        translation_status=status,
        candidate_fields=candidate_fields,
        translated_fields=translated_fields,
        unresolved_fields=unresolved_fields,
        batch_count=batch_count,
        input_sha256=input_sha256,
        output_sha256=_payload_sha256(payload),
        errors=list(dict.fromkeys(error for error in errors if error)),
        **audit,
    )


def invoke_translation_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    """Invoke Translation MCP through the Host-owned child-process boundary."""

    from app.mcp.protocol import call_mcp_tool

    return call_mcp_tool(
        agent_id="translation_agent",
        tool_id="mcp__translation__translate_json_payload",
        arguments=arguments,
    )


async def translation_mcp_spec() -> dict[str, Any]:
    tools = await translation_mcp.list_tools()
    return {
        "id": "translation",
        "name": translation_mcp.name,
        "tools": [
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema,
                "output_schema": tool.outputSchema or {},
            }
            for tool in tools
        ],
    }


def normalize_translation_language(value: Any) -> str:
    return normalize_target_language(value)


def _translation_cache_key(target: str, text: str) -> tuple[str, str, str]:
    return target, _CACHE_ENGINE_ID, hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_verified_offline_provenance(value: Any) -> bool:
    if type(value) is not _VerifiedOfflineProvenance:
        return False
    if type(value.resource_verified) is not bool or value.resource_verified is not True:
        return False
    metadata = (
        value.engine,
        value.engine_version,
        value.tokenizer,
        value.tokenizer_version,
        value.model_id,
    )
    return (
        all(type(item) is str and bool(item.strip()) for item in metadata)
        and type(value.model_sha256) is str
        and re.fullmatch(r"[0-9a-f]{64}", value.model_sha256) is not None
    )


def _verified_offline_provenance() -> _VerifiedOfflineProvenance | None:
    info = offline_translation_engine.info
    provenance = _VerifiedOfflineProvenance(
        engine=info.engine,
        engine_version=info.engine_version,
        tokenizer=info.tokenizer,
        tokenizer_version=info.tokenizer_version,
        model_id=info.model_id,
        model_sha256=info.model_sha256,
        resource_verified=info.resource_verified,
    )
    return provenance if _is_verified_offline_provenance(provenance) else None


def _translation_cache_get(target: str, text: str) -> _TranslationCacheEntry | None:
    key = _translation_cache_key(target, text)
    with _translation_cache_lock:
        value = _translation_cache.get(key)
        if value is None:
            return None
        if (
            type(value) is not _TranslationCacheEntry
            or type(value.translated) is not str
            or not value.translated
        ):
            _translation_cache.pop(key, None)
            return None
        if value.provenance is not None and not _is_verified_offline_provenance(
            value.provenance
        ):
            value = _TranslationCacheEntry(translated=value.translated)
            _translation_cache[key] = value
        _translation_cache.move_to_end(key)
        return value


def _translation_cache_put(
    target: str,
    text: str,
    translated: str,
    *,
    provenance: _VerifiedOfflineProvenance | None,
) -> None:
    if not translated:
        return
    if provenance is not None and not _is_verified_offline_provenance(provenance):
        provenance = None
    key = _translation_cache_key(target, text)
    with _translation_cache_lock:
        _translation_cache[key] = _TranslationCacheEntry(
            translated=translated,
            provenance=provenance,
        )
        _translation_cache.move_to_end(key)
        while len(_translation_cache) > _TRANSLATION_CACHE_LIMIT:
            _translation_cache.popitem(last=False)


def _collect_candidates(root: Any) -> list[_Candidate]:
    output: list[_Candidate] = []
    control_literals = _collect_control_machine_literals(root)

    def visit(value: Any, path: tuple[Any, ...]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                visit(item, (*path, str(key)))
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, (*path, index))
            return
        if isinstance(value, str) and _is_translatable_path(path, value):
            protected_literals = tuple(
                literal
                for literal in control_literals
                if literal in value
            )
            output.append(
                _Candidate(
                    identifier=f"t{len(output)}",
                    path=path,
                    text=value,
                    protected_literals=protected_literals,
                )
            )

    visit(root, ())
    return output


def _bind_object_row_table_columns(root: Any) -> None:
    def visit(value: Any, path: tuple[Any, ...]) -> None:
        if isinstance(value, dict):
            normalized_path = [str(item).lower() for item in path if not isinstance(item, int)]
            if any(item in _TABLE_CONTAINER_KEYS for item in normalized_path):
                _bind_table_columns(value)
            for key, item in value.items():
                visit(item, (*path, str(key)))
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, (*path, index))

    visit(root, ())


def _bind_table_columns(table: dict[str, Any]) -> None:
    columns = table.get("columns")
    rows = table.get("rows") if isinstance(table.get("rows"), list) else table.get("data")
    if not isinstance(columns, list) or not isinstance(rows, list):
        return
    object_rows = [row for row in rows if isinstance(row, dict)]
    if not object_rows:
        return

    row_keys = list(
        dict.fromkeys(
            str(key)
            for row in object_rows
            for key in row
            if not re.search(r"_(?:original|zh|zh_hant)$", str(key), flags=re.IGNORECASE)
        )
    )
    if not row_keys:
        return

    used_keys: set[str] = set()
    bound_columns: list[Any] = []
    for index, column in enumerate(columns):
        if not isinstance(column, str) or not column.strip():
            bound_columns.append(column)
            if isinstance(column, dict) and isinstance(column.get("key"), str):
                used_keys.add(column["key"])
            continue
        key = _matching_table_row_key(column, row_keys, used_keys)
        if key is None and index < len(row_keys) and row_keys[index] not in used_keys:
            key = row_keys[index]
        if key is None:
            key = next((candidate for candidate in row_keys if candidate not in used_keys), None)
        if key is None:
            bound_columns.append(column)
            continue
        used_keys.add(key)
        bound_columns.append({"key": key, "label": column})
    table["columns"] = bound_columns


def _matching_table_row_key(label: str, keys: list[str], used_keys: set[str]) -> str | None:
    normalized_label = _normalize_machine_key(label)
    available = [key for key in keys if key not in used_keys]
    direct = next((key for key in available if _normalize_machine_key(key) == normalized_label), None)
    if direct is not None:
        return direct
    aliases = {
        "vulnerability_id": ("id", "identifier", "cve", "cve_id", "vulnerability_id"),
        "cve_id": ("cve_id", "cve", "id", "identifier"),
        "finding_title": ("title", "finding_title", "name"),
        "review_status": ("status", "review_status", "state"),
    }
    candidates = aliases.get(normalized_label, ())
    return next((key for alias in candidates for key in available if _normalize_machine_key(key) == alias), None)


def _is_translatable_path(path: tuple[Any, ...], value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    keys = [str(item) for item in path if not isinstance(item, int)]
    if not keys:
        return False
    raw_key = keys[-1]
    key = raw_key.lower()
    ancestors = {item.lower() for item in keys[:-1]}
    if ancestors & _PROTECTED_ANCESTORS:
        return False
    if _is_structured_table_column_label_path(path):
        return (
            _contains_human_readable_text(text)
            or _TABLE_DISPLAY_ENUM_VALUE.fullmatch(text) is not None
        )
    if _is_structured_table_cell_path(path):
        # Table rows are presentation data, so prose in arbitrary column keys
        # must pass through the same Translation Agent as the surrounding
        # answer. Both the column key and the scalar value are checked so
        # object rows and positional array rows receive the same protection.
        machine_key = _normalize_machine_key(raw_key)
        return (
            not _is_table_machine_cell_key(path)
            and not _is_table_machine_value(text, key=machine_key)
            and (
                _contains_human_readable_text(text)
                or _is_table_display_enum_value(text, key=machine_key)
            )
        )
    if _MACHINE_VALUE.fullmatch(text):
        return False
    if key in _PROTECTED_KEYS or key in _DISPLAY_MACHINE_KEYS:
        return False
    if key in _TRANSLATABLE_KEYS:
        return True
    return "fields" in ancestors or "vulnerability_card" in ancestors or "interrupt" in ancestors


def _is_structured_table_column_label_path(path: tuple[Any, ...]) -> bool:
    normalized = [str(item).lower() for item in path if not isinstance(item, int)]
    if not _path_has_table_container(normalized):
        return False
    try:
        columns_index = len(normalized) - 1 - normalized[::-1].index("columns")
    except ValueError:
        return False
    if not any(item in _TABLE_CONTAINER_KEYS for item in normalized[:columns_index]):
        return False
    if isinstance(path[-1], int):
        return normalized[-1] == "columns"
    return normalized[-1] in _TABLE_COLUMN_LABEL_KEYS and columns_index < len(normalized) - 1


def _is_structured_table_cell_path(path: tuple[Any, ...]) -> bool:
    normalized = [str(item).lower() for item in path if not isinstance(item, int)]
    if not _path_has_table_container(normalized):
        return False
    table_index = max(
        index for index, item in enumerate(normalized) if item in _TABLE_CONTAINER_KEYS
    )
    return any(item in _TABLE_ROW_KEYS for item in normalized[table_index + 1 :])


def _path_has_table_container(normalized: list[str]) -> bool:
    return any(item in _TABLE_CONTAINER_KEYS for item in normalized)


def _normalize_machine_key(value: str) -> str:
    snake_case = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(
        r"[^a-z0-9\u3400-\u9fff]+", "_", snake_case.casefold()
    ).strip("_")


def _is_table_machine_cell_key(path: tuple[Any, ...]) -> bool:
    normalized = [
        _normalize_machine_key(str(item)) for item in path if not isinstance(item, int)
    ]
    key = normalized[-1]
    if key in _TABLE_MACHINE_CELL_KEYS:
        return True
    return key == "name" and bool(
        set(normalized[:-1]) & _TABLE_CONTEXTUAL_NAME_ANCESTORS
    )


def _is_table_machine_value(value: str, *, key: str) -> bool:
    if _is_table_display_enum_value(value, key=key):
        return False
    return bool(
        _MACHINE_VALUE.fullmatch(value)
        or _TABLE_MACHINE_VALUE.fullmatch(value)
        or _MACHINE_PATH.fullmatch(value)
        or _TECHNICAL_SEGMENT.fullmatch(value)
    )


def _is_table_display_enum_value(value: str, *, key: str) -> bool:
    return key in _TABLE_DISPLAY_ENUM_KEYS and bool(
        _TABLE_DISPLAY_ENUM_VALUE.fullmatch(value)
    )


def _contains_human_readable_text(value: str) -> bool:
    return bool(_CJK_CHAR.search(value) or _LATIN_PROSE.search(value))


def _collect_control_machine_literals(root: Any) -> tuple[str, ...]:
    literals: set[str] = set()

    def visit(value: Any, path: tuple[Any, ...]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                visit(item, (*path, str(key)))
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, (*path, index))
            return
        if not isinstance(value, str):
            return
        keys = [str(item).lower() for item in path if not isinstance(item, int)]
        if len(keys) < 2 or keys[-1] not in _CONTROL_MACHINE_KEYS:
            return
        if not set(keys[:-1]) & _CONTROL_MACHINE_ANCESTORS:
            return
        literal = value.strip()
        if len(literal) >= 2 and not re.search(r"\s", literal):
            literals.add(literal)

    visit(root, ())
    return tuple(sorted(literals, key=lambda item: (-len(item), item)))


def _candidate_batches(candidates: list[_Candidate]) -> list[list[_Candidate]]:
    batches: list[list[_Candidate]] = []
    current: list[_Candidate] = []
    current_size = 0
    for candidate in candidates:
        size = len(candidate.text.encode("utf-8"))
        if current and (len(current) >= _BATCH_MAX_ITEMS or current_size + size > _BATCH_MAX_BYTES):
            batches.append(current)
            current = []
            current_size = 0
        current.append(candidate)
        current_size += size
    if current:
        batches.append(current)
    return batches


def _translate_batch(
    root: Any,
    batch: list[_Candidate],
    *,
    target: str,
) -> _TranslationWorkResult:
    changed = 0
    engine_calls = 0
    provenances: set[_VerifiedOfflineProvenance] = set()
    pending: list[_Candidate] = []
    segmented: dict[str, list[tuple[bool, str]]] = {}
    prose_inputs: list[str] = []
    prose_locations: list[tuple[str, int]] = []
    product_entities: dict[tuple[str, int], tuple[tuple[str, str], ...]] = {}
    engine_candidates: set[str] = set()
    for candidate in batch:
        # The answer model already writes in the requested UI language. Pure
        # Simplified Chinese is therefore safe to publish without loading the
        # optional English-to-Chinese model; only mixed/English prose needs it.
        if target == "zh-Hans" and _candidate_already_localized(candidate, target):
            _set_path(root, candidate.path, candidate.text)
            continue
        cached = (
            None
            if candidate.protected_literals
            else _translation_cache_get(target, candidate.text)
        )
        if cached is not None and _valid_translation(
            candidate.text,
            cached.translated,
            target,
            protected_literals=candidate.protected_literals,
        ):
            changed += int(cached.translated != candidate.text)
            if cached.provenance is not None:
                provenances.add(cached.provenance)
            _set_path(root, candidate.path, cached.translated)
            continue
        # Large advisory descriptions are handled by the chunked single-item
        # retry below. Sending them in the first batch can stall the offline
        # engine on x86_64/Rosetta and delays every later translation request.
        if len(candidate.text) > _LONG_TEXT_CHARS:
            continue
        pending.append(candidate)
        parts = _split_protected_segments(candidate.text)
        segmented[candidate.identifier] = parts
        for part_index, (opaque, text) in enumerate(parts):
            if not opaque and _prose_requires_translation(text):
                override = _translate_prose_override(text, target)
                if override is None:
                    protected_literals = tuple(
                        literal
                        for literal in candidate.protected_literals
                        if literal in text
                    )
                    masked, entities = _mask_candidate_entities(text, protected_literals)
                    prose_inputs.append(_apply_security_glossary(masked, target))
                    prose_locations.append((candidate.identifier, part_index))
                    product_entities[(candidate.identifier, part_index)] = entities
                    engine_candidates.add(candidate.identifier)
                else:
                    parts[part_index] = (False, override)
    if not pending:
        return _TranslationWorkResult(
            changed=changed,
            engine_calls=engine_calls,
            provenances=frozenset(provenances),
        )

    invocation_provenance: _VerifiedOfflineProvenance | None = None
    if prose_inputs:
        outputs = offline_translation_engine.translate_batch(prose_inputs, target_language=target)
        engine_calls += 1
        if len(outputs) != len(prose_locations):
            raise OfflineTranslationUnavailable("Offline translation returned an incomplete batch")
        invocation_provenance = _verified_offline_provenance()
        if invocation_provenance is not None:
            provenances.add(invocation_provenance)
        for (identifier, part_index), translated in zip(prose_locations, outputs, strict=True):
            parts = segmented[identifier]
            source_part = parts[part_index][1]
            restored = _restore_product_entities(
                str(translated or ""),
                product_entities.get((identifier, part_index), ()),
            )
            parts[part_index] = (
                False,
                _preserve_edge_whitespace(source_part, restored or ""),
            )
    for candidate in pending:
        text = "".join(part for _opaque, part in segmented[candidate.identifier]).strip()
        text = _normalize_security_translation(candidate.text, text, target)
        if not _valid_translation(
            candidate.text,
            text,
            target,
            protected_literals=candidate.protected_literals,
        ):
            continue
        if text != candidate.text:
            candidate_provenance = (
                invocation_provenance
                if candidate.identifier in engine_candidates
                else None
            )
            if not candidate.protected_literals:
                _translation_cache_put(
                    target,
                    candidate.text,
                    text,
                    provenance=candidate_provenance,
                )
            if candidate_provenance is not None:
                provenances.add(candidate_provenance)
            changed += 1
        _set_path(root, candidate.path, text)
    return _TranslationWorkResult(
        changed=changed,
        engine_calls=engine_calls,
        provenances=frozenset(provenances),
    )


def _translate_single(
    root: Any,
    candidate: _Candidate,
    *,
    target: str,
) -> _TranslationWorkResult:
    cached = (
        None
        if candidate.protected_literals
        else _translation_cache_get(target, candidate.text)
    )
    if cached is not None and _valid_translation(
        candidate.text,
        cached.translated,
        target,
        protected_literals=candidate.protected_literals,
    ):
        _set_path(root, candidate.path, cached.translated)
        return _TranslationWorkResult(
            changed=int(cached.translated != candidate.text),
            engine_calls=0,
            provenances=(
                frozenset({cached.provenance})
                if cached.provenance is not None
                else frozenset()
            ),
        )
    chunks = (
        _split_long_text(candidate.text, _LONG_TEXT_CHUNK_CHARS)
        if len(candidate.text) > _LONG_TEXT_CHARS else [candidate.text]
    )
    translated_chunks: list[str] = []
    calls = 0
    provenances: set[_VerifiedOfflineProvenance] = set()
    for chunk in chunks:
        parts = _split_protected_segments(chunk)
        prose_indexes: list[int] = []
        prose_inputs: list[str] = []
        product_entities: list[tuple[tuple[str, str], ...]] = []
        for index, (opaque, text) in enumerate(parts):
            if opaque or not _prose_requires_translation(text):
                continue
            override = _translate_prose_override(text, target)
            if override is not None:
                parts[index] = (False, override)
            else:
                protected_literals = tuple(
                    literal
                    for literal in candidate.protected_literals
                    if literal in text
                )
                masked, entities = _mask_candidate_entities(text, protected_literals)
                prose_indexes.append(index)
                prose_inputs.append(_apply_security_glossary(masked, target))
                product_entities.append(entities)
        if prose_indexes:
            translated = offline_translation_engine.translate_batch(
                prose_inputs,
                target_language=target,
            )
            calls += 1
            provenance = _verified_offline_provenance()
            if provenance is not None:
                provenances.add(provenance)
            for index, text, entities in zip(
                prose_indexes,
                translated,
                product_entities,
                strict=True,
            ):
                restored = _restore_product_entities(str(text or ""), entities)
                parts[index] = (
                    False,
                    _preserve_edge_whitespace(parts[index][1], restored or ""),
                )
        restored = "".join(text for _opaque, text in parts).strip()
        restored = _normalize_security_translation(chunk, restored, target)
        chunk_literals = tuple(
            literal for literal in candidate.protected_literals if literal in chunk
        )
        if not _valid_translation(
            chunk,
            restored,
            target,
            protected_literals=chunk_literals,
        ):
            return _TranslationWorkResult(0, calls, frozenset(provenances))
        translated_chunks.append(restored)
    text = "\n\n".join(translated_chunks)
    if not _valid_translation(
        candidate.text,
        text,
        target,
        protected_literals=candidate.protected_literals,
    ):
        return _TranslationWorkResult(0, calls, frozenset(provenances))
    if text != candidate.text:
        cache_provenance = (
            next(iter(provenances)) if len(provenances) == 1 else None
        )
        if not candidate.protected_literals:
            _translation_cache_put(
                target,
                candidate.text,
                text,
                provenance=cache_provenance,
            )
    _set_path(root, candidate.path, text)
    return _TranslationWorkResult(
        changed=int(text != candidate.text),
        engine_calls=calls,
        provenances=frozenset(provenances),
    )


def _split_protected_segments(text: str) -> list[tuple[bool, str]]:
    """Split into prose and opaque evidence so evidence never enters Marian."""

    parts: list[tuple[bool, str]] = []
    cursor = 0
    for match in _TECHNICAL_SEGMENT.finditer(text):
        segment = match.group(0)
        if _is_soft_path_segment(segment) or segment in {"RCE", "XSS", "CSRF", "SSRF"}:
            continue
        if match.start() > cursor:
            parts.append((False, text[cursor : match.start()]))
        parts.append((True, segment))
        cursor = match.end()
    if cursor < len(text):
        parts.append((False, text[cursor:]))
    return parts or [(False, text)]


def _prose_requires_translation(text: str) -> bool:
    return bool(re.search(r"[A-Za-z\u3400-\u9fff]", text) and text.strip())


def _translate_prose_override(text: str, target: str) -> str | None:
    """Disambiguate security phrases split away from protected evidence."""

    normalized = re.sub(r"\s+", " ", text.strip()).casefold()
    simplified = {
        "remote code execution vulnerability in": "远程代码执行漏洞位于",
        "remote code execution vulnerabilities in": "远程代码执行漏洞位于",
        "remote code execution in": "远程代码执行存在于",
        "stored xss in": "存储型跨站脚本（XSS）存在于",
        "reflected xss in": "反射型跨站脚本（XSS）存在于",
        "command injection in": "命令注入存在于",
        "sql injection in": "SQL 注入存在于",
        "cross-site scripting in": "跨站脚本漏洞存在于",
        "firmware": "固件",
        "before": "，受影响版本早于",
        "after": "，受影响版本晚于",
        "at": "，位置为",
        "calls": "，调用",
        "allows": "允许",
        "and": "和",
        "or": "或",
        "see": "参见",
        "in": "位于",
        "of the file": "文件中的",
        "impacted is the function": "受影响函数为",
        "injection; see": "注入；参见",
        "injection. see": "注入。参见",
        "is vulnerable.": "存在漏洞。",
        "is vulnerable": "存在漏洞",
        "vulnerability.": "漏洞。",
    }
    value = simplified.get(normalized)
    if value is None:
        return None
    if target == "zh-Hant":
        traditional = {
            "远程代码执行漏洞位于": "遠端程式碼執行漏洞位於",
            "远程代码执行存在于": "遠端程式碼執行存在於",
            "存储型跨站脚本（XSS）存在于": "儲存型跨站腳本（XSS）存在於",
            "反射型跨站脚本（XSS）存在于": "反射型跨站腳本（XSS）存在於",
            "命令注入存在于": "命令注入存在於",
            "SQL 注入存在于": "SQL 注入存在於",
            "跨站脚本漏洞存在于": "跨站腳本漏洞存在於",
            "固件": "韌體",
            "，受影响版本早于": "，受影響版本早於",
            "，受影响版本晚于": "，受影響版本晚於",
            "，位置为": "，位置為",
            "，调用": "，呼叫",
            "允许": "允許",
            "和": "和",
            "或": "或",
            "参见": "參見",
            "位于": "位於",
            "文件中的": "檔案中的",
            "受影响函数为": "受影響函式為",
            "注入；参见": "注入；參見",
            "注入。参见": "注入。參見",
            "存在漏洞。": "存在漏洞。",
            "存在漏洞": "存在漏洞",
            "漏洞。": "漏洞。",
        }
        value = traditional[value]
    return _preserve_edge_whitespace(text, value)


def _preserve_edge_whitespace(source: str, translated: str) -> str:
    leading = re.match(r"^\s*", source).group(0)
    trailing = re.search(r"\s*$", source).group(0)
    return f"{leading}{translated.strip()}{trailing}"


def _apply_security_glossary(text: str, target: str) -> str:
    translated = text
    for pattern, simplified, traditional in _SECURITY_GLOSSARY:
        translated = re.sub(pattern, traditional if target == "zh-Hant" else simplified, translated)
    return translated


def _mask_product_entities(text: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    entities: list[tuple[str, str]] = []
    reserved = set(_PRESERVED_SEGMENT.findall(text))
    verified_spans = {
        (match.start(), match.end()) for match in _VERIFIED_PRODUCT_ENTITY_SEGMENT.finditer(text)
    }
    standalone_matches = list(_STANDALONE_PRODUCT_ENTITY.finditer(text))
    standalone_by_span = {
        (match.start(), match.end()): index for index, match in enumerate(standalone_matches)
    }

    def replace(match: re.Match[str]) -> str:
        entity = match.group(0)
        if entity.casefold() in _ENGLISH_PROSE_WORDS:
            return entity
        span = (match.start(), match.end())
        if span not in verified_spans and not _standalone_product_allowed(
            text,
            span,
            standalone_matches,
            standalone_by_span,
            verified_spans,
        ):
            return entity
        index = len(entities)
        token = _product_entity_marker(index)
        while token in text or token in reserved:
            index += 1
            token = _product_entity_marker(index)
        reserved.add(token)
        entities.append((token, entity))
        return token

    return _PRODUCT_ENTITY_SEGMENT.sub(replace, text), tuple(entities)


def _mask_candidate_entities(
    text: str,
    protected_literals: tuple[str, ...] = (),
) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Mask product names and caller-provided control literals for Marian.

    Product entities are detected from the prose itself.  Some structured
    payloads also repeat machine identifiers (for example a report or task
    name) inside a customer-visible sentence; those values are supplied via
    ``protected_literals`` and must survive translation byte-for-byte too.
    Each occurrence receives its own CJK marker because the restoration
    contract deliberately rejects a missing or duplicated marker.
    """

    masked, detected = _mask_product_entities(text)
    entities = list(detected)
    reserved = {token for token, _entity in entities}
    next_index = len(entities)
    for literal in sorted(
        {str(value) for value in protected_literals if str(value)},
        key=lambda value: (-len(value), value),
    ):
        while literal in masked:
            token = _product_entity_marker(next_index)
            next_index += 1
            while token in text or token in masked or token in reserved:
                token = _product_entity_marker(next_index)
                next_index += 1
            masked = masked.replace(literal, token, 1)
            reserved.add(token)
            entities.append((token, literal))
    return masked, tuple(entities)


def _standalone_product_allowed(
    text: str,
    span: tuple[int, int],
    matches: list[re.Match[str]],
    by_span: dict[tuple[int, int], int],
    verified_spans: set[tuple[int, int]],
) -> bool:
    index = by_span.get(span)
    if index is None:
        return False
    # In pure English prose an unverified capitalized word is normally a
    # sentence boundary, not a product. Contextual/camel-case products were
    # already admitted through ``verified_spans`` above.
    if not _CJK_CHAR.search(text):
        return False
    adjacent: list[tuple[int, int]] = []
    if index > 0:
        previous = matches[index - 1]
        if not text[previous.end() : span[0]].strip():
            adjacent.append((previous.start(), previous.end()))
    if index + 1 < len(matches):
        following = matches[index + 1]
        if not text[span[1] : following.start()].strip():
            adjacent.append((following.start(), following.end()))
    return not adjacent or any(item in verified_spans for item in adjacent)


def _product_entity_marker(index: int) -> str:
    value = max(0, index)
    digits = ""
    while True:
        digits = _PRODUCT_ENTITY_MARKER_DIGITS[value % len(_PRODUCT_ENTITY_MARKER_DIGITS)] + digits
        value = value // len(_PRODUCT_ENTITY_MARKER_DIGITS) - 1
        if value < 0:
            break
    return f"{digits}方"


def _restore_product_entities(
    text: str,
    entities: tuple[tuple[str, str], ...],
) -> str | None:
    restored = text
    for token, entity in entities:
        if restored.count(token) != 1:
            return None
        restored = restored.replace(token, entity, 1)
    return restored


def _mask_code_blocks(text: str) -> tuple[str, list[str]]:
    """Compatibility helper retained for security regression tests."""

    blocks = _FENCED_BLOCK.findall(text)
    masked = text
    for index, block in enumerate(blocks, 1):
        masked = masked.replace(block, f"[[SEC-BLOCK-{index}]]", 1)
    return masked, blocks


def _restore_code_blocks(text: str, blocks: list[str]) -> str | None:
    restored = text
    for index, block in enumerate(blocks, 1):
        token = f"[[SEC-BLOCK-{index}]]"
        if token not in restored:
            return None
        restored = restored.replace(token, block, 1)
    return restored


def _normalize_security_translation(source: str, translated: str, target: str) -> str:
    if target not in {"zh-Hans", "zh-Hant"}:
        return translated
    replacements = (
        ("RCE", "远程代码执行（RCE）", "遠端程式碼執行（RCE）"),
        ("XSS", "跨站脚本（XSS）", "跨站腳本（XSS）"),
        ("CSRF", "跨站请求伪造（CSRF）", "跨站請求偽造（CSRF）"),
        ("SSRF", "服务端请求伪造（SSRF）", "伺服器端請求偽造（SSRF）"),
    )
    clean = translated.replace("\u2581", " ")
    clean = re.sub(r"[ \t]{2,}", " ", clean)
    for acronym, simplified, traditional in replacements:
        if re.search(rf"\b{acronym}\b", source) and not _contains_equivalent_term(clean, acronym):
            clean = re.sub(rf"\b{acronym}\b", traditional if target == "zh-Hant" else simplified, clean)
    clean = _normalize_product_relations(source, clean, target)
    clean = _normalize_vulnerable_lookup_injection(source, clean, target)
    clean = _normalize_commit_references(source, clean, target)
    clean = _normalize_version_constraints(source, clean, target)
    return clean.strip()


def _normalize_product_relations(source: str, translated: str, target: str) -> str:
    clean = translated
    _masked, entities = _mask_product_entities(source)
    for _marker, entity in entities:
        escaped = re.escape(entity)
        if re.search(rf"(?i)\bin\s+{escaped}\b", source):
            relation = "存在於" if target == "zh-Hant" else "存在于"
            clean = re.sub(rf"(?:輸入|输入)\s*{escaped}", f"{relation} {entity}", clean)
        arbitrary = "執行任意程式碼" if target == "zh-Hant" else "执行任意代码"
        attacker = "遠程攻擊者可" if target == "zh-Hant" else "远程攻击者可"
        clean = re.sub(
            rf"(?:遠程攻擊者|远程攻击者)(?:可以|可)?\s*{arbitrary}\s*(?:輸入|输入|存在於|存在于)\s*{escaped}",
            f"{attacker}在 {entity} 中{arbitrary}",
            clean,
        )
        if re.search(rf"(?i)^\s*{escaped}\s+(?:before|after|prior\s+to|earlier\s+than|later\s+than)\b", source):
            vulnerable = f"{entity} 存在漏洞"
            clean = re.sub(
                rf"(?:前為|前为)\s*{escaped}\s*時?\s*(?:脆弱|存在漏洞)?",
                vulnerable,
                clean,
            )
            clean = re.sub(rf"{escaped}\s*脆弱", vulnerable, clean)
    return clean


def _normalize_vulnerable_lookup_injection(source: str, translated: str, target: str) -> str:
    match = re.fullmatch(
        r"\s*(?:(?P<prefix>[A-Z][A-Za-z0-9_-]*)\s+)?lookup\s+injection\s+in\s+"
        r"vulnerable\s+(?P<product>[A-Z][A-Za-z0-9_.+-]*)\s+versions?\s*[.!?]?\s*",
        source,
        flags=re.IGNORECASE,
    )
    if match is None:
        return translated
    prefix = f"{match.group('prefix')} " if match.group("prefix") else ""
    product = match.group("product")
    if target == "zh-Hant":
        return f"{prefix}查詢注入會影響存在漏洞的 {product} 版本。"
    return f"{prefix}查找注入会影响存在漏洞的 {product} 版本。"


def _normalize_commit_references(source: str, translated: str, target: str) -> str:
    clean = translated
    for match in re.finditer(r"(?i)\bcommit\s+([A-Fa-f0-9]{7,64})\b", source):
        commit_hash = match.group(1)
        label = "提交" if target == "zh-Hans" else "提交"
        clean = re.sub(
            rf"(?:和\s*)?(?:承諾|承诺|提交)\s*{re.escape(commit_hash)}",
            f"{label} {commit_hash}",
            clean,
        )
    return clean


def _normalize_version_constraints(source: str, translated: str, target: str) -> str:
    constraint = re.compile(
        r"(?i)\b(before|prior\s+to|earlier\s+than|after|later\s+than)\s+"
        r"(v?\d+(?:\.\d+){1,4}(?:(?:[-+._]?[A-Za-z][A-Za-z0-9_-]*)(?:\.\d+)*)?)"
    )
    matches = list(constraint.finditer(source))
    if not matches:
        return translated
    clean = translated
    rendered: list[str] = []
    for match in matches:
        operator = match.group(1).casefold()
        version = match.group(2)
        clean = clean.replace(version, " ")
        clean = re.sub(
            r"\s*(?:在此之前|在此之後|在此之后|之前的網頁中|之前的网页中|"
            r"時間在|时间在|之前為|之前为)\s*",
            " ",
            clean,
        )
        if operator in {"before", "prior to", "earlier than"}:
            phrase = f"受影響版本早於 {version}" if target == "zh-Hant" else f"受影响版本早于 {version}"
        else:
            phrase = f"受影響版本晚於 {version}" if target == "zh-Hant" else f"受影响版本晚于 {version}"
        if phrase not in rendered:
            rendered.append(phrase)
    clean = re.sub(r"\s{2,}", " ", clean).strip(" ,，.。;；")
    separator = "，" if clean else ""
    return f"{clean}{separator}{'；'.join(rendered)}。"


def _contains_equivalent_term(text: str, acronym: str) -> bool:
    terms = {
        "RCE": ("远程代码执行", "遠端程式碼執行", "遠程代碼執行"),
        "XSS": ("跨站脚本", "跨站腳本"),
        "CSRF": ("跨站请求伪造", "跨站請求偽造"),
        "SSRF": ("服务端请求伪造", "伺服器端請求偽造", "服務端請求偽造"),
    }
    return any(term in text for term in terms.get(acronym, ()))


def _valid_translation(
    source: str,
    translated: str,
    target: str,
    *,
    protected_literals: tuple[str, ...] = (),
) -> bool:
    if (
        not translated
        or not _preserves_machine_segments(source, translated)
        or not _preserves_protected_literals(source, translated, protected_literals)
    ):
        return False
    if target in {"zh-Hans", "zh-Hant"} and not _preserves_security_meaning(source, translated):
        return False
    _masked_source, source_entities = _mask_product_entities(source)
    allowed_segments = (
        *_preserved_segments(source),
        *(entity for _marker, entity in source_entities),
        *_mixed_localized_technical_segments(source),
        *protected_literals,
    )
    if target in {"zh-Hans", "zh-Hant"} and _requires_english_translation(
        source,
        allowed_segments=allowed_segments,
    ):
        if not _CJK_CHAR.search(translated) or _requires_english_translation(
            translated,
            allowed_segments=allowed_segments,
        ):
            return False
        source_sentences = _sentence_count(_unprotected_prose(source))
        translated_sentences = _sentence_count(_unprotected_prose(translated))
        if source_sentences >= 4 and translated_sentences < max(1, int(source_sentences * 0.8)):
            return False
    return True


def _preserves_protected_literals(
    source: str,
    translated: str,
    protected_literals: tuple[str, ...],
) -> bool:
    return all(
        translated.count(literal) == source.count(literal)
        for literal in protected_literals
        if literal
    )


def _preserves_security_meaning(source: str, translated: str) -> bool:
    for source_pattern, accepted_terms in _SECURITY_MEANING_ANCHORS:
        if re.search(source_pattern, source) and not any(term in translated for term in accepted_terms):
            return False
    return True


def _candidate_already_localized(candidate: _Candidate, target: str) -> bool:
    _masked, entities = _mask_product_entities(candidate.text)
    allowed_segments = (
        *_preserved_segments(candidate.text),
        *(entity for _marker, entity in entities),
        *_mixed_localized_technical_segments(candidate.text),
        *candidate.protected_literals,
    )
    return (
        target in {"zh-Hans", "zh-Hant"}
        and bool(_CJK_CHAR.search(candidate.text))
        and not _requires_english_translation(candidate.text, allowed_segments=allowed_segments)
    )


def _get_path(root: Any, path: tuple[Any, ...]) -> Any:
    current = root
    for item in path:
        current = current[item]
    return current


def _untranslated_candidates(candidates: list[_Candidate], root: Any, target: str) -> list[_Candidate]:
    if target not in {"zh-Hans", "zh-Hant"}:
        return []
    unresolved: list[_Candidate] = []
    for candidate in candidates:
        current = _get_path(root, candidate.path)
        if not isinstance(current, str) or not _valid_translation(
            candidate.text,
            current,
            target,
            protected_literals=candidate.protected_literals,
        ):
            unresolved.append(candidate)
    return unresolved


def _unprotected_prose(text: str) -> str:
    return "".join(segment for opaque, segment in _split_protected_segments(text) if not opaque)


def _requires_english_translation(
    text: str,
    *,
    allowed_segments: tuple[str, ...] | None = None,
) -> bool:
    prose = _unprotected_prose(text)
    verified_segments = _preserved_segments(text) if allowed_segments is None else allowed_segments
    for segment in sorted(verified_segments, key=len, reverse=True):
        prose = prose.replace(segment, " ")
    prose = _SAFE_TECHNICAL_ACRONYM.sub(" ", prose)
    words = _LATIN_PROSE.findall(prose)
    return bool(words)


def _preserved_segments(text: str) -> tuple[str, ...]:
    return tuple(
        segment
        for segment in _PRESERVED_SEGMENT.findall(text)
        if not _is_soft_path_segment(segment)
    )


def _mixed_localized_technical_segments(text: str) -> tuple[str, ...]:
    if not _CJK_CHAR.search(text):
        return ()
    return tuple(_MIXED_LOCALIZED_TECHNICAL_TOKEN.findall(text))


def _sentence_count(text: str) -> int:
    return len(re.findall(r"[.!?。！？]+(?:\s|$)", text))


def _split_prose_paragraphs(text: str, limit: int) -> list[str]:
    pieces: list[str] = []
    current = ""
    for paragraph in text.split("\n\n"):
        while len(paragraph) > limit:
            cut = paragraph.rfind("\n", 0, limit)
            if cut < limit // 2:
                cut = max(paragraph.rfind("。", 0, limit), paragraph.rfind(". ", 0, limit))
            if cut < limit // 2:
                cut = limit
            piece, paragraph = paragraph[:cut].strip(), paragraph[cut:].strip()
            if current:
                pieces.append(current)
                current = ""
            if piece:
                pieces.append(piece)
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if current and len(candidate) > limit:
            pieces.append(current)
            current = paragraph
        else:
            current = candidate
    if current:
        pieces.append(current)
    return [piece for piece in pieces if piece.strip()]


def _split_long_text(text: str, limit: int) -> list[str]:
    units: list[str] = []
    cursor = 0
    for match in _FENCED_BLOCK.finditer(text):
        if match.start() > cursor:
            units.extend(_split_prose_paragraphs(text[cursor : match.start()], limit))
        units.append(match.group(0))
        cursor = match.end()
    if cursor < len(text):
        units.extend(_split_prose_paragraphs(text[cursor:], limit))
    chunks: list[str] = []
    current = ""
    for unit in units:
        candidate = f"{current}\n\n{unit}" if current else unit
        if current and len(candidate) > limit:
            chunks.append(current)
            current = unit
        else:
            current = candidate
    if current:
        chunks.append(current)
    return [chunk for chunk in chunks if chunk.strip()]


def _is_soft_path_segment(segment: str) -> bool:
    if not _MACHINE_PATH.fullmatch(segment):
        return False
    if segment.startswith("@"):
        return False
    return not any(re.search(r"[.\d]", part) for part in segment.split("/"))


def _preserves_machine_segments(source: str, translated: str) -> bool:
    for segment in _PRESERVED_SEGMENT.findall(source):
        if segment in translated:
            continue
        if segment.startswith("`"):
            inner = segment.strip("`").strip()
            if inner and inner in translated:
                continue
            if len(inner) <= 2:
                continue
        if segment.endswith(".") and segment.rstrip(".") and segment.rstrip(".") in translated:
            continue
        if _is_soft_path_segment(segment):
            continue
        return False
    return True


def _set_path(root: Any, path: tuple[Any, ...], value: str) -> None:
    current = root
    for item in path[:-1]:
        current = current[item]
    current[path[-1]] = value


def _public_translation_error(exc: BaseException) -> str:
    clean = sanitize_public_text(str(exc)).strip()
    return (clean or "Offline translation failed")[:300]


def _json_value(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(deepcopy(value), ensure_ascii=False, default=str))


def _payload_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> None:
    translation_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
