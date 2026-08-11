from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections import OrderedDict
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from threading import Condition, RLock
from typing import Any, Iterator, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from app.llm import active_model_from_env, diagnose_chat_completion
from app.privacy import sanitize_public_text


_LANGUAGE_NAMES = {
    "zh-Hans": "Simplified Chinese",
    "zh-Hant": "Traditional Chinese",
    "en": "English",
    "ko": "Korean",
    "ja": "Japanese",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "it": "Italian",
    "ru": "Russian",
}

_TRANSLATABLE_KEYS = {
    "answer",
    "analysis",
    "conclusion",
    "content",
    "description",
    "detail",
    "fix_advice",
    "impact",
    "label",
    "message",
    "mitigation",
    "question",
    "reason",
    "recommendation",
    "remediation",
    "solution",
    "summary",
    "summary_zh",
    "text",
    "title",
}

_PROTECTED_KEYS = {
    "$schema",
    "action",
    "api_key",
    "artifact_id",
    "checksum",
    "code",
    "completed_at",
    "content_base64",
    "created_at",
    "cve",
    "cve_id",
    "digest",
    "ecosystem",
    "email",
    "file",
    "file_name",
    "fixed_code",
    "fixed_snippet",
    "fixed_version",
    "format",
    "generated_at",
    "ghsa",
    "hash",
    "href",
    "id",
    "identifier",
    "image_base64",
    "input_sha256",
    "interrupt_id",
    "kind",
    "language",
    "media_type",
    "mode",
    "model",
    "name",
    "operation_thread_id",
    "output_sha256",
    "package",
    "path",
    "payload_sha256",
    "provider",
    "reference",
    "reference_links",
    "renderer",
    "rule_id",
    "schema_version",
    "server",
    "session_id",
    "sha256",
    "snippet",
    "source",
    "source_kind",
    "source_url",
    "status",
    "task_id",
    "thread_id",
    "tool",
    "transport",
    "uri",
    "url",
    "user_id",
    "version",
    "vulnerable_snippet",
    "workspace_path",
}

_PROTECTED_ANCESTORS = {
    "artifacts",
    "audit",
    "chart_data",
    "code_blocks",
    "diagnostics",
    "diagrams",
    "events",
    "knowledge_graph",
    "orchestration",
    "report_mcps",
    "skill",
    "snippet_lines",
    "trace",
    "translation",
}

_MACHINE_VALUE = re.compile(
    r"^(?:https?://\S+|[A-Fa-f0-9]{32,}|CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|"
    r"v?\d+(?:\.\d+){1,4}(?:[-+][A-Za-z0-9.-]+)?|/[A-Za-z0-9._/\\-]+)$",
    flags=re.IGNORECASE,
)

_PRESERVED_SEGMENT = re.compile(
    r"```[\s\S]*?```|`[^`\n]+`|https?://[^\s,，；;）)]+|CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|"
    r"\b[A-Fa-f0-9]{32,}\b|(?<![\w.-])v?\d+(?:\.\d+){1,4}(?:[-+][A-Za-z0-9.-]+)?|"
    r"(?<![\w.-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(?:\:\d+)?",
    flags=re.IGNORECASE,
)

_CJK_CHAR = re.compile(r"[぀-ヿ㐀-䶿一-鿿豈-﫿]")

# 翻译专用输出预算：聊天配置里常见的 2048 max_tokens 会让批量翻译的 JSON
# 答案被截断（实测 12 条长描述即顶满），截断后整批解析失败并退化为逐字段
# 兜底，调用次数翻倍。翻译调用独立提高 maxTokens，不改动用户的聊天配置。
_TRANSLATION_MIN_MAX_TOKENS = int(os.environ.get("SECFLOW_TRANSLATION_MAX_TOKENS", "8192"))


def _translation_model(model: dict[str, Any] | None) -> dict[str, Any] | None:
    if not model:
        return model
    raised = dict(model)
    current = int(raised.get("maxTokens") or raised.get("max_tokens") or 0)
    if current < _TRANSLATION_MIN_MAX_TOKENS:
        raised["maxTokens"] = _TRANSLATION_MIN_MAX_TOKENS
    return raised


# 会话级翻译缓存：中断确认、恢复回复等 JSON 里大量字段文本完全相同（实测
# 一次会话里同一批 40 个字段被翻译两遍），按（目标语言, 模型, 原文哈希）
# 缓存已通过的译文，命中即零模型调用。缓存值必然已通过保护段校验。
_translation_cache: OrderedDict[tuple[str, str, str], str] = OrderedDict()
_TRANSLATION_CACHE_LIMIT = 2000
_translation_cache_lock = RLock()

# Interactive exports take priority over the catalog translation backfill.
# The background importer checks this gate before starting each model request;
# already-running requests finish normally, while new ones wait until the
# foreground batch has completed.
_translation_priority = Condition(RLock())
_foreground_translation_scopes = 0


@contextmanager
def foreground_translation_scope() -> Iterator[None]:
    global _foreground_translation_scopes
    with _translation_priority:
        _foreground_translation_scopes += 1
    try:
        yield
    finally:
        with _translation_priority:
            _foreground_translation_scopes = max(0, _foreground_translation_scopes - 1)
            _translation_priority.notify_all()


def _wait_for_translation_priority(content_scope: str) -> None:
    if not str(content_scope or "").startswith("vulnerability_catalog_"):
        return
    with _translation_priority:
        while _foreground_translation_scopes:
            _translation_priority.wait(timeout=0.5)


def _translation_cache_key(target: str, model: dict[str, Any], text: str) -> tuple[str, str, str]:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return (target, str(model.get("model") or model.get("id") or ""), digest)


def _translation_cache_get(target: str, model: dict[str, Any], text: str) -> str | None:
    key = _translation_cache_key(target, model, text)
    with _translation_cache_lock:
        value = _translation_cache.get(key)
        if value is not None:
            _translation_cache.move_to_end(key)
        return value


def _translation_cache_put(target: str, model: dict[str, Any], text: str, translated: str) -> None:
    if not translated:
        return
    key = _translation_cache_key(target, model, text)
    with _translation_cache_lock:
        _translation_cache[key] = translated
        _translation_cache.move_to_end(key)
        while len(_translation_cache) > _TRANSLATION_CACHE_LIMIT:
            _translation_cache.popitem(last=False)


class TranslationOutput(BaseModel):
    schema_version: int = 1
    renderer: Literal["secflow-json-translation"] = "secflow-json-translation"
    target_language: str
    payload: dict[str, Any]
    translation_status: Literal["translated", "passthrough", "fallback"]
    candidate_fields: int
    translated_fields: int
    batch_count: int
    model_used: bool
    input_sha256: str
    output_sha256: str
    errors: list[str]


@dataclass(frozen=True)
class _Candidate:
    identifier: str
    path: tuple[Any, ...]
    text: str


translation_mcp = FastMCP(
    "SecFlow Translation MCP",
    instructions=(
        "Translate only customer-visible text extracted from structured JSON. Preserve JSON structure, code, file paths, "
        "package names, vulnerability identifiers, versions, URLs, hashes, and audit fields exactly."
    ),
)


@translation_mcp.tool(
    name="translate_json_payload",
    description="Translate customer-visible JSON values while preserving machine-readable security evidence.",
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
    _wait_for_translation_priority(content_scope)
    target = normalize_translation_language(target_language)
    clean = _json_value(payload)
    input_sha256 = _payload_sha256(clean)
    translatable_root = clean.get("payload") if clean.get("$schema") == "secflow.scan-results/v1" else clean
    candidates = _collect_candidates(translatable_root)
    model = _translation_model(active_model_from_env(user_id))
    errors: list[str] = []
    translated_fields = 0
    batch_count = 0

    if model and candidates:
        for batch in _candidate_batches(candidates):
            batch_count += 1
            try:
                translated_fields += _translate_batch(
                    translatable_root,
                    batch,
                    target=target,
                    model=model,
                    user_id=user_id,
                    session_id=session_id,
                    content_scope=content_scope,
                )
            except Exception as exc:  # noqa: BLE001 - translation failure must not destroy verified facts.
                message = sanitize_public_text(str(exc)).strip() or "translation batch failed"
                errors.append(message[:300])
        # 目标语言核验：批次翻译后仍非中文的字段（小模型可能原样返回），逐字段纯文本模式兜底重试。
        # 模型输出存在波动，对仍失败的字段再做一轮全新尝试，尽量不让英文漏进报告。
        for _attempt in range(2 if retry_untranslated_fields else 0):
            unresolved = _untranslated_candidates(candidates, translatable_root, target)
            if not unresolved:
                break
            for candidate in unresolved:
                batch_count += 1
                try:
                    translated_fields += _translate_single(
                        translatable_root,
                        candidate,
                        target=target,
                        model=model,
                        user_id=user_id,
                        session_id=session_id,
                        content_scope=content_scope,
                    )
                except Exception as exc:  # noqa: BLE001 - retry failure must not destroy verified facts.
                    message = sanitize_public_text(str(exc)).strip() or "translation retry failed"
                    errors.append(message[:300])

    if clean.get("$schema") == "secflow.scan-results/v1":
        from app.reports import refresh_scan_result_json

        clean = refresh_scan_result_json(clean, language=target)

    output_sha256 = _payload_sha256(clean)
    if translated_fields:
        status: Literal["translated", "passthrough", "fallback"] = "translated"
    elif errors or (candidates and not model):
        status = "fallback"
    else:
        status = "passthrough"
    return TranslationOutput(
        target_language=target,
        payload=clean,
        translation_status=status,
        candidate_fields=len(candidates),
        translated_fields=translated_fields,
        batch_count=batch_count,
        model_used=bool(model),
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        errors=errors,
    )


def invoke_translation_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(translation_mcp.call_tool("translate_json_payload", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("Translation MCP did not return structured output")


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
    text = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "zh-hant": "zh-Hant",
        "zh-tw": "zh-Hant",
        "zh-hk": "zh-Hant",
        "en": "en",
        "en-us": "en",
        "ko": "ko",
        "ko-kr": "ko",
        "ja": "ja",
        "ja-jp": "ja",
        "es": "es",
        "es-es": "es",
        "fr": "fr",
        "fr-fr": "fr",
        "de": "de",
        "de-de": "de",
        "it": "it",
        "it-it": "it",
        "ru": "ru",
        "ru-ru": "ru",
    }
    return aliases.get(text, "zh-Hans")


def _collect_candidates(root: Any) -> list[_Candidate]:
    output: list[_Candidate] = []

    def visit(value: Any, path: tuple[Any, ...]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                visit(item, (*path, str(key)))
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, (*path, index))
            return
        if not isinstance(value, str) or not _is_translatable_path(path, value):
            return
        output.append(_Candidate(identifier=f"t{len(output)}", path=path, text=value))

    visit(root, ())
    return output


def _is_translatable_path(path: tuple[Any, ...], value: str) -> bool:
    text = value.strip()
    if not text or len(text) > 16_000 or _MACHINE_VALUE.fullmatch(text):
        return False
    keys = [str(item) for item in path if not isinstance(item, int)]
    if not keys:
        return False
    key = keys[-1].lower()
    ancestors = {item.lower() for item in keys[:-1]}
    if key in _PROTECTED_KEYS or ancestors & _PROTECTED_ANCESTORS:
        return False
    if key in _TRANSLATABLE_KEYS:
        return True
    return "fields" in ancestors or "vulnerability_card" in ancestors or "interrupt" in ancestors


# 批次上限按输出预算倒推：译文 JSON 与原文体量相当，8KB 原文约产出 4-6K
# token，给 8192 的输出预算留出足够余量；更大的批次实测会顶满预算被截断，
# 整批解析失败反而退化成逐字段兜底、调用次数翻倍。
_BATCH_MAX_ITEMS = 24
_BATCH_MAX_BYTES = 8_000

# 超长文本（GitHub 公告常上万字符）无法在一次调用内译完：按段落切块逐段
# 翻译再拼接，单块 2200 字符对应的中文译文远低于输出预算。
_LONG_TEXT_CHARS = 4_000
_LONG_TEXT_CHUNK_CHARS = 2_200


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
    model: dict[str, Any],
    user_id: str,
    session_id: str,
    content_scope: str,
) -> int:
    changed = 0
    pending: list[_Candidate] = []
    for candidate in batch:
        cached = _translation_cache_get(target, model, candidate.text)
        if cached is not None and _preserves_machine_segments(candidate.text, cached) and _accepts_for_target(candidate.text, cached, target):
            if cached != candidate.text:
                changed += 1
            _set_path(root, candidate.path, cached)
        else:
            pending.append(candidate)
    if not pending:
        return changed
    masks: dict[str, list[str]] = {}
    request_items: list[dict[str, str]] = []
    for item in pending:
        masked_text, blocks = _mask_code_blocks(item.text)
        masks[item.identifier] = blocks
        request_items.append({"id": item.identifier, "text": masked_text})
    request = {"items": request_items}
    messages = [
        {
            "role": "system",
            "content": (
                f"Translate every items[].text value into {_LANGUAGE_NAMES[target]}. Return strict JSON with only an items array. "
                "Keep every id unchanged and return exactly one item for each input id. Preserve Markdown structure, inline code, "
                "fenced code, CVE/GHSA identifiers, package and product names, versions, URLs, file paths, hashes, commands, and code "
                f"exactly. Do not summarize, omit, explain, or add facts.{_PLACEHOLDER_HINT}"
            ),
        },
        {"role": "user", "content": json.dumps(request, ensure_ascii=False, separators=(",", ":"))},
    ]
    try:
        parsed = _parse_json_object(
            _request_translation_answer(
                model,
                messages,
                json_mode=True,
                user_id=user_id,
                session_id=session_id,
                source=f"translation_mcp:{content_scope}",
            )
        )
    except Exception:
        # 部分免费/兼容端点不支持 response_format，或弱模型在 JSON 模式下输出异常：
        # 降级为普通对话调用重试，系统提示词仍要求严格 JSON，解析端保持容错。
        parsed = _parse_json_object(
            _request_translation_answer(
                model,
                messages,
                json_mode=False,
                user_id=user_id,
                session_id=session_id,
                source=f"translation_mcp:{content_scope}:retry",
            )
        )
    translated = parsed.get("items") if isinstance(parsed.get("items"), list) else []
    by_id = {
        str(item.get("id") or ""): str(item.get("text") or "")
        for item in translated
        if isinstance(item, dict)
    }
    for candidate in pending:
        text = by_id.get(candidate.identifier, "").strip()
        blocks = masks.get(candidate.identifier) or []
        if blocks:
            restored = _restore_code_blocks(text, blocks)
            text = restored if restored is not None else ""
        if not text or not _preserves_machine_segments(candidate.text, text):
            continue
        if not _accepts_for_target(candidate.text, text, target):
            # 模型回显原文（常只裁掉尾部空白）：不算翻译、不入缓存，留给逐字段兜底。
            continue
        if text != candidate.text:
            # 恒等结果不入缓存：模型暂时回显原文不代表该字段不可翻译。
            _translation_cache_put(target, model, candidate.text, text)
            changed += 1
        _set_path(root, candidate.path, text)
    return changed


def _request_translation_answer(
    model: dict[str, Any],
    messages: list[dict[str, str]],
    *,
    json_mode: bool,
    user_id: str,
    session_id: str,
    source: str,
) -> str:
    result = diagnose_chat_completion(
        model,
        messages,
        json_mode=json_mode,
        user_id=user_id,
        session_id=session_id,
        source=source,
    )
    if result.get("status") != "success":
        raise RuntimeError(str(result.get("message") or "translation model returned no result"))
    return str(result.get("answer") or "")


def _requires_cjk(target: str) -> bool:
    return target in {"zh-Hans", "zh-Hant"}


def _accepts_for_target(source: str, translated: str, target: str) -> bool:
    """CJK 目标下，原文不含中文而译文仍不含中文的结果一律视为未翻译。

    模型常见的"回显原文但裁掉尾部空白"会让译文与原文产生细微差异，若不做
    这道核验，英文原文会被当成译文计数并写入缓存，后续兜底全部短路。
    """
    if not _requires_cjk(target):
        return True
    return bool(_CJK_CHAR.search(source) or _CJK_CHAR.search(translated))


def _get_path(root: Any, path: tuple[Any, ...]) -> Any:
    current = root
    for item in path:
        current = current[item]
    return current


def _untranslated_candidates(
    candidates: list[_Candidate],
    root: Any,
    target: str,
) -> list[_Candidate]:
    """源文本非中文、批次翻译后仍不含中文的字段——小模型可能在 JSON 批次中原样返回。"""
    if not _requires_cjk(target):
        return []
    unresolved: list[_Candidate] = []
    for candidate in candidates:
        if _CJK_CHAR.search(candidate.text):
            continue
        current = _get_path(root, candidate.path)
        if not isinstance(current, str) or not _CJK_CHAR.search(current):
            unresolved.append(candidate)
    return unresolved


def _single_messages(text: str, target: str, *, has_placeholders: bool = False) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                f"Translate the user-provided text into {_LANGUAGE_NAMES[target]}. "
                "Output only the translated text, with no explanations, notes, or JSON wrappers. "
                "Preserve Markdown structure, inline code, fenced code, CVE/GHSA identifiers, package and product names, "
                f"versions, URLs, file paths, hashes, commands, and code exactly.{_PLACEHOLDER_HINT if has_placeholders else ''}"
            ),
        },
        {"role": "user", "content": text},
    ]


def _translate_plain_text(
    model: dict[str, Any],
    text: str,
    *,
    target: str,
    user_id: str,
    session_id: str,
    content_scope: str,
) -> str:
    """单字段纯文本翻译；围栏代码块先换占位符、译后逐字回填。"""
    masked, blocks = _mask_code_blocks(text)
    answer = _request_translation_answer(
        model,
        _single_messages(masked, target, has_placeholders=bool(blocks)),
        json_mode=False,
        user_id=user_id,
        session_id=session_id,
        source=f"translation_mcp:{content_scope}:field",
    ).strip()
    if not blocks:
        return answer
    restored = _restore_code_blocks(answer, blocks)
    return restored if restored is not None else ""


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
    """Split an over-long advisory into chunks the model can finish.

    围栏代码块是原子单元：切块不能从代码块中间截断（半块代码发给模型只会
    得到半块残缺的译文），叙述性文字再按段落聚合。
    """
    units: list[str] = []
    cursor = 0
    for match in _FENCED_BLOCK.finditer(text):
        if match.start() > cursor:
            units.extend(_split_prose_paragraphs(text[cursor : match.start()], limit))
        block = match.group(0)
        if len(block) > limit:
            # 罕见超大代码块：硬切，占位符掩码兜底不了时由校验拒收保留原文。
            units.extend(
                piece for offset in range(0, len(block), limit) if (piece := block[offset : offset + limit].strip())
            )
        else:
            units.append(block)
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


def _translate_single(
    root: Any,
    candidate: _Candidate,
    *,
    target: str,
    model: dict[str, Any],
    user_id: str,
    session_id: str,
    content_scope: str,
) -> int:
    cached = _translation_cache_get(target, model, candidate.text)
    if cached is not None and _preserves_machine_segments(candidate.text, cached) and _accepts_for_target(candidate.text, cached, target):
        changed = 1 if cached != candidate.text else 0
        _set_path(root, candidate.path, cached)
        return changed
    if len(candidate.text) > _LONG_TEXT_CHARS:
        # 超长公告分段翻译：单次调用的输出预算译不完上万字符，截断后只能弃译。
        translated_chunks: list[str] = []
        for chunk in _split_long_text(candidate.text, _LONG_TEXT_CHUNK_CHARS):
            chunk_text = _translate_plain_text(
                model,
                chunk,
                target=target,
                user_id=user_id,
                session_id=session_id,
                content_scope=content_scope,
            )
            if not chunk_text or not _preserves_machine_segments(chunk, chunk_text):
                return 0
            translated_chunks.append(chunk_text)
        text = "\n\n".join(translated_chunks)
    else:
        text = _translate_plain_text(
            model,
            candidate.text,
            target=target,
            user_id=user_id,
            session_id=session_id,
            content_scope=content_scope,
        )
    if not text or not _preserves_machine_segments(candidate.text, text):
        return 0
    if not _CJK_CHAR.search(candidate.text) and not _CJK_CHAR.search(text):
        return 0  # 单字段兜底仍未产出中文，保留可核验原文
    if text != candidate.text:
        # 恒等结果不入缓存：模型暂时回显原文不代表该字段不可翻译。
        _translation_cache_put(target, model, candidate.text, text)
    changed = 1 if text != candidate.text else 0
    _set_path(root, candidate.path, text)
    return changed


_MACHINE_PATH = re.compile(r"^(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(?::\d+)?$")

_FENCED_BLOCK = re.compile(r"```[\s\S]*?```")

_PLACEHOLDER_HINT = (
    " Tokens like [[SEC-BLOCK-1]] are opaque placeholders for fenced code blocks; "
    "keep each of them unchanged, in place, and never translate inside them."
)


def _mask_code_blocks(text: str) -> tuple[str, list[str]]:
    """把围栏代码块替换为占位符。

    PoC 型公告里代码块占大半体量：模型只需翻译叙述性文字，译文既不顶满输出
    预算，也不会因为"顺手翻译代码注释"而破坏证据校验。回填后代码块逐字还原。
    """
    blocks = _FENCED_BLOCK.findall(text)
    if not blocks:
        return text, []
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


def _is_soft_path_segment(segment: str) -> bool:
    """自然语言斜杠短语（no-code/low-code、list/read/write/delete）而非机器路径。

    保护段正则的 path 分支会把英文里的斜杠短语也抓进来；忠实翻译必然把这些
    短语译成中文，导致整段译文被误判为破坏证据而弃译。真正的机器标识用
    @scope/pkg、conf/conf.json、api/v1/... 这类特征（@ 开头、含点或数字）区分。
    """
    if not _MACHINE_PATH.fullmatch(segment):
        return False
    if segment.startswith("@"):
        return False
    return not any(re.search(r"[.\d]", part) for part in segment.split("/"))


def _preserves_machine_segments(source: str, translated: str) -> bool:
    for segment in _PRESERVED_SEGMENT.findall(source):
        if segment in translated:
            continue
        # 中文译文常保留标识符本身但去掉 Markdown 反引号（如 `email_verified`
        # 译成 email_verified）：代码段放宽为核对内部内容，避免把合格译文误杀。
        if segment.startswith("`"):
            inner = segment.strip("`").strip()
            if inner and inner in translated:
                continue
            if len(inner) <= 2:
                continue  # `@`、`(` 这类标点级内联段，译文省略不破坏证据
        # 正则常把句尾英文句号并入版本号/路径（5.0.0-beta.3.、I/O.），
        # 中文句子用句号「。」结尾时逐字比对必然失败，剥掉尾部句点再核对。
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


def _parse_json_object(value: str) -> dict[str, Any]:
    clean = value.strip()
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"\s*```$", "", clean)
    try:
        parsed = json.loads(clean)
    except json.JSONDecodeError:
        start = clean.find("{")
        end = clean.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("Translation model returned invalid JSON")
        parsed = json.loads(clean[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("Translation model returned a non-object JSON value")
    return parsed


def _json_value(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(deepcopy(value), ensure_ascii=False, default=str))


def _payload_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> None:
    translation_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
