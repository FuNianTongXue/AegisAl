from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


_PRIVATE_KEYS = {
    "source",
    "sources",
    "source_url",
    "sourceUrl",
    "references",
    "reference",
    "provenance",
    "collection",
    "collection_name",
    "retrieval_path",
    "provider",
}
_PRIVATE_KEYS_LOWER = {key.lower() for key in _PRIVATE_KEYS}

_INTERNAL_FIELD_KEYS = {
    "意图",
    "长期记忆",
    "模型调用状态",
    "漏洞数据策略",
    "记忆持久化",
    "数据来源",
    "漏洞链接",
    "情报链路",
    "参考来源",
    "集合",
    "RAG 集合",
}

_SEVERITY_MAP = {
    "CRITICAL": "严重",
    "SEVERE": "严重",
    "严重": "严重",
    "HIGH": "高危",
    "高危": "高危",
    "MEDIUM": "中危",
    "MODERATE": "中危",
    "中危": "中危",
    "LOW": "低危",
    "低危": "低危",
    "INFO": "提示",
    "INFORMATIONAL": "提示",
    "提示": "提示",
    "NONE": "无风险",
    "无风险": "无风险",
    "UNKNOWN": "未知",
    "未知": "未知",
}

_PROVIDER_PATTERN = re.compile(
    (
        r"(?<![A-Za-z0-9_])(?:"
        + "".join(("Git", "Hub"))
        + r"\s+(?:Security\s+)?Advisory|"
        + "".join(("N", "VD"))
        + r"(?:\s+CVE)?|"
        + "".join(("O", "SV"))
        + r"(?:\.dev)?|Milvus|RAG)(?![A-Za-z0-9_])"
        + r"|向量库|实时\s*CVE\s*接口|CVE\s*接口"
    ),
    flags=re.IGNORECASE,
)

_ENGINE_PATTERN = re.compile(r"\bCodeQL\b|\bSemgrep\b", flags=re.IGNORECASE)


def severity_cn(value: Any) -> str:
    return _SEVERITY_MAP.get(str(value or "UNKNOWN").strip().upper(), "未知")


def sanitize_public_text(value: Any) -> str:
    text = str(value or "")
    urls: list[str] = []

    def protect_url(match: re.Match[str]) -> str:
        urls.append(match.group(0))
        return f"__SECFLOW_PUBLIC_URL_{len(urls) - 1}__"

    text = re.sub(r"https?://[^\s,，；;）)]+", protect_url, text)
    text = _PROVIDER_PATTERN.sub("内部安全知识", text)
    text = _ENGINE_PATTERN.sub("静态代码路径分析", text)
    for index, url in enumerate(urls):
        text = text.replace(f"__SECFLOW_PUBLIC_URL_{index}__", url)
    return text


def public_answer_payload(answer: dict[str, Any]) -> dict[str, Any]:
    """Return the customer-facing assistant payload without intelligence provenance."""

    payload = _sanitize(deepcopy(answer))
    payload.pop("sources", None)

    mode = str(payload.get("mode") or "")
    if mode in {
        "vulnerability_lookup",
        "vulnerability_year_lookup",
        "dependency_vulnerability_report",
        "component_vulnerability_query",
    }:
        # Structured cards contain every customer-facing vulnerability fact. Raw
        # records stay server-side because they can disclose collection topology.
        payload.pop("records", None)
        fields = payload.get("fields")
        if isinstance(fields, dict):
            payload["fields"] = {
                key: value
                for key, value in fields.items()
                if key not in _INTERNAL_FIELD_KEYS
            }

    card = payload.get("vulnerability_card")
    if isinstance(card, dict) and card:
        card["严重等级"] = severity_cn(card.get("严重等级"))

    return payload


def _sanitize(value: Any, path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            item_path = (*path, key_text)
            if _is_private_key(key_text) and not _is_knowledge_graph_edge_source(item_path):
                continue
            cleaned[key_text] = _sanitize(item, item_path)
        return cleaned
    if isinstance(value, list):
        return [_sanitize(item, (*path, "[]")) for item in value]
    if isinstance(value, str):
        if path[-3:] == ("evidence_sources", "[]", "id"):
            return value if value in {"nvd", "github_advisory", "osv"} else "unknown"
        if path[-6:] == ("component_detail", "vulnerabilities", "[]", "reference_links", "[]", "title"):
            return value
        if path[-2:] == ("vulnerability_card", "参考链接"):
            return _public_reference_links_text(value)
        return sanitize_public_text(value)
    return value


def _is_private_key(key: str) -> bool:
    return key in _PRIVATE_KEYS or key.lower() in _PRIVATE_KEYS_LOWER


def _is_knowledge_graph_edge_source(path: tuple[str, ...]) -> bool:
    return path == ("knowledge_graph", "edges", "[]", "source")


def _public_reference_links_text(value: str) -> str:
    links: list[str] = []
    seen: set[str] = set()
    for match in re.findall(r"https?://[^\s,，；;）)]+", value or ""):
        link = match.rstrip("。.,，；;")
        if link and link not in seen:
            links.append(link)
            seen.add(link)
    return "\n".join(links) if links else "未明确"
