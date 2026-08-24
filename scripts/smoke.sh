#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
SMOKE_DATA_DIR="$(mktemp -d)"
trap 'rm -rf "$SMOKE_DATA_DIR"' EXIT

export SECFLOW_DATA_DIR="$SMOKE_DATA_DIR"
export DATABASE_URL=""
export POSTGRES_DSN=""
export SECFLOW_LLM_API_KEY=""
export DEEPSEEK_API_KEY=""
export OPENAI_API_KEY=""

"$PYTHON_BIN" -m compileall -q app
"$PYTHON_BIN" - <<'PY'
from app.collectors import _nvd_datetime, _nvd_references, _nvd_severity, collector_graph, collector_service
from app.api.routes.application import app
from app.langgraph.assistant_graph import knowledge_graph
from app.intelligence import build_knowledge_graph, intelligence_service
from datetime import datetime, timezone
from unittest.mock import patch

assert app.title == "AegisAl"
original_query = intelligence_service.query

def mocked_query(query, limit=10, sources=None):
    identifier = "CVE-2021-9999" if "2021 年" in query else "CVE-2021-44228"
    record = {
        "id": identifier,
        "title": "Mock vulnerability",
        "severity": "CRITICAL",
        "summary": "Deterministic smoke-test record.",
        "affected_versions": ["demo < 2.0"],
        "fixed_versions": ["demo 2.0"],
        "aliases": [identifier],
        "cwes": ["CWE-78"],
        "components": [{"name": "demo", "ecosystem": "generic", "affected": ["< 2.0"], "fixed": ["2.0"]}],
        "updated_at": "2021-12-31T00:00:00.000Z",
    }
    return {"status": "success", "records": [record], "graph": build_knowledge_graph([record], query), "trace": []}

intelligence_service.query = mocked_query
result = knowledge_graph.invoke("Explain CVE-2021-44228", 5)
assert result["mode"] == "vulnerability_lookup"
assert result["vulnerability_card"]["漏洞编号"] == "CVE-2021-44228"
assert result["vulnerability_card"]["严重等级"] in {"严重", "高危", "中危", "低危", "未知"}
assert "sources" not in result
assert "records" not in result
assert any(item["node"] == "translate_vulnerability_card" for item in result["trace"])

assert _nvd_references({"references": [{"url": "https://nvd.example/CVE-2025-0001"}]}) == [
    "https://nvd.example/CVE-2025-0001"
]
assert _nvd_severity({"metrics": {"cvssMetricV40": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}}) == "CRITICAL"
assert _nvd_datetime(datetime(2025, 1, 1, tzinfo=timezone.utc)).endswith("Z")
assert [node["id"] for node in collector_graph.graph_spec()["nodes"]] == [
    "validate_config",
    "fetch_records",
    "normalize_records",
    "translate_records",
    "persist_records",
    "compose_result",
]
with patch.object(collector_service, "_collect_cve", return_value=[]):
    credential_result = collector_service.collect("cve")
assert credential_result["status"] == "warning"
assert [item["node"] for item in credential_result["trace"]] == [
    "collector.validate_config",
    "collector.query_api",
    "collector.compose_result",
]

try:
    year_result = knowledge_graph.invoke(
        "2021 年最新 CVE 漏洞有哪些？",
        5,
        intent_plan={
            "intent": "vulnerability_year_lookup",
            "reason": "deterministic release smoke route",
            "confidence": 1.0,
        },
    )
    assert year_result["mode"] == "vulnerability_year_lookup"
    assert year_result["fields"]["年份过滤"] == "2021"
    assert "sources" not in year_result
    assert any(item["node"] == "query_intelligence" for item in year_result["trace"])
finally:
    intelligence_service.query = original_query

print("smoke-ok")
PY
"$PYTHON_BIN" -m unittest discover -s tests -p 'test_*.py'
