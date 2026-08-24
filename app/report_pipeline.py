from __future__ import annotations

from typing import Any

from app.reports import validate_report_document_json, validate_scan_result_json
from app.storage import now_iso


REPORT_PLAN_SCHEMA = "secflow.report-plan/v1"
REPORT_QA_SCHEMA = "secflow.report-qa/v1"
ENTERPRISE_REPORT_FORMATS = ("md", "html", "docx", "xlsx", "pdf")


def build_report_plan(
    scan_json: dict[str, Any],
    *,
    source_kind: str,
    language: str,
    template_id: str = "security",
) -> dict[str, Any]:
    """Create a deterministic plan from verified facts without asking an LLM to recount data."""

    source = validate_scan_result_json(scan_json)
    facts = source["facts"]
    counts = {key: int(value or 0) for key, value in source["counts"].items()}
    payload = source.get("payload") if isinstance(source.get("payload"), dict) else {}
    scan_type = _scan_type(payload, facts, source_kind)
    sections = ["executive_summary", "scope_and_method"]
    if scan_type in {"code_scan", "full_scan"}:
        sections.extend(["code_findings", "taint_analysis"])
    if scan_type in {"sbom", "full_scan"}:
        sections.extend(["component_inventory", "license_summary", "component_vulnerabilities"])
    sections.extend(["remediation_priorities", "audit_appendix"])
    source_sha256 = str((source.get("audit") or {}).get("payload_sha256") or "")
    return {
        "$schema": REPORT_PLAN_SCHEMA,
        "schema_version": 1,
        "planner": "AegisAl Report Planner Agent",
        "created_at": now_iso(),
        "scan_type": scan_type,
        "source_kind": str(source_kind or source.get("source_kind") or "assistant_scan"),
        "language": str(language or source.get("language") or "zh-Hans"),
        "template_id": str(template_id or "security"),
        "sections": sections,
        "formats": list(ENTERPRISE_REPORT_FORMATS),
        "fact_counts": counts,
        "source_sha256": source_sha256,
        "rules": {
            "single_source_of_truth": True,
            "allow_unverified_facts": False,
            "shared_template": True,
            "require_qa": True,
        },
    }


def validate_report_quality(report_document: dict[str, Any], report_plan: dict[str, Any]) -> dict[str, Any]:
    """QA Agent gate for canonical data, section scope, template and cross-format readiness."""

    document = validate_report_document_json(report_document)
    source = document["source"]
    expected_counts = {key: int(value or 0) for key, value in (report_plan.get("fact_counts") or {}).items()}
    actual_counts = {key: int(value or 0) for key, value in (source.get("counts") or {}).items()}
    source_sha256 = str((source.get("audit") or {}).get("payload_sha256") or "")
    expected_sha256 = str(report_plan.get("source_sha256") or "")
    sections = [item for item in (document.get("report") or {}).get("sections") or [] if isinstance(item, dict)]
    findings = document.get("findings") if isinstance(document.get("findings"), list) else []
    expected_findings = actual_counts.get("dependency_vulnerabilities", 0) + actual_counts.get("code_findings", 0)
    template = document.get("template") if isinstance(document.get("template"), dict) else {}
    formats = {str(item) for item in report_plan.get("formats") or []}
    checks = [
        _check("source_schema", source.get("$schema") == "secflow.scan-results/v1", "扫描事实 JSON schema 已验证"),
        _check("source_hash", bool(source_sha256) and source_sha256 == expected_sha256, "扫描事实哈希与报告规划一致"),
        _check("fact_counts", expected_counts == actual_counts, "统一 Report JSON 的事实计数一致"),
        _check("finding_count", len(findings) == expected_findings, "报告发现清单与扫描事实一致"),
        _check("sections", bool(sections), "报告至少包含一个结构化章节"),
        _check("template", bool(template.get("id") and template.get("style_tokens")), "所有格式共享同一模板配置"),
        _check("formats", set(ENTERPRISE_REPORT_FORMATS).issubset(formats), "企业报告格式规划完整"),
    ]
    errors = [item["message"] for item in checks if not item["passed"]]
    result = {
        "$schema": REPORT_QA_SCHEMA,
        "schema_version": 1,
        "agent": "AegisAl Report QA Agent",
        "status": "passed" if not errors else "failed",
        "score": round(sum(1 for item in checks if item["passed"]) / len(checks) * 100),
        "verified_at": now_iso(),
        "source_sha256": source_sha256,
        "checks": checks,
        "errors": errors,
    }
    if errors:
        raise ValueError("报告 QA 校验失败：" + "；".join(errors))
    return result


def _scan_type(payload: dict[str, Any], facts: dict[str, Any], source_kind: str) -> str:
    explicit = str(payload.get("scan_type") or payload.get("report_type") or "").strip().lower()
    if explicit in {"code_scan", "sbom", "full_scan"}:
        return explicit
    has_code = bool(facts.get("code_findings"))
    has_sbom = bool(facts.get("dependencies") or facts.get("licenses") or facts.get("dependency_vulnerabilities"))
    if has_code and has_sbom:
        return "full_scan"
    if has_sbom:
        return "sbom"
    if has_code:
        return "code_scan"
    task = payload.get("task") if isinstance(payload.get("task"), dict) else payload
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    if result.get("language_results") or str(source_kind) == "agent_task":
        return "code_scan"
    return "full_scan"


def _check(check_id: str, passed: bool, message: str) -> dict[str, Any]:
    return {"id": check_id, "passed": bool(passed), "message": message}
