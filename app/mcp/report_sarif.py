from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel


_SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"


class SarifReportOutput(BaseModel):
    schema_version: int = 1
    renderer: Literal["secflow-sarif-2.1.0"] = "secflow-sarif-2.1.0"
    sarif: dict[str, Any]
    input_sha256: str
    output_sha256: str
    result_count: int
    thread_flow_count: int
    thread_flow_location_count: int


report_sarif_mcp = FastMCP(
    "AegisAl SARIF MCP",
    instructions=(
        "Convert verified AegisAl scan-result JSON into SARIF 2.1.0. Preserve every supplied taint "
        "path node in codeFlows/threadFlows/locations, including order, role, file, line, label, and "
        "snippet. Never invent intermediate taint steps."
    ),
)


@report_sarif_mcp.tool(
    name="build_scan_sarif",
    description="Build auditable SARIF 2.1.0 results and complete taint thread-flow locations.",
    structured_output=True,
)
def build_scan_sarif(report_json: dict[str, Any]) -> SarifReportOutput:
    from app.reports import validate_scan_result_json

    scan_json = validate_scan_result_json(report_json)
    input_sha256 = str((scan_json.get("audit") or {}).get("payload_sha256") or "")
    facts = scan_json.get("facts") if isinstance(scan_json.get("facts"), dict) else {}
    findings = [item for item in facts.get("code_findings") or [] if isinstance(item, dict)]
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    location_count = 0

    for finding_index, finding in enumerate(findings):
        rule_id = str(finding.get("rule_id") or finding.get("rule") or finding.get("id") or f"secflow-{finding_index + 1}")
        title = str(finding.get("title") or finding.get("message") or rule_id).strip() or rule_id
        severity = _severity(finding.get("severity"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": _rule_name(rule_id),
                "shortDescription": {"text": title},
                "properties": {"security-severity": severity, "tags": ["security", "taint-analysis"]},
            },
        )
        locations = _finding_thread_flow_locations(finding)
        location_count += len(locations)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": _sarif_level(severity),
            "message": {"text": title},
            "locations": [_result_location(finding, locations)],
            "properties": {
                "secflowFindingId": str(finding.get("id") or f"finding-{finding_index + 1}"),
                "secflowSeverity": severity,
                "secflowDisposition": str(finding.get("disposition") or "confirmed"),
            },
        }
        if locations:
            result["codeFlows"] = [
                {
                    "message": {"text": "AegisAl taint path"},
                    "threadFlows": [
                        {
                            "id": f"taint-{finding_index + 1}",
                            "message": {"text": f"{title} source-to-sink path"},
                            "locations": locations,
                        }
                    ],
                }
            ]
        results.append(result)

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisAl",
                        "informationUri": "https://github.com/FuNianTongXue/secflow-knowledge-security-assistant",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {
                    "id": f"secflow/{input_sha256[:16] or 'scan'}",
                    "description": {"text": "Verified AegisAl code scan"},
                },
                "results": results,
                "properties": {
                    "secflowInputSha256": input_sha256,
                    "secflowSourceSchema": str(scan_json.get("$schema") or ""),
                },
            }
        ],
    }
    output_sha256 = _sha256_json(sarif)
    return SarifReportOutput(
        sarif=sarif,
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        result_count=len(results),
        thread_flow_count=sum(1 for result in results if result.get("codeFlows")),
        thread_flow_location_count=location_count,
    )


def invoke_report_sarif_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(report_sarif_mcp.call_tool("build_scan_sarif", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("SARIF MCP did not return structured output")


async def sarif_mcp_spec() -> dict[str, Any]:
    tools = await report_sarif_mcp.list_tools()
    return {
        "id": "report-sarif",
        "name": report_sarif_mcp.name,
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


def _finding_thread_flow_locations(finding: dict[str, Any]) -> list[dict[str, Any]]:
    raw_path = _finding_taint_path(finding)
    if not raw_path:
        source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
        sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
        raw_path = []
        if source:
            raw_path.append({**source, "kind": source.get("kind") or "source"})
        if sink and sink != source:
            raw_path.append({**sink, "kind": sink.get("kind") or "sink"})
    if not raw_path:
        raw_path = [
            {
                "kind": "sink",
                "file": finding.get("file_name") or finding.get("file") or finding.get("path"),
                "line": finding.get("risk_line") or finding.get("line"),
                "label": finding.get("title") or finding.get("message") or "finding",
            }
        ]

    locations: list[dict[str, Any]] = []
    for index, node in enumerate(raw_path):
        role = _path_role(node, index, len(raw_path))
        file_name = _node_file(node, finding)
        line = _positive_int(node.get("line") or node.get("start_line") or node.get("line_number"))
        end_line = _positive_int(node.get("end_line"))
        label = _node_label(node, role, file_name, line)
        snippet = str(node.get("snippet") or node.get("code") or node.get("evidence") or "").strip()
        physical: dict[str, Any] = {"artifactLocation": {"uri": file_name or "unknown"}}
        if line:
            region: dict[str, Any] = {"startLine": line}
            if end_line and end_line >= line:
                region["endLine"] = end_line
            if snippet:
                region["snippet"] = {"text": snippet}
            physical["region"] = region
        location: dict[str, Any] = {
            "physicalLocation": physical,
            "message": {"text": label},
            "properties": {"secflowRole": role, "secflowOriginalIndex": index},
        }
        locations.append(
            {
                "location": location,
                "executionOrder": index + 1,
                "importance": "essential" if role in {"source", "sink"} else "important",
                "kinds": [role],
                "state": {
                    "secflowRole": {"text": role},
                    "secflowLabel": {"text": label},
                },
            }
        )
    return locations


def _finding_taint_path(finding: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("taint_path", "dataflow", "path"):
        candidate = finding.get(key)
        if isinstance(candidate, list):
            nodes = [item for item in candidate if isinstance(item, dict)]
            if nodes:
                return nodes
        if isinstance(candidate, dict):
            nested = candidate.get("path") or candidate.get("nodes") or candidate.get("locations")
            if isinstance(nested, list):
                nodes = [item for item in nested if isinstance(item, dict)]
                if nodes:
                    return nodes
    return []


def _result_location(finding: dict[str, Any], locations: list[dict[str, Any]]) -> dict[str, Any]:
    if locations:
        return dict(locations[-1]["location"])
    file_name = str(finding.get("file_name") or finding.get("file") or "unknown")
    line = _positive_int(finding.get("risk_line") or finding.get("line"))
    physical: dict[str, Any] = {"artifactLocation": {"uri": file_name}}
    if line:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _path_role(node: dict[str, Any], index: int, count: int) -> str:
    clean = str(node.get("kind") or node.get("role") or node.get("type") or "").strip().lower()
    if "source" in clean or clean in {"input", "origin"}:
        return "source"
    if "sink" in clean or clean in {"dangerous-call", "target"}:
        return "sink"
    if "sanit" in clean or clean in {"validator", "guard"}:
        return "sanitizer"
    if index == 0 and count > 1:
        return "source"
    if index == count - 1:
        return "sink"
    return "propagation"


def _node_file(node: dict[str, Any], finding: dict[str, Any]) -> str:
    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
    return str(
        node.get("file")
        or node.get("file_name")
        or node.get("path")
        or finding.get("file_name")
        or finding.get("file")
        or sink.get("file")
        or source.get("file")
        or "unknown"
    ).strip()


def _node_label(node: dict[str, Any], role: str, file_name: str, line: int | None) -> str:
    label = str(node.get("label") or node.get("message") or node.get("name") or node.get("snippet") or "").strip()
    if label:
        return label
    location = f"{file_name}:{line}" if line else file_name
    return f"{role} - {location}"


def _severity(value: Any) -> str:
    clean = str(value or "UNKNOWN").strip().upper()
    aliases = {"SEVERE": "CRITICAL", "ERROR": "HIGH", "MODERATE": "MEDIUM", "WARNING": "MEDIUM", "INFO": "LOW"}
    return aliases.get(clean, clean if clean in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "UNKNOWN")


def _sarif_level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def _rule_name(rule_id: str) -> str:
    clean = "".join(character if character.isalnum() else " " for character in rule_id)
    return "".join(part.capitalize() for part in clean.split())[:120] or "AegisAlFinding"


def _positive_int(value: Any) -> int | None:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result > 0 else None


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> None:
    report_sarif_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
