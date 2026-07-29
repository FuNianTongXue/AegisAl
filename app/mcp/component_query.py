from __future__ import annotations

import argparse
import asyncio
import hashlib
import math
import re
from pathlib import Path
from threading import RLock
from typing import Any, Literal
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from app.intelligence import intelligence_service, localized_vulnerability_summary
from app.privacy import sanitize_public_text, severity_cn
from app.storage import DATA_DIR, now_iso


_ARTIFACT_ID = re.compile(r"^component-xlsx-[0-9]{14}-[a-f0-9]{12}$")
_XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


class AssistantArtifact(BaseModel):
    id: str
    kind: Literal["excel"] = "excel"
    file_name: str
    media_type: str = _XLSX_MEDIA_TYPE
    download_path: str
    sha256: str
    size: int
    generated_at: str


class SankeyNode(BaseModel):
    id: str
    label: str
    type: str
    severity: str | None = None
    column: int | None = None
    version: str | None = None
    ecosystem: str | None = None


class SankeyLink(BaseModel):
    source_id: str = Field(alias="from", serialization_alias="from")
    target_id: str = Field(alias="to", serialization_alias="to")
    type: str | None = None
    value: int = 1
    severity: str | None = None

    model_config = {"populate_by_name": True}


class SankeyPayload(BaseModel):
    schema_version: int = 1
    renderer: Literal["d3-sankey"] = "d3-sankey"
    nodes: list[SankeyNode]
    links: list[SankeyLink]


class ComponentDetailCoordinate(BaseModel):
    name: str
    version: str
    ecosystem: str = ""


class ComponentDetailAffectedPackage(BaseModel):
    name: str
    ecosystem: str
    affected_versions: list[str]
    fixed_versions: list[str]


class ComponentDetailReference(BaseModel):
    title: str
    url: str


class ComponentDetailCVSSMetric(BaseModel):
    key: str
    label: str
    value: str


class ComponentDetailCVSS(BaseModel):
    score: float | None = None
    rating: str
    vector: str = ""
    version: str = ""
    metrics: list[ComponentDetailCVSSMetric]


class ComponentVulnerabilityDetail(BaseModel):
    id: str
    title: str
    severity: str
    severity_label: str
    description: str
    vulnerability_type: str
    aliases: list[str]
    cwes: list[str]
    published_at: str
    updated_at: str
    affected_packages: list[ComponentDetailAffectedPackage]
    affected_versions: list[str]
    fixed_versions: list[str]
    remediation: str
    exploit_status: str
    exploit_status_code: Literal["confirmed", "poc", "unknown"]
    exploit_difficulty: str
    reference_links: list[ComponentDetailReference]
    cvss: ComponentDetailCVSS


class ComponentDetailPayload(BaseModel):
    schema_version: int = 1
    renderer: Literal["component-vulnerability-detail"] = "component-vulnerability-detail"
    component: ComponentDetailCoordinate
    total: int
    preview_count: int
    truncated: bool
    vulnerabilities: list[ComponentVulnerabilityDetail]
    generated_at: str


class ComponentArtifactStore:
    def __init__(self, root: Path | None = None, *, retain: int = 100) -> None:
        self.root = root or (DATA_DIR / "assistant_artifacts")
        self.retain = max(10, min(int(retain), 500))
        self._lock = RLock()

    def save(self, content: bytes, *, file_name: str, generated_at: str) -> AssistantArtifact:
        if not content.startswith(b"PK\x03\x04"):
            raise ValueError("Excel MCP 未生成有效的 XLSX 工作簿")
        digest = hashlib.sha256(content).hexdigest()
        timestamp = re.sub(r"\D", "", generated_at)[:14]
        if len(timestamp) != 14:
            timestamp = re.sub(r"\D", "", now_iso())[:14]
        artifact_id = f"component-xlsx-{timestamp}-{digest[:12]}"
        safe_name = _safe_excel_name(file_name)
        path = self.root / f"{artifact_id}.xlsx"
        temporary = self.root / f".{artifact_id}.tmp"
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            temporary.write_bytes(content)
            temporary.chmod(0o600)
            temporary.replace(path)
            self._prune()
        return AssistantArtifact(
            id=artifact_id,
            file_name=safe_name,
            download_path=f"/api/assistant/artifacts/{artifact_id}",
            sha256=digest,
            size=len(content),
            generated_at=generated_at,
        )

    def resolve(self, artifact_id: str) -> Path:
        clean_id = str(artifact_id or "").strip()
        if not _ARTIFACT_ID.fullmatch(clean_id):
            raise KeyError(artifact_id)
        path = self.root / f"{clean_id}.xlsx"
        if not path.is_file() or path.parent.resolve() != self.root.resolve():
            raise KeyError(artifact_id)
        return path

    def _prune(self) -> None:
        files = sorted(
            (path for path in self.root.glob("component-xlsx-*.xlsx") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in files[self.retain :]:
            path.unlink(missing_ok=True)


artifact_store = ComponentArtifactStore()

excel_mcp = FastMCP(
    "SecFlow Excel MCP",
    instructions="Generate auditable XLSX artifacts for verified component vulnerability queries.",
)
sankey_mcp = FastMCP(
    "SecFlow D3 Sankey MCP",
    instructions="Normalize verified knowledge graph data for the bundled D3 Sankey renderer.",
)
detail_mcp = FastMCP(
    "SecFlow Component Detail MCP",
    instructions=(
        "Build a customer-facing component vulnerability detail page only from verified structured records. "
        "Never infer missing versions, CVSS metrics, exploit status, or references."
    ),
)


@detail_mcp.tool(
    name="build_component_vulnerability_detail",
    description="Create the structured page model for one verified component version query.",
    structured_output=True,
)
def build_component_vulnerability_detail(
    component: dict[str, Any],
    records: list[dict[str, Any]],
    generated_at: str = "",
    response_language: str = "zh-Hans",
) -> ComponentDetailPayload:
    coordinate = ComponentDetailCoordinate(
        name=str(component.get("name") or "").strip(),
        version=str(component.get("version") or "").strip(),
        ecosystem=str(component.get("ecosystem") or "").strip(),
    )
    clean_records = [dict(record) for record in records if isinstance(record, dict)]
    preview = clean_records[:8]
    return ComponentDetailPayload(
        component=coordinate,
        total=len(clean_records),
        preview_count=len(preview),
        truncated=len(clean_records) > len(preview),
        vulnerabilities=[
            _component_vulnerability_detail(record, coordinate, response_language)
            for record in preview
        ],
        generated_at=str(generated_at or now_iso()),
    )


@excel_mcp.tool(
    name="export_component_vulnerabilities",
    description="Create a complete XLSX workbook for one concrete component version.",
    structured_output=True,
)
def export_component_vulnerabilities(
    name: str,
    version: str,
    ecosystem: str = "",
    include_realtime: bool = False,
    records: list[dict[str, Any]] | None = None,
    generated_at: str = "",
) -> AssistantArtifact:
    if records is not None:
        from app.vulnerability_export import build_component_vulnerability_workbook

        timestamp = str(generated_at or now_iso())
        clean_records = _component_workbook_records(records)
        content = build_component_vulnerability_workbook(
            clean_records,
            component_name=name,
            version=version,
            ecosystem=ecosystem,
            generated_at=timestamp,
        )
        metadata = {
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "generated_at": timestamp,
        }
    else:
        content, metadata = intelligence_service.export_component_vulnerabilities(
            name,
            version,
            ecosystem=ecosystem,
            include_realtime=include_realtime,
        )
    stem = "-".join(
        _safe_file_part(part)
        for part in ("SecFlow", metadata.get("ecosystem") or "auto", metadata["name"], metadata["version"], "vulnerabilities")
    )
    return artifact_store.save(
        content,
        file_name=f"{stem[:180]}.xlsx",
        generated_at=str(metadata.get("generated_at") or now_iso()),
    )


@excel_mcp.tool(
    name="export_component_vulnerability_catalog",
    description="Create an auditable XLSX workbook from one verified date-scoped component vulnerability result.",
    structured_output=True,
)
def export_component_vulnerability_catalog(
    records: list[dict[str, Any]],
    start_date: str,
    end_date: str,
    filters: dict[str, Any] | None = None,
    generated_at: str = "",
) -> AssistantArtifact:
    content, metadata = intelligence_service.export_component_vulnerability_catalog(
        records,
        start_date=start_date,
        end_date=end_date,
        filters=filters or {},
        generated_at=generated_at or now_iso(),
    )
    stem = "-".join(
        _safe_file_part(part)
        for part in ("SecFlow", "component-vulnerabilities", metadata["start_date"], "to", metadata["end_date"])
    )
    return artifact_store.save(
        content,
        file_name=f"{stem[:180]}.xlsx",
        generated_at=str(metadata.get("generated_at") or now_iso()),
    )


@sankey_mcp.tool(
    name="build_component_sankey",
    description="Convert a component vulnerability knowledge graph into D3 Sankey nodes and links.",
    structured_output=True,
)
def build_component_sankey(graph: dict[str, Any]) -> SankeyPayload:
    raw_nodes = [item for item in graph.get("nodes") or [] if isinstance(item, dict)]
    raw_edges = [item for item in graph.get("edges") or [] if isinstance(item, dict)]
    nodes: list[SankeyNode] = []
    node_types: dict[str, str] = {}
    node_labels: dict[str, str] = {}
    severities: dict[str, str] = {}
    vulnerability_fixes: dict[str, set[str]] = {}
    known_ids: set[str] = set()
    for item in raw_nodes:
        node_id = str(item.get("id") or "").strip()
        label = str(item.get("label") or node_id).strip()
        node_type = str(item.get("type") or "component").strip().lower()
        if not node_id or node_id in known_ids or node_type not in {"component", "vulnerability", "fix"}:
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        severity = _metadata_text(metadata.get("severity")) or None
        if severity:
            severities[node_id] = severity
        node_types[node_id] = node_type
        node_labels[node_id] = label
        if node_type == "vulnerability":
            vulnerability_fixes[node_id] = {
                str(value).strip().casefold()
                for value in metadata.get("fixed_versions") or []
                if str(value).strip()
            }
        nodes.append(
            SankeyNode(
                id=node_id,
                label=label or node_id,
                type=node_type,
                severity=severity,
                column=_sankey_column(node_type),
                version=label if node_type == "fix" else None,
                ecosystem=_metadata_text(metadata.get("ecosystem")) or None,
            )
        )
        known_ids.add(node_id)

    component_vulnerabilities: dict[str, set[str]] = {}
    component_fixes: list[tuple[str, str]] = []
    for item in raw_edges:
        source = str(item.get("source") or "").strip()
        target = str(item.get("target") or "").strip()
        edge_type = str(item.get("type") or "RELATED_TO").strip().upper()
        if source not in known_ids or target not in known_ids:
            continue
        source_type = node_types[source]
        target_type = node_types[target]
        if edge_type == "AFFECTS" and {source_type, target_type} == {"component", "vulnerability"}:
            component_id = source if source_type == "component" else target
            vulnerability_id = source if source_type == "vulnerability" else target
            component_vulnerabilities.setdefault(component_id, set()).add(vulnerability_id)
        elif edge_type == "FIXED_BY" and {source_type, target_type} == {"component", "fix"}:
            component_id = source if source_type == "component" else target
            fix_id = source if source_type == "fix" else target
            component_fixes.append((component_id, fix_id))

    links: list[SankeyLink] = []
    seen_links: set[tuple[str, str, str]] = set()

    def add_link(source: str, target: str, edge_type: str, severity: str | None) -> None:
        key = (source, target, edge_type)
        if source == target or key in seen_links:
            return
        links.append(
            SankeyLink(
                source_id=source,
                target_id=target,
                type=edge_type,
                value=1,
                severity=severity,
            )
        )
        seen_links.add(key)

    # The source knowledge graph stores AFFECTS as vulnerability -> component.
    # The component-query renderer presents the user workflow instead:
    # component -> vulnerability -> verified fixed version.
    for component_id, vulnerability_ids in component_vulnerabilities.items():
        for vulnerability_id in sorted(vulnerability_ids):
            add_link(component_id, vulnerability_id, "AFFECTED_BY", severities.get(vulnerability_id))

    for component_id, fix_id in component_fixes:
        vulnerability_ids = component_vulnerabilities.get(component_id, set())
        fix_label = node_labels.get(fix_id, "").casefold()
        matched = {
            vulnerability_id
            for vulnerability_id in vulnerability_ids
            if fix_label and fix_label in vulnerability_fixes.get(vulnerability_id, set())
        }
        if not matched and len(vulnerability_ids) == 1:
            matched = set(vulnerability_ids)
        for vulnerability_id in sorted(matched):
            add_link(vulnerability_id, fix_id, "FIXED_BY", severities.get(vulnerability_id))

    return SankeyPayload(nodes=nodes, links=links)


def _component_vulnerability_detail(
    record: dict[str, Any],
    coordinate: ComponentDetailCoordinate,
    response_language: str,
) -> ComponentVulnerabilityDetail:
    severity = str(record.get("severity") or "UNKNOWN").strip().upper()
    component_affected_versions = _unique_text(
        [
            value
            for component in record.get("components") or []
            if isinstance(component, dict)
            for value in component.get("affected") or []
        ]
    )
    component_fixed_versions = _unique_text(
        [
            value
            for component in record.get("components") or []
            if isinstance(component, dict)
            for value in component.get("fixed") or []
        ]
    )
    affected_versions = component_affected_versions or _unique_text(record.get("affected_versions") or [])
    fixed_versions = component_fixed_versions or _unique_text(record.get("fixed_versions") or [])
    vector = _component_cvss_vector(record)
    reported_score = _optional_float(record.get("cvss_score"))
    vector_score = _component_cvss_v3_score(vector)
    score = vector_score if vector_score is not None else reported_score
    cvss_metrics = _component_cvss_metrics(vector)
    exploit_status_code = _component_exploit_status(record)
    exploit_status = {
        "confirmed": "已确认在野利用",
        "poc": "存在公开 PoC",
        "unknown": "未明确",
    }[exploit_status_code]
    complexity = next((item.value for item in cvss_metrics if item.key == "AC"), "未明确")
    exploit_difficulty = {"低": "较低", "高": "较高"}.get(complexity, "未明确")
    record_id = str(record.get("id") or "UNKNOWN").strip().upper()
    return ComponentVulnerabilityDetail(
        id=record_id,
        title=sanitize_public_text(record.get("title") or record_id).strip() or record_id,
        severity=severity,
        severity_label=severity_cn(severity),
        description=localized_vulnerability_summary(record, response_language),
        vulnerability_type="、".join(_unique_text(record.get("cwes") or [])) or "未明确",
        aliases=_unique_text(record.get("aliases") or []),
        cwes=_unique_text(record.get("cwes") or []),
        published_at=str(record.get("published_at") or "").strip(),
        updated_at=str(record.get("updated_at") or "").strip(),
        affected_packages=_component_affected_packages(record, coordinate),
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
        remediation=_component_remediation(fixed_versions, affected_versions),
        exploit_status=exploit_status,
        exploit_status_code=exploit_status_code,
        exploit_difficulty=exploit_difficulty,
        reference_links=_component_references(record),
        cvss=ComponentDetailCVSS(
            score=score,
            rating=_component_cvss_rating(score, severity),
            vector=vector,
            version=_component_cvss_version(vector),
            metrics=cvss_metrics,
        ),
    )


def _component_workbook_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for raw in records:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        vector_score = _component_cvss_v3_score(_component_cvss_vector(record))
        if vector_score is not None:
            record["cvss_score"] = vector_score
        output.append(record)
    return output


def _component_affected_packages(
    record: dict[str, Any],
    coordinate: ComponentDetailCoordinate,
) -> list[ComponentDetailAffectedPackage]:
    output: list[ComponentDetailAffectedPackage] = []
    seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    for raw in record.get("components") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        ecosystem = str(raw.get("ecosystem") or "").strip()
        if not name:
            continue
        affected = _unique_text(raw.get("affected") or [])
        fixed = _unique_text(raw.get("fixed") or [])
        key = (ecosystem.casefold(), name.casefold(), tuple(affected), tuple(fixed))
        if key in seen:
            continue
        output.append(
            ComponentDetailAffectedPackage(
                name=name,
                ecosystem=ecosystem or coordinate.ecosystem or "generic",
                affected_versions=affected,
                fixed_versions=fixed,
            )
        )
        seen.add(key)
        if len(output) >= 40:
            break
    if not output and coordinate.name:
        output.append(
            ComponentDetailAffectedPackage(
                name=coordinate.name,
                ecosystem=coordinate.ecosystem or "generic",
                affected_versions=_unique_text(record.get("affected_versions") or []),
                fixed_versions=_unique_text(record.get("fixed_versions") or []),
            )
        )
    return output


def _component_references(record: dict[str, Any]) -> list[ComponentDetailReference]:
    output: list[ComponentDetailReference] = []
    seen: set[str] = set()
    for raw in [*(record.get("reference_links") or []), *(record.get("references") or [])]:
        url = str(raw or "").strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or url in seen:
            continue
        host = parsed.netloc.lower().removeprefix("www.")
        title = {
            "nvd.nist.gov": "NVD 漏洞详情",
            "osv.dev": "OSV 漏洞详情",
            "github.com": "GitHub 安全公告",
        }.get(host, host)
        output.append(ComponentDetailReference(title=title, url=url))
        seen.add(url)
        if len(output) >= 12:
            break
    return output


def _component_cvss_vector(record: dict[str, Any]) -> str:
    for key in ("cvss_vector", "cvssVector", "vector_string", "vector"):
        value = str(record.get(key) or "").strip()
        if value.startswith("CVSS:"):
            return value
    return ""


def _component_cvss_version(vector: str) -> str:
    match = re.match(r"CVSS:([^/]+)", vector)
    return match.group(1) if match else ""


def _component_cvss_v3_score(vector: str) -> float | None:
    if not re.match(r"^CVSS:3\.[01]/", vector.upper()):
        return None
    values = {
        key: value
        for key, value in re.findall(r"(?:^|/)(AV|AC|PR|UI|S|C|I|A):([A-Z])", vector.upper())
    }
    if set(values) != {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}:
        return None
    scope = values["S"]
    weights = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    privilege_weights = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    try:
        impact_base = 1 - (
            (1 - weights["C"][values["C"]])
            * (1 - weights["I"][values["I"]])
            * (1 - weights["A"][values["A"]])
        )
        if scope == "U":
            impact = 6.42 * impact_base
        elif scope == "C":
            impact = 7.52 * (impact_base - 0.029) - 3.25 * ((impact_base - 0.02) ** 15)
        else:
            return None
        exploitability = (
            8.22
            * weights["AV"][values["AV"]]
            * weights["AC"][values["AC"]]
            * privilege_weights[scope][values["PR"]]
            * weights["UI"][values["UI"]]
        )
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw_score = min((1.08 if scope == "C" else 1.0) * (impact + exploitability), 10.0)
    return math.ceil((raw_score * 10) - 1e-10) / 10


def _component_cvss_metrics(vector: str) -> list[ComponentDetailCVSSMetric]:
    raw_values = {
        key: value
        for key, value in re.findall(r"(?:^|/)(AV|AC|PR|UI|S|C|I|A):([A-Z])", vector.upper())
    }
    specifications = (
        ("AV", "攻击向量", {"N": "网络", "A": "相邻网络", "L": "本地", "P": "物理"}),
        ("AC", "攻击复杂性", {"L": "低", "H": "高"}),
        ("PR", "所需权限", {"N": "无", "L": "低", "H": "高"}),
        ("UI", "用户交互", {"N": "无", "R": "需要"}),
        ("S", "影响范围", {"U": "不变", "C": "改变"}),
        ("C", "机密性影响", {"N": "无", "L": "低", "H": "高"}),
        ("I", "完整性影响", {"N": "无", "L": "低", "H": "高"}),
        ("A", "可用性影响", {"N": "无", "L": "低", "H": "高"}),
    )
    return [
        ComponentDetailCVSSMetric(
            key=key,
            label=label,
            value=values.get(raw_values.get(key, ""), "未明确"),
        )
        for key, label, values in specifications
    ]


def _component_cvss_rating(score: Any, severity: str) -> str:
    numeric = _optional_float(score)
    if numeric is not None:
        if numeric >= 9.0:
            return "严重"
        if numeric >= 7.0:
            return "高危"
        if numeric >= 4.0:
            return "中危"
        if numeric > 0:
            return "低危"
    return severity_cn(severity)


def _component_exploit_status(record: dict[str, Any]) -> Literal["confirmed", "poc", "unknown"]:
    if any(bool(record.get(key)) for key in ("known_exploited", "knownExploited", "kev", "in_kev")):
        return "confirmed"
    if any(bool(record.get(key)) for key in ("poc", "has_poc", "exploit_available", "public_exploit")):
        return "poc"
    return "unknown"


def _component_remediation(fixed_versions: list[str], affected_versions: list[str]) -> str:
    if fixed_versions:
        return "建议升级到已确认修复版本：" + "、".join(fixed_versions[:8])
    if affected_versions:
        return "当前记录未提供明确修复版本，请先核验影响范围并持续跟进官方补丁。"
    return "当前记录未提供明确修复版本，请核验资产指纹并跟进官方安全公告。"


def _optional_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _unique_text(values: Any) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values if isinstance(values, (list, tuple, set)) else []:
        text = str(value or "").strip()
        if text and text not in seen:
            output.append(text)
            seen.add(text)
    return output


def invoke_detail_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    return _invoke_structured_tool(detail_mcp, "build_component_vulnerability_detail", arguments)


def invoke_excel_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    return _invoke_structured_tool(excel_mcp, "export_component_vulnerabilities", arguments)


def invoke_catalog_excel_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    return _invoke_structured_tool(excel_mcp, "export_component_vulnerability_catalog", arguments)


def invoke_sankey_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    return _invoke_structured_tool(sankey_mcp, "build_component_sankey", arguments)


async def component_mcp_specs() -> list[dict[str, Any]]:
    servers = (("component-detail", detail_mcp), ("excel", excel_mcp), ("d3-sankey", sankey_mcp))
    result: list[dict[str, Any]] = []
    for server_id, server in servers:
        tools = await server.list_tools()
        result.append(
            {
                "id": server_id,
                "name": server.name,
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
        )
    return result


def _invoke_structured_tool(server: FastMCP, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(tool_name, arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError(f"MCP tool {tool_name} did not return structured output")


def _sankey_column(node_type: str) -> int:
    if node_type == "component":
        return 0
    if node_type == "fix":
        return 2
    return 1


def _metadata_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return ""


def _safe_file_part(value: Any) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-")
    return clean or "component"


def _safe_excel_name(value: str) -> str:
    name = Path(str(value or "component-vulnerabilities.xlsx")).name
    stem = "-".join(_safe_file_part(part) for part in Path(name).stem.split("-"))
    return f"{stem[:180]}.xlsx"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a SecFlow component-query MCP server over stdio.")
    parser.add_argument("server", choices=("component-detail", "excel", "d3-sankey"))
    args = parser.parse_args()
    {
        "component-detail": detail_mcp,
        "excel": excel_mcp,
        "d3-sankey": sankey_mcp,
    }[args.server].run(transport="stdio")


if __name__ == "__main__":
    main()
