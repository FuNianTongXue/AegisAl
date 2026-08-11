from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

from app.intelligence import _vulnerability_match_priority, intelligence_service, localized_vulnerability_summary
from app.storage import now_iso


CYCLONEDX_SPEC_VERSION = "1.6"
SBOM_SCHEMA_VERSION = 1
_MATCH_BATCH_SIZE = 12
_MATCH_WORKERS = 4
_CJK_PATTERN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")


def build_cyclonedx_sbom(
    dependency_scan: dict[str, Any],
    *,
    project_name: str,
    workspace_path: str = "",
    generated_at: str = "",
    license_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    dependencies = [
        _normalize_dependency(item)
        for item in dependency_scan.get("dependencies") or []
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    ]
    dependencies.sort(
        key=lambda item: (
            item["ecosystem"].casefold(),
            item["name"].casefold(),
            item["version"].casefold(),
            item["source_file"].casefold(),
        )
    )
    project = str(project_name or "project").strip() or "project"
    timestamp = str(generated_at or now_iso())
    fingerprint_payload = {
        "project": project,
        "dependencies": dependencies,
        "files": list(dependency_scan.get("files") or []),
        "licenses": [
            {
                "spdx_id": str(item.get("spdx_id") or ""),
                "source_files": list(item.get("source_files") or []),
                "detection_methods": list(item.get("detection_methods") or []),
            }
            for item in (license_scan or {}).get("licenses") or []
            if isinstance(item, dict)
        ],
    }
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    components = [_cyclonedx_component(item) for item in dependencies]
    project_component: dict[str, Any] = {
        "type": "application",
        "bom-ref": f"project:{fingerprint[:24]}",
        "name": project,
    }
    project_licenses, project_license_properties = _cyclonedx_project_licenses(license_scan or {})
    if project_licenses:
        project_component["licenses"] = project_licenses
    if project_license_properties:
        project_component["properties"] = project_license_properties
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, f'secflow:{fingerprint}')}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "SecFlow SBOM Agent",
                        "version": "1",
                    }
                ]
            },
            "component": project_component,
            "properties": [
                {"name": "secflow:workspaceName", "value": Path(workspace_path).name if workspace_path else project},
                {"name": "secflow:sourceFileCount", "value": str(len(dependency_scan.get("files") or []))},
                {"name": "secflow:resultSha256", "value": fingerprint},
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": component["bom-ref"], "dependsOn": []}
            for component in components
        ],
        "vulnerabilities": [],
        "properties": [
            {"name": "secflow:schemaVersion", "value": str(SBOM_SCHEMA_VERSION)},
            {"name": "secflow:unresolvedVersionCount", "value": str(sum(not item["version"] for item in dependencies))},
            {"name": "secflow:rejectedFileCount", "value": str(len(dependency_scan.get("rejected_files") or []))},
        ],
    }
    if license_scan:
        registry = license_scan.get("registry") if isinstance(license_scan.get("registry"), dict) else {}
        license_sha256 = hashlib.sha256(
            json.dumps(license_scan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        result["metadata"]["properties"].extend(
            [
                {"name": "secflow:licenseCount", "value": str(int(license_scan.get("license_count") or 0))},
                {"name": "secflow:licenseCoverage", "value": str(license_scan.get("coverage_status") or "unknown")},
                {"name": "secflow:licenseRegistryStatus", "value": str(registry.get("status") or "unknown")},
                {"name": "secflow:licenseAnalysisSha256", "value": license_sha256},
            ]
        )
    return result


def match_sbom_vulnerabilities(
    sbom: dict[str, Any],
    dependency_scan: dict[str, Any],
    *,
    response_language: str = "zh-Hans",
) -> tuple[dict[str, Any], dict[str, Any]]:
    dependencies = [
        _normalize_dependency(item)
        for item in dependency_scan.get("dependencies") or []
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    ]
    concrete = [item for item in dependencies if _has_concrete_version(item["version"])]
    batches = [concrete[index : index + _MATCH_BATCH_SIZE] for index in range(0, len(concrete), _MATCH_BATCH_SIZE)]
    outcomes: list[dict[str, Any]] = []
    errors: list[str] = []
    if batches:
        with ThreadPoolExecutor(max_workers=min(_MATCH_WORKERS, len(batches))) as executor:
            futures = {
                executor.submit(
                    intelligence_service.query_dependencies,
                    batch,
                    limit_per_dependency=5,
                    response_language=response_language,
                ): index
                for index, batch in enumerate(batches)
            }
            ordered: dict[int, dict[str, Any]] = {}
            for future in as_completed(futures):
                index = futures[future]
                try:
                    ordered[index] = future.result()
                except Exception as exc:  # noqa: BLE001 - matching must preserve partial, auditable coverage.
                    errors.append(f"batch-{index + 1}: {type(exc).__name__}")
            outcomes = [ordered[index] for index in sorted(ordered)]

    records = _localize_vulnerability_records(
        sorted(
            _merge_vulnerability_records(
                record
                for outcome in outcomes
                for record in outcome.get("records") or []
                if isinstance(record, dict)
            ),
            key=_vulnerability_match_priority,
            reverse=True,
        )
    )
    source_status = _merge_source_status(
        status
        for outcome in outcomes
        for status in outcome.get("source_status") or []
        if isinstance(status, dict)
    )
    component_refs = _component_reference_index(sbom)
    vulnerabilities = [_cyclonedx_vulnerability(record, component_refs) for record in records]
    vulnerabilities = [item for item in vulnerabilities if item.get("affects")]
    matched_refs = {
        str(affect.get("ref") or "")
        for vulnerability in vulnerabilities
        for affect in vulnerability.get("affects") or []
        if str(affect.get("ref") or "")
    }
    updated_sbom = deepcopy(sbom)
    updated_sbom["vulnerabilities"] = vulnerabilities
    generated_at = now_iso()
    matching = {
        "schema_version": SBOM_SCHEMA_VERSION,
        "generated_at": generated_at,
        "requested_component_count": len(dependencies),
        "versioned_component_count": len(concrete),
        "unresolved_version_count": len(dependencies) - len(concrete),
        "attempted_component_count": sum(len(batch) for batch in batches),
        "completed_batch_count": len(outcomes),
        "failed_batch_count": len(errors),
        "matched_component_count": len(matched_refs),
        "vulnerability_count": len(vulnerabilities),
        "coverage_status": "complete" if not errors and len(outcomes) == len(batches) else "partial",
        "errors": errors,
        "source_status": source_status,
        "records": records,
    }
    updated_sbom.setdefault("metadata", {}).setdefault("properties", []).extend(
        [
            {"name": "secflow:vulnerabilityMatching", "value": matching["coverage_status"]},
            {"name": "secflow:vulnerabilityCount", "value": str(len(vulnerabilities))},
            {"name": "secflow:vulnerabilityMatchedAt", "value": generated_at},
        ]
    )
    return updated_sbom, matching


def canonical_sbom_json(sbom: dict[str, Any]) -> str:
    return json.dumps(sbom, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalize_dependency(value: dict[str, Any]) -> dict[str, str]:
    return {
        "ecosystem": str(value.get("ecosystem") or "generic").strip() or "generic",
        "name": str(value.get("name") or "").strip(),
        "version": str(value.get("version") or "").strip(),
        "source_file": str(value.get("source_file") or value.get("sourceFile") or "").strip(),
        "source_type": str(value.get("source_type") or value.get("sourceType") or "").strip(),
        "declaration": str(value.get("declaration") or "").strip(),
        "confidence": str(value.get("confidence") or "medium").strip() or "medium",
    }


def _cyclonedx_component(dependency: dict[str, str]) -> dict[str, Any]:
    purl = _package_url(dependency["ecosystem"], dependency["name"], dependency["version"])
    identity = purl or f"{dependency['ecosystem']}|{dependency['name']}|{dependency['version']}"
    bom_ref = f"component:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": dependency["name"],
        "version": dependency["version"] or "UNKNOWN",
        "properties": [
            {"name": "secflow:ecosystem", "value": dependency["ecosystem"]},
            {"name": "secflow:sourceFile", "value": dependency["source_file"]},
            {"name": "secflow:sourceType", "value": dependency["source_type"]},
            {"name": "secflow:declaration", "value": dependency["declaration"]},
            {"name": "secflow:confidence", "value": dependency["confidence"]},
            {"name": "secflow:versionResolved", "value": "true" if dependency["version"] else "false"},
        ],
    }
    if purl:
        component["purl"] = purl
    if dependency["ecosystem"].casefold() == "maven" and ":" in dependency["name"]:
        group, name = dependency["name"].split(":", 1)
        component["group"] = group
        component["name"] = name
    return component


def _cyclonedx_project_licenses(license_scan: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    choices: list[dict[str, Any]] = []
    properties: list[dict[str, str]] = []
    for item in license_scan.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        license_id = str(item.get("spdx_id") or "").strip()
        name = str(item.get("name") or license_id).strip()
        osi = item.get("osi") if isinstance(item.get("osi"), dict) else {}
        license_value: dict[str, Any] = {}
        if license_id:
            license_value["id"] = license_id
        if name:
            license_value["name"] = name
        if str(osi.get("official_url") or "").startswith("https://"):
            license_value["url"] = str(osi["official_url"])
        if license_value:
            choices.append({"license": license_value})
        evidence = {
            "source_files": list(item.get("source_files") or []),
            "detection_methods": list(item.get("detection_methods") or []),
            "declarations": list(item.get("declarations") or []),
            "confidence": float(item.get("confidence") or 0),
            "osi": osi,
        }
        properties.append(
            {
                "name": f"secflow:license:{license_id or name}:evidence",
                "value": json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            }
        )
    return choices, properties


def _package_url(ecosystem: str, name: str, version: str) -> str:
    ecosystem_key = ecosystem.casefold()
    package_types = {
        "maven": "maven",
        "npm": "npm",
        "pypi": "pypi",
        "go": "golang",
        "golang": "golang",
        "crates.io": "cargo",
        "cargo": "cargo",
        "nuget": "nuget",
        "rubygems": "gem",
        "packagist": "composer",
    }
    package_type = package_types.get(ecosystem_key)
    if not package_type or not name:
        return ""
    if package_type == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        path = f"{quote(group, safe='.')}/{quote(artifact, safe='._-')}"
    else:
        path = quote(name, safe="/._-")
    return f"pkg:{package_type}/{path}" + (f"@{quote(version, safe='._+-')}" if version else "")


def _has_concrete_version(version: str) -> bool:
    clean = str(version or "").strip()
    return bool(clean and clean not in {"*", "latest", "unknown", "UNKNOWN"} and not any(char in clean for char in "${}[](),<> "))


def _merge_vulnerability_records(records: Any) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for raw in records:
        identifier = str(raw.get("id") or "").strip().upper()
        if not identifier:
            continue
        if identifier not in merged:
            merged[identifier] = deepcopy(raw)
            continue
        current = merged[identifier]
        for key in ("matched_dependencies", "fixed_versions", "affected_versions", "references", "aliases", "provenance"):
            values = [*current.get(key, []), *raw.get(key, [])]
            seen: set[str] = set()
            unique: list[Any] = []
            for item in values:
                fingerprint = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                unique.append(item)
            current[key] = unique
    return sorted(merged.values(), key=lambda item: str(item.get("id") or ""))


def _localize_vulnerability_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    localized: list[dict[str, Any]] = []
    for record in records:
        item = deepcopy(record)
        summary_zh = str(item.get("summary_zh") or "").strip()
        if not summary_zh or not _CJK_PATTERN.search(summary_zh):
            summary_zh = localized_vulnerability_summary(item, "zh-Hans", prefer_translation=True)
        item["summary_zh"] = summary_zh
        localized.append(item)
    return localized


def _merge_source_status(statuses: Any) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    rank = {"failed": 3, "warning": 2, "success": 1, "completed": 1}
    for status in statuses:
        source = str(status.get("id") or "unknown")
        current = merged.setdefault(source, {"id": source, "status": "success", "count": 0, "message": "查询完成"})
        current["count"] = int(current.get("count") or 0) + int(status.get("count") or 0)
        incoming_status = str(status.get("status") or "warning")
        if rank.get(incoming_status, 2) > rank.get(str(current.get("status") or "success"), 1):
            current["status"] = incoming_status
            current["message"] = str(status.get("message") or "")
    return sorted(merged.values(), key=lambda item: item["id"])


def _component_reference_index(sbom: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for component in sbom.get("components") or []:
        properties = {
            str(item.get("name") or ""): str(item.get("value") or "")
            for item in component.get("properties") or []
            if isinstance(item, dict)
        }
        ecosystem = properties.get("secflow:ecosystem", "")
        display_name = str(component.get("name") or "")
        group = str(component.get("group") or "")
        coordinate = f"{group}:{display_name}" if group else display_name
        version = "" if str(component.get("version") or "") == "UNKNOWN" else str(component.get("version") or "")
        ref = str(component.get("bom-ref") or "")
        for key in (
            f"{ecosystem}|{coordinate}|{version}",
            f"{ecosystem}|{coordinate}",
            f"|{coordinate}|{version}",
            f"|{coordinate}",
        ):
            result[key.casefold()] = ref
    return result


def _cyclonedx_vulnerability(record: dict[str, Any], component_refs: dict[str, str]) -> dict[str, Any]:
    affects: list[dict[str, str]] = []
    candidates = list(record.get("matched_dependencies") or [])
    if not candidates:
        candidates = list(record.get("components") or [])
    for item in candidates:
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "")
        name = str(item.get("name") or "")
        version = str(item.get("version") or "")
        ref = component_refs.get(f"{ecosystem}|{name}|{version}".casefold())
        ref = ref or component_refs.get(f"{ecosystem}|{name}".casefold())
        ref = ref or component_refs.get(f"|{name}|{version}".casefold())
        ref = ref or component_refs.get(f"|{name}".casefold())
        if ref and {"ref": ref} not in affects:
            affects.append({"ref": ref})
    severity = str(record.get("severity") or "UNKNOWN").lower()
    score = record.get("cvss_score")
    rating: dict[str, Any] = {"severity": severity if severity in {"critical", "high", "medium", "low", "info", "none"} else "unknown"}
    if isinstance(score, (int, float)):
        rating["score"] = float(score)
    source_names = [str(value).strip() for value in record.get("provenance") or [] if str(value).strip()]
    original_source = "; ".join(source_names) or "SecFlow vulnerability intelligence"
    source_name = localized_intelligence_source(original_source)
    original_description = str(record.get("summary") or record.get("title") or "").strip()
    result: dict[str, Any] = {
        "id": str(record.get("id") or ""),
        "source": {"name": str(source_name)},
        "ratings": [rating],
        "description": str(
            record.get("summary_zh")
            or localized_vulnerability_summary(record, "zh-Hans", prefer_translation=True)
        ),
        "affects": affects,
        "properties": [
            {"name": "secflow:fixedVersions", "value": "; ".join(str(item) for item in record.get("fixed_versions") or [])},
            {"name": "secflow:publishedAt", "value": str(record.get("published_at") or "")},
            {"name": "secflow:updatedAt", "value": str(record.get("updated_at") or "")},
            {"name": "secflow:descriptionLanguage", "value": "zh-Hans"},
            {"name": "secflow:sourceOriginal", "value": original_source},
            {"name": "secflow:descriptionOriginal", "value": original_description},
        ],
    }
    references = [str(item) for item in record.get("references") or [] if str(item).startswith(("https://", "http://"))]
    if references:
        result["advisories"] = [{"url": value} for value in references[:20]]
    return result


def localized_intelligence_source(value: Any) -> str:
    """Return a stable Chinese display label while keeping raw provenance in audit data."""

    text = str(value or "").strip()
    if not text:
        return "SecFlow 漏洞情报库"

    source_labels = {
        "nvd": "美国国家漏洞数据库（NVD）",
        "national vulnerability database": "美国国家漏洞数据库（NVD）",
        "osv": "OSV 开源漏洞数据库",
        "github advisory": "GitHub 安全公告数据库",
        "github_advisory": "GitHub 安全公告数据库",
        "github security advisory": "GitHub 安全公告数据库",
        "ghsa": "GitHub 安全公告数据库",
        "cisa": "美国网络安全和基础设施安全局（CISA）",
        "cisa kev": "CISA 已知被利用漏洞目录（KEV）",
        "cisa_kev": "CISA 已知被利用漏洞目录（KEV）",
        "kev": "CISA 已知被利用漏洞目录（KEV）",
        "exploitdb": "Exploit-DB 漏洞利用数据库",
        "exploit-db": "Exploit-DB 漏洞利用数据库",
        "secflow vulnerability intelligence": "SecFlow 漏洞情报库",
    }
    labels: list[str] = []
    for raw_part in re.split(r"[;,|]", text):
        part = raw_part.strip()
        key = re.sub(r"\s+", " ", part.casefold())
        label = source_labels.get(key)
        if label is None:
            if "secflow" in key:
                label = source_labels["secflow vulnerability intelligence"]
            elif "github" in key and ("advisory" in key or "security" in key):
                label = source_labels["github advisory"]
            elif "nvd" in key or "national vulnerability database" in key:
                label = source_labels["nvd"]
            elif "cisa" in key and "kev" in key:
                label = source_labels["cisa kev"]
            elif "cisa" in key:
                label = source_labels["cisa"]
            elif "osv" in key:
                label = source_labels["osv"]
            elif "exploit" in key:
                label = source_labels["exploitdb"]
            elif _CJK_PATTERN.search(part):
                label = part
            else:
                label = "SecFlow 漏洞情报库"
        if label not in labels:
            labels.append(label)
    return "；".join(labels) or "SecFlow 漏洞情报库"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
