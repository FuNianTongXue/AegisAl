from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.intelligence_runtime import default_headers, intelligence_endpoint
from app.models import CollectorConfigUpdate
from app.storage import now_iso, store


class CollectorService:
    def snapshot(self) -> dict[str, Any]:
        return {
            "collectors": {},
            "records": [],
            "stats": self._stats([]),
        }

    def update_config(self, collector_id: str, payload: CollectorConfigUpdate) -> dict[str, Any]:
        state = store.read()
        if collector_id not in state["collectors"]:
            raise KeyError(collector_id)
        config = state["collectors"][collector_id]
        updates = payload.model_dump(exclude_unset=True)
        for key, value in updates.items():
            if value is None:
                continue
            config[key] = value
        store.write(state)
        return {
            "collector": store.public_state()["collectors"][collector_id],
            "message": f"{config['name']} configuration saved.",
        }

    def test_config(self, collector_id: str) -> dict[str, Any]:
        state = store.read()
        if collector_id not in state["collectors"]:
            raise KeyError(collector_id)
        config = state["collectors"][collector_id]
        credential_error = _credential_error(collector_id, config)
        if credential_error:
            result = {"status": "warning", "message": credential_error, "checked_at": now_iso()}
            config["last_test"] = result
            store.write(state)
            return result
        try:
            if collector_id == "cve":
                result = self._test_cve(config)
            elif collector_id == "github_advisory":
                result = self._test_github_advisory(config)
            else:
                raise KeyError(collector_id)
        except Exception as exc:  # noqa: BLE001
            result = {"status": "failed", "message": str(exc), "checked_at": now_iso()}
        config["last_test"] = result
        store.write(state)
        return result

    def collect(self, collector_id: str) -> dict[str, Any]:
        state = store.read()
        if collector_id not in state["collectors"]:
            raise KeyError(collector_id)
        config = state["collectors"][collector_id]
        trace = [_collector_trace("validate_config", "接口配置已读取，执行实时查询。")]
        if not config.get("enabled", True):
            return {
                "status": "warning",
                "message": "接口已停用，未执行查询。",
                "inserted": 0,
                "fetched": 0,
                "records": [],
                "years": [],
                "errors": [],
                "trace": [*trace, _collector_trace("compose_result", "接口查询已跳过。", "warning")],
            }
        try:
            if collector_id == "cve":
                records = self._collect_cve(config)
            elif collector_id == "github_advisory":
                records = self._collect_github_advisory(config)
            else:
                raise KeyError(collector_id)
            status = "success" if records else "warning"
            return {
                "status": status,
                "message": f"API query finished with {len(records)} record(s). No local vulnerability storage was written.",
                "inserted": 0,
                "fetched": len(records),
                "records": records,
                "years": [],
                "errors": [],
                "trace": [
                    *trace,
                    _collector_trace("query_api", f"接口返回 {len(records)} 条漏洞记录。", status),
                    _collector_trace("compose_result", "实时接口查询结果已汇总。", status),
                ],
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "failed",
                "message": str(exc),
                "inserted": 0,
                "fetched": 0,
                "records": [],
                "years": [],
                "errors": [str(exc)],
                "trace": [*trace, _collector_trace("query_api", str(exc), "failed")],
            }

    def collect_cve_by_years(self, years: list[int], max_results: int = 20) -> dict[str, Any]:
        state = store.read()
        config = state["collectors"]["cve"]
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        for year in years:
            try:
                records.extend(self._collect_cve(config, year=year, max_results=max_results))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{year}: {exc}")
        status = "warning" if errors else "success"
        if not records and errors:
            status = "failed"
        return {
            "status": status,
            "message": f"API year query finished with {len(records)} record(s). No local vulnerability storage was written.",
            "inserted": 0,
            "fetched": len(records),
            "records": records,
            "years": years,
            "errors": errors,
            "trace": [
                _collector_trace("validate_config", "接口配置已读取，执行年份实时查询。"),
                _collector_trace("query_api", f"接口返回 {len(records)} 条漏洞记录。", status),
                _collector_trace("compose_result", "年份接口查询结果已汇总。", status),
            ],
        }

    @staticmethod
    def credential_error(collector_id: str, config: dict[str, Any]) -> str:
        return _credential_error(collector_id, config)

    @staticmethod
    def search(question: str, top_k: int = 5) -> list[dict[str, Any]]:
        state = store.read()
        query_terms = set(_tokens(question))
        scored: list[tuple[int, dict[str, Any]]] = []
        for record in state["records"]:
            text = " ".join(
                [
                    str(record.get("id", "")),
                    str(record.get("title", "")),
                    str(record.get("summary", "")),
                    str(record.get("title_zh", "")),
                    str(record.get("summary_zh", "")),
                    str(record.get("severity", "")),
                    str(record.get("source", "")),
                ]
            )
            terms = set(_tokens(text))
            score = len(query_terms & terms)
            if str(record.get("id", "")).lower() in question.lower():
                score += 20
            if score > 0:
                scored.append((score, deepcopy(record)))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [record for _, record in scored[:top_k]]

    @staticmethod
    def search_by_years(question: str, years: list[int], top_k: int = 5) -> list[dict[str, Any]]:
        state = store.read()
        query_terms = set(_tokens(question))
        year_set = {str(year) for year in years}
        scored: list[tuple[int, str, dict[str, Any]]] = []
        for record in state["records"]:
            record_year = _record_year(record)
            if record_year not in year_set:
                continue
            text = " ".join(
                [
                    str(record.get("id", "")),
                    str(record.get("title", "")),
                    str(record.get("summary", "")),
                    str(record.get("title_zh", "")),
                    str(record.get("summary_zh", "")),
                    str(record.get("severity", "")),
                    str(record.get("source", "")),
                    str(record.get("published_at", "")),
                    str(record.get("updated_at", "")),
                ]
            )
            terms = set(_tokens(text))
            score = len(query_terms & terms) + _severity_score(str(record.get("severity", "")))
            if str(record.get("collection", "")).lower() == "cve":
                score += 3
            scored.append((score, str(record.get("published_at") or record.get("updated_at") or ""), deepcopy(record)))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [record for _, _, record in scored[:top_k]]

    @staticmethod
    def _stats(records: list[dict[str, Any]]) -> dict[str, Any]:
        by_collection: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for record in records:
            by_collection[record.get("collection", "unknown")] = by_collection.get(record.get("collection", "unknown"), 0) + 1
            sev = str(record.get("severity", "unknown")).upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {"total": len(records), "by_collection": by_collection, "by_severity": by_severity}

    @staticmethod
    def _test_cve(config: dict[str, Any]) -> dict[str, Any]:
        params = {"resultsPerPage": "1"}
        headers = default_headers()
        if config.get("api_key"):
            headers["apiKey"] = config["api_key"]
        with httpx.Client(timeout=12.0, follow_redirects=True) as client:
            response = client.get(_collector_endpoint(config, "api_primary"), params=params, headers=headers)
            response.raise_for_status()
        return {"status": "success", "message": "固定接口可访问。", "checked_at": now_iso()}

    @staticmethod
    def _test_github_advisory(config: dict[str, Any]) -> dict[str, Any]:
        headers = default_headers(auth="secondary")
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        with httpx.Client(timeout=12.0, follow_redirects=True) as client:
            response = client.get(_collector_endpoint(config, "api_secondary"), params={"per_page": "1"}, headers=headers)
            response.raise_for_status()
        return {"status": "success", "message": "固定接口可访问。", "checked_at": now_iso()}

    def _collect_cve(self, config: dict[str, Any], year: int | None = None, max_results: int | None = None) -> list[dict[str, Any]]:
        headers = default_headers()
        if config.get("api_key"):
            headers["apiKey"] = config["api_key"]
        limit = min(int(max_results or config.get("max_results", 20)), 200)
        page_size = min(max(limit * 5, 100), 2000)
        base_params = {"resultsPerPage": str(page_size)}
        windows = _nvd_year_windows(year) if year else [(None, None)]
        allowed = {str(item).upper() for item in config.get("severity_filter", [])}
        records: dict[str, dict[str, Any]] = {}
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            for start, end in windows:
                params = dict(base_params)
                if start and end:
                    params["pubStartDate"] = _nvd_datetime(start)
                    params["pubEndDate"] = _nvd_datetime(end)
                response = client.get(_collector_endpoint(config, "api_primary"), params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
                total_results = int(data.get("totalResults") or 0)
                if total_results > page_size:
                    params["startIndex"] = str(max(0, total_results - page_size))
                    response = client.get(_collector_endpoint(config, "api_primary"), params=params, headers=headers)
                    response.raise_for_status()
                    data = response.json()
                for item in data.get("vulnerabilities", []):
                    record = _nvd_record(item.get("cve", {}), config, year)
                    if not record or (allowed and str(record["severity"]).upper() not in allowed):
                        continue
                    records[str(record["id"]).lower()] = record
                if len(records) >= limit:
                    break
        return sorted(records.values(), key=_record_sort_key, reverse=True)[:limit]

    def _collect_github_advisory(self, config: dict[str, Any], max_results: int | None = None) -> list[dict[str, Any]]:
        headers = default_headers(auth="secondary")
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        params = {"per_page": str(min(int(max_results or config.get("max_results", 20)), 100))}
        if config.get("ecosystem"):
            params["ecosystem"] = config["ecosystem"]
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            response = client.get(_collector_endpoint(config, "api_secondary"), params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        records: list[dict[str, Any]] = []
        allowed = {str(item).lower() for item in config.get("severity_filter", [])}
        for item in data if isinstance(data, list) else []:
            ghsa_id = str(item.get("ghsa_id", "")).upper()
            if not ghsa_id:
                continue
            severity = str(item.get("severity") or "unknown")
            if allowed and severity.lower() not in allowed:
                continue
            references = [item.get("html_url")] if item.get("html_url") else []
            affected_versions, fixed_versions = _github_version_facts(item)
            records.append(
                {
                    "id": ghsa_id,
                    "title": item.get("summary") or ghsa_id,
                    "severity": severity,
                    "cvss_score": _github_cvss_score(item),
                    "source": "fixed-api",
                    "summary": item.get("description") or item.get("summary") or "",
                    "affected_versions": affected_versions,
                    "fixed_versions": fixed_versions,
                    "references": references,
                    "collection": config.get("collection_name", "github_advisory"),
                    "updated_at": item.get("updated_at") or now_iso(),
                }
            )
        return records


def _description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _credential_error(collector_id: str, config: dict[str, Any]) -> str:
    return ""


def _collector_endpoint(config: dict[str, Any], endpoint_name: str) -> str:
    configured = str(config.get("api_url") or "").strip()
    return configured or intelligence_endpoint(endpoint_name)


def _collector_trace(node: str, message: str, status: str = "completed") -> dict[str, str]:
    return {"node": f"collector.{node}", "status": status, "message": message, "time": now_iso()}


def _nvd_record(cve: dict[str, Any], config: dict[str, Any], year: int | None) -> dict[str, Any] | None:
    cve_id = str(cve.get("id", "")).upper()
    if not cve_id or (year and not cve_id.startswith(f"CVE-{year}-")):
        return None
    if str(cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    summary = _description(cve)
    return {
        "id": cve_id,
        "title": summary[:160] or cve_id,
        "severity": _nvd_severity(cve),
        "cvss_score": _nvd_cvss_score(cve),
        "cvss_vector": _nvd_cvss_vector(cve),
        "source": "fixed-api",
        "summary": summary,
        "affected_versions": _nvd_affected_versions(cve),
        "fixed_versions": _nvd_fixed_versions(cve),
        "references": _nvd_references(cve),
        "has_poc": _nvd_has_poc(cve),
        "collection": config.get("collection_name", "cve"),
        "published_at": cve.get("published") or "",
        "updated_at": cve.get("lastModified") or now_iso(),
    }


def _nvd_references(cve: dict[str, Any]) -> list[str]:
    references = cve.get("references") or []
    if isinstance(references, dict):
        references = references.get("referenceData") or []
    if not isinstance(references, list):
        return []
    return [str(reference["url"]) for reference in references if isinstance(reference, dict) and reference.get("url")]


def _nvd_has_poc(cve: dict[str, Any]) -> bool:
    references = cve.get("references") or []
    if isinstance(references, dict):
        references = references.get("referenceData") or []
    if not isinstance(references, list):
        return False
    return any(
        "exploit" in {str(tag or "").strip().casefold() for tag in reference.get("tags") or []}
        for reference in references
        if isinstance(reference, dict)
    )


def _nvd_severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            cvss = values[0].get("cvssData", {})
            return str(cvss.get("baseSeverity") or values[0].get("baseSeverity") or "UNKNOWN")
    return "UNKNOWN"


def _nvd_cvss_score(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        raw = (values[0].get("cvssData") or {}).get("baseScore")
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def _nvd_cvss_vector(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        vector = str((values[0].get("cvssData") or {}).get("vectorString") or "").strip()
        if vector.startswith("CVSS:"):
            return vector
    return ""


def _nvd_affected_versions(cve: dict[str, Any]) -> list[str]:
    """Extract version facts from legacy CPE and current CNA/NVD records."""

    values: list[str] = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                criteria = str(match.get("criteria") or "")
                parts = criteria.split(":")
                product = " ".join(part.replace("_", " ") for part in parts[3:5] if part and part not in {"*", "-"})
                exact = parts[5] if len(parts) > 5 and parts[5] not in {"", "*", "-"} else ""
                bounds: list[str] = []
                if match.get("versionStartIncluding"):
                    bounds.append(f">= {match['versionStartIncluding']}")
                if match.get("versionStartExcluding"):
                    bounds.append(f"> {match['versionStartExcluding']}")
                if match.get("versionEndIncluding"):
                    bounds.append(f"<= {match['versionEndIncluding']}")
                if match.get("versionEndExcluding"):
                    bounds.append(f"< {match['versionEndExcluding']}")
                version_text = exact or ", ".join(bounds)
                if not version_text:
                    continue
                label = f"{product} {version_text}".strip()
                if label and label not in values:
                    values.append(label)
    modern_affected, _modern_fixed = _nvd_modern_version_facts(cve)
    for value in modern_affected:
        if value not in values:
            values.append(value)
    return values[:12]


def _nvd_fixed_versions(cve: dict[str, Any]) -> list[str]:
    """Return only fixed versions explicitly stated by structured or CNA text facts."""

    _affected, structured_fixed = _nvd_modern_version_facts(cve)
    entries = _nvd_modern_affected_entries(cve)
    component_labels = _unique_text(
        _nvd_modern_component_label(entry)
        for entry in entries
        if _nvd_modern_component_label(entry)
    )
    text_fixed = _explicit_fixed_versions(_description(cve))
    if len(component_labels) == 1:
        text_fixed = [f"{component_labels[0]} {version}" for version in text_fixed]
    return _unique_text([*structured_fixed, *text_fixed])[:12]


def _nvd_modern_components(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize CNA affected products into the component contract used by the graph."""

    components: dict[str, dict[str, Any]] = {}
    entries = _nvd_modern_affected_entries(cve)
    for entry in entries:
        name = str(entry.get("product") or entry.get("packageName") or entry.get("package") or "").strip()
        vendor = str(entry.get("vendor") or entry.get("collectionURL") or "").strip()
        ecosystem = _nvd_modern_ecosystem(entry) or vendor or "generic"
        if not name or name in {"*", "-", "n/a"}:
            continue
        affected, fixed = _nvd_entry_version_facts(entry, include_component=False)
        key = f"{ecosystem}:{name}".lower()
        component = components.setdefault(
            key,
            {"name": name, "ecosystem": ecosystem, "affected": [], "fixed": []},
        )
        component["affected"] = _unique_text([*component["affected"], *affected])
        component["fixed"] = _unique_text([*component["fixed"], *fixed])

    if len(components) == 1:
        component = next(iter(components.values()))
        component["fixed"] = _unique_text(
            [*component["fixed"], *_explicit_fixed_versions(_description(cve))]
        )
    return list(components.values())[:20]


def _nvd_modern_version_facts(cve: dict[str, Any]) -> tuple[list[str], list[str]]:
    affected: list[str] = []
    fixed: list[str] = []
    for entry in _nvd_modern_affected_entries(cve):
        entry_affected, entry_fixed = _nvd_entry_version_facts(entry, include_component=True)
        affected.extend(entry_affected)
        fixed.extend(entry_fixed)
    return _unique_text(affected)[:12], _unique_text(fixed)[:12]


def _nvd_modern_affected_entries(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Accept NVD's affectedData wrapper and native CVE 5 container records."""

    entries: list[dict[str, Any]] = []

    def append_items(values: Any) -> None:
        if not isinstance(values, list):
            return
        for value in values:
            if not isinstance(value, dict):
                continue
            affected_data = value.get("affectedData")
            if isinstance(affected_data, list):
                entries.extend(item for item in affected_data if isinstance(item, dict))
            elif value.get("versions") or value.get("product") or value.get("packageName"):
                entries.append(value)

    append_items(cve.get("affected"))
    containers = cve.get("containers") or {}
    if isinstance(containers, dict):
        cna = containers.get("cna") or {}
        if isinstance(cna, dict):
            append_items(cna.get("affected"))
        for provider in containers.get("adp") or []:
            if isinstance(provider, dict):
                append_items(provider.get("affected"))

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        key = repr(
            (
                entry.get("vendor"),
                entry.get("product"),
                entry.get("packageName"),
                entry.get("versions"),
            )
        )
        if key not in seen:
            unique.append(entry)
            seen.add(key)
    return unique


def _nvd_entry_version_facts(entry: dict[str, Any], *, include_component: bool) -> tuple[list[str], list[str]]:
    affected: list[str] = []
    fixed: list[str] = []
    prefix = _nvd_modern_component_label(entry) if include_component else ""
    default_status = str(entry.get("defaultStatus") or "").strip().lower()
    for item in entry.get("versions") or []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unknown").strip().lower()
        version_text = _nvd_version_range_text(item)
        if status == "affected" and version_text:
            affected.append(_prefixed_version(prefix, version_text))
        elif status in {"fixed", "unaffected"}:
            concrete = _concrete_version(str(item.get("version") or ""))
            if concrete:
                fixed.append(_prefixed_version(prefix, concrete))

        if status == "affected" and default_status in {"fixed", "unaffected"}:
            boundary = _concrete_version(str(item.get("lessThan") or ""))
            if boundary:
                fixed.append(_prefixed_version(prefix, boundary))

        current_status = status
        for change in item.get("changes") or []:
            if not isinstance(change, dict):
                continue
            next_status = str(change.get("status") or "").strip().lower()
            at = _concrete_version(str(change.get("at") or ""))
            if current_status == "affected" and next_status in {"fixed", "unaffected"} and at:
                fixed.append(_prefixed_version(prefix, at))
            current_status = next_status or current_status
    return _unique_text(affected), _unique_text(fixed)


def _nvd_version_range_text(item: dict[str, Any]) -> str:
    version = str(item.get("version") or "").strip()
    less_than = str(item.get("lessThan") or "").strip()
    less_equal = str(item.get("lessThanOrEqual") or "").strip()
    lower = "" if version in {"", "*", "-", "0"} else version
    if less_than:
        return f">= {lower}, < {less_than}" if lower else f"< {less_than}"
    if less_equal:
        return f">= {lower}, <= {less_equal}" if lower else f"<= {less_equal}"
    return version if version not in {"", "*", "-"} else ""


def _nvd_modern_component_label(entry: dict[str, Any]) -> str:
    vendor = str(entry.get("vendor") or "").strip()
    product = str(entry.get("product") or entry.get("packageName") or entry.get("package") or "").strip()
    if vendor.lower() == product.lower():
        vendor = ""
    return " ".join(value for value in (vendor, product) if value and value not in {"*", "-", "n/a"})


def _nvd_modern_ecosystem(entry: dict[str, Any]) -> str:
    purl = str(entry.get("packageURL") or entry.get("packageUrl") or entry.get("purl") or "").strip()
    match = re.match(r"pkg:([A-Za-z0-9.+-]+)/", purl)
    return match.group(1) if match else ""


def _explicit_fixed_versions(text: str) -> list[str]:
    """Extract release versions only from sentences that explicitly state a fix."""

    versions: list[str] = []
    sentences = re.split(r"(?<=[.!?。！？])\s+|[\r\n]+", str(text or ""))
    fix_markers = re.compile(
        r"(?:\bfixed\b|\bpatched\b|\bresolved\b|\baddressed\b|修复(?:版本)?|修补(?:版本)?|补丁版本)",
        flags=re.IGNORECASE,
    )
    version_pattern = re.compile(r"(?<![A-Za-z0-9_-])v?(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)(?![A-Za-z0-9_-])")
    for sentence in sentences:
        if re.search(
            r"(?:partial(?:ly)?|incomplete|not\s+fully|not\s+completely|attempted).{0,40}(?:fixed|patched)"
            r"|(?:fixed|patched).{0,40}(?:partial(?:ly)?|incomplete|not\s+fully|not\s+completely)",
            sentence,
            flags=re.IGNORECASE,
        ):
            continue
        marker = fix_markers.search(sentence)
        if not marker:
            continue
        tail = sentence[marker.start():]
        for value in version_pattern.findall(tail):
            if value not in versions:
                versions.append(value)
            if len(versions) >= 12:
                return versions
    return versions


def _concrete_version(value: str) -> str:
    clean = value.strip().lstrip("vV")
    if not clean or clean in {"*", "-", "0"} or any(token in clean for token in ("<", ">", "=", ",", " ")):
        return ""
    return clean if re.fullmatch(r"\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?", clean) else ""


def _prefixed_version(prefix: str, version: str) -> str:
    return f"{prefix} {version}".strip()


def _unique_text(values: Any) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text)
    return result


def _github_version_facts(item: dict[str, Any]) -> tuple[list[str], list[str]]:
    affected: list[str] = []
    fixed: list[str] = []
    for vulnerability in item.get("vulnerabilities") or []:
        package = vulnerability.get("package") or {}
        package_name = str(package.get("name") or "").strip()
        ecosystem = str(package.get("ecosystem") or "").strip()
        prefix = " / ".join(value for value in (ecosystem, package_name) if value)
        version_range = str(vulnerability.get("vulnerable_version_range") or "").strip()
        if version_range:
            label = f"{prefix}: {version_range}" if prefix else version_range
            if label not in affected:
                affected.append(label)
        first_patched = vulnerability.get("first_patched_version") or {}
        if isinstance(first_patched, dict):
            identifier = str(first_patched.get("identifier") or "").strip()
        else:
            identifier = str(first_patched).strip()
        if identifier:
            label = f"{prefix}: {identifier}" if prefix else identifier
            if label not in fixed:
                fixed.append(label)
    return affected[:12], fixed[:12]


def _github_cvss_score(item: dict[str, Any]) -> float | None:
    raw = (item.get("cvss") or {}).get("score")
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _tokens(text: str) -> list[str]:
    lowered = text.lower()
    tokens = re.findall(r"cve-\d{4}-\d{4,8}|ghsa-[a-z0-9-]+|cwe-\d+|[a-z0-9_.+-]{2,}", lowered)
    tokens.extend(re.findall(r"[\u4e00-\u9fff]{2,}", lowered))
    return tokens


def _nvd_year_windows(year: int | None) -> list[tuple[datetime, datetime]]:
    if not year:
        return []
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = datetime(year, 1, 1, tzinfo=timezone.utc)
    final = datetime(year + 1, 1, 1, tzinfo=timezone.utc) - timedelta(seconds=1)
    if year >= now.year:
        final = min(final, now)
    windows: list[tuple[datetime, datetime]] = []
    cursor = final
    while cursor >= start:
        window_start = max(start, cursor - timedelta(days=89, hours=23, minutes=59, seconds=59))
        windows.append((window_start, cursor))
        cursor = window_start - timedelta(seconds=1)
    return windows


def _nvd_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _record_year(record: dict[str, Any]) -> str:
    cve = re.match(r"CVE-(\d{4})-", str(record.get("id", "")), flags=re.IGNORECASE)
    if cve:
        return cve.group(1)
    for key in ("published_at", "updated_at"):
        value = str(record.get(key, ""))
        if re.match(r"\d{4}-", value):
            return value[:4]
    return ""


def _record_sort_key(record: dict[str, Any]) -> tuple[str, int]:
    timestamp = str(record.get("published_at") or record.get("updated_at") or "")
    return (timestamp, _severity_score(str(record.get("severity", ""))))


def _severity_score(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity.upper(), 0)


collector_service = CollectorService()

# Import after the adapters are defined so the graph can reuse them without a
# module import cycle.
from app.langgraph.collector_graph import CollectorGraph  # noqa: E402

collector_graph = CollectorGraph(collector_service)
