from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


KNOWN_LANGUAGES = {"java", "python", "go", "c", "cpp", "csharp", "rust", "solidity"}
CWE_RE = re.compile(r"^CWE-\d+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MIN_POSITIVE_CASES = 598
DEFAULT_MIN_NEGATIVE_CASES = 598


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a sealed SecFlow CWE-complete security truth manifest before it is "
            "eligible for formal qualification scoring."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--forbidden-manifest",
        type=Path,
        action="append",
        default=[],
        help="Previously observed development/high-star/adjudication manifest that must not overlap.",
    )
    parser.add_argument("--partition", default="qualification")
    parser.add_argument("--min-positive-cases", type=int, default=DEFAULT_MIN_POSITIVE_CASES)
    parser.add_argument("--min-negative-cases", type=int, default=DEFAULT_MIN_NEGATIVE_CASES)
    parser.add_argument("--max-failures", type=int, default=50, help="Maximum failure messages printed to stdout.")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    manifest = load_json_object(args.manifest)
    forbidden = [load_json_object(path) for path in args.forbidden_manifest]
    report = validate_manifest_report(
        manifest,
        manifest_path=args.manifest,
        forbidden_manifests=forbidden,
        forbidden_manifest_paths=args.forbidden_manifest,
        partition=args.partition,
        min_positive_cases=args.min_positive_cases,
        min_negative_cases=args.min_negative_cases,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    visible_failures = report["failures"][: max(0, args.max_failures)]
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "summary": report["summary"],
                "failure_count": len(report["failures"]),
                "failures": visible_failures,
                "truncated_failures": max(0, len(report["failures"]) - len(visible_failures)),
            },
            ensure_ascii=False,
        )
    )
    return 0 if report["passed"] else 1


def load_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def validate_manifest_report(
    manifest: dict[str, Any],
    *,
    manifest_path: Path | None = None,
    forbidden_manifests: list[dict[str, Any]] | None = None,
    forbidden_manifest_paths: list[Path] | None = None,
    partition: str = "qualification",
    min_positive_cases: int = DEFAULT_MIN_POSITIVE_CASES,
    min_negative_cases: int = DEFAULT_MIN_NEGATIVE_CASES,
) -> dict[str, Any]:
    forbidden_manifests = forbidden_manifests or []
    forbidden_manifest_paths = forbidden_manifest_paths or []
    failures = check_sealed_truth_manifest(
        manifest,
        forbidden_manifests=forbidden_manifests,
        partition=partition,
        min_positive_cases=min_positive_cases,
        min_negative_cases=min_negative_cases,
    )
    selected = selected_cases(manifest, partition)
    positive_cases = sum(1 for case in selected if case.get("vulnerable") is True)
    negative_cases = sum(1 for case in selected if case.get("vulnerable") is False)
    languages = sorted({str(case.get("language") or "").lower() for case in selected if case.get("language")})
    cwes = sorted({str(cwe) for case in selected for cwe in case.get("cwes") or []}, key=cwe_sort_key)
    return {
        "manifest": str(manifest_path.resolve()) if manifest_path else None,
        "manifest_sha256": sha256_file(manifest_path) if manifest_path else None,
        "forbidden_manifests": [
            {"path": str(path.resolve()), "sha256": sha256_file(path)}
            for path in forbidden_manifest_paths
        ],
        "partition": partition,
        "passed": not failures,
        "failure_count": len(failures),
        "failures": failures,
        "summary": {
            "cases": len(selected),
            "positive_cases": positive_cases,
            "negative_cases": negative_cases,
            "languages": languages,
            "cwes": cwes,
            "min_positive_cases": min_positive_cases,
            "min_negative_cases": min_negative_cases,
        },
    }


def check_sealed_truth_manifest(
    manifest: dict[str, Any],
    *,
    forbidden_manifests: list[dict[str, Any]] | None = None,
    partition: str = "qualification",
    min_positive_cases: int = DEFAULT_MIN_POSITIVE_CASES,
    min_negative_cases: int = DEFAULT_MIN_NEGATIVE_CASES,
) -> list[str]:
    failures: list[str] = []
    methodology = manifest.get("methodology") or {}
    if not isinstance(methodology, dict):
        failures.append("methodology must be a JSON object")
        methodology = {}
    cases = manifest.get("cases") or []
    if not isinstance(cases, list):
        failures.append("cases must be a JSON list")
        return failures

    selected = selected_cases(manifest, partition)
    if not selected:
        failures.append(f"manifest must contain cases for partition {partition!r}")

    if methodology.get("qualification_eligible") is not True:
        failures.append("methodology.qualification_eligible must be true for sealed qualification manifests")
    negative_scope = str(methodology.get("negative_label_scope") or "").casefold()
    if negative_scope != "cwe_complete":
        failures.append(f"methodology.negative_label_scope must be cwe_complete, got {negative_scope!r}")
    if methodology.get("cwe_complete_negative_labels") is not True:
        failures.append("methodology.cwe_complete_negative_labels must be true")
    if methodology.get("adjudication_applied") is True or "adjudications" in manifest or "adjudication" in manifest:
        failures.append("sealed qualification manifests must not include adjudication overlays")
    seal_status = str(methodology.get("seal_status") or "").casefold()
    if seal_status != "sealed":
        failures.append("methodology.seal_status must be sealed")
    leakage_policy = str(methodology.get("leakage_policy") or "").casefold()
    if "sealed" not in leakage_policy or "freeze" not in leakage_policy:
        failures.append("methodology.leakage_policy must state that labels stay sealed until rules are frozen")
    if "not available" in str(methodology.get("ground_truth") or "").casefold():
        failures.append("sealed truth manifest must not use an engineering-only no-ground-truth corpus")

    ids: set[str] = set()
    material_fingerprints: set[str] = set()
    positive_cases = 0
    negative_cases = 0
    for index, case in enumerate(selected):
        if not isinstance(case, dict):
            failures.append(f"case[{index}] must be a JSON object")
            continue
        case_id = str(case.get("id") or "").strip()
        if not case_id:
            failures.append(f"case[{index}] missing id")
        elif case_id in ids:
            failures.append(f"duplicate case id: {case_id}")
        else:
            ids.add(case_id)
        vulnerable = case.get("vulnerable")
        if vulnerable is True:
            positive_cases += 1
        elif vulnerable is False:
            negative_cases += 1
        else:
            failures.append(f"case {case_id or index} vulnerable must be boolean")

        language = str(case.get("language") or "").strip().lower()
        if language not in KNOWN_LANGUAGES:
            failures.append(f"case {case_id or index} language must be one of {sorted(KNOWN_LANGUAGES)}, got {language!r}")

        cwes = case.get("cwes") or []
        if not isinstance(cwes, list) or not cwes:
            failures.append(f"case {case_id or index} must include a non-empty cwes list")
        else:
            invalid_cwes = [str(cwe) for cwe in cwes if not CWE_RE.fullmatch(str(cwe))]
            if invalid_cwes:
                failures.append(f"case {case_id or index} has invalid CWE ids: {invalid_cwes[:5]}")

        label_scope = str(case.get("label_scope") or methodology.get("case_label_scope") or "").casefold()
        if label_scope != "cwe_complete":
            failures.append(f"case {case_id or index} label_scope must be cwe_complete")
        if not _bounded_text(case.get("label_evidence") or case.get("evidence"), 20_000):
            failures.append(f"case {case_id or index} must include label_evidence or evidence")

        hashes = case_hashes(case)
        if not hashes:
            failures.append(f"case {case_id or index} must include code_hash/content_sha256 or files[].sha256")
        invalid_hashes = [value for value in hashes if not SHA256_RE.fullmatch(value)]
        if invalid_hashes:
            failures.append(f"case {case_id or index} has invalid SHA-256 values: {invalid_hashes[:5]}")
        material = material_fingerprint(case)
        if material:
            if material in material_fingerprints:
                failures.append(f"duplicate source material fingerprint in partition {partition}: {case_id or index}")
            material_fingerprints.add(material)
        if not source_reference_present(case):
            failures.append(f"case {case_id or index} must include a source reference")

    if positive_cases < min_positive_cases:
        failures.append(f"qualification partition requires at least {min_positive_cases} positive cases, got {positive_cases}")
    if negative_cases < min_negative_cases:
        failures.append(f"qualification partition requires at least {min_negative_cases} negative cases, got {negative_cases}")

    forbidden_ids, forbidden_materials = forbidden_identity_sets(forbidden_manifests or [])
    overlapping_ids = sorted(ids & forbidden_ids)
    if overlapping_ids:
        failures.append(f"sealed manifest reuses forbidden case ids: {overlapping_ids[:10]}")
    overlapping_materials = sorted(material_fingerprints & forbidden_materials)
    if overlapping_materials:
        failures.append(f"sealed manifest reuses forbidden source material fingerprints: {overlapping_materials[:10]}")
    return failures


def selected_cases(manifest: dict[str, Any], partition: str) -> list[dict[str, Any]]:
    cases = manifest.get("cases") or []
    if not isinstance(cases, list):
        return []
    if any(isinstance(case, dict) and "partition" in case for case in cases):
        return [case for case in cases if isinstance(case, dict) and str(case.get("partition") or "") == partition]
    return [case for case in cases if isinstance(case, dict)]


def forbidden_identity_sets(manifests: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    ids: set[str] = set()
    materials: set[str] = set()
    for manifest in manifests:
        for case in manifest.get("cases") or []:
            if not isinstance(case, dict):
                continue
            case_id = str(case.get("id") or "").strip()
            if case_id:
                ids.add(case_id)
            material = material_fingerprint(case)
            if material:
                materials.add(material)
        for project in manifest.get("projects") or []:
            if not isinstance(project, dict):
                continue
            slug = str(project.get("slug") or "").strip()
            ref = str(project.get("ref") or project.get("commit") or "").strip()
            if slug and ref:
                materials.add(f"repo:{slug}@{ref}")
    return ids, materials


def material_fingerprint(case: dict[str, Any]) -> str:
    hashes = case_hashes(case)
    if hashes:
        return "sha256:" + ",".join(sorted(hashes))
    slug = str(case.get("slug") or case.get("repository") or "").strip()
    ref = str(case.get("ref") or case.get("commit") or "").strip()
    path = str(case.get("source_path") or case.get("file") or "").strip()
    line = str(case.get("line") or "").strip()
    if slug and ref:
        return f"repo:{slug}@{ref}:{path}:{line}"
    return ""


def case_hashes(case: dict[str, Any]) -> list[str]:
    hashes = []
    for key in ("code_hash", "content_sha256", "source_sha256"):
        value = str(case.get(key) or "").strip().lower()
        if value:
            hashes.append(value)
    for file_item in case.get("files") or []:
        if not isinstance(file_item, dict):
            continue
        value = str(file_item.get("sha256") or file_item.get("content_sha256") or "").strip().lower()
        if value:
            hashes.append(value)
    return list(dict.fromkeys(hashes))


def source_reference_present(case: dict[str, Any]) -> bool:
    if case.get("source_path") or case.get("file") or case.get("url") or case.get("repository") or case.get("slug"):
        return True
    files = case.get("files") or []
    return any(isinstance(file_item, dict) and (file_item.get("path") or file_item.get("source_path")) for file_item in files)


def cwe_sort_key(value: str) -> tuple[int, str]:
    match = re.search(r"\d+", value)
    return (int(match.group(0)) if match else 999999, value)


def sha256_file(path: Path | None) -> str | None:
    if path is None:
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bounded_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


if __name__ == "__main__":
    raise SystemExit(main())
