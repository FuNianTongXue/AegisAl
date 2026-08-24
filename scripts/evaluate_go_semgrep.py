from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the offline AegisAl Go OWASP baseline on pinned repositories.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "config" / "evaluation" / "github-go-high-star-random-100-2026-07-21.json",
    )
    parser.add_argument("--rules", type=Path, default=ROOT / "config" / "semgrep")
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/secflow-go-owasp-evaluation"))
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "github-go-high-star-100-owasp-results.json")
    parser.add_argument("--semgrep", default=os.getenv("SECFLOW_SEMGREP_BIN", str(Path(sys_executable()).with_name("semgrep"))))
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--scan-timeout", type=int, default=900)
    parser.add_argument("--jobs", type=int, default=max(1, min(6, (os.cpu_count() or 4) - 1)))
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def sys_executable() -> str:
    import sys

    return sys.executable


def run(command: list[str], *, cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, env=env)


def git(*args: str, cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return run(["git", "-c", "http.proxy=", "-c", "https.proxy=", *args], cwd=cwd, timeout=timeout)


def ensure_checkout(spec: dict[str, Any], repositories: Path) -> tuple[Path, str]:
    slug = str(spec["slug"])
    target = repositories / slug.replace("/", "__")
    ref = str(spec.get("ref") or "").strip()
    created = False
    if not (target / ".git").is_dir():
        target.parent.mkdir(parents=True, exist_ok=True)
        cloned = git("clone", "--filter=blob:none", "--no-checkout", "--depth", "1", str(spec["url"]), str(target), timeout=900)
        if cloned.returncode != 0:
            raise RuntimeError((cloned.stderr or cloned.stdout).strip())
        created = True
        sparse = git("sparse-checkout", "set", "--no-cone", "*.go", "go.mod", "go.sum", cwd=target)
        if sparse.returncode != 0:
            raise RuntimeError((sparse.stderr or sparse.stdout).strip())
    current = git("rev-parse", "HEAD", cwd=target)
    if not created and (current.returncode != 0 or (ref and current.stdout.strip() != ref)):
        fetched = git("fetch", "--depth", "1", "origin", ref or "HEAD", cwd=target, timeout=900)
        if fetched.returncode != 0:
            raise RuntimeError((fetched.stderr or fetched.stdout).strip())
        checked = git("checkout", "--detach", "FETCH_HEAD", cwd=target, timeout=900)
        if checked.returncode != 0:
            raise RuntimeError((checked.stderr or checked.stdout).strip())
    if created or not any(target.rglob("*.go")):
        reapplied = git("sparse-checkout", "reapply", cwd=target)
        if reapplied.returncode != 0:
            raise RuntimeError((reapplied.stderr or reapplied.stdout).strip())
        checked = git("checkout", "--force", "--detach", ref or "HEAD", cwd=target, timeout=900)
        if checked.returncode != 0:
            raise RuntimeError((checked.stderr or checked.stdout).strip())
    commit = git("rev-parse", "HEAD", cwd=target)
    if commit.returncode != 0:
        raise RuntimeError((commit.stderr or commit.stdout).strip())
    return target, commit.stdout.strip()


def source_counts(root: Path) -> dict[str, int]:
    go_files = sum(1 for path in root.rglob("*.go") if path.is_file() and "/vendor/" not in path.as_posix())
    modules = sum(1 for path in root.rglob("go.mod") if path.is_file())
    return {"go": go_files, "go_mod": modules}


def normalized_rule_id(value: str) -> str:
    marker = "secflow."
    return marker + value.split(marker, 1)[1] if marker in value else value


def scan_project(
    semgrep: str,
    rules: Path,
    root: Path,
    result_path: Path,
    *,
    jobs: int,
    scan_timeout: int,
) -> dict[str, Any]:
    result_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        semgrep,
        "scan",
        "--config",
        str(rules.resolve()),
        "--json-output",
        str(result_path.resolve()),
        "--dataflow-traces",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--project-root",
        str(root.resolve()),
        "--jobs",
        str(jobs),
        "--timeout",
        "15",
        "--timeout-threshold",
        "3",
        "--max-target-bytes",
        "3000000",
        "--exclude",
        "**/vendor/**",
        "--exclude",
        "**/testdata/**",
        "--exclude",
        "**/*_test.go",
        "--exclude",
        "**/*_fuzz.go",
        "--exclude",
        "**/*fuzz*/**",
        "--exclude",
        "**/*playground*/**",
        str(root.resolve()),
    ]
    started = time.monotonic()
    try:
        completed = run(command, cwd=root, timeout=scan_timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "elapsed_seconds": round(time.monotonic() - started, 2)}
    elapsed = round(time.monotonic() - started, 2)
    if not result_path.is_file():
        return {
            "status": "failed",
            "elapsed_seconds": elapsed,
            "returncode": completed.returncode,
            "error": "\n".join((completed.stderr or completed.stdout).splitlines()[-8:]),
        }
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    results = payload.get("results") or []
    rule_counts: Counter[str] = Counter()
    owasp_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    review_sample: list[dict[str, Any]] = []
    unique_locations: set[tuple[str, str, int]] = set()
    for item in results:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule = normalized_rule_id(str(item.get("check_id") or ""))
        path = str(item.get("path") or "")
        line = int((item.get("start") or {}).get("line") or 0)
        source_lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if Path(path).is_file() else []
        context = "\n".join(source_lines[max(0, line - 3) : min(len(source_lines), line + 1)])
        if "#nosec" in context.lower() or "nolint:gosec" in context.lower():
            continue
        location_key = (rule, path, line)
        if location_key in unique_locations:
            continue
        unique_locations.add(location_key)
        rule_counts[rule] += 1
        severity_counts[str(extra.get("severity") or "UNKNOWN")] += 1
        confidence = str(metadata.get("confidence") or "UNKNOWN").upper()
        confidence_counts[confidence] += 1
        for value in metadata.get("owasp") or []:
            owasp_counts[str(value)] += 1
        for value in metadata.get("cwe") or []:
            cwe_counts[str(value).split(":", 1)[0]] += 1
        if len(review_sample) < 20:
            review_sample.append(
                {
                    "rule": rule,
                    "path": path,
                    "line": line,
                    "message": str(extra.get("message") or ""),
                    "confidence": str(metadata.get("confidence") or ""),
                }
            )
    return {
        "status": "completed" if completed.returncode == 0 else "warning",
        "elapsed_seconds": elapsed,
        "returncode": completed.returncode,
        "findings": sum(rule_counts.values()),
        "unique_findings": len(unique_locations),
        "scanned_targets": len((payload.get("paths") or {}).get("scanned") or []),
        "rule_counts": dict(rule_counts.most_common()),
        "owasp_counts": dict(owasp_counts.most_common()),
        "cwe_counts": dict(cwe_counts.most_common()),
        "severity_counts": dict(severity_counts.most_common()),
        "confidence_counts": dict(confidence_counts.most_common()),
        "errors": len(payload.get("errors") or []),
        "review_sample": review_sample,
    }


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    specs = manifest.get("projects") if isinstance(manifest, dict) else manifest
    specs = list(specs or [])
    if args.limit > 0:
        specs = specs[: args.limit]
    repositories = args.workspace / "repositories"
    raw_results = args.workspace / "results"
    previous_by_slug: dict[str, dict[str, Any]] = {}
    if args.resume and args.output.is_file():
        previous = json.loads(args.output.read_text(encoding="utf-8"))
        previous_by_slug = {str(item.get("slug") or ""): item for item in previous.get("projects") or []}
    version = run([args.semgrep, "--version"])
    if version.returncode != 0:
        raise SystemExit(version.stderr or "Semgrep is not available")
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "semgrep_version": version.stdout.strip(),
        "rules": str(args.rules.resolve()),
        "selection_methodology": manifest.get("methodology", {}) if isinstance(manifest, dict) else {},
        "evaluation_policy": {
            "baseline": "OWASP-mapped Go source-code baseline",
            "covered_owasp_categories": ["A01:2021", "A02:2021", "A03:2021", "A05:2021", "A07:2021", "A10:2021"],
            "category_coverage": "6/10",
            "out_of_scope_categories": ["A04:2021", "A06:2021", "A08:2021", "A09:2021"],
            "scope_note": "Uncovered categories require architecture, configuration, dependency/SCA, identity, integrity, or runtime logging evidence and are not inferred from this Semgrep-only run.",
            "metrics": "off",
            "network_rules": False,
            "ground_truth": "not available for ordinary high-star repositories",
            "accuracy_statement": "precision, false-positive rate, and false-negative rate are not computable from this corpus",
        },
        "projects": [],
    }
    for index, spec in enumerate(specs, start=1):
        slug = str(spec["slug"])
        print(f"[{index}/{len(specs)}] {slug}", flush=True)
        previous = previous_by_slug.get(slug)
        result_path = raw_results / f"{slug.replace('/', '__')}.json"
        if args.resume and previous and previous.get("status") in {"completed", "warning"} and previous.get("commit") == spec.get("ref"):
            report["projects"].append(previous)
            print("  reused completed result", flush=True)
            continue
        item: dict[str, Any] = {"slug": slug, "url": spec["url"], "stars": int(spec.get("stars") or 0)}
        try:
            checkout, commit = ensure_checkout(spec, repositories)
            item["commit"] = commit
            item["source_files"] = source_counts(checkout)
            item.update(scan_project(args.semgrep, args.rules, checkout, result_path, jobs=args.jobs, scan_timeout=args.scan_timeout))
        except Exception as exc:  # noqa: BLE001
            item.update({"status": "failed", "error": str(exc)})
        report["projects"].append(item)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    completed = [item for item in report["projects"] if item.get("status") in {"completed", "warning"}]
    aggregate_rules: Counter[str] = Counter()
    aggregate_owasp: Counter[str] = Counter()
    aggregate_confidence: Counter[str] = Counter()
    for item in completed:
        aggregate_rules.update(item.get("rule_counts") or {})
        aggregate_owasp.update(item.get("owasp_counts") or {})
        aggregate_confidence.update(item.get("confidence_counts") or {})
    report["summary"] = {
        "requested_projects": len(specs),
        "completed_projects": len(completed),
        "completion_rate": round(len(completed) / len(specs), 6) if specs else 0.0,
        "total_go_files": sum(int((item.get("source_files") or {}).get("go") or 0) for item in completed),
        "total_scanned_targets": sum(int(item.get("scanned_targets") or 0) for item in completed),
        "total_unique_findings": sum(int(item.get("unique_findings") or 0) for item in completed),
        "total_errors": sum(int(item.get("errors") or 0) for item in completed),
        "parser_error_rate": round(
            sum(int(item.get("errors") or 0) for item in completed)
            / max(1, sum(int(item.get("scanned_targets") or 0) for item in completed)),
            6,
        ),
        "total_elapsed_seconds": round(sum(float(item.get("elapsed_seconds") or 0) for item in completed), 2),
        "rule_counts": dict(aggregate_rules.most_common()),
        "owasp_counts": dict(aggregate_owasp.most_common()),
        "confidence_counts": dict(aggregate_confidence.most_common()),
        "high_confidence_unique_findings": int(aggregate_confidence.get("HIGH", 0)),
        "accuracy": None,
        "false_positive_rate": None,
        "false_negative_rate": None,
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if len(completed) == len(specs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
