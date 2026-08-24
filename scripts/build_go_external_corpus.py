from __future__ import annotations

import argparse
import random
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from go_external_corpus import (
    GOSEC_COMMIT,
    GOSEC_REPOSITORY,
    SEMGREP_RULES_COMMIT,
    SEMGREP_RULES_REPOSITORY,
    ensure_checkout,
    extract_gosec_cases,
    extract_semgrep_cases,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a reproducible external Go security qualification corpus.")
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/secflow-go-labeled-corpus"))
    parser.add_argument("--seed", type=int, default=20260722)
    parser.add_argument("--positive", type=int, default=598)
    parser.add_argument("--negative", type=int, default=598)
    parser.add_argument("--gosec-source", type=Path)
    parser.add_argument("--semgrep-source", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "config" / "evaluation" / "go-external-random-598x2-2026-07-22.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sources = args.workspace / "sources"
    gosec_root = _source_checkout(args.gosec_source, GOSEC_REPOSITORY, GOSEC_COMMIT, sources / "gosec")
    semgrep_root = _source_checkout(
        args.semgrep_source,
        SEMGREP_RULES_REPOSITORY,
        SEMGREP_RULES_COMMIT,
        sources / "semgrep-rules",
    )
    pool = [*extract_gosec_cases(gosec_root), *extract_semgrep_cases(semgrep_root)]
    positives = sorted((case for case in pool if case["vulnerable"]), key=lambda case: case["id"])
    negatives = sorted((case for case in pool if not case["vulnerable"]), key=lambda case: case["id"])
    if len(positives) < args.positive or len(negatives) < args.negative:
        raise SystemExit(
            f"Insufficient unique cases: positive={len(positives)}, negative={len(negatives)}; "
            f"requested {args.positive}/{args.negative}"
        )

    randomizer = random.Random(args.seed)
    qualification_ids = {
        str(case["id"])
        for case in [
            *randomizer.sample(positives, args.positive),
            *randomizer.sample(negatives, args.negative),
        ]
    }
    cases: list[dict[str, Any]] = []
    for case in pool:
        cases.append({**case, "partition": "qualification" if case["id"] in qualification_ids else "diagnostic"})

    partition_counts: Counter[str] = Counter(
        f"{case['partition']}:{'positive' if case['vulnerable'] else 'negative'}"
        for case in cases
    )
    source_counts: Counter[str] = Counter(
        f"{case['partition']}:{case['source']}:{'positive' if case['vulnerable'] else 'negative'}"
        for case in cases
    )
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "methodology": {
            "seed": args.seed,
            "selection": "uniform random sample without replacement from unique external labeled cases",
            "qualification_positive": args.positive,
            "qualification_negative": args.negative,
            "deduplication": "gosec normalized multi-file SHA-256; semgrep unique source path and target line",
            "label_matching": "external rule CWE must intersect the AegisAl finding CWE",
            "leakage_policy": "diagnostic cases may guide tuning; qualification cases remain sealed until rules are frozen",
            "independence_note": "Cases are unique published labels from two independently maintained repositories; observations remain clustered by upstream suite and are not claimed to be IID real-world vulnerabilities.",
        },
        "sources": {
            "securego/gosec": {"url": GOSEC_REPOSITORY, "commit": GOSEC_COMMIT},
            "semgrep/semgrep-rules": {"url": SEMGREP_RULES_REPOSITORY, "commit": SEMGREP_RULES_COMMIT},
        },
        "pool": {
            "positive": len(positives),
            "negative": len(negatives),
            "partition_counts": dict(sorted(partition_counts.items())),
            "source_counts": dict(sorted(source_counts.items())),
        },
        "cases": sorted(cases, key=lambda case: (case["partition"], case["id"])),
    }
    write_json(args.output, manifest)
    print(f"Wrote {len(cases)} cases ({args.positive}+{args.negative} qualification) to {args.output}")
    return 0


def _source_checkout(explicit: Path | None, url: str, commit: str, destination: Path) -> Path:
    if explicit is None:
        return ensure_checkout(url, commit, destination)
    root = explicit.expanduser().resolve()
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or completed.stdout.strip() != commit:
        raise SystemExit(f"Source checkout must be pinned at {commit}: {root}")
    return root


if __name__ == "__main__":
    raise SystemExit(main())
