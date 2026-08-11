from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from go_external_corpus import GOSEC_COMMIT, extract_gosec_cases, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate a pinned Go corpus manifest after a materialization-only extractor fix."
    )
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--gosec-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.source_manifest.read_text(encoding="utf-8"))
    gosec_root = args.gosec_source.expanduser().resolve()
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=gosec_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or completed.stdout.strip() != GOSEC_COMMIT:
        raise SystemExit(f"Source checkout must be pinned at {GOSEC_COMMIT}: {gosec_root}")

    extracted = {str(case["id"]): case for case in extract_gosec_cases(gosec_root)}
    changed_ids: list[str] = []
    migrated_cases: list[dict[str, Any]] = []
    immutable_fields = ("source", "source_path", "external_rules", "cwes", "vulnerable")
    for existing in manifest.get("cases") or []:
        if existing.get("source") != "securego/gosec":
            migrated_cases.append(existing)
            continue
        case_id = str(existing["id"])
        current = extracted.get(case_id)
        if current is None:
            raise SystemExit(f"Pinned gosec case disappeared after extraction: {case_id}")
        for field in immutable_fields:
            if existing.get(field) != current.get(field):
                raise SystemExit(f"Pinned label changed for {case_id}: {field}")
        migrated = {
            **existing,
            "code_hash": current["code_hash"],
            "file_count": current["file_count"],
        }
        if (
            migrated["code_hash"] != existing.get("code_hash")
            or migrated["file_count"] != existing.get("file_count")
        ):
            changed_ids.append(case_id)
        migrated_cases.append(migrated)

    methodology = dict(manifest.get("methodology") or {})
    methodology["gosec_materialization"] = (
        "Each top-level []string element is one file; constant raw/interpreted string "
        "concatenations are evaluated without executing Go code."
    )
    migrated_manifest = {
        **manifest,
        "generated_at": datetime.now(UTC).isoformat(),
        "methodology": methodology,
        "migration": {
            "source_manifest": args.source_manifest.name,
            "revision": "go-string-expression-v2",
            "selection_ids_preserved": True,
            "changed_gosec_cases": len(changed_ids),
            "changed_case_ids": changed_ids,
        },
        "cases": migrated_cases,
    }
    write_json(args.output, migrated_manifest)
    print(f"Migrated {len(changed_ids)} gosec cases without changing sample IDs or labels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
