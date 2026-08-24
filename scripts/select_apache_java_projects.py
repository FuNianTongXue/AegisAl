from __future__ import annotations

import argparse
import json
import os
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SEARCH_ENDPOINT = "https://api.github.com/search/repositories"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select and pin high-star Apache Java repositories.")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "config/evaluation/apache-high-star-java-100.json",
    )
    parser.add_argument("--workers", type=int, default=8)
    return parser.parse_args()


def fetch_repositories(limit: int) -> list[dict[str, Any]]:
    if limit < 1 or limit > 100:
        raise ValueError("GitHub search selection supports between 1 and 100 repositories per run.")
    query = urllib.parse.urlencode(
        {
            "q": "org:apache language:Java archived:false fork:false",
            "sort": "stars",
            "order": "desc",
            "per_page": limit,
            "page": 1,
        }
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AegisAl-Java-Evaluation",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"{SEARCH_ENDPOINT}?{query}", headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.load(response)
    items = payload.get("items") or []
    selected = [
        item
        for item in items
        if str(item.get("full_name") or "").lower().startswith("apache/")
        and str(item.get("language") or "").lower() == "java"
        and not item.get("archived")
        and not item.get("fork")
    ]
    if len(selected) != limit:
        raise RuntimeError(f"GitHub returned {len(selected)} eligible repositories; expected {limit}.")
    return selected


def resolve_head(url: str) -> str:
    completed = subprocess.run(
        ["git", "ls-remote", "--exit-code", url, "HEAD"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError((completed.stderr or completed.stdout or f"Unable to resolve {url}").strip())
    commit = completed.stdout.split()[0].strip().lower()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RuntimeError(f"Invalid HEAD commit returned for {url}: {commit}")
    return commit


def pin_repositories(items: list[dict[str, Any]], workers: int) -> list[dict[str, Any]]:
    commits: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as executor:
        futures = {
            executor.submit(resolve_head, str(item["clone_url"])): str(item["full_name"])
            for item in items
        }
        for future in as_completed(futures):
            slug = futures[future]
            commits[slug] = future.result()
            print(f"Pinned {len(commits)}/{len(items)}: {slug}", flush=True)

    return [
        {
            "slug": str(item["full_name"]),
            "url": str(item["clone_url"]),
            "ref": commits[str(item["full_name"])],
            "stars": int(item.get("stargazers_count") or 0),
            "default_branch": str(item.get("default_branch") or ""),
        }
        for item in items
    ]


def main() -> int:
    args = parse_args()
    selected = fetch_repositories(args.limit)
    manifest = pin_repositories(selected, args.workers)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(manifest)} pinned repositories to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
