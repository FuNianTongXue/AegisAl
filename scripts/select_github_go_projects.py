from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SEARCH_ENDPOINT = "https://api.github.com/search/repositories"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select a reproducible random sample of high-star Go repositories.")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--pool-size", type=int, default=300)
    parser.add_argument("--min-stars", type=int, default=1000)
    parser.add_argument("--max-size-kb", type=int, default=500000)
    parser.add_argument("--seed", type=int, default=20260721)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "config" / "evaluation" / "github-go-high-star-random-100-2026-07-21.json",
    )
    return parser.parse_args()


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AegisAl-Go-OWASP-Evaluation",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_candidate_pool(pool_size: int, min_stars: int, max_size_kb: int) -> list[dict[str, Any]]:
    if not 1 <= pool_size <= 1000:
        raise ValueError("--pool-size must be between 1 and 1000")
    candidates: list[dict[str, Any]] = []
    pages = (pool_size + 99) // 100
    query_text = f"language:Go stars:>={min_stars} archived:false fork:false size:<{max_size_kb}"
    for page in range(1, pages + 1):
        query = urllib.parse.urlencode(
            {
                "q": query_text,
                "sort": "stars",
                "order": "desc",
                "per_page": min(100, pool_size - len(candidates)),
                "page": page,
            }
        )
        request = urllib.request.Request(f"{SEARCH_ENDPOINT}?{query}", headers=github_headers())
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = json.load(response)
        for item in payload.get("items") or []:
            if (
                str(item.get("language") or "").lower() == "go"
                and not item.get("archived")
                and not item.get("fork")
                and int(item.get("stargazers_count") or 0) >= min_stars
                and int(item.get("size") or 0) < max_size_kb
            ):
                candidates.append(item)
        if len(candidates) >= pool_size:
            break
    unique = {str(item.get("full_name") or ""): item for item in candidates if item.get("full_name")}
    return list(unique.values())[:pool_size]


def git_command(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "http.proxy=", "-c", "https.proxy=", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def resolve_head(url: str) -> str:
    completed = git_command("ls-remote", "--exit-code", url, "HEAD")
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
            "size_kb": int(item.get("size") or 0),
            "default_branch": str(item.get("default_branch") or ""),
        }
        for item in items
    ]


def main() -> int:
    args = parse_args()
    if args.limit < 1 or args.limit > args.pool_size:
        raise SystemExit("--limit must be between 1 and --pool-size")
    candidates = fetch_candidate_pool(args.pool_size, args.min_stars, args.max_size_kb)
    if len(candidates) < args.limit:
        raise SystemExit(f"GitHub returned only {len(candidates)} eligible repositories; need {args.limit}")
    randomizer = random.Random(args.seed)
    selected = randomizer.sample(candidates, args.limit)
    projects = pin_repositories(selected, args.workers)
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "methodology": {
            "query": f"language:Go stars:>={args.min_stars} archived:false fork:false size:<{args.max_size_kb}",
            "candidate_pool_size": len(candidates),
            "sample_size": len(projects),
            "seed": args.seed,
            "selection": "uniform random sample without replacement from GitHub star-sorted candidate pool",
            "commit_policy": "HEAD resolved and pinned at selection time",
        },
        "projects": projects,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(projects)} pinned repositories to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
