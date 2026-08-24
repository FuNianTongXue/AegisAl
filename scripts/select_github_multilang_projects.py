from __future__ import annotations

import argparse
import json
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SEARCH_ENDPOINT = "https://api.github.com/search/repositories"


@dataclass(frozen=True)
class LanguageSample:
    github_language: str
    quota: int
    min_stars: int


DEFAULT_SAMPLES = (
    LanguageSample("Java", 65, 1_000),
    LanguageSample("Python", 65, 1_000),
    LanguageSample("Go", 65, 1_000),
    LanguageSample("C", 60, 1_000),
    LanguageSample("C++", 65, 1_000),
    LanguageSample("C#", 60, 500),
    LanguageSample("Rust", 60, 1_000),
    LanguageSample("Solidity", 60, 100),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select a reproducible, language-stratified sample of high-star GitHub repositories."
    )
    parser.add_argument("--seed", type=int, default=20260723)
    parser.add_argument("--pool-multiplier", type=int, default=3)
    parser.add_argument("--max-size-kb", type=int, default=500_000)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "config" / "evaluation" / "github-multilang-high-star-random-500-2026-07-23.json",
    )
    return parser.parse_args()


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AegisAl-Multilang-500-Evaluation",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_candidate_pool(
    sample: LanguageSample,
    *,
    pool_multiplier: int,
    max_size_kb: int,
) -> tuple[list[dict[str, Any]], str]:
    pool_size = min(1_000, max(sample.quota, sample.quota * pool_multiplier))
    candidates: list[dict[str, Any]] = []
    query_text = (
        f"language:{sample.github_language} stars:>={sample.min_stars} "
        f"archived:false fork:false size:<{max_size_kb}"
    )
    pages = (pool_size + 99) // 100
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
                str(item.get("language") or "").casefold() == sample.github_language.casefold()
                and not item.get("archived")
                and not item.get("fork")
                and int(item.get("stargazers_count") or 0) >= sample.min_stars
                and int(item.get("size") or 0) < max_size_kb
            ):
                candidates.append(item)
        if len(candidates) >= pool_size:
            break
    unique = {str(item.get("full_name") or ""): item for item in candidates if item.get("full_name")}
    return list(unique.values())[:pool_size], query_text


def resolve_head(slug: str, default_branch: str) -> str:
    encoded_slug = urllib.parse.quote(slug, safe="/")
    encoded_branch = urllib.parse.quote(default_branch or "HEAD", safe="")
    url = f"https://api.github.com/repos/{encoded_slug}/commits/{encoded_branch}"
    payload: dict[str, Any] | None = None
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers=github_headers())
            with urllib.request.urlopen(request, timeout=90) as response:
                payload = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in {403, 429, 500, 502, 503, 504} or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))
        except urllib.error.URLError:
            if attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))
    commit = str((payload or {}).get("sha") or "").strip().lower()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RuntimeError(f"Invalid default-branch commit returned for {slug}: {commit}")
    return commit


def pin_repositories(items: list[dict[str, Any]], workers: int) -> list[dict[str, Any]]:
    commits: dict[str, str] = {}
    failures: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 24))) as executor:
        futures = {
            executor.submit(
                resolve_head,
                str(item["full_name"]),
                str(item.get("default_branch") or "HEAD"),
            ): str(item["full_name"])
            for item in items
        }
        for future in as_completed(futures):
            slug = futures[future]
            try:
                commits[slug] = future.result()
            except Exception as exc:  # noqa: BLE001 - preserve every pin failure in one report
                failures[slug] = str(exc)
            completed = len(commits) + len(failures)
            if completed % 25 == 0 or completed == len(items):
                print(f"Pinned {completed}/{len(items)} repositories", flush=True)
    if failures:
        detail = "; ".join(f"{slug}: {message}" for slug, message in sorted(failures.items())[:5])
        raise RuntimeError(f"Failed to pin {len(failures)} repositories: {detail}")
    return [
        {
            "slug": str(item["full_name"]),
            "url": str(item["clone_url"]),
            "ref": commits[str(item["full_name"])],
            "language": str(item.get("language") or ""),
            "stars": int(item.get("stargazers_count") or 0),
            "size_kb": int(item.get("size") or 0),
            "default_branch": str(item.get("default_branch") or ""),
            "license": str((item.get("license") or {}).get("spdx_id") or "NOASSERTION"),
        }
        for item in items
    ]


def main() -> int:
    args = parse_args()
    if args.pool_multiplier < 1:
        raise SystemExit("--pool-multiplier must be at least 1")
    expected_total = sum(sample.quota for sample in DEFAULT_SAMPLES)
    if expected_total != 500:
        raise SystemExit(f"Default language quotas must total 500, got {expected_total}")

    selected: list[dict[str, Any]] = []
    strata: list[dict[str, Any]] = []
    for index, sample in enumerate(DEFAULT_SAMPLES):
        candidates, query = fetch_candidate_pool(
            sample,
            pool_multiplier=args.pool_multiplier,
            max_size_kb=args.max_size_kb,
        )
        if len(candidates) < sample.quota:
            raise SystemExit(
                f"GitHub returned only {len(candidates)} eligible {sample.github_language} repositories; "
                f"need {sample.quota}"
            )
        randomizer = random.Random(args.seed + index)
        language_selection = randomizer.sample(candidates, sample.quota)
        selected.extend(language_selection)
        strata.append(
            {
                "language": sample.github_language,
                "query": query,
                "candidate_pool_size": len(candidates),
                "sample_size": sample.quota,
                "min_stars": sample.min_stars,
                "seed": args.seed + index,
            }
        )
        print(
            f"Selected {sample.quota} {sample.github_language} repositories "
            f"from {len(candidates)} candidates",
            flush=True,
        )

    slugs = [str(item.get("full_name") or "") for item in selected]
    if len(set(slugs)) != len(slugs):
        raise SystemExit("Language strata produced duplicate repositories")
    projects = pin_repositories(selected, args.workers)
    projects.sort(key=lambda item: (item["language"].casefold(), item["slug"].casefold()))
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "methodology": {
            "sample_size": len(projects),
            "seed": args.seed,
            "selection": "language-stratified uniform random sample without replacement from GitHub star-sorted pools",
            "commit_policy": "HEAD resolved and pinned at selection time",
            "archived": False,
            "forks": False,
            "max_size_kb": args.max_size_kb,
            "ground_truth": "not available for ordinary high-star repositories",
            "metric_policy": (
                "This corpus measures scan completion, parser stability, finding density, and review yield. "
                "It must not be used to claim precision, recall, FPR, or FNR."
            ),
            "strata": strata,
        },
        "projects": projects,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(projects)} pinned repositories to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
