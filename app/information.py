from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import mimetypes
import os
import re
import socket
import ssl
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from threading import BoundedSemaphore, Lock, RLock
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree

import httpx
import truststore

from app.storage import DATA_DIR, now_iso, store


@dataclass(frozen=True)
class InformationSourceDefinition:
    id: str
    name: str
    kind: str
    url: str
    default_category: str
    website: str
    region: str
    source_image_url: str
    image_hosts: tuple[str, ...] = ()
    filter_security: bool = False
    group: str = "精选来源"
    catalog: str = "curated"
    default_enabled: bool = True
    refresh_interval_seconds: int = 900
    max_response_bytes: int = 4_000_000


@dataclass(frozen=True)
class InformationFetchResult:
    items: list[dict[str, Any]]
    etag: str = ""
    last_modified: str = ""
    not_modified: bool = False


@dataclass(frozen=True)
class OfficialSourceBrand:
    logo_url: str
    image_hosts: tuple[str, ...] = ()


INFORMATION_RESOURCE_DIR = Path(__file__).resolve().parent / "resources"
BUNDLED_OPML_PATH = INFORMATION_RESOURCE_DIR / "Chinese-Security-RSS.opml"
WECHAT_RSS_HOST = "wechat2rss.xlab.app"
WECHAT_IMAGE_HOSTS = ("mmbiz.qpic.cn", "mmbiz.qlogo.cn", "wx.qlogo.cn", "qpic.cn")
MAX_OPML_SOURCES = 1_000
MAX_ENABLED_OPML_SOURCES = 50
INFORMATION_FEED_PARSER_VERSION = 3
INFORMATION_RESPONSE_LANGUAGES = ("zh-Hans", "zh-Hant", "en")
INFORMATION_REFRESH_WORKERS = 12
INFORMATION_SOURCE_LOGO_RETRY_SECONDS = 3_600
OFFICIAL_SOURCE_BRANDS = {
    "tech.meituan.com": OfficialSourceBrand(
        logo_url="https://p0.meituan.net/meituantechblog/00c62e57b4c4a1f40b47d7152b3e54b511963.png",
        image_hosts=("meituan.net",),
    ),
    "www.huawei.com": OfficialSourceBrand(
        logo_url="https://cdn.simpleicons.org/huawei/E60012",
        image_hosts=("simpleicons.org",),
    ),
    "www.seebug.org": OfficialSourceBrand(
        logo_url="https://www.knownsec.com/static/favicon.ico",
        image_hosts=("knownsec.com",),
    ),
}


CURATED_INFORMATION_SOURCES = (
    InformationSourceDefinition(
        id="cisa_advisories",
        name="CISA 官方安全公告",
        kind="rss",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        default_category="漏洞披露",
        website="https://www.cisa.gov/news-events/cybersecurity-advisories",
        region="国际",
        source_image_url="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/favicon.png",
    ),
    InformationSourceDefinition(
        id="cisa_kev",
        name="CISA 已知在野利用目录",
        kind="kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        default_category="漏洞披露",
        website="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        region="国际",
        source_image_url="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/favicon.png",
    ),
    InformationSourceDefinition(
        id="freebuf",
        name="FreeBuf",
        kind="rss",
        url="https://www.freebuf.com/feed",
        default_category="行业动态",
        website="https://www.freebuf.com/",
        region="国内",
        source_image_url="https://www.freebuf.com/images/logo_b.png",
        image_hosts=("image.3001.net",),
    ),
    InformationSourceDefinition(
        id="aliyun_xz",
        name="阿里云先知社区",
        kind="rss",
        url="https://xz.aliyun.com/feed",
        default_category="攻击技术",
        website="https://xz.aliyun.com/",
        region="国内",
        source_image_url="https://xz.aliyun.com/favicon.ico",
        image_hosts=("alicdn.com",),
    ),
    InformationSourceDefinition(
        id="tencent_security",
        name="腾讯安全应急响应中心",
        kind="rss",
        url="https://security.tencent.com/index.php/feed/blog/0",
        default_category="行业动态",
        website="https://security.tencent.com/",
        region="国内",
        source_image_url="https://security.tencent.com/static/v2.0/images/favicon.ico",
        image_hosts=("qpic.cn",),
    ),
    InformationSourceDefinition(
        id="tencent_xlab",
        name="腾讯玄武实验室",
        kind="rss",
        url="https://xlab.tencent.com/cn/feed/",
        default_category="攻击技术",
        website="https://xlab.tencent.com/cn/",
        region="国内",
        source_image_url="https://xlab.tencent.com/cn/favicon.png?v=1.1",
        image_hosts=("qpic.cn",),
    ),
    InformationSourceDefinition(
        id="microsoft_security",
        name="Microsoft Security Blog",
        kind="rss",
        url="https://www.microsoft.com/en-us/security/blog/feed/",
        default_category="行业动态",
        website="https://www.microsoft.com/en-us/security/blog/",
        region="国际",
        source_image_url="https://www.microsoft.com/favicon.ico",
        image_hosts=("microsoft.com",),
    ),
    InformationSourceDefinition(
        id="talos",
        name="Cisco Talos Intelligence",
        kind="rss",
        url="https://blog.talosintelligence.com/rss/",
        default_category="攻击技术",
        website="https://blog.talosintelligence.com/",
        region="国际",
        source_image_url="https://blog.talosintelligence.com/favicon.ico",
        image_hosts=("storage.ghost.io",),
    ),
    InformationSourceDefinition(
        id="portswigger_research",
        name="PortSwigger Research",
        kind="rss",
        url="https://portswigger.net/research/rss",
        default_category="攻击技术",
        website="https://portswigger.net/research",
        region="国际",
        source_image_url="https://portswigger.net/content/images/logos/apple-touch-icon.png",
    ),
    InformationSourceDefinition(
        id="sans_isc",
        name="SANS Internet Storm Center",
        kind="rss",
        url="https://isc.sans.edu/rssfeed.xml",
        default_category="攻击技术",
        website="https://isc.sans.edu/",
        region="国际",
        source_image_url="https://isc.sans.edu/favicon-32x32.png",
    ),
)


def _catalog_url_key(value: str) -> str:
    clean = html.unescape(value).strip()
    parts = urlsplit(clean)
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        return ""
    query = [
        (key, item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
        if not key.casefold().startswith("utm_")
        and key.casefold() not in {"fbclid", "gclid", "mc_cid", "mc_eid"}
    ]
    return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(), parts.path, urlencode(query), ""))


def load_bundled_opml_sources(path: Path = BUNDLED_OPML_PATH) -> tuple[InformationSourceDefinition, ...]:
    try:
        payload = path.read_bytes()
    except OSError:
        return ()
    if not payload or len(payload) > 1_000_000:
        return ()
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return ()

    existing_urls = {_catalog_url_key(source.url) for source in CURATED_INFORMATION_SOURCES}
    seen_urls = {url for url in existing_urls if url}
    sources: list[InformationSourceDefinition] = []
    for node in root.iter():
        if str(node.tag).rsplit("}", 1)[-1].split(":")[-1] != "outline" or not node.attrib.get("xmlUrl"):
            continue
        if len(sources) >= MAX_OPML_SOURCES:
            break
        url = _catalog_url_key(str(node.attrib.get("xmlUrl") or ""))
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        title = re.sub(
            r"\s+",
            " ",
            html.unescape(str(node.attrib.get("title") or node.attrib.get("text") or "RSS 来源")),
        ).strip()[:120] or "RSS 来源"
        website_candidate = html.unescape(str(node.attrib.get("htmlUrl") or "")).strip()
        website = website_candidate if website_candidate.startswith(("http://", "https://")) else url
        host = (urlsplit(url).hostname or "").casefold()
        is_wechat = host == WECHAT_RSS_HOST
        website_host = (urlsplit(website).hostname or "").casefold()
        official_brand = OFFICIAL_SOURCE_BRANDS.get(website_host)
        source_image_url = (
            official_brand.logo_url
            if official_brand is not None
            else next(
                (
                    curated.source_image_url
                    for curated in CURATED_INFORMATION_SOURCES
                    if curated.source_image_url
                    and website_host
                    and website_host
                    in {
                        (urlsplit(curated.url).hostname or "").casefold(),
                        (urlsplit(curated.website).hostname or "").casefold(),
                    }
                ),
                urljoin(website, "/favicon.ico"),
            )
        )
        image_hosts = (
            WECHAT_IMAGE_HOSTS
            if is_wechat
            else official_brand.image_hosts if official_brand is not None else ()
        )
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        sources.append(
            InformationSourceDefinition(
                id=f"opml_{'wechat' if is_wechat else 'rss'}_{digest}",
                name=title,
                kind="rss",
                url=url,
                default_category="行业动态",
                website="https://mp.weixin.qq.com/" if is_wechat else website,
                region="国内",
                source_image_url=source_image_url,
                image_hosts=image_hosts,
                group="微信公众号" if is_wechat else "安全 RSS",
                catalog="chinese-security-rss",
                default_enabled=False,
                refresh_interval_seconds=1_800 if is_wechat else 900,
                max_response_bytes=8_000_000 if is_wechat else 4_000_000,
            )
        )
    return tuple(sources)


INFORMATION_SOURCES = CURATED_INFORMATION_SOURCES + load_bundled_opml_sources()
INFORMATION_SOURCE_BY_ID = {source.id: source for source in INFORMATION_SOURCES}

CATEGORY_ORDER = (
    "全部",
    "AI 安全",
    "大模型",
    "漏洞披露",
    "数据安全",
    "政策法规",
    "云安全",
    "供应链安全",
    "行业动态",
    "攻击技术",
)

SECURITY_TERMS = (
    "security",
    "cyber",
    "vulnerability",
    "exploit",
    "malware",
    "ransomware",
    "privacy",
    "breach",
    "phishing",
    "threat",
    "attack",
    "cve-",
    "安全",
    "漏洞",
    "攻击",
)

INFORMATION_IMAGE_CACHE_DIR = DATA_DIR / "information-images"
INFORMATION_SOURCE_LOGO_CACHE_DIR = INFORMATION_IMAGE_CACHE_DIR / "sources"
_information_image_cache_lock = RLock()
_information_source_logo_locks_guard = RLock()
_information_source_logo_locks: dict[str, Lock] = {}
_information_source_logo_retry_after: dict[str, datetime] = {}


@dataclass(frozen=True)
class InformationImageResult:
    data: bytes
    content_type: str
    kind: str
    etag: str


class InformationService:
    def __init__(
        self,
        state_store=store,
        fetcher: Callable[
            [InformationSourceDefinition],
            list[dict[str, Any]] | InformationFetchResult,
        ] | None = None,
        image_enricher: Callable[[list[dict[str, Any]], list[InformationSourceDefinition]], None] | None = None,
    ) -> None:
        self._store = state_store
        self._fetcher = fetcher
        self._image_enricher = image_enricher if image_enricher is not None else (
            enrich_information_images if fetcher is None else None
        )
        self._lock = RLock()
        self._refresh_state_lock = RLock()
        self._refresh_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="secflow-information-refresh")
        self._refresh_future: Future[dict[str, Any]] | None = None
        self._refresh_started_at = ""
        self._image_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="secflow-information-artwork")
        self._image_future: Future[None] | None = None
        self._image_pending = False

    def snapshot(
        self,
        *,
        query: str = "",
        category: str = "全部",
        sort: str = "latest",
        limit: int = 80,
        refresh: bool = False,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        language = normalize_information_language(response_language)
        state = self._store.read()
        info = _information_state(state)
        should_refresh = (
            refresh
            or not info["items"]
            or _cache_is_stale(str(info.get("updated_at") or ""))
        )
        if should_refresh:
            return self.request_refresh(
                query=query,
                category=category,
                sort=sort,
                limit=limit,
                force=refresh,
                response_language=language,
            )
        return self._current_snapshot(
            query=query,
            category=category,
            sort=sort,
            limit=limit,
            response_language=language,
        )

    def request_refresh(
        self,
        *,
        query: str = "",
        category: str = "全部",
        sort: str = "latest",
        limit: int = 80,
        force: bool = False,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        language = normalize_information_language(response_language)
        with self._refresh_state_lock:
            if self._refresh_future is None or self._refresh_future.done():
                self._refresh_started_at = now_iso()
                self._refresh_future = self._refresh_executor.submit(self._run_background_refresh, force, language)
        return self._current_snapshot(
            query=query,
            category=category,
            sort=sort,
            limit=limit,
            response_language=language,
        )

    def _run_background_refresh(self, force: bool, response_language: str) -> dict[str, Any]:
        try:
            snapshot = self.refresh(
                force=force,
                _enrich_images=False,
                response_language=response_language,
            )
        except Exception as exc:  # noqa: BLE001 - cached content remains readable after a background failure.
            with self._lock:
                state = self._store.read()
                info = _information_state(state)
                info["message"] = f"后台刷新失败，已保留本地缓存：{_compact_error(exc)}"
                info["last_refresh"] = now_iso()
                self._store.write(state)
            return self._current_snapshot(response_language=response_language)
        self._schedule_image_enrichment()
        return snapshot

    def _current_snapshot(
        self,
        *,
        query: str = "",
        category: str = "全部",
        sort: str = "latest",
        limit: int = 80,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        language = normalize_information_language(response_language)
        state = self._store.read()
        info = _information_state(state)
        snapshot = _build_snapshot(
            info,
            query=query,
            category=category,
            sort=sort,
            limit=limit,
            response_language=language,
        )
        with self._refresh_state_lock:
            future = self._refresh_future
            refreshing = future is not None and not future.done()
            started_at = self._refresh_started_at if refreshing else ""
            image_future = self._image_future
            artwork_refreshing = image_future is not None and not image_future.done()
        snapshot["refreshing"] = refreshing
        snapshot["refresh_started_at"] = started_at
        snapshot["artwork_refreshing"] = artwork_refreshing
        if refreshing:
            snapshot["message"] = "正在后台更新资讯，现有内容可继续浏览。"
        elif artwork_refreshing:
            snapshot["message"] = "资讯已更新，正在补全文章配图和来源 Logo。"
        return snapshot

    def _schedule_image_enrichment(self) -> None:
        if self._image_enricher is None and self._store is not store:
            return
        with self._refresh_state_lock:
            if self._image_future is not None and not self._image_future.done():
                self._image_pending = True
                return
            self._image_pending = False
            self._image_future = self._image_executor.submit(self._run_image_enrichment)

    def _run_image_enrichment(self) -> None:
        try:
            self._enrich_information_artwork_once()
        finally:
            with self._refresh_state_lock:
                if self._image_pending:
                    self._image_pending = False
                    self._image_future = self._image_executor.submit(self._run_image_enrichment)
                else:
                    self._image_future = None

    def _enrich_information_artwork_once(self) -> None:
        state = self._store.read()
        info = _information_state(state)
        statuses = _source_statuses(info)
        enabled = [source for source in INFORMATION_SOURCES if statuses[source.id].get("enabled")]
        if self._store is store:
            precache_information_source_logos(enabled)
        if self._image_enricher is None:
            return

        items = [item for item in info.get("items", []) if isinstance(item, dict)]
        before = {
            str(item.get("id") or ""): (
                str(item.get("image_url") or ""),
                str(item.get("image_checked_at") or ""),
            )
            for item in items
        }
        try:
            self._image_enricher(items, enabled)
        except Exception:  # noqa: BLE001 - optional artwork must not affect the feed.
            return
        changed = {
            str(item.get("id") or ""): (
                str(item.get("image_url") or ""),
                str(item.get("image_checked_at") or ""),
            )
            for item in items
            if before.get(str(item.get("id") or ""))
            != (str(item.get("image_url") or ""), str(item.get("image_checked_at") or ""))
        }
        if not changed:
            return
        with self._lock:
            latest_state = self._store.read()
            latest_info = _information_state(latest_state)
            for item in latest_info.get("items", []):
                if not isinstance(item, dict):
                    continue
                update = changed.get(str(item.get("id") or ""))
                if update is None:
                    continue
                item["image_url"], item["image_checked_at"] = update
            self._store.write(latest_state)

    def refresh(
        self,
        *,
        query: str = "",
        category: str = "全部",
        sort: str = "latest",
        limit: int = 80,
        force: bool = False,
        _enrich_images: bool = True,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        language = normalize_information_language(response_language)
        with self._lock:
            state = self._store.read()
            info = _information_state(state)
            sources = _source_statuses(info)
            enabled = [source for source in INFORMATION_SOURCES if sources[source.id]["enabled"]]
            previous = [
                _prepare_information_item(item)
                for item in info.get("items", [])
                if isinstance(item, dict)
            ]
            info["items"] = previous
            previous_published_at = {
                (str(item.get("source_id") or ""), _canonical_url(str(item.get("url") or ""))): str(
                    item.get("published_at") or ""
                )
                for item in previous
                if item.get("source_id") and item.get("url") and item.get("published_at")
            }
            refreshed_at = now_iso()
            if not enabled:
                info["message"] = "当前没有启用的资讯来源。"
                info["last_refresh"] = refreshed_at
                self._store.write(state)
                return _build_snapshot(
                    info,
                    query=query,
                    category=category,
                    sort=sort,
                    limit=limit,
                    response_language=language,
                )

            due = [source for source in enabled if _source_refresh_due(source, sources[source.id], force=force)]
            if not due:
                info["message"] = f"{len(enabled)} 个已启用来源均未到刷新时间。"
                info["last_refresh"] = refreshed_at
                info["updated_at"] = refreshed_at
                self._store.write(state)
                return _build_snapshot(
                    info,
                    query=query,
                    category=category,
                    sort=sort,
                    limit=limit,
                    response_language=language,
                )

            replacements: dict[str, list[dict[str, Any]]] = {}
            failures: list[str] = []
            unchanged = 0
            worker_limit = max(
                1,
                min(
                    int(os.getenv("SECFLOW_INFORMATION_REFRESH_WORKERS", str(INFORMATION_REFRESH_WORKERS))),
                    24,
                    len(due),
                ),
            )
            host_semaphores: dict[str, BoundedSemaphore] = {}
            for source in due:
                host = (urlsplit(source.url).hostname or "").casefold()
                limit_for_host = (
                    max(1, min(int(os.getenv("SECFLOW_WECHAT_RSS_HOST_CONCURRENCY", "4")), 6))
                    if host == WECHAT_RSS_HOST
                    else worker_limit
                )
                host_semaphores.setdefault(host, BoundedSemaphore(limit_for_host))

            def fetch_due(source: InformationSourceDefinition) -> InformationFetchResult:
                host = (urlsplit(source.url).hostname or "").casefold()
                with host_semaphores[host]:
                    return self._fetch_source(source, sources[source.id])

            with ThreadPoolExecutor(max_workers=worker_limit, thread_name_prefix="secflow-information") as pool:
                futures = {pool.submit(fetch_due, source): source for source in due}
                for future in as_completed(futures):
                    source = futures[future]
                    status = sources[source.id]
                    status["last_checked"] = refreshed_at
                    try:
                        result = future.result()
                        if result.not_modified:
                            unchanged += 1
                            _mark_source_success(status, result, refreshed_at, item_count=None)
                            status["message"] = "内容未变化，继续使用本地缓存。"
                            continue
                        if source.kind == "rss":
                            status["feed_parser_version"] = INFORMATION_FEED_PARSER_VERSION
                        normalized = [
                            item
                            for raw in result.items
                            if (
                                item := _normalize_item(
                                    source,
                                    raw,
                                    refreshed_at,
                                    previous_published_at=previous_published_at.get(
                                        (source.id, _canonical_url(str(raw.get("url") or ""))),
                                        "",
                                    ),
                                )
                            )
                            is not None
                        ]
                        replacements[source.id] = normalized
                        _mark_source_success(status, result, refreshed_at, item_count=len(normalized))
                    except Exception as exc:  # noqa: BLE001 - one source must not break the feed.
                        if source.kind == "rss":
                            status["feed_parser_version"] = INFORMATION_FEED_PARSER_VERSION
                        message = _compact_error(exc)
                        failures.append(f"{source.name}: {message}")
                        _mark_source_failure(status, message, refreshed_at)

            refreshed_items = [item for items in replacements.values() for item in items]
            if replacements:
                _reuse_cached_images(refreshed_items, previous)
                refreshed_items = [_prepare_information_item(item) for item in refreshed_items]
                if self._image_enricher is not None and _enrich_images:
                    try:
                        self._image_enricher(
                            refreshed_items,
                            [source for source in due if source.id in replacements],
                        )
                    except Exception:  # noqa: BLE001 - covers are optional; news must remain available.
                        pass
                enabled_ids = {source.id for source in enabled}
                retained = [
                    item
                    for item in previous
                    if str(item.get("source_id") or "") in enabled_ids
                    and str(item.get("source_id") or "") not in replacements
                ]
                cache_limit = max(400, min(int(os.getenv("SECFLOW_INFORMATION_CACHE_ITEMS", "2000")), 10_000))
                info["items"] = _deduplicate_items([*refreshed_items, *retained])[:cache_limit]
                info["updated_at"] = refreshed_at
            elif unchanged:
                info["updated_at"] = refreshed_at
            info["last_refresh"] = refreshed_at
            info["sources"] = sources
            parts = [f"检测 {len(due)} 个来源"]
            if replacements:
                parts.append(f"{len(replacements)} 个已更新")
            if unchanged:
                parts.append(f"{unchanged} 个无变化")
            if failures:
                parts.append(f"{len(failures)} 个暂时不可用")
            info["message"] = "，".join(parts) + "。"
            self._store.write(state)
            return self._current_snapshot(
                query=query,
                category=category,
                sort=sort,
                limit=limit,
                response_language=language,
            )

    def set_source_enabled(self, source_id: str, enabled: bool) -> dict[str, Any]:
        return self.set_sources_enabled([source_id], enabled)[0]

    def set_sources_enabled(self, source_ids: list[str], enabled: bool) -> list[dict[str, Any]]:
        unique_ids = list(dict.fromkeys(str(source_id).strip() for source_id in source_ids if str(source_id).strip()))
        if not unique_ids:
            raise ValueError("至少选择一个资讯来源")
        unknown = [source_id for source_id in unique_ids if source_id not in INFORMATION_SOURCE_BY_ID]
        if unknown:
            raise KeyError(unknown[0])
        with self._lock:
            state = self._store.read()
            info = _information_state(state)
            statuses = _source_statuses(info)
            enabled_opml = {
                source_id
                for source_id, status in statuses.items()
                if status.get("enabled") and INFORMATION_SOURCE_BY_ID[source_id].catalog == "chinese-security-rss"
            }
            for source_id in unique_ids:
                source = INFORMATION_SOURCE_BY_ID[source_id]
                if source.catalog != "chinese-security-rss":
                    continue
                if enabled:
                    enabled_opml.add(source_id)
                else:
                    enabled_opml.discard(source_id)
            if len(enabled_opml) > MAX_ENABLED_OPML_SOURCES:
                raise ValueError(f"内置 OPML 来源最多同时启用 {MAX_ENABLED_OPML_SOURCES} 个")
            for source_id in unique_ids:
                status = statuses[source_id]
                status.update(
                    enabled=bool(enabled),
                    status="idle",
                    failure_count=0,
                    next_retry_at="",
                    message="已启用，刷新后接入最新资讯。" if enabled else "已暂停订阅。",
                )
                if enabled:
                    status["last_checked"] = ""
            info["sources"] = statuses
            self._store.write(state)
        return [statuses[source_id] for source_id in unique_ids]

    def test_source(self, source_id: str) -> dict[str, Any]:
        source = INFORMATION_SOURCE_BY_ID.get(source_id)
        if source is None:
            raise KeyError(source_id)
        with self._lock:
            state = self._store.read()
            info = _information_state(state)
            statuses = _source_statuses(info)
            status = statuses[source_id]
            checked_at = now_iso()
            status["last_checked"] = checked_at
            try:
                result = self._fetch_source(source, status)
                if source.kind == "rss" and not result.not_modified:
                    status["feed_parser_version"] = INFORMATION_FEED_PARSER_VERSION
                item_count = None if result.not_modified else len(result.items)
                _mark_source_success(status, result, checked_at, item_count=item_count)
                status["message"] = (
                    "连接正常，内容未变化。"
                    if result.not_modified
                    else f"连接正常，可读取 {len(result.items)} 条资讯。"
                )
            except Exception as exc:  # noqa: BLE001 - test result is returned to the source manager.
                _mark_source_failure(status, _compact_error(exc), checked_at)
            info["sources"] = statuses
            self._store.write(state)
            return status

    def _fetch_source(
        self,
        source: InformationSourceDefinition,
        status: dict[str, Any],
    ) -> InformationFetchResult:
        if self._fetcher is not None:
            result = self._fetcher(source)
            if isinstance(result, InformationFetchResult):
                return result
            return InformationFetchResult(items=result)
        parser_is_current = (
            source.kind != "rss"
            or int(status.get("feed_parser_version") or 0) >= INFORMATION_FEED_PARSER_VERSION
        )
        return fetch_information_source(
            source,
            etag=str(status.get("etag") or "") if parser_is_current else "",
            last_modified=str(status.get("last_modified") or "") if parser_is_current else "",
        )


def fetch_information_source(
    source: InformationSourceDefinition,
    *,
    etag: str = "",
    last_modified: str = "",
) -> InformationFetchResult:
    headers = {
        "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.5",
        "User-Agent": "SecFlow-Information/1.0 (+local defensive security intelligence client)",
    }
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    timeout = _information_request_timeout()
    retry_count = max(0, min(int(os.getenv("SECFLOW_INFORMATION_TIMEOUT_RETRIES", "1")), 2))
    with httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers=headers,
        trust_env=False,
        verify=_system_ssl_context(),
    ) as client:
        for attempt in range(retry_count + 1):
            try:
                with client.stream("GET", source.url) as response:
                    _reject_https_downgrade(source.url, str(response.url))
                    if response.status_code == 304:
                        return InformationFetchResult(
                            items=[],
                            etag=str(response.headers.get("etag") or etag),
                            last_modified=str(response.headers.get("last-modified") or last_modified),
                            not_modified=True,
                        )
                    response.raise_for_status()
                    payload = _read_limited_response(response, source.max_response_bytes)
                    response_etag = str(response.headers.get("etag") or "")
                    response_last_modified = str(response.headers.get("last-modified") or "")
                break
            except httpx.TimeoutException:
                if attempt >= retry_count:
                    raise
    if source.kind == "kev":
        return InformationFetchResult(
            items=parse_kev(json.loads(payload)),
            etag=response_etag,
            last_modified=response_last_modified,
        )
    return InformationFetchResult(
        items=parse_feed(payload, security_only=source.filter_security),
        etag=response_etag,
        last_modified=response_last_modified,
    )


def _information_request_timeout() -> httpx.Timeout:
    read_seconds = max(5.0, float(os.getenv("SECFLOW_INFORMATION_TIMEOUT_SECONDS", "18")))
    connect_seconds = max(2.0, float(os.getenv("SECFLOW_INFORMATION_CONNECT_TIMEOUT_SECONDS", "6")))
    return httpx.Timeout(read_seconds, connect=connect_seconds)


def _system_ssl_context() -> ssl.SSLContext:
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _reject_https_downgrade(initial_url: str, final_url: str) -> None:
    if urlsplit(initial_url).scheme.casefold() == "https" and urlsplit(final_url).scheme.casefold() != "https":
        raise ValueError("资讯来源重定向试图从 HTTPS 降级到非加密连接")


def _read_limited_response(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > limit:
            raise ValueError(f"来源响应超过 {max(1, limit // 1_000_000)} MB 限制")
        chunks.append(chunk)
    return b"".join(chunks)


def _source_refresh_due(
    source: InformationSourceDefinition,
    status: dict[str, Any],
    *,
    force: bool,
) -> bool:
    if source.kind == "rss" and int(status.get("feed_parser_version") or 0) < INFORMATION_FEED_PARSER_VERSION:
        return True
    now = datetime.now(timezone.utc)
    retry_at = _parse_iso_datetime(str(status.get("next_retry_at") or ""))
    if retry_at is not None and retry_at > now:
        return False
    if force:
        return True
    checked_at = _parse_iso_datetime(str(status.get("last_checked") or ""))
    if checked_at is None:
        return True
    return (now - checked_at).total_seconds() >= source.refresh_interval_seconds


def _mark_source_success(
    status: dict[str, Any],
    result: InformationFetchResult,
    checked_at: str,
    *,
    item_count: int | None,
) -> None:
    status.update(
        status="ready",
        last_checked=checked_at,
        last_success=checked_at,
        failure_count=0,
        next_retry_at="",
        etag=result.etag or str(status.get("etag") or ""),
        last_modified=result.last_modified or str(status.get("last_modified") or ""),
    )
    if item_count is not None:
        status["item_count"] = item_count
        status["last_updated"] = checked_at
        status["message"] = f"已获取 {item_count} 条"


def _mark_source_failure(status: dict[str, Any], message: str, checked_at: str) -> None:
    failure_count = max(0, int(status.get("failure_count") or 0)) + 1
    base_seconds = max(60, int(os.getenv("SECFLOW_INFORMATION_BACKOFF_SECONDS", "300")))
    delay_seconds = min(21_600, base_seconds * (2 ** min(failure_count - 1, 6)))
    checked = _parse_iso_datetime(checked_at) or datetime.now(timezone.utc)
    status.update(
        status="error",
        last_checked=checked_at,
        failure_count=failure_count,
        next_retry_at=(checked + timedelta(seconds=delay_seconds)).replace(microsecond=0).isoformat(),
        message=message,
    )


def _parse_iso_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def load_information_image(item_id: str) -> InformationImageResult:
    state = store.read()
    info = _information_state(state)
    item = next(
        (
            value
            for value in info.get("items", [])
            if isinstance(value, dict) and str(value.get("id") or "") == item_id
        ),
        None,
    )
    if item is None:
        raise KeyError(item_id)
    source = INFORMATION_SOURCE_BY_ID.get(str(item.get("source_id") or ""))
    if source is None:
        raise KeyError(item_id)

    image_url = str(item.get("image_url") or "")
    if image_url:
        cached = _read_cached_information_image(image_url, "article")
        if cached is not None:
            return cached
        if _image_url_allowed(image_url, source) or _remote_url_is_public(image_url):
            try:
                return _download_information_image(image_url, "article", source, allow_public=True)
            except Exception:  # noqa: BLE001 - an article cover may fall back to its publisher mark.
                pass
    return _load_information_source_image(info, source, preferred_item=item)


def load_information_source_image(source_id: str) -> InformationImageResult:
    state = store.read()
    info = _information_state(state)
    source = INFORMATION_SOURCE_BY_ID.get(source_id)
    if source is None:
        raise KeyError(source_id)
    return _load_information_source_image(info, source)


def _load_information_source_image(
    info: dict[str, Any],
    source: InformationSourceDefinition,
    *,
    preferred_item: dict[str, Any] | None = None,
) -> InformationImageResult:
    with _information_source_logo_lock(source.id):
        cached_source = _read_cached_information_source_logo(source.id)
        if cached_source is not None:
            return cached_source
        retry_after = _information_source_logo_retry_after.get(source.id)
        if retry_after is not None and retry_after > datetime.now(timezone.utc):
            raise ValueError("资讯来源 Logo 暂时不可用")

        for image_url in _source_logo_candidates(info.get("items", []), source, preferred_item=preferred_item):
            if not image_url or not _image_url_allowed(image_url, source):
                continue
            cached = _read_cached_information_image(image_url, "source")
            if cached is not None:
                return _write_cached_information_source_logo(source.id, cached)
            try:
                downloaded = _download_information_image(image_url, "source", source)
                return _write_cached_information_source_logo(source.id, downloaded)
            except Exception:  # noqa: BLE001 - try the next known publisher mark.
                continue

        for image_url in _discover_source_logo_candidates(source):
            try:
                downloaded = _download_information_image(image_url, "source", source, allow_public=True)
                return _write_cached_information_source_logo(source.id, downloaded)
            except Exception:  # noqa: BLE001 - malformed or unavailable website artwork is optional.
                continue

        _information_source_logo_retry_after[source.id] = datetime.now(timezone.utc) + timedelta(
            seconds=INFORMATION_SOURCE_LOGO_RETRY_SECONDS
        )
        raise ValueError("资讯来源 Logo 暂时不可用")


def _download_information_image(
    image_url: str,
    kind: str,
    source: InformationSourceDefinition,
    *,
    allow_public: bool = False,
) -> InformationImageResult:
    if not _image_url_allowed(image_url, source) and not (allow_public and _remote_url_is_public(image_url)):
        raise ValueError("图片地址不在允许范围内")
    timeout = httpx.Timeout(8.0, connect=4.0)
    headers = {
        "Accept": "image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (Macintosh; Apple Silicon Mac OS X) SecFlow-Information/1.0",
    }
    image_host = (urlsplit(image_url).hostname or "").casefold()
    if source.group == "微信公众号" or any(
        image_host == host or image_host.endswith(f".{host}") for host in WECHAT_IMAGE_HOSTS
    ):
        headers["Referer"] = "https://mp.weixin.qq.com/"
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers, trust_env=False) as client:
        with client.stream("GET", image_url) as response:
            response.raise_for_status()
            if not _image_url_allowed(str(response.url), source) and not (
                allow_public and _remote_url_is_public(str(response.url))
            ):
                raise ValueError("图片重定向到了未授权域名")
            content_type = str(response.headers.get("content-type") or "").split(";", 1)[0].strip().casefold()
            if not content_type.startswith("image/"):
                guessed = mimetypes.guess_type(urlsplit(str(response.url)).path)[0] or ""
                content_type = guessed.casefold()
            if not content_type.startswith("image/"):
                raise ValueError("远端响应不是图片")
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 8_000_000:
                    raise ValueError("资讯图片超过 8 MB 限制")
                chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise ValueError("远端图片为空")
    return _write_cached_information_image(image_url, data, content_type, kind)


def _image_url_allowed(value: str, source: InformationSourceDefinition) -> bool:
    host = (urlsplit(value).hostname or "").casefold().rstrip(".")
    if not host:
        return False
    allowed_hosts = {
        (urlsplit(candidate).hostname or "").casefold().rstrip(".")
        for candidate in (source.url, source.website, source.source_image_url)
    }
    allowed_hosts.update(item.casefold().rstrip(".") for item in source.image_hosts)
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts if allowed)


def _image_cache_paths(image_url: str) -> tuple[Path, Path, str]:
    digest = hashlib.sha256(image_url.encode("utf-8")).hexdigest()
    return (
        INFORMATION_IMAGE_CACHE_DIR / f"{digest}.bin",
        INFORMATION_IMAGE_CACHE_DIR / f"{digest}.mime",
        digest,
    )


def _information_source_logo_lock(source_id: str) -> Lock:
    with _information_source_logo_locks_guard:
        return _information_source_logo_locks.setdefault(source_id, Lock())


def _source_logo_cache_paths(source_id: str) -> tuple[Path, Path, str]:
    digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()
    return (
        INFORMATION_SOURCE_LOGO_CACHE_DIR / f"{digest}.bin",
        INFORMATION_SOURCE_LOGO_CACHE_DIR / f"{digest}.mime",
        digest,
    )


def _read_cached_information_source_logo(source_id: str) -> InformationImageResult | None:
    data_path, mime_path, digest = _source_logo_cache_paths(source_id)
    try:
        data = data_path.read_bytes()
        content_type = mime_path.read_text(encoding="ascii").strip()
    except OSError:
        return None
    if not data or len(data) > 8_000_000 or not content_type.startswith("image/"):
        return None
    return InformationImageResult(data=data, content_type=content_type, kind="source", etag=digest)


def _write_cached_information_source_logo(
    source_id: str,
    result: InformationImageResult,
) -> InformationImageResult:
    data_path, mime_path, digest = _source_logo_cache_paths(source_id)
    with _information_image_cache_lock:
        INFORMATION_SOURCE_LOGO_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        data_tmp = data_path.with_name(f"{data_path.name}.tmp")
        mime_tmp = mime_path.with_name(f"{mime_path.name}.tmp")
        data_tmp.write_bytes(result.data)
        mime_tmp.write_text(result.content_type, encoding="ascii")
        os.replace(data_tmp, data_path)
        os.replace(mime_tmp, mime_path)
        _prune_information_source_logo_cache()
    _information_source_logo_retry_after.pop(source_id, None)
    return InformationImageResult(
        data=result.data,
        content_type=result.content_type,
        kind="source",
        etag=digest,
    )


def _prune_information_source_logo_cache() -> None:
    entries = sorted(
        INFORMATION_SOURCE_LOGO_CACHE_DIR.glob("*.bin"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    retained_size = 0
    for index, path in enumerate(entries):
        try:
            retained_size += path.stat().st_size
            if index < 1_000 and retained_size <= 128 * 1_024 * 1_024:
                continue
            path.unlink(missing_ok=True)
            path.with_suffix(".mime").unlink(missing_ok=True)
        except OSError:
            continue


def _read_cached_information_image(image_url: str, kind: str) -> InformationImageResult | None:
    data_path, mime_path, digest = _image_cache_paths(image_url)
    try:
        data = data_path.read_bytes()
        content_type = mime_path.read_text(encoding="ascii").strip()
    except OSError:
        return None
    if not data or len(data) > 8_000_000 or not content_type.startswith("image/"):
        return None
    return InformationImageResult(data=data, content_type=content_type, kind=kind, etag=digest)


def _write_cached_information_image(
    image_url: str,
    data: bytes,
    content_type: str,
    kind: str,
) -> InformationImageResult:
    data_path, mime_path, digest = _image_cache_paths(image_url)
    with _information_image_cache_lock:
        INFORMATION_IMAGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        data_tmp = data_path.with_name(f"{data_path.name}.tmp")
        mime_tmp = mime_path.with_name(f"{mime_path.name}.tmp")
        data_tmp.write_bytes(data)
        mime_tmp.write_text(content_type, encoding="ascii")
        os.replace(data_tmp, data_path)
        os.replace(mime_tmp, mime_path)
        _prune_information_image_cache()
    return InformationImageResult(data=data, content_type=content_type, kind=kind, etag=digest)


def _prune_information_image_cache() -> None:
    entries = sorted(
        INFORMATION_IMAGE_CACHE_DIR.glob("*.bin"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    retained_size = 0
    for index, path in enumerate(entries):
        try:
            retained_size += path.stat().st_size
            if index < 500 and retained_size <= 256 * 1_024 * 1_024:
                continue
            path.unlink(missing_ok=True)
            path.with_suffix(".mime").unlink(missing_ok=True)
        except OSError:
            continue


def parse_feed(payload: bytes | str, *, security_only: bool = False) -> list[dict[str, Any]]:
    root = ElementTree.fromstring(payload)
    entries = [node for node in root.iter() if _local_name(node.tag) in {"item", "entry"}]
    source_image_url = _feed_source_image(root)
    result: list[dict[str, Any]] = []
    for entry in entries[:60]:
        title = _child_text(entry, "title")
        link = _entry_link(entry)
        content_fragments = _entry_content_fragments(entry)
        content = content_fragments[0] if content_fragments else ""
        categories = [str(node.text or "").strip() for node in entry if _local_name(node.tag) == "category"]
        searchable = " ".join([title, content, *categories]).casefold()
        if security_only and not any(term in searchable for term in SECURITY_TERMS):
            continue
        result.append(
            {
                "title": title,
                "url": link,
                "summary": _plain_text(content, 520),
                "published_at": _first_text(entry, ("pubDate", "published", "updated", "date")),
                "author": _entry_author(entry),
                "image_url": _entry_image(entry, content_fragments, link),
                "source_image_url": source_image_url,
                "feed_categories": categories,
            }
        )
    return result


def parse_kev(payload: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else []
    if not isinstance(vulnerabilities, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in sorted(vulnerabilities, key=lambda item: str(item.get("dateAdded") or ""), reverse=True)[:60]:
        cve_id = str(entry.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        vendor = str(entry.get("vendorProject") or "").strip()
        product = str(entry.get("product") or "").strip()
        title = str(entry.get("vulnerabilityName") or "").strip() or f"{cve_id} 已确认在野利用"
        action = str(entry.get("requiredAction") or "").strip()
        description = str(entry.get("shortDescription") or "").strip()
        result.append(
            {
                "title": f"{cve_id}: {title}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": _plain_text(" ".join(part for part in [description, action] if part), 520),
                "published_at": str(entry.get("dateAdded") or ""),
                "author": "CISA KEV",
                "image_url": "",
                "feed_categories": ["Known Exploited Vulnerability", vendor, product],
                "tags": [cve_id, "在野利用", vendor, product],
                "breaking": True,
            }
        )
    return result


def _normalize_item(
    source: InformationSourceDefinition,
    raw: dict[str, Any],
    fetched_at: str,
    *,
    previous_published_at: str = "",
) -> dict[str, Any] | None:
    title = _plain_text(str(raw.get("title") or ""), 260)
    url = _canonical_url(str(raw.get("url") or ""))
    if not title or not url.startswith(("http://", "https://")):
        return None
    summary = _plain_text(str(raw.get("summary") or ""), 520)
    category = _classify_category(title, summary, raw.get("feed_categories"), source.default_category)
    tags = _extract_tags(title, summary, raw.get("tags"), category)
    published_at = (
        _normalize_datetime(str(raw.get("published_at") or ""), "")
        or _published_at_from_url(url)
        or _normalize_datetime(previous_published_at, "")
        or fetched_at
    )
    digest = hashlib.sha256(f"{source.id}|{url}|{title.casefold()}".encode("utf-8")).hexdigest()[:24]
    candidate_source_image = _safe_remote_url(str(raw.get("source_image_url") or ""))
    source_image_url = (
        candidate_source_image
        if candidate_source_image and _image_url_allowed(candidate_source_image, source)
        else source.source_image_url
    )
    return {
        "id": f"news-{digest}",
        "source_id": source.id,
        "source_name": source.name,
        "source_kind": source.kind,
        "title": title,
        "summary": summary,
        "title_original": title,
        "summary_original": summary,
        "url": url,
        "image_url": _safe_remote_url(str(raw.get("image_url") or "")),
        "source_image_url": source_image_url,
        "image_checked_at": "",
        "published_at": published_at,
        "author": _plain_text(str(raw.get("author") or source.name), 100),
        "category": category,
        "tags": tags,
        "breaking": bool(raw.get("breaking")) or _is_breaking(title, summary),
    }


def normalize_information_language(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "zh": "zh-Hans",
        "zh-cn": "zh-Hans",
        "zh-sg": "zh-Hans",
        "zh-hans": "zh-Hans",
        "zh-tw": "zh-Hant",
        "zh-hk": "zh-Hant",
        "zh-mo": "zh-Hant",
        "zh-hant": "zh-Hant",
        "en": "en",
        "en-us": "en",
        "en-gb": "en",
    }
    language = aliases.get(text)
    if language is None:
        requested = str(value or "").strip() or "<empty>"
        raise ValueError(
            f"Unsupported information response language: {requested}. "
            f"Supported languages: {', '.join(INFORMATION_RESPONSE_LANGUAGES)}"
        )
    return language


def _prepare_information_item(item: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(item)
    title = _plain_text(str(prepared.get("title_original") or prepared.get("title") or ""), 260)
    summary = _plain_text(str(prepared.get("summary_original") or prepared.get("summary") or ""), 520)
    prepared["title"] = title
    prepared["summary"] = summary
    prepared["title_original"] = title
    prepared["summary_original"] = summary
    for field in (
        "title_zh",
        "summary_zh",
        "title_zh_hant",
        "summary_zh_hant",
        "title_en",
        "summary_en",
        "information_translation",
    ):
        prepared.pop(field, None)
    return prepared


def _project_information_item(item: dict[str, Any]) -> dict[str, Any]:
    projected = {
        key: deepcopy(item[key])
        for key in (
            "id",
            "source_id",
            "source_name",
            "source_kind",
            "url",
            "image_url",
            "source_image_url",
            "image_checked_at",
            "published_at",
            "author",
            "category",
            "tags",
            "breaking",
        )
        if key in item
    }
    projected.update(
        {
            "title": str(item.get("title_original") or item.get("title") or ""),
            "summary": str(item.get("summary_original") or item.get("summary") or ""),
        }
    )
    return projected


def _build_snapshot(
    info: dict[str, Any],
    *,
    query: str,
    category: str,
    sort: str,
    limit: int,
    response_language: str = "zh-Hans",
) -> dict[str, Any]:
    language = normalize_information_language(response_language)
    statuses = _source_statuses(info)
    enabled_ids = {source_id for source_id, status in statuses.items() if status.get("enabled")}
    source_by_id = INFORMATION_SOURCE_BY_ID
    all_items = [
        item for item in info.get("items", [])
        if isinstance(item, dict) and str(item.get("source_id") or "") in enabled_ids
    ]
    preferred_source_logos = {
        source_id: logos[0]
        for source_id in enabled_ids
        if (source := source_by_id.get(source_id)) is not None
        and (logos := _source_logo_candidates(all_items, source))
    }
    for item in all_items:
        source_id = str(item.get("source_id") or "")
        source = source_by_id.get(source_id)
        item.setdefault("image_url", "")
        item["source_image_url"] = preferred_source_logos.get(
            source_id,
            source.source_image_url if source is not None else "",
        )
    all_items.sort(key=lambda item: (str(item.get("published_at") or ""), str(item.get("id") or "")), reverse=True)
    counts = {name: 0 for name in CATEGORY_ORDER}
    counts["全部"] = len(all_items)
    for item in all_items:
        item_category = str(item.get("category") or "行业动态")
        counts[item_category] = counts.get(item_category, 0) + 1

    selected_category = category if category in CATEGORY_ORDER else "全部"
    filtered = all_items if selected_category == "全部" else [item for item in all_items if item.get("category") == selected_category]
    normalized_query = query.strip().casefold()
    if normalized_query:
        filtered = [
            item for item in filtered
            if normalized_query in " ".join(
                [
                    str(item.get("title") or ""),
                    str(item.get("summary") or ""),
                    str(item.get("source_name") or ""),
                    " ".join(str(tag) for tag in item.get("tags") or []),
                ]
            ).casefold()
        ]
    if sort == "source":
        filtered.sort(key=lambda item: (str(item.get("source_name") or ""), str(item.get("published_at") or "")), reverse=True)
    else:
        filtered.sort(key=lambda item: str(item.get("published_at") or ""), reverse=True)

    safe_limit = max(1, min(int(limit), 200))
    source_list = [statuses[source.id] for source in INFORMATION_SOURCES]
    projected_items = [_project_information_item(item) for item in filtered[:safe_limit]]
    projected_briefs = [_project_information_item(item) for item in all_items[:6]]
    return {
        "items": projected_items,
        "total": len(filtered),
        "available_total": len(all_items),
        "categories": [
            {"id": _category_id(name), "label": name, "count": counts.get(name, 0)}
            for name in CATEGORY_ORDER
            if name == "全部" or counts.get(name, 0) > 0
        ],
        "popular_tags": _popular_tags(all_items),
        "briefs": projected_briefs,
        "sources": source_list,
        "source_summary": {
            "total": len(source_list),
            "enabled": sum(1 for source in source_list if source.get("enabled")),
            "opml_total": sum(1 for source in INFORMATION_SOURCES if source.catalog == "chinese-security-rss"),
            "opml_enabled": sum(
                1
                for source in INFORMATION_SOURCES
                if source.catalog == "chinese-security-rss" and statuses[source.id].get("enabled")
            ),
            "opml_enabled_limit": MAX_ENABLED_OPML_SOURCES,
        },
        "updated_at": str(info.get("updated_at") or ""),
        "last_refresh": str(info.get("last_refresh") or ""),
        "stale": _cache_is_stale(str(info.get("updated_at") or "")),
        "partial": any(source.get("enabled") and source.get("status") == "error" for source in source_list),
        "message": str(info.get("message") or "等待首次在线更新。"),
        "response_language": language,
    }


class _SourceLogoParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.candidates: list[tuple[int, int, str]] = []
        self._index = 0

    @property
    def urls(self) -> list[str]:
        ordered = sorted(self.candidates, key=lambda item: (item[0], -item[1]), reverse=True)
        return list(dict.fromkeys(url for _, _, url in ordered))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {str(key).casefold(): str(value or "") for key, value in attrs}
        tag = tag.casefold()
        raw_url = ""
        score = 0
        if tag == "link":
            rel = set(attributes.get("rel", "").casefold().split())
            if not rel.intersection({"icon", "shortcut", "apple-touch-icon", "mask-icon"}):
                return
            raw_url = attributes.get("href", "")
            score = 500 if "apple-touch-icon" in rel else 400
            dimensions = [int(value) for value in re.findall(r"\d+", attributes.get("sizes", ""))]
            if dimensions:
                score += min(max(dimensions), 512)
        elif tag == "meta":
            marker = " ".join(
                [attributes.get("name", ""), attributes.get("property", ""), attributes.get("itemprop", "")]
            ).casefold()
            if marker.strip() not in {"logo", "og:logo", "msapplication-tileimage"}:
                return
            raw_url = attributes.get("content", "")
            score = 300
        if not raw_url:
            return
        candidate = _safe_remote_url(urljoin(self.base_url, html.unescape(raw_url).strip()))
        if candidate:
            self.candidates.append((score, self._index, candidate))
            self._index += 1

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def _discover_source_logo_candidates(source: InformationSourceDefinition) -> list[str]:
    website = _safe_remote_url(source.website)
    if not website or not _remote_url_is_public(website):
        return []
    timeout = httpx.Timeout(5.0, connect=3.0)
    headers = {
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.4",
        "User-Agent": "Mozilla/5.0 (Macintosh; Apple Silicon Mac OS X) SecFlow-Information/1.0",
    }
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers, trust_env=False) as client:
            with client.stream("GET", website) as response:
                response.raise_for_status()
                final_url = str(response.url)
                if not _remote_url_is_public(final_url):
                    return []
                content_type = str(response.headers.get("content-type") or "").casefold()
                if "html" not in content_type:
                    return []
                payload = _read_limited_response(response, 1_000_000)
    except Exception:  # noqa: BLE001 - logo discovery is a best-effort fallback.
        return []

    parser = _SourceLogoParser(final_url)
    try:
        parser.feed(payload.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - malformed publisher HTML should only lose its logo.
        return []
    standard = [
        urljoin(final_url, "/apple-touch-icon.png"),
        urljoin(final_url, "/favicon.png"),
    ]
    return list(dict.fromkeys([*parser.urls, *standard]))


def precache_information_source_logos(sources: list[InformationSourceDefinition]) -> None:
    limit = max(0, min(int(os.getenv("SECFLOW_INFORMATION_LOGO_PRECACHE_TOTAL", "50")), 100))
    candidates = sources[:limit]
    if not candidates:
        return
    state = store.read()
    info = _information_state(state)

    def load(source: InformationSourceDefinition) -> None:
        try:
            _load_information_source_image(info, source)
        except ValueError:
            pass

    workers = min(8, len(candidates))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="secflow-information-logos") as pool:
        list(pool.map(load, candidates))


def _source_logo_candidates(
    items: list[dict[str, Any]],
    source: InformationSourceDefinition,
    *,
    preferred_item: dict[str, Any] | None = None,
) -> list[str]:
    candidates: list[str] = []
    if preferred_item is not None:
        candidates.append(str(preferred_item.get("source_image_url") or ""))
    candidates.extend(
        str(item.get("source_image_url") or "")
        for item in items
        if isinstance(item, dict) and str(item.get("source_id") or "") == source.id
    )
    candidates.append(source.source_image_url)

    unique: dict[str, None] = {}
    for candidate in candidates:
        normalized = _safe_remote_url(candidate)
        if normalized and _image_url_allowed(normalized, source):
            unique.setdefault(normalized, None)
    return sorted(unique, key=lambda value: _source_logo_rank(value, source), reverse=True)


def _source_logo_rank(value: str, source: InformationSourceDefinition) -> tuple[int, int]:
    host = (urlsplit(value).hostname or "").casefold().rstrip(".")
    if any(host == allowed or host.endswith(f".{allowed}") for allowed in WECHAT_IMAGE_HOSTS):
        return (3, len(value))
    if source.group == "微信公众号" and host == WECHAT_RSS_HOST:
        return (0, len(value))
    return (2, len(value))


def _information_state(state: dict[str, Any]) -> dict[str, Any]:
    info = state.setdefault("information", {})
    if not isinstance(info, dict):
        info = {}
        state["information"] = info
    info.setdefault("sources", {})
    info.setdefault("items", [])
    info.setdefault("updated_at", "")
    info.setdefault("last_refresh", "")
    info.setdefault("message", "等待首次在线更新。")
    _source_statuses(info)
    return info


def _source_statuses(info: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = info.setdefault("sources", {})
    if not isinstance(raw, dict):
        raw = {}
        info["sources"] = raw
    result: dict[str, dict[str, Any]] = {}
    for source in INFORMATION_SOURCES:
        existing = raw.get(source.id)
        status = existing if isinstance(existing, dict) else {}
        enabled = bool(status["enabled"]) if "enabled" in status else source.default_enabled
        if not enabled:
            status.update(
                status="idle",
                failure_count=0,
                next_retry_at="",
                message="已暂停订阅。",
            )
        status.update(
            id=source.id,
            name=source.name,
            kind=source.kind,
            website=source.website,
            region=source.region,
            group=source.group,
            catalog=source.catalog,
            secure_transport=urlsplit(source.url).scheme.casefold() == "https",
            enabled=enabled,
            status=str(status.get("status") or "idle"),
            item_count=int(status.get("item_count") or 0),
            last_updated=str(status.get("last_updated") or ""),
            last_checked=str(status.get("last_checked") or ""),
            last_success=str(status.get("last_success") or ""),
            next_retry_at=str(status.get("next_retry_at") or ""),
            failure_count=max(0, int(status.get("failure_count") or 0)),
            feed_parser_version=max(0, int(status.get("feed_parser_version") or 0)),
            refresh_interval_seconds=source.refresh_interval_seconds,
            message=str(status.get("message") or "等待更新"),
        )
        raw[source.id] = status
        result[source.id] = status
    return result


def _deduplicate_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items.sort(key=lambda item: str(item.get("published_at") or ""), reverse=True)
    seen_urls: set[str] = set()
    seen_titles: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        url_key = str(item.get("url") or "").casefold()
        title_key = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", str(item.get("title") or "").casefold())
        if not url_key or url_key in seen_urls or (len(title_key) > 20 and title_key in seen_titles):
            continue
        seen_urls.add(url_key)
        seen_titles.add(title_key)
        result.append(item)
    return result


def _reuse_cached_images(items: list[dict[str, Any]], previous: list[dict[str, Any]]) -> None:
    cached = {
        (str(item.get("source_id") or ""), str(item.get("url") or "")): (
            str(item.get("image_url") or ""),
            str(item.get("image_checked_at") or ""),
        )
        for item in previous
        if item.get("image_url") or item.get("image_checked_at")
    }
    for item in items:
        cached_value = cached.get((str(item.get("source_id") or ""), str(item.get("url") or "")))
        if cached_value is None:
            continue
        image_url, checked_at = cached_value
        if image_url:
            item["image_url"] = image_url
        if checked_at:
            item["image_checked_at"] = checked_at


def enrich_information_images(
    items: list[dict[str, Any]],
    sources: list[InformationSourceDefinition],
) -> None:
    source_by_id = {source.id: source for source in sources}
    per_source_limit = max(0, min(int(os.getenv("SECFLOW_INFORMATION_IMAGE_LOOKUPS_PER_SOURCE", "12")), 30))
    if per_source_limit == 0:
        return

    missing_by_source: dict[str, list[dict[str, Any]]] = {}
    for item in sorted(items, key=lambda value: str(value.get("published_at") or ""), reverse=True):
        source_id = str(item.get("source_id") or "")
        source = source_by_id.get(source_id)
        if (
            source is None
            or source.kind != "rss"
            or item.get("image_url")
            or _image_lookup_is_recent(str(item.get("image_checked_at") or ""))
        ):
            continue
        source_limit = min(per_source_limit, 2) if source.catalog == "chinese-security-rss" else per_source_limit
        bucket = missing_by_source.setdefault(source_id, [])
        if len(bucket) < source_limit and _article_url_allowed(str(item.get("url") or ""), source):
            bucket.append(item)

    candidates = [
        (item, source_by_id[source_id])
        for source_id, source_items in missing_by_source.items()
        for item in source_items
    ]
    global_limit = max(0, min(int(os.getenv("SECFLOW_INFORMATION_IMAGE_LOOKUPS_TOTAL", "60")), 200))
    candidates = candidates[:global_limit]
    if not candidates:
        return

    timeout = httpx.Timeout(
        float(os.getenv("SECFLOW_INFORMATION_IMAGE_TIMEOUT_SECONDS", "7")),
        connect=4.0,
    )
    headers = {
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        "User-Agent": "Mozilla/5.0 (Macintosh; Apple Silicon Mac OS X) SecFlow-Information/1.0",
    }
    workers = min(8, len(candidates))
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers, trust_env=False) as client:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="secflow-information-images") as pool:
            futures = {
                pool.submit(_fetch_article_image, client, item, source): item
                for item, source in candidates
            }
            for future in as_completed(futures):
                item = futures[future]
                try:
                    image_url = future.result()
                except Exception:  # noqa: BLE001 - one publisher page must not affect the feed.
                    image_url = ""
                item["image_checked_at"] = now_iso()
                if image_url:
                    item["image_url"] = image_url


def _image_lookup_is_recent(value: str) -> bool:
    if not value:
        return False
    try:
        checked_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    ttl = max(900, int(os.getenv("SECFLOW_INFORMATION_IMAGE_RETRY_SECONDS", "21600")))
    return (datetime.now(timezone.utc) - checked_at.astimezone(timezone.utc)).total_seconds() < ttl


def _fetch_article_image(
    client: httpx.Client,
    item: dict[str, Any],
    source: InformationSourceDefinition,
) -> str:
    response = client.get(str(item.get("url") or ""))
    response.raise_for_status()
    if not _article_url_allowed(str(response.url), source):
        return ""
    content_type = str(response.headers.get("content-type") or "").casefold()
    if "html" not in content_type or len(response.content) > 2_500_000:
        return ""
    return parse_article_image(response.text, str(response.url))


def _article_url_allowed(value: str, source: InformationSourceDefinition) -> bool:
    host = (urlsplit(value).hostname or "").casefold().rstrip(".")
    if not host:
        return False
    allowed_hosts = {
        (urlsplit(candidate).hostname or "").casefold().rstrip(".")
        for candidate in (source.url, source.website)
    }
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts if allowed)


def parse_article_image(payload: str, base_url: str) -> str:
    parser = _ArticleImageParser(base_url)
    try:
        parser.feed(payload)
        if not parser.best_url:
            embedded_images = re.findall(r"<img\b[^>]{1,2000}>", payload, flags=re.IGNORECASE)
            if embedded_images:
                fragments = "".join(
                    html.unescape(fragment).replace(r'\"', '"').replace(r"\'", "'")
                    for fragment in embedded_images[:80]
                )
                parser.feed(f'<article class="article-body">{fragments}</article>')
    except Exception:  # noqa: BLE001 - malformed publisher HTML should only lose its cover.
        return ""
    return parser.best_url


class _ArticleImageParser(HTMLParser):
    _void_elements = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
    _content_markers = ("article", "artical", "post", "content-detail", "article-body", "markdown-body", "entry-content")
    _excluded_markers = ("avatar", "badge", "comment", "footer", "header", "icon", "logo", "nav", "qrcode", "qr-code", "sidebar")

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.stack: list[tuple[str, str]] = []
        self.candidates: list[tuple[int, int, str]] = []
        self._index = 0

    @property
    def best_url(self) -> str:
        if not self.candidates:
            return ""
        return max(self.candidates, key=lambda candidate: (candidate[0], -candidate[1]))[2]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        attributes = {str(key).casefold(): str(value or "") for key, value in attrs}
        marker = " ".join([attributes.get("id", ""), attributes.get("class", "")]).casefold()
        context = " ".join(value for _, value in [*self.stack, (tag, marker)] if value)

        if tag == "meta":
            key = " ".join(
                [attributes.get("property", ""), attributes.get("name", ""), attributes.get("itemprop", "")]
            ).casefold()
            if key.strip() in {"og:image", "og:image:url", "twitter:image", "twitter:image:src", "image"}:
                self._add_candidate(attributes.get("content", ""), 1_000)
        elif tag == "img":
            raw_url = _image_attribute_url(attributes)
            score = 0
            if any(parent_tag == "article" for parent_tag, _ in self.stack):
                score += 300
            if any(term in context for term in self._content_markers):
                score += 220
            width = _positive_int(attributes.get("width", ""))
            height = _positive_int(attributes.get("height", ""))
            if width >= 300 or height >= 180:
                score += 80
            if attributes.get("alt", "").strip():
                score += 10
            excluded_text = f"{context} {raw_url}".casefold()
            if any(term in excluded_text for term in self._excluded_markers):
                score -= 500
            if raw_url.casefold().split("?", 1)[0].endswith((".svg", ".gif")):
                score -= 300
            if score >= 100:
                self._add_candidate(raw_url, score)

        self.stack.append((tag, marker))
        if tag in self._void_elements:
            self.stack.pop()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def _add_candidate(self, value: str, score: int) -> None:
        candidate = _safe_remote_url(urljoin(self.base_url, html.unescape(value).strip()))
        if not candidate:
            return
        self.candidates.append((score, self._index, candidate))
        self._index += 1


def _image_attribute_url(attributes: dict[str, str]) -> str:
    for name in ("src", "data-src", "data-original", "data-lazy-src"):
        if attributes.get(name, "").strip():
            return attributes[name].strip()
    srcset = attributes.get("srcset", "").strip()
    if not srcset:
        return ""
    final = srcset.split(",")[-1].strip()
    return final.split()[0] if final else ""


def _positive_int(value: str) -> int:
    match = re.match(r"\s*(\d+)", value)
    return int(match.group(1)) if match else 0


def _classify_category(title: str, summary: str, feed_categories: Any, fallback: str) -> str:
    categories = " ".join(str(item) for item in feed_categories or [])
    text = f"{title} {summary} {categories}".casefold()
    rules = (
        ("大模型", ("large language model", " llm", "gpt-", "chatgpt", "gemini", "claude", "prompt injection", "jailbreak", "大模型")),
        ("AI 安全", ("artificial intelligence", " ai ", "machine learning", "deepfake", "model security", "人工智能", "模型安全")),
        ("政策法规", ("regulation", "legislation", "compliance", "directive", "executive order", "gdpr", "policy", "法规", "合规", "政策")),
        ("数据安全", ("data breach", "data leak", "privacy", "personal data", "database exposure", "数据泄露", "隐私")),
        ("供应链安全", ("supply chain", "dependency confusion", "package repository", "npm", "pypi", "software bill of materials", "sbom", "供应链")),
        ("云安全", ("cloud security", "kubernetes", "container escape", "aws", "azure", "google cloud", "云安全", "容器逃逸")),
        ("攻击技术", ("ransomware", "phishing", "malware", "apt ", "botnet", "backdoor", "campaign", "threat actor", "攻击", "勒索", "钓鱼", "恶意软件")),
        ("漏洞披露", ("cve-", "vulnerability", "zero-day", "0-day", "exploit", "security advisory", "patch", "漏洞", "零日")),
    )
    for category, terms in rules:
        if any(term in text for term in terms):
            return category
    return fallback if fallback in CATEGORY_ORDER else "行业动态"


def _extract_tags(title: str, summary: str, provided: Any, category: str) -> list[str]:
    tags = [str(item).strip() for item in provided or [] if str(item).strip()]
    text = f"{title} {summary}".casefold()
    tag_rules = (
        ("AI 安全", ("artificial intelligence", " ai ", "machine learning", "ai safety")),
        ("LLM", (" llm", "large language model", "gpt-", "gemini", "claude")),
        ("CVE", ("cve-", "vulnerability")),
        ("零日漏洞", ("zero-day", "0-day", "zero day")),
        ("勒索软件", ("ransomware",)),
        ("数据泄露", ("data breach", "data leak")),
        ("云安全", ("cloud security", "kubernetes", "container")),
        ("供应链攻击", ("supply chain", "dependency confusion", "package repository")),
        ("隐私保护", ("privacy", "personal data", "gdpr")),
        ("APT", ("apt ", "advanced persistent threat", "threat actor")),
        ("钓鱼攻击", ("phishing",)),
    )
    for tag, terms in tag_rules:
        if any(term in text for term in terms):
            tags.append(tag)
    if category not in {"全部", "行业动态"}:
        tags.append(category)
    cve_matches = re.findall(r"CVE-\d{4}-\d{4,8}", f"{title} {summary}", flags=re.IGNORECASE)
    tags.extend(match.upper() for match in cve_matches[:2])
    return list(dict.fromkeys(tag for tag in tags if tag))[:8]


def _popular_tags(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in items:
        for tag in item.get("tags") or []:
            clean = str(tag).strip()
            if clean and not re.fullmatch(r"CVE-\d{4}-\d{4,8}", clean, flags=re.IGNORECASE):
                counts[clean] = counts.get(clean, 0) + 1
    return [
        {"name": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:14]
    ]


def _cache_is_stale(updated_at: str) -> bool:
    if not updated_at:
        return True
    try:
        parsed = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    ttl = max(60, int(os.getenv("SECFLOW_INFORMATION_CACHE_SECONDS", "900")))
    return (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() >= ttl


def _normalize_datetime(value: str, fallback: str) -> str:
    text = value.strip()
    if not text:
        return fallback
    parsed: datetime | None = None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.strptime(text[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _published_at_from_url(value: str) -> str:
    path = urlsplit(value).path
    match = re.search(r"(?:^|/)(20\d{2})/([01]\d)/([0-3]\d)(?:/|$)", path)
    if match is None:
        return ""
    try:
        parsed = datetime(*(int(part) for part in match.groups()), tzinfo=timezone.utc)
    except ValueError:
        return ""
    return parsed.replace(microsecond=0).isoformat()


def _entry_link(entry: ElementTree.Element) -> str:
    for node in entry:
        if _local_name(node.tag) != "link":
            continue
        href = str(node.attrib.get("href") or "").strip()
        rel = str(node.attrib.get("rel") or "alternate").strip()
        if href and rel in {"alternate", ""}:
            return href
        if str(node.text or "").strip():
            return str(node.text or "").strip()
    return _child_text(entry, "guid")


def _entry_author(entry: ElementTree.Element) -> str:
    author = next((node for node in entry if _local_name(node.tag) in {"author", "creator"}), None)
    if author is None:
        return ""
    name = next((node for node in author if _local_name(node.tag) == "name"), None)
    return str((name.text if name is not None else author.text) or "").strip()


def _entry_content_fragments(entry: ElementTree.Element) -> list[str]:
    fragments: list[str] = []
    for name in ("description", "summary", "content", "encoded"):
        for node in entry.iter():
            if _local_name(node.tag) != name:
                continue
            value = "".join(node.itertext()).strip()
            if value and value not in fragments:
                fragments.append(value)
    return fragments


def _feed_source_image(root: ElementTree.Element) -> str:
    container = root
    if _local_name(root.tag) != "feed":
        container = next((node for node in root if _local_name(node.tag) == "channel"), root)
    for node in container:
        local = _local_name(node.tag)
        if local == "image":
            value = str(node.attrib.get("url") or node.attrib.get("href") or _child_text(node, "url") or "").strip()
        elif local in {"icon", "logo"}:
            value = str(node.attrib.get("url") or node.attrib.get("href") or node.text or "").strip()
        else:
            continue
        candidate = _safe_remote_url(value)
        if candidate:
            return candidate
    return ""


def _entry_image(entry: ElementTree.Element, content_fragments: list[str], base_url: str) -> str:
    for node in entry.iter():
        local = _local_name(node.tag)
        url = str(node.attrib.get("url") or node.attrib.get("href") or "").strip()
        media_type = str(node.attrib.get("type") or "").lower()
        if url and (local == "thumbnail" or local == "content" or (local == "enclosure" and media_type.startswith("image/"))):
            candidate = _safe_remote_url(urljoin(base_url, html.unescape(url)))
            if candidate:
                return candidate
    if not content_fragments:
        return ""
    payload = '<article class="article-body">' + "\n".join(content_fragments) + "</article>"
    return parse_article_image(payload, base_url)


def _first_text(entry: ElementTree.Element, names: tuple[str, ...]) -> str:
    for name in names:
        value = _child_text(entry, name)
        if value:
            return value
    return ""


def _child_text(entry: ElementTree.Element, name: str) -> str:
    for node in entry.iter():
        if node is not entry and _local_name(node.tag) == name:
            return "".join(node.itertext()).strip()
    return ""


def _local_name(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1].split(":")[-1]


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())


def _plain_text(value: str, limit: int) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html.unescape(value))
        text = " ".join(parser.parts)
    except Exception:  # noqa: BLE001 - malformed publisher HTML falls back to stripping.
        text = re.sub(r"<[^>]+>", " ", value)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+([,.;:!?，。；：！？])", r"\1", text)
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)].rstrip() + "…"


def _canonical_url(value: str) -> str:
    clean = html.unescape(value).strip()
    if not clean.startswith(("http://", "https://")):
        return clean
    parts = urlsplit(clean)
    query = [
        (key, item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid", "mc_cid", "mc_eid"}
    ]
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, urlencode(query), ""))


def _safe_remote_url(value: str) -> str:
    clean = html.unescape(value).strip()
    try:
        parts = urlsplit(clean)
        port = parts.port
    except ValueError:
        return ""
    if (
        parts.scheme.casefold() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or port not in {None, 80, 443}
    ):
        return ""
    return clean


def _remote_url_is_public(value: str) -> bool:
    clean = _safe_remote_url(value)
    if not clean:
        return False
    host = (urlsplit(clean).hostname or "").casefold().rstrip(".")
    return _remote_host_is_public(host)


@lru_cache(maxsize=512)
def _remote_host_is_public(host: str) -> bool:
    clean = host.casefold().rstrip(".")
    if not clean or clean == "localhost" or clean.endswith((".localhost", ".local", ".internal")):
        return False
    try:
        return ipaddress.ip_address(clean).is_global
    except ValueError:
        pass
    try:
        addresses = {
            str(entry[4][0]).split("%", 1)[0]
            for entry in socket.getaddrinfo(clean, 443, type=socket.SOCK_STREAM)
            if entry[4]
        }
        return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)
    except (OSError, ValueError):
        return False


def _is_breaking(title: str, summary: str) -> bool:
    text = f"{title} {summary}".casefold()
    return any(term in text for term in ("actively exploited", "zero-day", "0-day", "critical vulnerability", "emergency", "在野利用", "紧急"))


def _category_id(name: str) -> str:
    mapping = {
        "全部": "all",
        "AI 安全": "ai-security",
        "大模型": "llm",
        "漏洞披露": "vulnerability",
        "数据安全": "data-security",
        "政策法规": "policy",
        "云安全": "cloud-security",
        "供应链安全": "supply-chain",
        "行业动态": "industry",
        "攻击技术": "attack-techniques",
    }
    return mapping.get(name, "industry")


def _compact_error(error: Exception) -> str:
    message = re.sub(r"\s+", " ", str(error)).strip()
    return message[:220] or error.__class__.__name__


information_service = InformationService()
