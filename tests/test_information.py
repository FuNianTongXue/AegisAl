from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic, sleep
from unittest.mock import patch

import app.information as information_module
from app.information import (
    CURATED_INFORMATION_SOURCES,
    INFORMATION_FEED_PARSER_VERSION,
    INFORMATION_SOURCES,
    MAX_ENABLED_OPML_SOURCES,
    InformationFetchResult,
    InformationService,
    parse_article_image,
    parse_feed,
    parse_kev,
)
from app.storage import default_state


class FakeStore:
    def __init__(self) -> None:
        self.state = default_state()

    def read(self):
        return deepcopy(self.state)

    def write(self, state):
        self.state = deepcopy(state)


class InformationServiceTests(unittest.TestCase):
    @staticmethod
    def state_with_only_enabled(source_id: str) -> dict:
        state = default_state()
        state["information"]["sources"] = {
            source.id: {"enabled": source.id == source_id}
            for source in INFORMATION_SOURCES
        }
        return state

    def test_bundled_opml_catalog_is_deduplicated_and_disabled_by_default(self) -> None:
        opml_sources = [source for source in INFORMATION_SOURCES if source.catalog == "chinese-security-rss"]
        urls = [source.url for source in INFORMATION_SOURCES]

        self.assertEqual(len(CURATED_INFORMATION_SOURCES), 3)
        self.assertEqual(len(opml_sources), 505)
        self.assertEqual(len(urls), len(set(urls)))
        self.assertTrue(all(not source.default_enabled for source in opml_sources))
        self.assertTrue(all(source.source_image_url for source in opml_sources))
        self.assertEqual(sum(source.group == "微信公众号" for source in opml_sources), 321)
        self.assertEqual(sum(source.group == "精选来源" for source in opml_sources), 5)
        self.assertTrue(
            all(source.max_response_bytes == 8_000_000 for source in opml_sources if source.group == "微信公众号")
        )
        xlab_atom = next(source for source in opml_sources if source.url == "https://xlab.tencent.com/cn/atom.xml")
        self.assertEqual(xlab_atom.source_image_url, "https://xlab.tencent.com/cn/favicon.png?v=1.1")

    def test_featured_sources_are_official_security_and_response_channels(self) -> None:
        featured = {source.name: source for source in INFORMATION_SOURCES if source.group == "精选来源"}

        self.assertEqual(
            set(featured),
            {
                "CISA 官方安全公告",
                "CISA 已知在野利用目录",
                "FreeBuf",
                "腾讯安全应急响应中心",
                "阿里云应急响应",
                "百度安全应急响应中心",
                "OPPO安全应急响应中心",
                "小米安全中心",
            },
        )
        self.assertEqual(featured["FreeBuf"].source_image_url, "https://www.freebuf.com/favicon.ico")
        self.assertEqual(featured["腾讯安全应急响应中心"].website, "https://security.tencent.com/")
        self.assertEqual(featured["阿里云应急响应"].source_image_url, "https://developer.aliyun.com/favicon.ico")
        self.assertEqual(featured["百度安全应急响应中心"].source_image_url, "https://bsrc.baidu.com/statics/imgs/favicon.ico")
        self.assertEqual(featured["小米安全中心"].source_image_url, "https://trust.mi.com/favicon.png")

    def test_meituan_source_uses_official_logo_and_image_cdn(self) -> None:
        source = next(source for source in INFORMATION_SOURCES if source.url == "https://tech.meituan.com/feed")

        self.assertEqual(
            source.source_image_url,
            "https://p0.meituan.net/meituantechblog/00c62e57b4c4a1f40b47d7152b3e54b511963.png",
        )
        self.assertEqual(source.image_hosts, ("meituan.net",))
        self.assertTrue(
            information_module._image_url_allowed(
                "https://p1.meituan.net/meituantechblog/article-cover.png",
                source,
            )
        )
        self.assertFalse(
            information_module._image_url_allowed(
                "https://untrusted.example/article-cover.png",
                source,
            )
        )

    def test_unreliable_vendor_favicons_use_controlled_official_brand_images(self) -> None:
        huawei = next(source for source in INFORMATION_SOURCES if source.name == "华为安全通告")
        seebug = next(source for source in INFORMATION_SOURCES if source.name == "Seebug漏洞社区")

        self.assertEqual(
            huawei.source_image_url,
            "https://cdn.simpleicons.org/huawei/E60012",
        )
        self.assertTrue(information_module._image_url_allowed(huawei.source_image_url, huawei))
        self.assertEqual(seebug.source_image_url, "https://www.knownsec.com/static/favicon.ico")
        self.assertTrue(information_module._image_url_allowed(seebug.source_image_url, seebug))

    def test_opml_source_selection_is_limited_to_fifty(self) -> None:
        fake_store = FakeStore()
        service = InformationService(fake_store, fetcher=lambda _source: [])
        opml_ids = [
            source.id
            for source in INFORMATION_SOURCES
            if source.catalog == "chinese-security-rss"
        ]

        enabled = service.set_sources_enabled(opml_ids[:MAX_ENABLED_OPML_SOURCES], True)
        self.assertEqual(len(enabled), MAX_ENABLED_OPML_SOURCES)
        with self.assertRaisesRegex(ValueError, "最多同时启用"):
            service.set_sources_enabled([opml_ids[MAX_ENABLED_OPML_SOURCES]], True)

    def test_snapshot_starts_one_nonblocking_background_refresh(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        started = Event()
        release = Event()
        calls = 0

        def slow_fetcher(_source):
            nonlocal calls
            calls += 1
            started.set()
            release.wait(timeout=2)
            return [
                {
                    "title": "Background security update",
                    "url": "https://example.test/background-update",
                    "summary": "A cached result becomes available without blocking the request.",
                }
            ]

        service = InformationService(fake_store, fetcher=slow_fetcher)
        requested_at = monotonic()
        first = service.snapshot()
        elapsed = monotonic() - requested_at

        self.assertLess(elapsed, 0.2)
        self.assertTrue(first["refreshing"])
        self.assertTrue(started.wait(timeout=1))
        second = service.request_refresh(force=True)
        self.assertTrue(second["refreshing"])
        self.assertEqual(calls, 1)

        release.set()
        deadline = monotonic() + 2
        while monotonic() < deadline and service._current_snapshot()["refreshing"]:
            sleep(0.01)
        completed = service.snapshot()

        self.assertFalse(completed["refreshing"])
        self.assertEqual(completed["available_total"], 1)
        self.assertEqual(calls, 1)

    def test_not_modified_response_preserves_cached_items_and_headers(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        fake_store.state["information"]["sources"]["freebuf"].update(
            etag='"old"',
            last_modified="Mon, 20 Jul 2026 00:00:00 GMT",
        )
        fake_store.state["information"]["items"] = [
            {
                "id": "news-cached",
                "source_id": "freebuf",
                "title": "Cached security article",
                "url": "https://example.test/cached",
                "published_at": "2026-07-20T00:00:00+00:00",
            }
        ]
        service = InformationService(
            fake_store,
            fetcher=lambda _source: InformationFetchResult(
                items=[],
                etag='"new"',
                last_modified="Tue, 21 Jul 2026 00:00:00 GMT",
                not_modified=True,
            ),
        )

        snapshot = service.refresh(force=True)

        self.assertEqual(snapshot["items"][0]["id"], "news-cached")
        status = fake_store.state["information"]["sources"]["freebuf"]
        self.assertEqual(status["etag"], '"new"')
        self.assertEqual(status["failure_count"], 0)
        self.assertIn("未变化", status["message"])

    def test_failure_backoff_skips_immediate_forced_retry_and_keeps_cache(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        fake_store.state["information"]["items"] = [
            {
                "id": "news-cached",
                "source_id": "freebuf",
                "title": "Cached security article",
                "url": "https://example.test/cached",
                "published_at": "2026-07-20T00:00:00+00:00",
            }
        ]
        calls = 0

        def failing_fetcher(_source):
            nonlocal calls
            calls += 1
            raise RuntimeError("temporary failure")

        service = InformationService(fake_store, fetcher=failing_fetcher)
        first = service.refresh(force=True)
        second = service.refresh(force=True)

        self.assertEqual(calls, 1)
        self.assertEqual(first["items"][0]["id"], "news-cached")
        self.assertEqual(second["items"][0]["id"], "news-cached")
        status = fake_store.state["information"]["sources"]["freebuf"]
        self.assertEqual(status["failure_count"], 1)
        self.assertTrue(status["next_retry_at"])
        self.assertEqual(status["feed_parser_version"], INFORMATION_FEED_PARSER_VERSION)

    def test_feed_upgrade_bypasses_historical_failure_backoff_once(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        fake_store.state["information"]["sources"]["freebuf"].update(
            status="error",
            failure_count=3,
            next_retry_at="2099-01-01T00:00:00+00:00",
            feed_parser_version=INFORMATION_FEED_PARSER_VERSION - 1,
        )
        calls = 0

        def fetcher(_source):
            nonlocal calls
            calls += 1
            return []

        service = InformationService(fake_store, fetcher=fetcher)

        service.refresh()

        status = fake_store.state["information"]["sources"]["freebuf"]
        self.assertEqual(calls, 1)
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["failure_count"], 0)
        self.assertEqual(status["next_retry_at"], "")
        self.assertEqual(status["feed_parser_version"], INFORMATION_FEED_PARSER_VERSION)

    def test_missing_feed_date_is_recovered_from_meituan_article_url(self) -> None:
        source = next(source for source in INFORMATION_SOURCES if source.url == "https://tech.meituan.com/feed")
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled(source.id)
        service = InformationService(
            fake_store,
            fetcher=lambda _source: [
                {
                    "title": "LongCat 2.0 Open Source",
                    "url": "https://tech.meituan.com/2026/07/12/LongCat-2.0-Open-source.html",
                    "summary": "",
                }
            ],
        )

        snapshot = service.refresh(force=True)

        self.assertEqual(snapshot["items"][0]["published_at"], "2026-07-12T00:00:00+00:00")

    def test_missing_feed_date_keeps_first_observed_timestamp_across_refreshes(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        service = InformationService(
            fake_store,
            fetcher=lambda _source: [
                {
                    "title": "Undated security research",
                    "url": "https://example.test/research/undated",
                    "summary": "",
                }
            ],
        )

        with patch.object(
            information_module,
            "now_iso",
            side_effect=["2026-07-26T01:00:00+00:00", "2026-07-27T01:00:00+00:00"],
        ):
            first = service.refresh(force=True)
            second = service.refresh(force=True)

        self.assertEqual(first["items"][0]["published_at"], "2026-07-26T01:00:00+00:00")
        self.assertEqual(second["items"][0]["published_at"], first["items"][0]["published_at"])

    def test_default_fetcher_receives_conditional_request_metadata(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        fake_store.state["information"]["sources"]["freebuf"].update(
            etag='"catalog-etag"',
            last_modified="Tue, 21 Jul 2026 00:00:00 GMT",
            feed_parser_version=INFORMATION_FEED_PARSER_VERSION,
        )
        service = InformationService(fake_store)

        with patch.object(
            information_module,
            "fetch_information_source",
            return_value=InformationFetchResult(items=[], not_modified=True),
        ) as fetch:
            service.refresh(force=True)

        fetch.assert_called_once()
        self.assertEqual(fetch.call_args.kwargs["etag"], '"catalog-etag"')
        self.assertEqual(fetch.call_args.kwargs["last_modified"], "Tue, 21 Jul 2026 00:00:00 GMT")

    def test_old_feed_parser_cache_is_refetched_without_validators_once(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        fake_store.state["information"]["sources"]["freebuf"].update(
            etag='"old-parser-etag"',
            last_modified="Tue, 21 Jul 2026 00:00:00 GMT",
        )
        service = InformationService(fake_store)

        with patch.object(
            information_module,
            "fetch_information_source",
            return_value=InformationFetchResult(items=[]),
        ) as fetch:
            service.refresh(force=True)

        self.assertEqual(fetch.call_args.kwargs["etag"], "")
        self.assertEqual(fetch.call_args.kwargs["last_modified"], "")
        status = fake_store.state["information"]["sources"]["freebuf"]
        self.assertEqual(status["feed_parser_version"], INFORMATION_FEED_PARSER_VERSION)

    def test_source_connection_test_records_error_without_raising(self) -> None:
        fake_store = FakeStore()
        service = InformationService(fake_store, fetcher=lambda _source: (_ for _ in ()).throw(RuntimeError("offline")))

        status = service.test_source("freebuf")

        self.assertEqual(status["status"], "error")
        self.assertEqual(status["failure_count"], 1)
        self.assertIn("offline", status["message"])

    def test_refresh_deduplicates_and_keeps_partial_results(self) -> None:
        fake_store = FakeStore()

        def fetcher(source):
            if source.id == "cisa_advisories":
                raise RuntimeError("temporary failure")
            return [
                {
                    "title": "Critical CVE-2026-12345 vulnerability is actively exploited",
                    "url": "https://example.test/advisory?utm_source=feed",
                    "summary": "A security patch is available.",
                    "published_at": "2026-07-19T00:00:00Z",
                }
            ]

        snapshot = InformationService(fake_store, fetcher=fetcher).refresh()

        self.assertEqual(snapshot["available_total"], 1)
        self.assertEqual(snapshot["items"][0]["category"], "漏洞披露")
        self.assertIn("CVE", snapshot["items"][0]["tags"])
        self.assertTrue(snapshot["partial"])
        self.assertNotIn("utm_source", snapshot["items"][0]["url"])

    def test_disabled_source_is_not_fetched(self) -> None:
        fake_store = FakeStore()
        called: list[str] = []

        def fetcher(source):
            called.append(source.id)
            return []

        service = InformationService(fake_store, fetcher=fetcher)
        service.set_source_enabled("freebuf", False)
        service.refresh()

        self.assertNotIn("freebuf", called)
        self.assertFalse(fake_store.state["information"]["sources"]["freebuf"]["enabled"])

    def test_source_toggle_clears_failure_backoff_and_reenabled_source_refreshes_immediately(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        fake_store.state["information"]["sources"]["freebuf"].update(
            status="error",
            failure_count=3,
            next_retry_at="2099-01-01T00:00:00+00:00",
            last_checked="2026-07-27T00:00:00+00:00",
            message="certificate failure",
        )
        called: list[str] = []
        service = InformationService(fake_store, fetcher=lambda source: called.append(source.id) or [])

        disabled = service.set_source_enabled("freebuf", False)
        enabled = service.set_source_enabled("freebuf", True)
        service.refresh()

        self.assertEqual(disabled["status"], "idle")
        self.assertEqual(disabled["failure_count"], 0)
        self.assertEqual(disabled["next_retry_at"], "")
        self.assertEqual(enabled["last_checked"], "")
        self.assertEqual(called, ["freebuf"])

    def test_snapshot_migrates_stale_error_state_for_already_disabled_source(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        disabled_source = next(
            source
            for source in INFORMATION_SOURCES
            if source.catalog == "chinese-security-rss" and source.group != "精选来源"
        )
        fake_store.state["information"]["sources"][disabled_source.id].update(
            status="error",
            failure_count=4,
            next_retry_at="2099-01-01T00:00:00+00:00",
            message="old timeout",
        )

        snapshot = InformationService(fake_store, fetcher=lambda _source: [])._current_snapshot()
        migrated = next(source for source in snapshot["sources"] if source["id"] == disabled_source.id)

        self.assertEqual(migrated["status"], "idle")
        self.assertEqual(migrated["failure_count"], 0)
        self.assertEqual(migrated["next_retry_at"], "")
        self.assertEqual(migrated["message"], "已暂停订阅。")

    def test_information_transport_uses_system_trust_and_extended_timeouts(self) -> None:
        timeout = information_module._information_request_timeout()
        context = information_module._system_ssl_context()

        self.assertEqual(timeout.connect, 6.0)
        self.assertEqual(timeout.read, 18.0)
        self.assertEqual(type(context).__module__, "truststore._api")

    def test_information_uses_source_text_and_ignores_old_translation_failures(self) -> None:
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled("freebuf")
        fake_store.state["information"]["items"] = [
            {
                "id": "news-original",
                "source_id": "freebuf",
                "source_name": "FreeBuf",
                "title": "企业漏洞优先级怎么排？",
                "summary": "结合资产与在野利用情况确定修复顺序。",
                "title_original": "企业漏洞优先级怎么排？",
                "summary_original": "结合资产与在野利用情况确定修复顺序。",
                "url": "https://example.test/original",
                "published_at": "2026-08-20T00:00:00+00:00",
                "information_translation": {
                    "version": 1,
                    "languages": {"zh-Hans": {"status": "failed"}},
                },
            }
        ]

        snapshot = InformationService(fake_store, fetcher=lambda _source: [])._current_snapshot(
            response_language="zh-Hans"
        )
        prepared = information_module._prepare_information_item(
            fake_store.state["information"]["items"][0]
        )

        self.assertEqual(snapshot["items"][0]["title"], "企业漏洞优先级怎么排？")
        self.assertEqual(snapshot["items"][0]["summary"], "结合资产与在野利用情况确定修复顺序。")
        self.assertNotIn("translation_status", snapshot["items"][0])
        self.assertNotIn("translation_status", snapshot)
        self.assertNotIn("information_translation", prepared)

    def test_https_feed_redirect_cannot_downgrade_transport(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            information_module._reject_https_downgrade(
                "https://security.example/feed",
                "http://security.example/feed",
            )

    def test_rss_and_atom_fields_are_parsed_structurally(self) -> None:
        rss = b"""<?xml version='1.0'?><rss><channel><item>
        <title>Security advisory</title><link>https://example.test/a</link>
        <description><![CDATA[<p>Patch <b>now</b>.</p><img src='https://example.test/a.jpg'>]]></description>
        <pubDate>Sun, 19 Jul 2026 10:00:00 GMT</pubDate></item></channel></rss>"""

        items = parse_feed(rss)

        self.assertEqual(items[0]["title"], "Security advisory")
        self.assertEqual(items[0]["summary"], "Patch now.")
        self.assertEqual(items[0]["image_url"], "https://example.test/a.jpg")

    def test_rss_uses_encoded_article_image_and_channel_logo(self) -> None:
        rss = b"""<?xml version='1.0'?><rss xmlns:content='http://purl.org/rss/1.0/modules/content/'>
        <channel><image><url>https://wx.qlogo.cn/publisher/0</url></image><item>
        <title>Security advisory</title><link>https://mp.weixin.qq.com/s/example</link>
        <description>Summary without an image.</description>
        <content:encoded><![CDATA[<p><img data-src='https://mmbiz.qpic.cn/cover.jpg'></p>]]></content:encoded>
        </item></channel></rss>"""

        items = parse_feed(rss)

        self.assertEqual(items[0]["image_url"], "https://mmbiz.qpic.cn/cover.jpg")
        self.assertEqual(items[0]["source_image_url"], "https://wx.qlogo.cn/publisher/0")

    def test_snapshot_reuses_real_vendor_logo_for_older_source_items(self) -> None:
        source = next(item for item in INFORMATION_SOURCES if item.name == "数世咨询")
        generic_logo = "https://wechat2rss.xlab.app/favicon.ico"
        vendor_logo = "https://wx.qlogo.cn/mmhead/vendor-avatar/0"
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled(source.id)
        info = fake_store.state["information"]
        info["items"] = [
            {
                "id": "news-old",
                "source_id": source.id,
                "source_name": source.name,
                "title": "Older item",
                "url": "https://mp.weixin.qq.com/s/old",
                "image_url": "",
                "source_image_url": generic_logo,
                "published_at": "2026-07-21T00:00:00+00:00",
                "category": "行业动态",
                "tags": [],
            },
            {
                "id": "news-new",
                "source_id": source.id,
                "source_name": source.name,
                "title": "New item",
                "url": "https://mp.weixin.qq.com/s/new",
                "image_url": "https://mmbiz.qpic.cn/cover.jpg",
                "source_image_url": vendor_logo,
                "published_at": "2026-07-22T00:00:00+00:00",
                "category": "行业动态",
                "tags": [],
            },
        ]

        snapshot = information_module._build_snapshot(
            info,
            query="",
            category="全部",
            sort="latest",
            limit=20,
        )

        self.assertEqual({item["source_image_url"] for item in snapshot["items"]}, {vendor_logo})

    def test_image_loader_prefers_real_vendor_logo_over_generic_feed_icon(self) -> None:
        source = next(item for item in INFORMATION_SOURCES if item.name == "代码卫士")
        generic_logo = "https://wechat2rss.xlab.app/favicon.ico"
        vendor_logo = "https://wx.qlogo.cn/mmhead/vendor-avatar/0"
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled(source.id)
        fake_store.state["information"]["items"] = [
            {
                "id": "news-target",
                "source_id": source.id,
                "image_url": "",
                "source_image_url": generic_logo,
            },
            {
                "id": "news-with-logo",
                "source_id": source.id,
                "image_url": "",
                "source_image_url": vendor_logo,
            },
        ]
        downloaded_urls: list[str] = []

        def fake_download(image_url, kind, _source):
            downloaded_urls.append(image_url)
            return information_module.InformationImageResult(
                data=b"logo",
                content_type="image/png",
                kind=kind,
                etag="test",
            )

        with (
            patch.object(information_module, "store", fake_store),
            patch.object(information_module, "_read_cached_information_source_logo", return_value=None),
            patch.object(
                information_module,
                "_write_cached_information_source_logo",
                side_effect=lambda _source_id, result, _cache_version: result,
            ),
            patch.object(information_module, "_read_cached_information_image", return_value=None),
            patch.object(information_module, "_download_information_image", side_effect=fake_download),
        ):
            result = information_module.load_information_image("news-target")

        self.assertEqual(result.kind, "source")
        self.assertEqual(downloaded_urls, [vendor_logo])

    def test_source_logo_loader_is_shared_across_items_from_same_vendor(self) -> None:
        source = next(item for item in INFORMATION_SOURCES if item.name == "代码卫士")
        generic_logo = "https://wechat2rss.xlab.app/favicon.ico"
        vendor_logo = "https://wx.qlogo.cn/mmhead/vendor-avatar/0"
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled(source.id)
        fake_store.state["information"]["items"] = [
            {
                "id": "news-with-generic-logo",
                "source_id": source.id,
                "source_image_url": generic_logo,
            },
            {
                "id": "news-with-vendor-logo",
                "source_id": source.id,
                "source_image_url": vendor_logo,
            },
        ]
        downloaded_urls: list[str] = []

        def fake_download(image_url, kind, _source):
            downloaded_urls.append(image_url)
            return information_module.InformationImageResult(
                data=b"vendor-logo",
                content_type="image/png",
                kind=kind,
                etag="source-logo",
            )

        with (
            patch.object(information_module, "store", fake_store),
            patch.object(information_module, "_read_cached_information_source_logo", return_value=None),
            patch.object(
                information_module,
                "_write_cached_information_source_logo",
                side_effect=lambda _source_id, result, _cache_version: result,
            ),
            patch.object(information_module, "_read_cached_information_image", return_value=None),
            patch.object(information_module, "_download_information_image", side_effect=fake_download),
        ):
            result = information_module.load_information_source_image(source.id)

        self.assertEqual(result.kind, "source")
        self.assertEqual(downloaded_urls, [vendor_logo])

    def test_item_without_cover_falls_back_to_meituan_official_logo(self) -> None:
        source = next(source for source in INFORMATION_SOURCES if source.url == "https://tech.meituan.com/feed")
        fake_store = FakeStore()
        fake_store.state = self.state_with_only_enabled(source.id)
        fake_store.state["information"]["items"] = [
            {
                "id": "news-without-cover",
                "source_id": source.id,
                "image_url": "",
                "source_image_url": source.source_image_url,
            }
        ]
        downloaded_urls: list[str] = []

        def fake_download(image_url, kind, _source):
            downloaded_urls.append(image_url)
            return information_module.InformationImageResult(
                data=b"meituan-logo",
                content_type="image/png",
                kind=kind,
                etag="meituan-logo",
            )

        with (
            patch.object(information_module, "store", fake_store),
            patch.object(information_module, "_read_cached_information_source_logo", return_value=None),
            patch.object(
                information_module,
                "_write_cached_information_source_logo",
                side_effect=lambda _source_id, result, _cache_version: result,
            ),
            patch.object(information_module, "_read_cached_information_image", return_value=None),
            patch.object(information_module, "_download_information_image", side_effect=fake_download),
        ):
            result = information_module.load_information_image("news-without-cover")

        self.assertEqual(result.kind, "source")
        self.assertEqual(downloaded_urls, [source.source_image_url])

    def test_source_logo_parser_prefers_declared_touch_icon(self) -> None:
        parser = information_module._SourceLogoParser("https://security.example/")
        parser.feed(
            """<html><head>
            <link rel="icon" href="/favicon.ico" sizes="32x32">
            <link rel="apple-touch-icon" href="https://cdn.example/logo-180.png" sizes="180x180">
            </head></html>"""
        )

        self.assertEqual(parser.urls[0], "https://cdn.example/logo-180.png")
        self.assertIn("https://security.example/favicon.ico", parser.urls)

    def test_remote_image_fallback_rejects_private_hosts_and_ports(self) -> None:
        self.assertFalse(information_module._remote_url_is_public("http://127.0.0.1/logo.png"))
        self.assertFalse(information_module._remote_url_is_public("http://169.254.169.254/latest/meta-data"))
        self.assertFalse(information_module._remote_url_is_public("https://8.8.8.8:8443/logo.png"))
        self.assertTrue(information_module._remote_url_is_public("https://8.8.8.8/logo.png"))

    def test_image_signature_validation_rejects_html_disguised_as_favicon(self) -> None:
        self.assertFalse(information_module._looks_like_information_image(b"<!DOCTYPE html>", "image/x-icon"))
        self.assertTrue(
            information_module._looks_like_information_image(
                b"\x00\x00\x01\x00\x01\x00favicon-data",
                "image/x-icon",
            )
        )
        self.assertTrue(
            information_module._looks_like_information_image(
                b"\x89PNG\r\n\x1a\nimage-data",
                "image/png",
            )
        )

    def test_source_logo_disk_cache_is_shared_by_source(self) -> None:
        result = information_module.InformationImageResult(
            data=b"company-logo",
            content_type="image/png",
            kind="source",
            etag="remote",
        )
        with TemporaryDirectory() as directory, patch.object(
            information_module,
            "INFORMATION_SOURCE_LOGO_CACHE_DIR",
            Path(directory),
        ):
            saved = information_module._write_cached_information_source_logo("company-source", result)
            loaded = information_module._read_cached_information_source_logo("company-source")
            stale = information_module._read_cached_information_source_logo("company-source", "new-logo-url")

        self.assertEqual(saved.kind, "source")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.data, b"company-logo")
        self.assertEqual(loaded.content_type, "image/png")
        self.assertIsNone(stale)

    def test_article_image_prefers_open_graph_metadata(self) -> None:
        html = """<html><head>
        <meta content='/covers/advisory.jpg' property='og:image'>
        </head><body><article><img src='/content/detail.png' width='800'></article></body></html>"""

        image_url = parse_article_image(html, "https://example.test/posts/1")

        self.assertEqual(image_url, "https://example.test/covers/advisory.jpg")

    def test_article_image_uses_main_content_and_ignores_navigation_logo(self) -> None:
        html = """<html><body>
        <nav><img src='/logo.png' width='900' alt='Logo'></nav>
        <div class='markdown-body article-body'><p><img data-src='/images/finding.png' width='640'></p></div>
        </body></html>"""

        image_url = parse_article_image(html, "https://example.test/advisory")

        self.assertEqual(image_url, "https://example.test/images/finding.png")

    def test_article_image_reads_ssr_embedded_html(self) -> None:
        html = """<html><body><script>window.__STATE__ = {
        "content": "<p><img src=\\"https://cdn.example.test/finding.jpg\\" alt=\\"image\\"></p>"
        };</script></body></html>"""

        image_url = parse_article_image(html, "https://example.test/advisory")

        self.assertEqual(image_url, "https://cdn.example.test/finding.jpg")

    def test_information_image_disk_cache_keeps_data_and_mime_separate(self) -> None:
        with TemporaryDirectory() as directory, patch.object(
            information_module,
            "INFORMATION_IMAGE_CACHE_DIR",
            Path(directory),
        ):
            saved = information_module._write_cached_information_image(
                "https://example.test/image.png",
                b"test-image-bytes",
                "image/png",
                "article",
            )
            loaded = information_module._read_cached_information_image(
                "https://example.test/image.png",
                "article",
            )

        self.assertEqual(saved.data, b"test-image-bytes")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.data, b"test-image-bytes")
        self.assertEqual(loaded.content_type, "image/png")

    def test_kev_adapter_builds_actionable_items(self) -> None:
        items = parse_kev(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-1111",
                        "vulnerabilityName": "Example flaw",
                        "shortDescription": "Actively exploited.",
                        "requiredAction": "Apply the update.",
                        "dateAdded": "2026-07-18",
                        "vendorProject": "Example",
                        "product": "Widget",
                    }
                ]
            }
        )

        self.assertIn("CVE-2026-1111", items[0]["title"])
        self.assertIn("Apply the update", items[0]["summary"])
        self.assertTrue(items[0]["breaking"])


if __name__ == "__main__":
    unittest.main()
