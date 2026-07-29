from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
import re
import sqlite3
import time as monotonic_time
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from copy import deepcopy
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from threading import Event, RLock, Thread
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from app.collectors import (
    _github_cvss_score,
    _github_version_facts,
    _nvd_affected_versions,
    _nvd_cvss_score,
    _nvd_modern_components,
    _nvd_record,
    _nvd_severity,
)
from app.llm import active_model_from_env, diagnose_chat_completion
from app.privacy import sanitize_public_text, severity_cn
from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text, secure_metadata_key
from app.storage import DATA_DIR, now_iso, store
from app.intelligence_runtime import default_headers, intelligence_endpoint


VULNERABILITY_ID = re.compile(r"\b(?:CVE-\d{4}-\d{4,8}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.I)
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I)
GHSA_ID = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.I)
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_FIXED_SOURCE_ORDER = ["nvd", "github_advisory", "osv"]
_BATCH_INTERVAL_SECONDS = 15 * 60
_BATCH_LOOKBACK_DAYS = 7
_BATCH_LIMIT = 500
_CATALOG_SCHEMA_VERSION = "4"
_CATALOG_RECORD_PURPOSE = "secflow-vulnerability-catalog-record"
_DEPENDENCY_LOOKUP_BUDGET_SECONDS = 12.0
_DEPENDENCY_TOTAL_BUDGET_SECONDS = 8.0
_DEPENDENCY_REQUEST_TIMEOUT_SECONDS = 8.0
_DEPENDENCY_DETAIL_TIMEOUT_SECONDS = 3.5
_DEPENDENCY_RECORD_LIMIT = 5
_DEPENDENCY_QUERY_LIMIT = 12
_REALTIME_QUERY_BUDGET_SECONDS = 10.0
_DASHBOARD_REFRESH_BUDGET_SECONDS = 20.0
_OSV_BATCH_BUDGET_SECONDS = 8.0
_PATCH_ENRICHMENT_BUDGET_SECONDS = 4.0
_PATCH_ENRICHMENT_MAX_COMMITS = 3
_RECORD_NORMALIZATION_VERSION = 2
_COMPONENT_EXPORT_RECORD_LIMIT = 25_000
_COMPONENT_GRAPH_RECORD_LIMIT = 80
_COMPONENT_REALTIME_RECORD_LIMIT = 1_000
_GITHUB_BATCH_PAGE_SIZE = 100
_GITHUB_BATCH_MAX_PAGES = 50
_GITHUB_BATCH_MAX_RECORDS = 5_000
_GITHUB_BATCH_BUDGET_SECONDS = 18.0


def _collect_futures_with_budget(futures: dict[Any, Any], budget_seconds: float) -> tuple[list[tuple[Any, Any]], list[Any]]:
    """Collect completed futures until a hard budget expires without waiting for stragglers."""

    if not futures:
        return [], []
    pending = set(futures)
    completed: list[tuple[Any, Any]] = []
    deadline = monotonic_time.monotonic() + max(0.0, float(budget_seconds))
    while pending:
        remaining = deadline - monotonic_time.monotonic()
        if remaining <= 0:
            break
        done, pending = wait(pending, timeout=min(0.25, remaining), return_when=FIRST_COMPLETED)
        if not done:
            continue
        for future in done:
            key = futures[future]
            try:
                completed.append((key, future.result()))
            except Exception as exc:  # noqa: BLE001 - callers convert one task failure into partial results.
                completed.append((key, exc))
    timed_out: list[Any] = []
    for future in pending:
        timed_out.append(futures[future])
        future.cancel()
    return completed, timed_out


def _catalog_timestamp(record: dict[str, Any]) -> str:
    value = str(record.get("published_at") or "").strip()
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except ValueError:
        return value


def _transient_feed_name(label: str) -> str:
    digest = hashlib.sha256(f"secflow-feed:{label}".encode("utf-8")).hexdigest()
    return f"{digest[:32]}.cache"


class _VulnerabilityCatalog:
    """Persistent, deduplicated dashboard index used for cumulative and range counts."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    canonical_id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    record_date TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_record_date
                    ON vulnerabilities(record_date);
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
                    ON vulnerabilities(severity);
                CREATE TABLE IF NOT EXISTS vulnerability_aliases (
                    alias TEXT PRIMARY KEY,
                    canonical_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vulnerability_components (
                    component_key TEXT NOT NULL,
                    canonical_id TEXT NOT NULL,
                    PRIMARY KEY(component_key, canonical_id)
                );
                CREATE INDEX IF NOT EXISTS idx_vulnerability_components_key
                    ON vulnerability_components(component_key);
                CREATE TABLE IF NOT EXISTS catalog_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            row = connection.execute("SELECT value FROM catalog_metadata WHERE key = 'schema_version'").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO catalog_metadata(key, value) VALUES ('schema_version', ?)",
                    (_CATALOG_SCHEMA_VERSION,),
                )
                self._set_metadata_in_connection(connection, "record_encryption_migration_status", "complete")
            elif str(row["value"]) != _CATALOG_SCHEMA_VERSION:
                self._migrate_catalog_metadata(connection)
                connection.execute(
                    "INSERT OR REPLACE INTO catalog_metadata(key, value) VALUES ('schema_version', ?)",
                    (_CATALOG_SCHEMA_VERSION,),
                )
                self._set_metadata_in_connection(connection, "record_encryption_migration_status", "pending")
                self._set_metadata_in_connection(connection, "record_encryption_migration_cursor", "")

    def _migrate_catalog_metadata(self, connection: sqlite3.Connection) -> None:
        metadata_rows = connection.execute("SELECT key, value FROM catalog_metadata WHERE key <> 'schema_version'").fetchall()
        for row in metadata_rows:
            old_key = str(row["key"])
            secure_key = old_key if old_key.startswith("m:") else secure_metadata_key(old_key)
            value = self._decode_metadata_value(old_key, str(row["value"]))
            connection.execute(
                "INSERT OR REPLACE INTO catalog_metadata(key, value) VALUES (?, ?)",
                (secure_key, self._encode_metadata_value(secure_key, value)),
            )
            if old_key != secure_key:
                connection.execute("DELETE FROM catalog_metadata WHERE key = ?", (old_key,))

    def encryption_migration_pending(self) -> bool:
        return self.metadata("record_encryption_migration_status") == "pending"

    def migrate_encrypted_catalog_incrementally(
        self,
        stop: Event,
        *,
        batch_size: int = 100,
        pause_seconds: float = 0.02,
    ) -> None:
        """Encrypt legacy rows in bounded transactions without blocking service startup."""

        if not self.encryption_migration_pending():
            return
        cursor = self.metadata("record_encryption_migration_cursor")
        while not stop.is_set():
            with self._lock, self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT canonical_id, record_json
                    FROM vulnerabilities
                    WHERE canonical_id > ?
                    ORDER BY canonical_id
                    LIMIT ?
                    """,
                    (cursor, max(1, min(int(batch_size), 500))),
                ).fetchall()
                if not rows:
                    self._set_metadata_in_connection(connection, "record_encryption_migration_status", "complete")
                    self._set_metadata_in_connection(connection, "record_encryption_migration_cursor", "")
                    return

                updates: list[tuple[str, str]] = []
                for row in rows:
                    raw = str(row["record_json"])
                    if not raw.lstrip().startswith('{"__secflow_encrypted__"'):
                        updates.append((self._encode_record(self._decode_record(raw)), str(row["canonical_id"])))
                if updates:
                    connection.executemany(
                        "UPDATE vulnerabilities SET record_json = ? WHERE canonical_id = ?",
                        updates,
                    )
                cursor = str(rows[-1]["canonical_id"])
                self._set_metadata_in_connection(connection, "record_encryption_migration_cursor", cursor)
            if stop.wait(max(0.0, float(pause_seconds))):
                return

    def _set_metadata_in_connection(self, connection: sqlite3.Connection, key: str, value: str) -> None:
        secure_key = secure_metadata_key(key)
        connection.execute(
            "INSERT OR REPLACE INTO catalog_metadata(key, value) VALUES (?, ?)",
            (secure_key, self._encode_metadata_value(secure_key, value)),
        )
        if secure_key != key:
            connection.execute("DELETE FROM catalog_metadata WHERE key = ?", (key,))

    def upsert(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        with self._lock, self._connect() as connection:
            for incoming in records:
                aliases = {
                    str(value or "").upper()
                    for value in [incoming.get("id"), *incoming.get("aliases", [])]
                    if value
                }
                existing_ids: set[str] = set()
                if aliases:
                    placeholders = ",".join("?" for _ in aliases)
                    rows = connection.execute(
                        f"SELECT canonical_id FROM vulnerability_aliases WHERE alias IN ({placeholders})",
                        tuple(aliases),
                    ).fetchall()
                    existing_ids.update(str(row["canonical_id"]) for row in rows)

                existing: list[dict[str, Any]] = []
                if existing_ids:
                    placeholders = ",".join("?" for _ in existing_ids)
                    rows = connection.execute(
                        f"SELECT record_json FROM vulnerabilities WHERE canonical_id IN ({placeholders})",
                        tuple(existing_ids),
                    ).fetchall()
                    existing = [self._decode_record(str(row["record_json"])) for row in rows]

                merged = _records_by_canonical_vulnerability_id([*existing, incoming])
                if not merged:
                    continue
                record = _catalog_record(merged[0])
                canonical_id = _canonical_vulnerability_id(record)
                record["id"] = canonical_id
                record_aliases = {
                    str(value or "").upper()
                    for value in [canonical_id, *record.get("aliases", [])]
                    if value
                }

                for old_id in existing_ids - {canonical_id}:
                    connection.execute("DELETE FROM vulnerabilities WHERE canonical_id = ?", (old_id,))
                    connection.execute("DELETE FROM vulnerability_aliases WHERE canonical_id = ?", (old_id,))
                    connection.execute("DELETE FROM vulnerability_components WHERE canonical_id = ?", (old_id,))

                connection.execute(
                    """
                    INSERT INTO vulnerabilities(canonical_id, severity, record_date, updated_at, record_json)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(canonical_id) DO UPDATE SET
                        severity = excluded.severity,
                        record_date = excluded.record_date,
                        updated_at = excluded.updated_at,
                        record_json = excluded.record_json
                    """,
                    (
                        canonical_id,
                        str(record.get("severity") or "UNKNOWN").upper(),
                        _catalog_timestamp(record),
                        str(record.get("updated_at") or now_iso()),
                        self._encode_record(record),
                    ),
                )
                connection.execute("DELETE FROM vulnerability_aliases WHERE canonical_id = ?", (canonical_id,))
                connection.executemany(
                    "INSERT OR REPLACE INTO vulnerability_aliases(alias, canonical_id) VALUES (?, ?)",
                    [(alias, canonical_id) for alias in record_aliases],
                )
                connection.execute("DELETE FROM vulnerability_components WHERE canonical_id = ?", (canonical_id,))
                component_keys = _record_component_keys(record)
                if component_keys:
                    connection.executemany(
                        "INSERT OR REPLACE INTO vulnerability_components(component_key, canonical_id) VALUES (?, ?)",
                        [(component_key, canonical_id) for component_key in component_keys],
                    )
            connection.execute(
                "INSERT OR REPLACE INTO catalog_metadata(key, value) VALUES (?, ?)",
                (secure_metadata_key("last_sync"), self._encode_metadata_value(secure_metadata_key("last_sync"), now_iso())),
            )

    def find_by_identifier(self, identifier: str, limit: int = 10) -> list[dict[str, Any]]:
        clean = str(identifier or "").strip().upper()
        if not clean:
            return []
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT v.record_json
                FROM vulnerability_aliases a
                JOIN vulnerabilities v ON v.canonical_id = a.canonical_id
                WHERE a.alias = ?
                ORDER BY v.record_date DESC, v.updated_at DESC
                LIMIT ?
                """,
                (clean, max(1, int(limit))),
            ).fetchall()
        return [self._decode_record(str(row["record_json"])) for row in rows]

    def find_by_dependencies(self, dependencies: list[dict[str, Any]], limit: int = 30) -> list[dict[str, Any]]:
        key_to_dependency: dict[str, dict[str, Any]] = {}
        for dependency in dependencies:
            for key in _dependency_component_keys(dependency):
                key_to_dependency.setdefault(key, dependency)
        if not key_to_dependency:
            return []
        keys = list(key_to_dependency)
        with self._connect() as connection:
            placeholders = ",".join("?" for _ in keys)
            rows = connection.execute(
                f"""
                SELECT DISTINCT v.record_json, c.component_key
                FROM vulnerability_components c
                JOIN vulnerabilities v ON v.canonical_id = c.canonical_id
                WHERE c.component_key IN ({placeholders})
                ORDER BY v.record_date DESC, v.updated_at DESC
                LIMIT ?
                """,
                (*keys, max(100, int(limit) * 5)),
            ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            record = self._decode_record(str(row["record_json"]))
            dependency = key_to_dependency.get(str(row["component_key"]) or "")
            if dependency and _record_affects_dependency(record, dependency):
                record = _tag_dependency_record(record, dependency)
                records.append(record)
            if len(records) >= max(1, int(limit)):
                break
        return _records_by_canonical_vulnerability_id(_merge_records(records))

    def find_component_vulnerabilities(
        self,
        name: str,
        version: str,
        ecosystem: str = "",
        *,
        limit: int = _COMPONENT_EXPORT_RECORD_LIMIT,
    ) -> tuple[list[dict[str, Any]], list[str], bool]:
        clean_name = re.sub(r"\s+", " ", str(name or "").strip().lower())
        clean_ecosystem = re.sub(r"\s+", " ", str(ecosystem or "").strip().lower())
        clean_version = str(version or "").strip()
        if not clean_name or not _is_concrete_dependency_version(clean_version):
            return [], [], False
        safe_limit = max(1, min(int(limit), _COMPONENT_EXPORT_RECORD_LIMIT))
        with self._connect() as connection:
            if clean_ecosystem:
                rows = connection.execute(
                    """
                    SELECT DISTINCT v.record_json, c.component_key
                    FROM vulnerability_components c
                    JOIN vulnerabilities v ON v.canonical_id = c.canonical_id
                    WHERE c.component_key = ?
                    ORDER BY v.record_date DESC, v.updated_at DESC
                    LIMIT ?
                    """,
                    (_component_key(clean_ecosystem, clean_name), safe_limit * 5 + 1),
                ).fetchall()
            else:
                escaped_name = clean_name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                rows = connection.execute(
                    """
                    SELECT DISTINCT v.record_json, c.component_key
                    FROM vulnerability_components c
                    JOIN vulnerabilities v ON v.canonical_id = c.canonical_id
                    WHERE c.component_key LIKE ? ESCAPE '\\'
                    ORDER BY v.record_date DESC, v.updated_at DESC
                    LIMIT ?
                    """,
                    (f"%|{escaped_name}", safe_limit * 5 + 1),
                ).fetchall()
        ecosystems: set[str] = set()
        records: list[dict[str, Any]] = []
        for row in rows:
            component_key = str(row["component_key"] or "")
            matched_ecosystem, _, _ = component_key.partition("|")
            if not matched_ecosystem:
                continue
            ecosystems.add(matched_ecosystem)
            dependency = {
                "ecosystem": clean_ecosystem or matched_ecosystem,
                "name": clean_name,
                "version": clean_version,
            }
            record = self._decode_record(str(row["record_json"]))
            if _record_affects_dependency(record, dependency):
                records.append(_tag_dependency_record(record, dependency))
        merged = _records_by_canonical_vulnerability_id(_merge_records(records))
        truncated = len(merged) > safe_limit or len(rows) > safe_limit * 5
        return merged[:safe_limit], sorted(ecosystems), truncated

    def metadata(self, key: str, default: str = "") -> str:
        secure_key = secure_metadata_key(key)
        with self._connect() as connection:
            row = connection.execute("SELECT key, value FROM catalog_metadata WHERE key = ?", (secure_key,)).fetchone()
            if row is None and secure_key != key:
                row = connection.execute("SELECT key, value FROM catalog_metadata WHERE key = ?", (key,)).fetchone()
        return self._decode_metadata_value(str(row["key"]), str(row["value"])) if row else default

    def set_metadata(self, key: str, value: str) -> None:
        secure_key = secure_metadata_key(key)
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO catalog_metadata(key, value) VALUES (?, ?)",
                (secure_key, self._encode_metadata_value(secure_key, value)),
            )
            if secure_key != key:
                connection.execute("DELETE FROM catalog_metadata WHERE key = ?", (key,))

    def snapshot(self, *, start: datetime | None = None, end: datetime | None = None) -> dict[str, Any]:
        clauses: list[str] = []
        values: list[str] = []
        if start is not None:
            clauses.append("record_date >= ?")
            values.append(start.astimezone(timezone.utc).replace(microsecond=0).isoformat())
        if end is not None:
            clauses.append("record_date < ?")
            values.append(end.astimezone(timezone.utc).replace(microsecond=0).isoformat())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

        severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        with self._connect() as connection:
            total = int(connection.execute(f"SELECT COUNT(*) FROM vulnerabilities{where}", values).fetchone()[0])
            rows = connection.execute(
                f"SELECT severity, COUNT(*) AS count FROM vulnerabilities{where} GROUP BY severity",
                values,
            ).fetchall()
            for row in rows:
                key = str(row["severity"] or "UNKNOWN").upper()
                if key in severity:
                    severity[key] = int(row["count"])
            recent_clauses = [*clauses, "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')"]
            recent_where = f" WHERE {' AND '.join(recent_clauses)}"
            recent_rows = connection.execute(
                f"SELECT record_json FROM vulnerabilities{recent_where} ORDER BY record_date DESC, updated_at DESC LIMIT 5",
                values,
            ).fetchall()
        return {
            "total": total,
            "severity": severity,
            "records": [self._decode_record(str(row["record_json"])) for row in recent_rows],
        }

    def component_records_in_range(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int = _COMPONENT_EXPORT_RECORD_LIMIT,
    ) -> tuple[list[dict[str, Any]], bool]:
        safe_limit = max(1, min(int(limit), _COMPONENT_EXPORT_RECORD_LIMIT))
        values = [
            start.astimezone(timezone.utc).replace(microsecond=0).isoformat(),
            end.astimezone(timezone.utc).replace(microsecond=0).isoformat(),
            safe_limit + 1,
        ]
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT v.record_json
                FROM vulnerabilities v
                WHERE v.record_date >= ? AND v.record_date < ?
                  AND EXISTS (
                      SELECT 1 FROM vulnerability_components c
                      WHERE c.canonical_id = v.canonical_id
                  )
                ORDER BY v.record_date DESC, v.updated_at DESC
                LIMIT ?
                """,
                values,
            ).fetchall()
        truncated = len(rows) > safe_limit
        return [self._decode_record(str(row["record_json"])) for row in rows[:safe_limit]], truncated

    @staticmethod
    def _encode_record(record: dict[str, Any]) -> str:
        return encrypt_json_to_text(record, _CATALOG_RECORD_PURPOSE, compact=True)

    @staticmethod
    def _decode_record(value: str) -> dict[str, Any]:
        decoded = decrypt_json_from_text(value, _CATALOG_RECORD_PURPOSE)
        if not isinstance(decoded, dict):
            raise ValueError("catalog record payload is not an object")
        return decoded

    @staticmethod
    def _encode_metadata_value(key: str, value: str) -> str:
        return encrypt_json_to_text({"value": value}, f"secflow-catalog-metadata:{key}", compact=True)

    @staticmethod
    def _decode_metadata_value(key: str, value: str) -> str:
        try:
            decoded = decrypt_json_from_text(value, f"secflow-catalog-metadata:{key}")
        except Exception:  # noqa: BLE001 - legacy plaintext metadata stays readable during migration.
            return value
        if isinstance(decoded, dict) and "value" in decoded:
            return str(decoded["value"])
        return str(decoded)


class RealtimeIntelligenceService:
    """Query upstream APIs and build an enriched graph without persisting records."""

    def __init__(self, catalog_path: Path | None = None) -> None:
        self._lock = RLock()
        self._catalog = _VulnerabilityCatalog(catalog_path or (DATA_DIR / "vulnerability_catalog.sqlite3"))
        self._recent: list[dict[str, Any]] = []
        self._batch_records: list[dict[str, Any]] = []
        self._batch_sources: list[dict[str, Any]] = []
        self._batch_graph: dict[str, Any] = {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0}
        self._batch_generated_at = ""
        self._batch_refreshing = False
        self._scheduler_stop: Event | None = None
        self._scheduler_thread: Thread | None = None
        self._bootstrap_thread: Thread | None = None
        self._catalog_migration_thread: Thread | None = None

    def query(
        self,
        query: str,
        *,
        limit: int = 10,
        sources: list[str] | None = None,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        clean_query = " ".join(str(query or "").split())
        if not clean_query:
            raise ValueError("query must not be empty")
        language = _normalize_response_language(response_language)
        limit = max(1, min(int(limit), 50))
        selected = list(_FIXED_SOURCE_ORDER)
        trace = [_trace("resolve_query", f"已解析漏洞查询：{clean_query}")]
        records: list[dict[str, Any]] = []
        source_status: list[dict[str, Any]] = []

        identifier = VULNERABILITY_ID.search(clean_query)
        local_records: list[dict[str, Any]] = []
        repair_local_catalog = False
        if identifier:
            local_records = self._catalog.find_by_identifier(identifier.group(0).upper(), limit)
            if local_records and not any(_record_needs_realtime_enrichment(record) for record in local_records):
                merged = _merge_records(local_records)[:limit]
                merged = _enrich_records_with_reference_patches(merged)
                graph = build_knowledge_graph(merged, clean_query, language=language)
                public_records = _public_records(merged)
                trace.append(_trace("query_local_catalog", f"本地漏洞 catalog 命中 {len(public_records)} 条记录。"))
                trace.append(_trace("enrich_knowledge_graph", f"已生成 {len(graph['nodes'])} 个节点和 {len(graph['edges'])} 条关联。"))
                result = {
                    "status": "success",
                    "query": clean_query,
                    "records": public_records,
                    "graph": graph,
                    "source_status": _public_source_status([]),
                    "trace": [*trace, _trace("compose_result", "已优先使用本地漏洞情报生成结果。", "success")],
                    "persistence": "local-catalog",
                    "persisted": {"inserted": 0, "updated": 0},
                    "generated_at": now_iso(),
                }
                self._remember(result)
                return deepcopy(result)
            if local_records:
                records.extend(local_records)
                repair_local_catalog = True
                trace.append(
                    _trace(
                        "query_local_catalog",
                        "本地漏洞 catalog 已命中，但关键事实不完整，使用实时接口补齐。",
                        "warning",
                    )
                )
            else:
                trace.append(_trace("query_local_catalog", "本地漏洞 catalog 未命中，使用实时接口补齐。", "warning"))
        else:
            trace.append(_trace("query_local_catalog", "本地漏洞 catalog 未命中，使用实时接口补齐。", "warning"))

        executor = ThreadPoolExecutor(max_workers=max(1, len(selected)))
        try:
            futures = {executor.submit(self._query_source, source, clean_query, limit): source for source in selected}
            completed, timed_out_sources = _collect_futures_with_budget(futures, _realtime_query_budget_seconds())
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        for source, outcome in completed:
            if isinstance(outcome, Exception):
                source_status.append({"id": source, "status": "failed", "count": 0, "message": "接口查询失败"})
                continue
            source_records = outcome
            records.extend(source_records)
            source_status.append({"id": source, "status": "success", "count": len(source_records), "message": "查询完成"})
        for source in timed_out_sources:
            source_status.append({"id": source, "status": "warning", "count": 0, "message": "接口查询超时，已跳过"})
        if timed_out_sources:
            trace.append(_trace("query_sources_budget", "部分实时接口超过响应预算，已先返回本地和已完成接口结果。", "warning"))

        trace.append(_trace("query_sources", f"已查询 {len(selected)} 个 API 接口，取得 {len(records)} 条原始记录。", _aggregate_status(source_status)))
        merged = _merge_records(records)[:limit]
        if identifier:
            merged = _enrich_records_with_reference_patches(merged)
        trace.append(_trace("normalize_records", f"按漏洞编号和别名归并为 {len(merged)} 条记录。"))
        persisted = {"inserted": 0, "updated": 0}
        persistence = "api-only"
        if repair_local_catalog and merged:
            self._catalog.upsert(merged)
            persisted["updated"] = len(merged)
            persistence = "local-catalog-refreshed"
            trace.append(_trace("refresh_local_catalog", f"已补全 {len(merged)} 条本地漏洞事实。"))
        graph = build_knowledge_graph(merged, clean_query, language=language)
        public_records = _public_records(merged)
        trace.append(_trace("enrich_knowledge_graph", f"已生成 {len(graph['nodes'])} 个节点和 {len(graph['edges'])} 条关联。"))
        status = "success" if merged else "warning"
        result = {
            "status": status,
            "query": clean_query,
            "records": public_records,
            "graph": graph,
            "source_status": _public_source_status(source_status),
            "trace": [*trace, _trace("compose_result", "实时查询与图谱富化完成。", status)],
            "persistence": persistence,
            "persisted": persisted,
            "generated_at": now_iso(),
        }
        self._remember(result)
        return deepcopy(result)

    def query_dependencies(
        self,
        dependencies: list[dict[str, Any]],
        *,
        limit_per_dependency: int = 5,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        clean_dependencies = _normalize_dependency_facts(dependencies)
        language = _normalize_response_language(response_language)
        limit_per_dependency = max(1, min(int(limit_per_dependency), _dependency_record_limit()))
        trace = [_trace("scan_dependencies", f"已识别 {len(clean_dependencies)} 个依赖坐标。")]
        if not clean_dependencies:
            result = {
                "status": "warning",
                "query": "dependency-scan",
                "records": [],
                "graph": build_knowledge_graph([], "dependency-scan", language=language),
                "dependencies": [],
                "source_status": _public_source_status([]),
                "trace": [*trace, _trace("compose_result", "未识别到可用于漏洞匹配的依赖。", "warning")],
                "persistence": "api-only",
                "persisted": {"inserted": 0, "updated": 0},
                "generated_at": now_iso(),
            }
            self._remember(result)
            return deepcopy(result)

        versioned_dependencies = [dependency for dependency in clean_dependencies if _is_concrete_dependency_version(dependency.get("version"))]
        unresolved_count = len(clean_dependencies) - len(versioned_dependencies)
        if unresolved_count:
            trace.append(
                _trace(
                    "dependency_versions",
                    f"{unresolved_count} 个依赖版本未明确，仅保留依赖清单，不计入漏洞命中。",
                    "warning",
                )
            )
        if not versioned_dependencies:
            result = {
                "status": "warning",
                "query": "dependency-scan",
                "records": [],
                "graph": build_knowledge_graph([], "dependency-scan", language=language),
                "dependencies": clean_dependencies,
                "source_status": [],
                "trace": [*trace, _trace("compose_result", "缺少可核验的依赖版本，未生成依赖漏洞结论。", "warning")],
                "persistence": "api-only",
                "persisted": {"inserted": 0, "updated": 0},
                "generated_at": now_iso(),
            }
            self._remember(result)
            return deepcopy(result)

        queried_dependencies = versioned_dependencies[: _dependency_query_limit()]
        skipped_dependency_count = max(0, len(versioned_dependencies) - len(queried_dependencies))
        if skipped_dependency_count:
            trace.append(
                _trace(
                    "dependency_query_budget",
                    f"快速分析模式已优先查询 {len(queried_dependencies)} 个依赖，其余 {skipped_dependency_count} 个依赖会进入报告清单但不阻塞本次分析。",
                    "warning",
                )
            )

        records: list[dict[str, Any]] = self._catalog.find_by_dependencies(queried_dependencies, limit=max(10, len(queried_dependencies) * limit_per_dependency))
        local_record_count = len(records)
        source_status: list[dict[str, Any]] = []
        if records:
            trace.append(_trace("query_local_catalog", f"本地漏洞 catalog 按组件命中 {len(records)} 条记录。"))
        missing_dependencies = _dependencies_missing_local_hits(queried_dependencies, records)
        if not missing_dependencies:
            trace.append(_trace("query_dependencies", "所有优先依赖均已由本地漏洞情报命中，跳过实时接口。"))
            source_status.append({"id": "local_catalog", "status": "success", "count": len(records), "message": "本地命中"})
        else:
            trace.append(
                _trace(
                    "query_local_catalog",
                    f"本地未覆盖 {len(missing_dependencies)} 个依赖，使用短预算实时接口补齐。",
                    "warning",
                )
            )

        api_records: list[dict[str, Any]] = []
        if missing_dependencies:
            executor = ThreadPoolExecutor(max_workers=min(4, len(missing_dependencies)))
            try:
                futures = {
                    executor.submit(self._query_osv_dependency, dependency, limit_per_dependency): dependency
                    for dependency in missing_dependencies
                }
                completed, timed_out_dependencies = _collect_futures_with_budget(futures, _dependency_total_budget_seconds())
            finally:
                executor.shutdown(wait=False, cancel_futures=True)

            package_record_count = 0
            failures = 0
            for dependency, outcome in completed:
                if isinstance(outcome, Exception):
                    failures += 1
                    api_records.append(_dependency_lookup_error_record(dependency))
                    continue
                dependency_records = outcome
                package_record_count += len(dependency_records)
                api_records.extend(dependency_records)
            timeout_count = len(timed_out_dependencies)
            if timeout_count:
                trace.append(
                    _trace(
                        "dependency_query_budget",
                        f"实时补齐超过响应预算，已跳过 {timeout_count} 个未完成依赖并返回本地/已完成结果。",
                        "warning",
                    )
                )
            status = "failed" if failures == len(missing_dependencies) and not timeout_count else "warning" if failures or timeout_count else "success"
            message = "实时补齐超时，已返回部分结果" if timeout_count else "查询完成"
            source_status.append({"id": "osv", "status": status, "count": package_record_count, "message": message})
        records.extend(api_records)

        enrichment_counts = {"nvd": 0, "github_advisory": 0}
        identifiers = _record_identifiers(records)[: min(4, max(1, len(queried_dependencies) * 2))]
        if identifiers and _dependency_secondary_enrichment_enabled():
            executor = ThreadPoolExecutor(max_workers=4)
            try:
                futures: dict[Any, str] = {}
                for identifier in identifiers:
                    futures[executor.submit(self._query_nvd, identifier, 3)] = "nvd"
                    futures[executor.submit(self._query_github, identifier, 3)] = "github_advisory"
                completed, timed_out_sources = _collect_futures_with_budget(futures, min(_dependency_total_budget_seconds(), _realtime_query_budget_seconds()))
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            for source, outcome in completed:
                if isinstance(outcome, Exception):
                    continue
                enriched = outcome
                enrichment_counts[source] += len(enriched)
                records.extend(enriched)
            if timed_out_sources:
                trace.append(_trace("dependency_enrichment_budget", "二次富化超过响应预算，已跳过未完成接口以避免分析超时。", "warning"))
        elif identifiers:
            trace.append(_trace("fast_dependency_report", "已启用快速依赖分析模式，跳过非必要二次富化以避免分析请求超时。"))
        source_status.extend(
            {"id": source, "status": "success", "count": count, "message": "查询完成"}
            for source, count in enrichment_counts.items()
        )

        merged = _records_by_canonical_vulnerability_id(_merge_records(records))
        merged = [record for record in merged if not record.get("lookup_error")]
        public_records = _public_records(merged)
        graph = build_knowledge_graph(merged, "dependency-scan", language=language)
        trace.append(_trace("query_dependencies", f"依赖漏洞匹配命中 {len(public_records)} 条归并记录。", "completed" if public_records else "warning"))
        trace.append(_trace("enrich_knowledge_graph", f"已生成 {len(graph['nodes'])} 个节点和 {len(graph['edges'])} 条关联。", "completed" if graph.get("node_count") else "warning"))
        result = {
            "status": "success" if public_records else "warning",
            "query": "dependency-scan",
            "records": public_records,
            "graph": graph,
            "dependencies": clean_dependencies,
            "source_status": _public_source_status(source_status),
            "trace": [*trace, _trace("compose_result", "依赖漏洞报告生成完成。", "success" if public_records else "warning")],
            "persistence": "local-first" if local_record_count else "api-only",
            "persisted": {"inserted": 0, "updated": 0},
            "generated_at": now_iso(),
        }
        self._remember(result)
        return deepcopy(result)

    def query_component_vulnerabilities(
        self,
        name: str,
        version: str,
        *,
        ecosystem: str = "",
        include_realtime: bool = True,
        preview_limit: int = 200,
    ) -> dict[str, Any]:
        records, metadata = self._resolve_component_vulnerabilities(
            name,
            version,
            ecosystem=ecosystem,
            include_realtime=include_realtime,
        )
        public_records = _public_records(records)
        visible_limit = max(1, min(int(preview_limit), _COMPONENT_GRAPH_RECORD_LIMIT))
        graph_records = records[:visible_limit]
        query = f"{metadata['name']}@{metadata['version']}"
        return {
            "status": "success" if public_records else "warning",
            "query": query,
            "component": {
                "name": metadata["name"],
                "version": metadata["version"],
                "ecosystem": metadata["ecosystem"],
            },
            "records": public_records[:visible_limit],
            "total": len(public_records),
            "preview_limit": visible_limit,
            "truncated": metadata["truncated"],
            "ecosystems": metadata["ecosystems"],
            "graph": build_knowledge_graph(graph_records, query),
            "source": metadata["source"],
            "generated_at": metadata["generated_at"],
        }

    def query_component_vulnerability_catalog(
        self,
        start_date: date | str,
        end_date: date | str,
        *,
        ecosystems: list[str] | None = None,
        severities: list[str] | None = None,
        component_names: list[str] | None = None,
        include_realtime: bool = True,
        limit: int = 5000,
    ) -> dict[str, Any]:
        range_start, range_end = _dashboard_date_range(start_date, end_date)
        if range_start is None or range_end is None:
            raise ValueError("组件漏洞目录必须提供开始日期和结束日期")
        safe_limit = max(1, min(int(limit), _COMPONENT_EXPORT_RECORD_LIMIT))
        source_status: list[dict[str, Any]] = []
        realtime_refreshed = False
        if include_realtime:
            try:
                refreshed = self.refresh_dashboard_batch(
                    start_date=start_date,
                    end_date=end_date,
                    limit=min(safe_limit, _BATCH_LIMIT),
                )
                source_status = list(refreshed.get("sources") or [])
                realtime_refreshed = True
            except Exception:  # noqa: BLE001 - the encrypted catalog remains queryable when upstream sources fail.
                source_status = self.sources_status()

        records, catalog_truncated = self._catalog.component_records_in_range(
            start=range_start,
            end=range_end,
            limit=_COMPONENT_EXPORT_RECORD_LIMIT,
        )
        ecosystem_filter = {str(value).strip().casefold() for value in ecosystems or [] if str(value).strip()}
        severity_filter = {str(value).strip().upper() for value in severities or [] if str(value).strip()}
        name_filter = {str(value).strip().casefold() for value in component_names or [] if str(value).strip()}
        filtered: list[dict[str, Any]] = []
        for record in records:
            if severity_filter and str(record.get("severity") or "UNKNOWN").upper() not in severity_filter:
                continue
            components = [item for item in record.get("components") or [] if isinstance(item, dict)]
            matched_components = [
                component
                for component in components
                if (not ecosystem_filter or str(component.get("ecosystem") or "").casefold() in ecosystem_filter)
                and (
                    not name_filter
                    or any(
                        requested_name == str(component.get("name") or "").casefold()
                        or requested_name in str(component.get("name") or "").casefold()
                        for requested_name in name_filter
                    )
                )
            ]
            if not matched_components:
                continue
            filtered_record = deepcopy(record)
            filtered_record["components"] = deepcopy(matched_components)
            filtered.append(filtered_record)

        filtered = _records_by_canonical_vulnerability_id(_merge_records(filtered))
        filtered.sort(
            key=lambda item: (str(item.get("published_at") or ""), str(item.get("updated_at") or "")),
            reverse=True,
        )
        total = len(filtered)
        visible = filtered[:safe_limit]
        severity_counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
        component_keys: set[str] = set()
        ecosystem_counts: dict[str, int] = {}
        for record in visible:
            severity = str(record.get("severity") or "UNKNOWN").upper()
            severity_counts[severity if severity in severity_counts else "UNKNOWN"] += 1
            for component in record.get("components") or []:
                if not isinstance(component, dict):
                    continue
                ecosystem = str(component.get("ecosystem") or "未标明生态").strip() or "未标明生态"
                name = str(component.get("name") or "未提供组件名称").strip() or "未提供组件名称"
                component_keys.add(f"{ecosystem.casefold()}|{name.casefold()}")
                ecosystem_counts[ecosystem] = ecosystem_counts.get(ecosystem, 0) + 1
        query = f"component-catalog:{start_date}:{end_date}"
        graph_records = visible[: min(200, len(visible))]
        public_records = _public_records(visible)
        from app.vulnerability_export import component_catalog_result_fingerprint

        result = {
            "status": "success" if visible else "warning",
            "query": query,
            "start_date": str(start_date)[:10],
            "end_date": str(end_date)[:10],
            "records": public_records,
            "total": total,
            "component_count": len(component_keys),
            "severity": severity_counts,
            "ecosystem_counts": dict(sorted(ecosystem_counts.items(), key=lambda item: (-item[1], item[0].casefold()))),
            "filters": {
                "ecosystems": sorted(ecosystem_filter),
                "severities": sorted(severity_filter),
                "component_names": sorted(name_filter),
            },
            "truncated": catalog_truncated or total > safe_limit,
            "graph": build_knowledge_graph(graph_records, query),
            "source_status": _public_source_status(source_status),
            "source": "local-catalog+realtime" if realtime_refreshed else "local-catalog",
            "generated_at": now_iso(),
            "result_sha256": component_catalog_result_fingerprint(
                public_records,
                start_date=str(start_date)[:10],
                end_date=str(end_date)[:10],
                filters={
                    "ecosystems": sorted(ecosystem_filter),
                    "severities": sorted(severity_filter),
                    "component_names": sorted(name_filter),
                },
            ),
        }
        self._remember(result)
        return deepcopy(result)

    @staticmethod
    def export_component_vulnerability_catalog(
        records: list[dict[str, Any]],
        *,
        start_date: str,
        end_date: str,
        filters: dict[str, Any] | None = None,
        generated_at: str | None = None,
    ) -> tuple[bytes, dict[str, Any]]:
        from app.vulnerability_export import build_component_vulnerability_catalog_workbook

        clean_records = [dict(record) for record in records if isinstance(record, dict)]
        timestamp = str(generated_at or now_iso())
        content = build_component_vulnerability_catalog_workbook(
            clean_records,
            start_date=str(start_date)[:10],
            end_date=str(end_date)[:10],
            filters=dict(filters or {}),
            generated_at=timestamp,
        )
        component_count = len(
            {
                f"{str(component.get('ecosystem') or '').casefold()}|{str(component.get('name') or '').casefold()}"
                for record in clean_records
                for component in record.get("components") or []
                if isinstance(component, dict)
            }
        )
        return content, {
            "start_date": str(start_date)[:10],
            "end_date": str(end_date)[:10],
            "filters": dict(filters or {}),
            "total": len(clean_records),
            "component_count": component_count,
            "generated_at": timestamp,
        }

    def export_component_vulnerabilities(
        self,
        name: str,
        version: str,
        *,
        ecosystem: str = "",
        include_realtime: bool = True,
    ) -> tuple[bytes, dict[str, Any]]:
        records, metadata = self._resolve_component_vulnerabilities(
            name,
            version,
            ecosystem=ecosystem,
            include_realtime=include_realtime,
        )
        from app.vulnerability_export import build_component_vulnerability_workbook

        content = build_component_vulnerability_workbook(
            _public_records(records),
            component_name=metadata["name"],
            version=metadata["version"],
            ecosystem=metadata["ecosystem"],
            generated_at=metadata["generated_at"],
        )
        return content, {**metadata, "total": len(records)}

    def export_vulnerability_components(self, identifier: str) -> tuple[bytes, dict[str, Any]]:
        clean_identifier = " ".join(str(identifier or "").split()).upper()
        if not VULNERABILITY_ID.fullmatch(clean_identifier):
            raise ValueError("请输入有效的 CVE 或 GHSA 漏洞编号")

        result = self.query(clean_identifier, limit=50)
        records = [
            record
            for record in result.get("records") or []
            if clean_identifier
            in {
                str(record.get("id") or "").upper(),
                *(str(value or "").upper() for value in record.get("aliases") or []),
            }
        ]
        if not records:
            raise ValueError(f"未找到漏洞 {clean_identifier} 的组件版本范围")

        from app.vulnerability_export import build_vulnerability_component_workbook

        generated_at = str(result.get("generated_at") or now_iso())
        content = build_vulnerability_component_workbook(
            records,
            identifier=clean_identifier,
            generated_at=generated_at,
        )
        component_count = sum(len(record.get("components") or []) for record in records)
        return content, {
            "identifier": clean_identifier,
            "total": len(records),
            "component_count": component_count,
            "generated_at": generated_at,
            "source": result.get("persistence") or "api-only",
        }

    def _resolve_component_vulnerabilities(
        self,
        name: str,
        version: str,
        *,
        ecosystem: str,
        include_realtime: bool,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        clean_name = " ".join(str(name or "").split())
        clean_version = str(version or "").strip()
        clean_ecosystem = " ".join(str(ecosystem or "").split())
        if not clean_name:
            raise ValueError("组件名称不能为空")
        if not _is_concrete_dependency_version(clean_version):
            raise ValueError("请输入明确的组件版本，不能使用 latest、* 或变量占位符")

        local_records, discovered_ecosystems, truncated = self._catalog.find_component_vulnerabilities(
            clean_name,
            clean_version,
            clean_ecosystem,
            limit=_COMPONENT_EXPORT_RECORD_LIMIT,
        )
        records = list(local_records)
        source = "local-catalog" if records else "local-catalog-miss"
        realtime_records: list[dict[str, Any]] = []
        if include_realtime and clean_ecosystem:
            dependency = {"ecosystem": clean_ecosystem, "name": clean_name, "version": clean_version}
            try:
                realtime_records = self._query_osv_dependency(dependency, _COMPONENT_REALTIME_RECORD_LIMIT)
            except Exception:  # noqa: BLE001 - a complete local result remains exportable if OSV is unavailable.
                realtime_records = []
            if realtime_records:
                records.extend(realtime_records)
                source = "local-catalog+osv-realtime" if local_records else "osv-realtime"
                truncated = truncated or len(realtime_records) >= _COMPONENT_REALTIME_RECORD_LIMIT

        merged = _records_by_canonical_vulnerability_id(_merge_records(records))[:_COMPONENT_EXPORT_RECORD_LIMIT]
        if realtime_records and merged:
            self._catalog.upsert(merged)
        ecosystems = sorted({*discovered_ecosystems, *([clean_ecosystem] if clean_ecosystem else [])})
        return merged, {
            "name": clean_name,
            "version": clean_version,
            "ecosystem": clean_ecosystem,
            "ecosystems": ecosystems,
            "truncated": truncated or len(merged) >= _COMPONENT_EXPORT_RECORD_LIMIT,
            "source": source,
            "generated_at": now_iso(),
        }

    def recent(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(self._recent)

    def start_batch_scheduler(self, interval_seconds: int = _BATCH_INTERVAL_SECONDS) -> None:
        with self._lock:
            if self._scheduler_thread and self._scheduler_thread.is_alive():
                return
            stop = Event()
            self._scheduler_stop = stop
            self._scheduler_thread = Thread(
                target=self._batch_scheduler_loop,
                args=(max(60, int(interval_seconds)), stop),
                daemon=True,
                name="secflow-intelligence-batch-refresh",
            )
            self._scheduler_thread.start()
            if self._catalog.encryption_migration_pending():
                self._catalog_migration_thread = Thread(
                    target=self._catalog.migrate_encrypted_catalog_incrementally,
                    args=(stop,),
                    daemon=True,
                    name="secflow-catalog-encryption-migration",
                )
                self._catalog_migration_thread.start()
            if self._catalog.metadata("baseline_complete") != "true":
                self._bootstrap_thread = Thread(
                    target=self._bootstrap_catalog,
                    args=(stop,),
                    daemon=True,
                    name="secflow-vulnerability-catalog-bootstrap",
                )
                self._bootstrap_thread.start()

    def stop_batch_scheduler(self) -> None:
        with self._lock:
            stop = self._scheduler_stop
            self._scheduler_stop = None
        if stop:
            stop.set()

    def refresh_dashboard_batch(
        self,
        *,
        limit: int = _BATCH_LIMIT,
        days: int = _BATCH_LOOKBACK_DAYS,
        start_date: date | str | None = None,
        end_date: date | str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 1000))
        days = max(1, min(int(days), 30))
        range_start, range_end = _dashboard_date_range(start_date, end_date)
        if range_start is None:
            query_end = datetime.now(timezone.utc)
            query_start = query_end - timedelta(days=days)
            date_field = "modified"
        else:
            query_start = range_start
            query_end = range_end or datetime.now(timezone.utc)
            date_field = "published"
        with self._lock:
            if self._batch_refreshing:
                return self.dashboard(start_date=start_date, end_date=end_date)
            self._batch_refreshing = True
        try:
            records: list[dict[str, Any]] = []
            source_status: list[dict[str, Any]] = []
            executor = ThreadPoolExecutor(max_workers=2)
            batch_stop = Event()
            try:
                futures = {
                    executor.submit(self._query_nvd_batch, query_start, query_end, date_field): "nvd",
                    executor.submit(
                        self._query_github_batch,
                        query_start,
                        query_end,
                        date_field,
                        batch_stop,
                    ): "github_advisory",
                }
                completed, timed_out_sources = _collect_futures_with_budget(futures, _dashboard_refresh_budget_seconds())
            finally:
                batch_stop.set()
                executor.shutdown(wait=False, cancel_futures=True)

            for source, outcome in completed:
                if isinstance(outcome, Exception):
                    source_status.append({"id": source, "status": "failed", "count": 0, "message": "接口查询失败"})
                    continue
                source_records = outcome
                records.extend(source_records)
                source_status.append({"id": source, "status": "success", "count": len(source_records), "message": "查询完成"})
            for source in timed_out_sources:
                source_status.append({"id": source, "status": "warning", "count": 0, "message": "接口查询超时，已跳过"})

            identifiers = _record_identifiers(records)[: min(limit, 100)]
            if date_field == "modified":
                try:
                    identifiers = _unique([
                        *identifiers,
                        *self._query_osv_modified_identifiers(query_start, query_end),
                    ])
                except Exception:  # noqa: BLE001 - the other incremental interfaces still update the catalog.
                    pass
            try:
                osv_records = self._query_osv_batch(identifiers)
                records.extend(osv_records)
                source_status.append({"id": "osv", "status": "success", "count": len(osv_records), "message": "查询完成"})
            except Exception:  # noqa: BLE001
                source_status.append({"id": "osv", "status": "failed", "count": 0, "message": "接口查询失败"})

            merged = _records_by_canonical_vulnerability_id(_merge_records(records))
            self._catalog.upsert(merged)
            public_records = _public_records(merged)
            public_sources = _public_source_status(source_status)
            graph = build_knowledge_graph(merged[:20], "batch-dashboard")
            generated_at = now_iso()
            with self._lock:
                if public_records or not self._batch_records:
                    self._batch_records = public_records
                    self._batch_graph = graph
                    self._batch_generated_at = generated_at
                self._batch_sources = public_sources
            return self.dashboard(start_date=start_date, end_date=end_date)
        finally:
            with self._lock:
                self._batch_refreshing = False

    def dashboard(
        self,
        *,
        start_date: date | str | None = None,
        end_date: date | str | None = None,
    ) -> dict[str, Any]:
        range_start, range_end = _dashboard_date_range(start_date, end_date)
        with self._lock:
            batch_sources = deepcopy(self._batch_sources)
            batch_graph = deepcopy(self._batch_graph)
            batch_generated_at = self._batch_generated_at
        snapshot = self._catalog.snapshot(start=range_start, end=range_end)
        catalog_snapshot = snapshot if range_start is None else self._catalog.snapshot()
        severity = snapshot["severity"]
        graph = batch_graph
        sources = batch_sources
        catalog_status = self._catalog.metadata("baseline_status", "pending")
        try:
            catalog_progress = int(self._catalog.metadata("baseline_progress", "0") or 0)
        except ValueError:
            catalog_progress = 0
        return {
            "vulnerability_count": snapshot["total"],
            "high_risk_count": severity["CRITICAL"] + severity["HIGH"],
            "query_count": snapshot["total"],
            "graph_node_count": int(graph.get("node_count") or 0),
            "severity": severity,
            "recent_records": _public_records(snapshot["records"]),
            "sources": sources if sources else self.sources_status(),
            "persistence": "local-catalog",
            "generated_at": self._catalog.metadata("last_sync", batch_generated_at or now_iso()),
            "scope": "range" if range_start is not None else "all",
            "range_start": range_start.date().isoformat() if range_start is not None else None,
            "range_end": (range_end - timedelta(days=1)).date().isoformat() if range_end is not None else None,
            "catalog_status": catalog_status,
            "catalog_progress": max(0, min(catalog_progress, 100)),
            "catalog_count": catalog_snapshot["total"],
        }

    def sources_status(self, latest: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        latest = latest or {}
        statuses = []
        for source in _FIXED_SOURCE_ORDER:
            state = latest.get(source, {})
            statuses.append({"id": source, "status": state.get("status", "ready"), "count": state.get("count", 0), "message": state.get("message", "等待 API 实时查询")})
        return _public_source_status(statuses)

    @staticmethod
    def source_catalog_ids() -> set[str]:
        return {"nvd", "github_advisory", "osv"}

    def _remember(self, result: dict[str, Any]) -> None:
        with self._lock:
            self._recent.insert(0, deepcopy(result))
            self._recent = self._recent[:30]

    def _batch_scheduler_loop(self, interval_seconds: int, stop: Event) -> None:
        while not stop.is_set():
            try:
                self.refresh_dashboard_batch()
            except Exception:
                pass
            if stop.wait(interval_seconds):
                return

    def _bootstrap_catalog(self, stop: Event) -> None:
        self._cleanup_plaintext_feed_archives()
        feeds_dir = DATA_DIR / ".secflow-feed-cache"
        feeds_dir.mkdir(parents=True, exist_ok=True)
        start_year = 2002
        end_year = datetime.now(timezone.utc).year
        total_steps = end_year - start_year + 2
        completed_steps = 0
        self._catalog.set_metadata("baseline_status", "building")
        try:
            for year in range(start_year, end_year + 1):
                if stop.is_set():
                    return
                checkpoint = f"nvd_feed_{year}"
                if self._catalog.metadata(checkpoint) != "complete":
                    archive = feeds_dir / _transient_feed_name(f"nvd:{year}")
                    self._download_archive(intelligence_endpoint("baseline_yearly").format(year=year), archive, stop)
                    if stop.is_set():
                        return
                    self._import_nvd_feed(archive, stop)
                    archive.unlink(missing_ok=True)
                    if stop.is_set():
                        return
                    self._catalog.set_metadata(checkpoint, "complete")
                completed_steps += 1
                self._catalog.set_metadata("baseline_progress", str(int(completed_steps / total_steps * 100)))

            if not stop.is_set() and self._catalog.metadata("osv_full_dump") != "complete":
                archive = feeds_dir / _transient_feed_name("osv:all")
                self._download_archive(intelligence_endpoint("baseline_bundle"), archive, stop)
                if stop.is_set():
                    return
                self._import_osv_dump(archive, stop)
                archive.unlink(missing_ok=True)
                if stop.is_set():
                    return
                self._catalog.set_metadata("osv_full_dump", "complete")
            if stop.is_set():
                return
            self._catalog.set_metadata("baseline_progress", "100")
            self._catalog.set_metadata("baseline_status", "ready")
            self._catalog.set_metadata("baseline_complete", "true")
        except Exception:  # noqa: BLE001 - the incremental API path remains available while bootstrap retries later.
            self._catalog.set_metadata("baseline_status", "retrying")

    @staticmethod
    def _download_archive(url: str, destination: Path, stop: Event) -> None:
        if destination.exists() and destination.stat().st_size > 0:
            return
        temporary = destination.with_suffix(destination.suffix + ".part")
        temporary.unlink(missing_ok=True)
        headers = default_headers()
        with httpx.stream("GET", url, headers=headers, timeout=120.0, follow_redirects=True) as response:
            response.raise_for_status()
            with temporary.open("wb") as handle:
                for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                    if stop.is_set():
                        temporary.unlink(missing_ok=True)
                        return
                    handle.write(chunk)
        temporary.replace(destination)

    @staticmethod
    def _cleanup_plaintext_feed_archives() -> None:
        legacy_dir = DATA_DIR / "vulnerability-feeds"
        if legacy_dir.exists():
            for item in legacy_dir.iterdir():
                if item.is_file() and item.suffix.lower() in {".gz", ".zip", ".part"}:
                    item.unlink(missing_ok=True)

    def _import_nvd_feed(self, archive: Path, stop: Event) -> None:
        with gzip.open(archive, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        vulnerabilities = payload.get("vulnerabilities", [])
        for offset in range(0, len(vulnerabilities), 500):
            if stop.is_set():
                return
            records = _nvd_records_from_items(vulnerabilities[offset : offset + 500])
            self._catalog.upsert(_records_by_canonical_vulnerability_id(records))

    def _import_osv_dump(self, archive: Path, stop: Event) -> None:
        batch: list[dict[str, Any]] = []
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if stop.is_set():
                    return
                if not name.lower().endswith(".json"):
                    continue
                try:
                    payload = json.loads(bundle.read(name))
                except (json.JSONDecodeError, KeyError, OSError):
                    continue
                if not isinstance(payload, dict) or not payload.get("id") or payload.get("withdrawn"):
                    continue
                batch.append(_osv_record(payload))
                if len(batch) >= 500:
                    self._catalog.upsert(_records_by_canonical_vulnerability_id(_merge_records(batch)))
                    batch = []
        if batch:
            self._catalog.upsert(_records_by_canonical_vulnerability_id(_merge_records(batch)))

    def _query_source(self, source: str, query: str, limit: int) -> list[dict[str, Any]]:
        if source == "nvd":
            return self._query_nvd(query, limit)
        if source == "github_advisory":
            return self._query_github(query, limit)
        if source == "osv":
            return self._query_osv(query)
        raise KeyError(source)

    @staticmethod
    def _query_nvd_batch(start: datetime, end: datetime, date_field: str) -> list[dict[str, Any]]:
        page_size = 2000
        headers = default_headers(auth="primary")
        records: list[dict[str, Any]] = []
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            window_start = start
            while window_start < end:
                window_end = min(window_start + timedelta(days=120), end)
                start_index = 0
                total_results: int | None = None
                while total_results is None or start_index < total_results:
                    params: dict[str, str] = {
                        "resultsPerPage": str(page_size),
                        "startIndex": str(start_index),
                    }
                    prefix = "lastMod" if date_field == "modified" else "pub"
                    params[f"{prefix}StartDate"] = _nvd_api_datetime(window_start)
                    params[f"{prefix}EndDate"] = _nvd_api_datetime(window_end - timedelta(milliseconds=1))
                    response = client.get(intelligence_endpoint("api_primary"), params=params, headers=headers)
                    response.raise_for_status()
                    payload = response.json()
                    total_results = int(payload.get("totalResults") or 0)
                    vulnerabilities = payload.get("vulnerabilities", [])
                    records.extend(_nvd_records_from_items(vulnerabilities))
                    if not vulnerabilities:
                        break
                    start_index += len(vulnerabilities)
                window_start = window_end
        return records

    @staticmethod
    def _query_github_batch(
        start: datetime,
        end: datetime,
        date_field: str,
        stop: Event | None = None,
    ) -> list[dict[str, Any]]:
        headers = default_headers(auth="secondary")
        records: list[dict[str, Any]] = []
        page = 1
        seen_page_fingerprints: set[str] = set()
        seen_advisory_ids: set[str] = set()
        deadline = monotonic_time.monotonic() + _GITHUB_BATCH_BUDGET_SECONDS
        range_value = f"{start.date().isoformat()}..{(end - timedelta(milliseconds=1)).date().isoformat()}"
        filter_key = "updated" if date_field == "modified" else "published"
        with httpx.Client(timeout=8.0, follow_redirects=True) as client:
            while page <= _GITHUB_BATCH_MAX_PAGES and len(records) < _GITHUB_BATCH_MAX_RECORDS:
                if stop is not None and stop.is_set():
                    break
                if monotonic_time.monotonic() >= deadline:
                    break
                params = {
                    "per_page": str(_GITHUB_BATCH_PAGE_SIZE),
                    "page": str(page),
                    "sort": filter_key,
                    "direction": "desc",
                    filter_key: range_value,
                    "is_withdrawn": "false",
                }
                response = client.get(intelligence_endpoint("api_secondary"), params=params, headers=headers)
                response.raise_for_status()
                payload = response.json()
                items = payload if isinstance(payload, list) else []
                if not items:
                    break
                page_ids = [
                    str(item.get("ghsa_id") or "").strip().upper()
                    for item in items
                    if isinstance(item, dict) and item.get("ghsa_id")
                ]
                if not page_ids:
                    break
                page_fingerprint = hashlib.sha256("\n".join(page_ids).encode("utf-8")).hexdigest()
                if page_fingerprint in seen_page_fingerprints:
                    break
                seen_page_fingerprints.add(page_fingerprint)
                for item, advisory_id in zip(
                    (item for item in items if isinstance(item, dict) and item.get("ghsa_id")),
                    page_ids,
                ):
                    if advisory_id in seen_advisory_ids:
                        continue
                    seen_advisory_ids.add(advisory_id)
                    records.append(_github_record(item))
                    if len(records) >= _GITHUB_BATCH_MAX_RECORDS:
                        break
                if len(items) < _GITHUB_BATCH_PAGE_SIZE or "next" not in response.links:
                    break
                page += 1
        return records

    @staticmethod
    def _query_osv_batch(identifiers: list[str]) -> list[dict[str, Any]]:
        if not identifiers:
            return []

        def fetch(identifier: str) -> dict[str, Any] | None:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                response = client.get(f"{intelligence_endpoint('api_relation')}/{identifier}", headers=default_headers())
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                payload = response.json()
                if payload.get("id") and not payload.get("withdrawn"):
                    return _osv_record(payload)
            return None

        records: list[dict[str, Any]] = []
        executor = ThreadPoolExecutor(max_workers=min(6, len(identifiers)))
        try:
            futures = {executor.submit(fetch, identifier): identifier for identifier in identifiers}
            completed, _timed_out_identifiers = _collect_futures_with_budget(futures, _osv_batch_budget_seconds())
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        for _identifier, outcome in completed:
            if isinstance(outcome, Exception):
                continue
            if outcome:
                records.append(outcome)
        return records

    @staticmethod
    def _query_osv_modified_identifiers(start: datetime, end: datetime) -> list[str]:
        headers = default_headers()
        response = httpx.get(intelligence_endpoint("baseline_delta"), headers=headers, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
        identifiers: list[str] = []
        for row in csv.reader(response.text.splitlines()):
            if len(row) < 2:
                continue
            try:
                modified = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
            except ValueError:
                continue
            if modified >= end:
                continue
            if modified < start:
                break
            identifier = Path(row[1]).name.strip()
            if identifier:
                identifiers.append(identifier.upper())
        return _unique(identifiers)

    @staticmethod
    def _query_nvd(query: str, limit: int) -> list[dict[str, Any]]:
        match = VULNERABILITY_ID.search(query)
        if match and match.group(0).upper().startswith("GHSA-"):
            return []
        params: dict[str, str] = {"resultsPerPage": str(min(limit, 50))}
        if match:
            params["cveId"] = match.group(0).upper()
        else:
            keyword = _keyword_query(query)
            if not keyword:
                return []
            params["keywordSearch"] = keyword
        headers = default_headers(auth="primary")
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            response = client.get(intelligence_endpoint("api_primary"), params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
        records: list[dict[str, Any]] = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            record = _nvd_record(cve, {"collection_name": "realtime"}, None)
            if not record:
                continue
            record.update(
                {
                    "aliases": [record["id"]],
                    "cwes": _nvd_cwes(cve),
                    "components": _nvd_components(cve),
                    "provenance": ["nvd"],
                }
            )
            record["fixed_versions"] = _unique(
                [*record.get("fixed_versions", []), *_fixed_commit_facts(record.get("summary") or "")]
            )
            records.append(record)
        return records

    @staticmethod
    def _query_github(query: str, limit: int) -> list[dict[str, Any]]:
        match = VULNERABILITY_ID.search(query)
        if not match:
            return []
        identifier = match.group(0).upper()
        url = intelligence_endpoint("api_secondary")
        params: dict[str, str] = {}
        if identifier.startswith("GHSA-"):
            url = f"{url}/{identifier.lower()}"
        else:
            params = {"cve_id": identifier, "per_page": str(min(limit, 50))}
        headers = default_headers(auth="secondary")
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            response = client.get(url, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
        items = payload if isinstance(payload, list) else [payload]
        return [_github_record(item) for item in items if item.get("ghsa_id")]

    @staticmethod
    def _query_osv(query: str) -> list[dict[str, Any]]:
        match = VULNERABILITY_ID.search(query)
        if not match:
            return []
        identifier = match.group(0).upper()
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            response = client.get(f"{intelligence_endpoint('api_relation')}/{identifier}", headers=default_headers())
            if response.status_code == 404:
                return []
            response.raise_for_status()
            payload = response.json()
        return [_osv_record(payload)] if payload.get("id") else []

    @staticmethod
    def _query_osv_dependency(dependency: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        package_name = str(dependency.get("name") or "").strip()
        ecosystem = str(dependency.get("ecosystem") or "").strip()
        version = str(dependency.get("version") or "").strip()
        if not package_name or not ecosystem or not _is_concrete_dependency_version(version):
            return []

        body: dict[str, Any] = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            body["version"] = version

        headers = default_headers()
        records: list[dict[str, Any]] = []
        deadline = monotonic_time.monotonic() + _dependency_lookup_budget_seconds()
        with httpx.Client(timeout=_dependency_request_timeout_seconds(), follow_redirects=True) as client:
            response = client.post(intelligence_endpoint("api_relation_query"), json=body, headers=headers)
            response.raise_for_status()
            payload = response.json()
            for item in (payload.get("vulns") or [])[: max(1, limit * 2)]:
                remaining = deadline - monotonic_time.monotonic()
                if remaining <= 0:
                    break
                if not isinstance(item, dict) or item.get("withdrawn"):
                    continue
                full_item = item
                if item.get("id") and not (item.get("affected") or item.get("details") or item.get("summary")):
                    detail_timeout = max(1.0, min(_dependency_detail_timeout_seconds(), remaining))
                    detail_response = client.get(f"{intelligence_endpoint('api_relation')}/{item['id']}", headers=headers, timeout=detail_timeout)
                    if detail_response.status_code == 404:
                        continue
                    detail_response.raise_for_status()
                    full_item = detail_response.json()
                if full_item.get("id") and not full_item.get("withdrawn"):
                    records.append(_tag_dependency_record(_osv_record(full_item), dependency))
                if len(records) >= limit:
                    break
        return records


def build_knowledge_graph(records: list[dict[str, Any]], query: str = "", language: str = "zh-Hans") -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    localize_summary = query != "batch-dashboard"
    language = _normalize_response_language(language)

    def node(node_id: str, label: str, node_type: str, **metadata: Any) -> None:
        nodes.setdefault(node_id, {"id": node_id, "label": label, "type": node_type, "metadata": metadata})

    def edge(source: str, target: str, edge_type: str, label: str) -> None:
        edge_id = f"{source}|{edge_type}|{target}"
        edges.setdefault(edge_id, {"id": edge_id, "source": source, "target": target, "type": edge_type, "label": label})

    for record in records:
        record_id = str(record.get("id") or "UNKNOWN").upper()
        vulnerability_node = f"vulnerability:{record_id.lower()}"
        node(
            vulnerability_node,
            record_id,
            "vulnerability",
            severity=record.get("severity", "UNKNOWN"),
            severity_zh=_severity_label(record.get("severity", "UNKNOWN"), language),
            cvss_score=record.get("cvss_score"),
            title=record.get("title", ""),
            summary=record.get("summary", ""),
            summary_zh=_localized_vulnerability_summary(record, language) if localize_summary else "",
            affected_versions=record.get("affected_versions") or [],
            fixed_versions=record.get("fixed_versions") or [],
            remediation_zh=_vulnerability_remediation(record, language),
            mitigation_zh=_vulnerability_mitigation(record, language),
            reference_links=_public_reference_links(record),
            aliases=record.get("aliases") or [],
            cwes=record.get("cwes") or [],
            published_at=record.get("published_at", ""),
            updated_at=record.get("updated_at", ""),
        )
        for alias in record.get("aliases", []):
            alias_text = str(alias).upper()
            if alias_text == record_id:
                continue
            alias_node = f"advisory:{alias_text.lower()}"
            node(alias_node, alias_text, "advisory")
            edge(vulnerability_node, alias_node, "ALIAS_OF", "别名")
        for cwe in record.get("cwes", []):
            cwe_text = str(cwe).upper()
            cwe_node = f"weakness:{cwe_text.lower()}"
            node(cwe_node, cwe_text, "weakness")
            edge(vulnerability_node, cwe_node, "HAS_WEAKNESS", "弱点类型")
        for component in record.get("components", [])[:10]:
            name = str(component.get("name") or "unknown-component")
            ecosystem = str(component.get("ecosystem") or "generic")
            component_node = f"component:{ecosystem.lower()}:{name.lower()}"
            node(component_node, name, "component", ecosystem=ecosystem, affected=component.get("affected", []), fixed=component.get("fixed", []))
            edge(vulnerability_node, component_node, "AFFECTS", "影响组件")
            for fixed in component.get("fixed", []):
                fixed_text = str(fixed)
                fixed_node = f"fix:{ecosystem.lower()}:{name.lower()}:{fixed_text.lower()}"
                node(fixed_node, fixed_text, "fix", component=name)
                edge(component_node, fixed_node, "FIXED_BY", "修复版本")

    return {
        "query": query,
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


_LANGUAGE_NAMES = {
    "zh-Hans": "简体中文",
    "zh-Hant": "繁體中文",
    "en": "English",
    "ko": "한국어",
    "ja": "日本語",
    "es": "Español",
    "fr": "Français",
    "de": "Deutsch",
    "it": "Italiano",
    "ru": "Русский",
}


def _normalize_response_language(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    if text in {"zh-hant", "zh-tw", "zh-hk", "zhtw", "zhhant", "traditional-chinese"}:
        return "zh-Hant"
    if text in {"en", "en-us", "english"}:
        return "en"
    if text in {"ko", "ko-kr", "kr", "korean"}:
        return "ko"
    if text in {"ja", "ja-jp", "jp", "japanese"}:
        return "ja"
    if text in {"es", "es-es", "spanish", "español"}:
        return "es"
    if text in {"fr", "fr-fr", "french", "français"}:
        return "fr"
    if text in {"de", "de-de", "german", "deutsch"}:
        return "de"
    if text in {"it", "it-it", "italian", "italiano"}:
        return "it"
    if text in {"ru", "ru-ru", "russian", "русский"}:
        return "ru"
    return "zh-Hans"


def _language_name(language: str) -> str:
    return _LANGUAGE_NAMES.get(_normalize_response_language(language), _LANGUAGE_NAMES["zh-Hans"])


def _severity_label(value: Any, language: str) -> str:
    normalized = str(value or "").strip().upper()
    language = _normalize_response_language(language)
    if normalized in {"CRITICAL", "SEVERE", "严重"}:
        return {"zh-Hans": "严重", "zh-Hant": "嚴重", "en": "Critical", "ko": "심각", "ja": "重大", "es": "Crítica", "fr": "Critique", "de": "Kritisch", "it": "Critica", "ru": "Критическая"}.get(language, "严重")
    if normalized in {"HIGH", "高危"}:
        return {"zh-Hans": "高危", "zh-Hant": "高危", "en": "High", "ko": "높음", "ja": "高", "es": "Alta", "fr": "Élevée", "de": "Hoch", "it": "Alta", "ru": "Высокая"}.get(language, "高危")
    if normalized in {"MEDIUM", "MODERATE", "中危"}:
        return {"zh-Hans": "中危", "zh-Hant": "中危", "en": "Medium", "ko": "중간", "ja": "中", "es": "Media", "fr": "Moyenne", "de": "Mittel", "it": "Media", "ru": "Средняя"}.get(language, "中危")
    if normalized in {"LOW", "低危"}:
        return {"zh-Hans": "低危", "zh-Hant": "低危", "en": "Low", "ko": "낮음", "ja": "低", "es": "Baja", "fr": "Faible", "de": "Niedrig", "it": "Bassa", "ru": "Низкая"}.get(language, "低危")
    return {"zh-Hans": "未知", "zh-Hant": "未知", "en": "Unknown", "ko": "알 수 없음", "ja": "不明", "es": "Desconocido", "fr": "Inconnu", "de": "Unbekannt", "it": "Sconosciuto", "ru": "Неизвестно"}.get(language, "未知")


def _not_specified(language: str) -> str:
    return {
        "zh-Hans": "未明确",
        "zh-Hant": "未明確",
        "en": "Not specified",
        "ko": "명확하지 않음",
        "ja": "未指定",
        "es": "No especificado",
        "fr": "Non spécifié",
        "de": "Nicht angegeben",
        "it": "Non specificato",
        "ru": "Не указано",
    }.get(_normalize_response_language(language), "未明确")


def _localized_vulnerability_summary(record: dict[str, Any], language: str = "zh-Hans") -> str:
    language = _normalize_response_language(language)
    summary = str(record.get("summary") or record.get("title") or "").strip()
    if not summary:
        return _fallback_vulnerability_summary(record, language)
    if language == "zh-Hans" and _contains_cjk(summary):
        return sanitize_public_text(summary)
    if language == "en" and not _contains_cjk(summary):
        return sanitize_public_text(summary)

    if _llm_summary_translation_enabled():
        translated = _translate_vulnerability_summary(summary, language)
        if translated:
            return translated
    return _fallback_vulnerability_summary(record, language)


def localized_vulnerability_summary(
    record: dict[str, Any],
    language: str = "zh-Hans",
    *,
    prefer_translation: bool = False,
) -> str:
    """Return a public, sanitized description in the requested report language."""

    language = _normalize_response_language(language)
    summary = str(record.get("summary") or record.get("title") or "").strip()
    if prefer_translation and summary:
        requires_translation = (language == "zh-Hans" and not _contains_cjk(summary)) or (
            language == "en" and _contains_cjk(summary)
        )
        if requires_translation:
            translated = _translate_vulnerability_summary(summary, language)
            if translated and (language != "zh-Hans" or _contains_cjk(translated)):
                return translated
    return _localized_vulnerability_summary(record, language)


def _translate_vulnerability_summary(summary: str, language: str = "zh-Hans") -> str:
    active_model = active_model_from_env()
    if not active_model:
        return ""
    language = _normalize_response_language(language)
    result = diagnose_chat_completion(
        active_model,
        [
            {
                "role": "system",
                "content": (
                    f"你是安全漏洞信息翻译助手。请把漏洞描述翻译为{_language_name(language)}。"
                    "要求：保留 CVE、GHSA、产品名、包名、函数名、版本号、URL 和技术术语；"
                    "不要添加情报来源、链接或额外解释；"
                    "只输出译文正文。"
                ),
            },
            {"role": "user", "content": summary[:1800]},
        ],
    )
    if result.get("status") != "success":
        return ""
    return sanitize_public_text(str(result.get("answer") or "").strip())


def _llm_summary_translation_enabled() -> bool:
    """Keep graph construction deterministic; per-record LLM calls scale linearly."""

    return str(os.getenv("SECFLOW_ENABLE_LLM_SUMMARY_TRANSLATION", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _fallback_vulnerability_summary(record: dict[str, Any], language: str = "zh-Hans") -> str:
    language = _normalize_response_language(language)
    record_id = str(record.get("id") or "该漏洞")
    severity = _severity_label(record.get("severity", "UNKNOWN"), language)
    score = record.get("cvss_score")
    affected = _join_limited(record.get("affected_versions") or [])
    fixed = _join_limited(record.get("fixed_versions") or [])
    if language == "en":
        score_text = f" Its CVSS score is {score}." if score is not None else ""
        affected_text = f" Known affected ranges include: {affected}." if affected else " Verify affected components and versions against the asset inventory."
        fixed_text = f" Upgrade to the confirmed fixed version(s): {fixed}." if fixed else " If no fixed version is confirmed, reduce exposure, restrict access, and keep monitoring patch availability."
        return sanitize_public_text(f"{record_id} is a {severity} vulnerability.{score_text}{affected_text}{fixed_text}")
    if language == "ja":
        score_text = f" CVSS スコアは {score} です。" if score is not None else ""
        affected_text = f" 既知の影響範囲：{affected}。" if affected else " 資産台帳と照合して影響を受けるコンポーネントとバージョンを確認してください。"
        fixed_text = f" 確認済みの修正バージョンへアップグレードしてください：{fixed}。" if fixed else " 修正バージョンが未確認の場合は、露出面を隔離し、アクセスを制限し、パッチ情報を継続監視してください。"
        return sanitize_public_text(f"{record_id} は {severity} 脆弱性です。{score_text}{affected_text}{fixed_text}")
    if language == "ko":
        score_text = f" CVSS 점수는 {score}입니다." if score is not None else ""
        affected_text = f" 알려진 영향 범위: {affected}." if affected else " 자산 목록과 대조해 영향받는 컴포넌트와 버전을 확인하세요."
        fixed_text = f" 확인된 수정 버전으로 업그레이드하세요: {fixed}." if fixed else " 수정 버전이 명확하지 않다면 노출면을 줄이고 접근을 제한하며 패치 정보를 지속적으로 확인하세요."
        return sanitize_public_text(f"{record_id}은(는) {severity} 취약점입니다.{score_text}{affected_text}{fixed_text}")
    score_text = f"CVSS 评分为 {score}，" if score is not None else ""
    affected_text = f"已知影响范围包括：{affected}。" if affected else "请结合资产清单核查受影响组件和版本。"
    fixed_text = f"建议升级到修复版本：{fixed}。" if fixed else "如暂未明确修复版本，应优先隔离暴露面、限制访问并持续关注补丁。"
    return sanitize_public_text(f"{record_id} 是一个{severity_cn(record.get('severity', 'UNKNOWN'))}漏洞，{score_text}{affected_text}{fixed_text}")


def _vulnerability_remediation(record: dict[str, Any], language: str = "zh-Hans") -> str:
    language = _normalize_response_language(language)
    fixed = _join_limited(record.get("fixed_versions") or [], limit=8)
    affected = _join_limited(record.get("affected_versions") or [], limit=5)
    if fixed:
        if "修复提交" in fixed:
            if language == "en":
                return sanitize_public_text(
                    f"Apply the confirmed fix commit(s): {fixed}. Review the change scope and complete workflow and business regression testing before release."
                )
            if language == "ja":
                return sanitize_public_text(
                    f"確認済みの修正コミットを適用してください：{fixed}。適用前に変更範囲を確認し、テスト環境でワークフローと業務回帰を検証してください。"
                )
            if language == "ko":
                return sanitize_public_text(
                    f"확인된 수정 커밋을 적용하세요: {fixed}. 적용 전 변경 범위를 확인하고 테스트 환경에서 워크플로와 비즈니스 회귀를 검증하세요."
                )
            return sanitize_public_text(
                f"建议采用已确认的{fixed}。应用前请核对变更范围，并在测试环境完成工作流与业务回归验证后再发布。"
            )
        if language == "en":
            return sanitize_public_text(
                f"Prioritize upgrading to the confirmed fixed version(s): {fixed}. Before release, verify affected components, assess compatibility, and complete dependency and business regression testing in a staging environment."
            )
        if language == "ja":
            return sanitize_public_text(
                f"確認済みの修正バージョンへのアップグレードを優先してください：{fixed}。リリース前に影響コンポーネントを確認し、互換性評価、依存関係検証、業務回帰テストをテスト環境で完了してください。"
            )
        if language == "ko":
            return sanitize_public_text(
                f"확인된 수정 버전으로 우선 업그레이드하세요: {fixed}. 배포 전 영향 컴포넌트를 확인하고 호환성 평가, 의존성 검증, 비즈니스 회귀 테스트를 테스트 환경에서 완료하세요."
            )
        return sanitize_public_text(
            f"建议优先升级到已确认的修复版本：{fixed}。升级前请核对受影响组件、完成兼容性评估，"
            "并在测试环境验证业务流程、依赖兼容和回归用例后再发布到生产环境。"
        )
    if affected:
        if language == "en":
            return sanitize_public_text(
                f"No confirmed fixed version is present in the current knowledge record. First verify the affected range: {affected}, then track the vendor patch or secure release and complete the normal upgrade validation once it is available."
            )
        if language == "ja":
            return sanitize_public_text(
                f"現在の知識レコードには明確な修正バージョンがありません。まず影響範囲を確認してください：{affected}。その後、公式パッチまたは安全バージョンを追跡し、利用可能になり次第、変更手順に従ってアップグレード検証を完了してください。"
            )
        if language == "ko":
            return sanitize_public_text(
                f"현재 지식 레코드에는 명확한 수정 버전이 없습니다. 먼저 영향 범위를 확인하세요: {affected}. 이후 공식 패치 또는 안전 버전을 추적하고 사용 가능해지면 변경 절차에 따라 업그레이드 검증을 완료하세요."
            )
        return sanitize_public_text(
            f"当前知识记录尚未给出明确修复版本。请先核验受影响范围：{affected}，"
            "随后跟进官方补丁或安全版本，在补丁可用后按变更流程完成升级验证。"
        )
    if language == "en":
        return "No confirmed fixed version is present in the current knowledge record. Verify asset fingerprints first, then decide whether to upgrade, replace, or temporarily isolate the affected component."
    if language == "ja":
        return "現在の知識レコードには明確な修正バージョンがありません。まず資産フィンガープリントを確認し、影響コンポーネントを特定してからアップグレード、置換、または一時隔離を判断してください。"
    if language == "ko":
        return "현재 지식 레코드에는 명확한 수정 버전이 없습니다. 먼저 자산 지문을 확인하고 영향 컴포넌트를 식별한 뒤 업그레이드, 교체 또는 임시 격리 여부를 결정하세요."
    return "当前知识记录尚未给出明确修复版本。建议先完成资产指纹核验，确认受影响组件后再制定升级或替换方案。"


def _vulnerability_mitigation(record: dict[str, Any], language: str = "zh-Hans") -> str:
    language = _normalize_response_language(language)
    severity = _severity_label(record.get("severity", "UNKNOWN"), language)
    affected = _join_limited(record.get("affected_versions") or [], limit=4)
    critical_or_high = str(record.get("severity") or "").strip().upper() in {"CRITICAL", "HIGH", "SEVERE", "严重", "高危"}
    if language == "en":
        affected_text = f" Prioritize: {affected}." if affected else " Prioritize assets exposed to the public internet, cross-tenant boundaries, or privileged paths."
        if critical_or_high:
            return sanitize_public_text(
                f"Until remediation is complete, reduce attack surface and strengthen monitoring.{affected_text} Restrict unnecessary network entry points and permissions, enable alerts for abnormal requests, authentication failures, privilege escalation, and sensitive operations; where exploitable entry points exist, temporarily block them with gateway, WAF, access control, or feature flags."
            )
        return sanitize_public_text(
            f"Until the remediation window arrives, keep monitoring related assets and reduce unnecessary exposure.{affected_text} Preserve access logs for anomaly detection and follow-up investigation."
        )
    if language == "ja":
        affected_text = f" 重点対象：{affected}。" if affected else " 公開インターネット、クロステナント境界、または高権限パスに露出している関連資産を優先してください。"
        if critical_or_high:
            return sanitize_public_text(
                f"修正完了まで攻撃面を一時的に縮小し、監視を強化してください。{affected_text}不要なネットワーク入口と権限を制限し、異常リクエスト、認証失敗、権限昇格、機密操作のアラートを有効化してください。悪用可能な入口がある場合は、ゲートウェイ、WAF、アクセス制御、または機能フラグで一時的に遮断してください。"
            )
        return sanitize_public_text(
            f"修正ウィンドウまで関連資産を継続監視し、不要な露出面を縮小してください。{affected_text}異常呼び出しの検出と後続調査のためにアクセスログを保持してください。"
        )
    if language == "ko":
        affected_text = f" 우선 범위: {affected}." if affected else " 공용 인터넷, 테넌트 경계 또는 고권한 경로에 노출된 관련 자산을 우선 확인하세요."
        if critical_or_high:
            return sanitize_public_text(
                f"수정이 완료될 때까지 공격면을 임시로 줄이고 모니터링을 강화하세요.{affected_text} 불필요한 네트워크 진입점과 권한을 제한하고 비정상 요청, 인증 실패, 권한 상승, 민감 작업에 대한 알림을 활성화하세요. 악용 가능한 진입점이 있으면 게이트웨이, WAF, 접근 제어 또는 기능 플래그로 임시 차단하세요."
            )
        return sanitize_public_text(
            f"수정 기간 전까지 관련 자산을 지속적으로 모니터링하고 불필요한 노출면을 줄이세요.{affected_text} 비정상 호출 탐지와 후속 추적을 위해 접근 로그를 보존하세요."
        )
    severity = severity_cn(record.get("severity", "UNKNOWN"))
    affected_text = f"重点覆盖：{affected}。" if affected else "重点覆盖暴露在公网、跨租户或高权限路径中的相关资产。"
    if severity in {"严重", "高危"}:
        return sanitize_public_text(
            f"在完成修复前，应临时降低攻击面并加强监控。{affected_text}"
            "建议限制不必要的网络入口和访问权限，启用异常请求、认证失败、权限提升和敏感操作告警；"
            "如存在可利用入口，可结合网关、WAF、访问控制或功能开关进行临时阻断。"
        )
    return sanitize_public_text(
        f"在修复窗口到来前，建议持续监控相关资产并收敛不必要暴露面。{affected_text}"
        "同时保留访问日志，便于发现异常调用和后续溯源。"
    )


def _public_reference_links(record: dict[str, Any], limit: int = 6) -> list[str]:
    links: list[str] = []
    values: list[Any] = []
    for field in (record.get("references"), record.get("reference_links")):
        values.extend(field if isinstance(field, list) else [field] if field else [])
    for value in values:
        text = str(value or "").strip()
        if text.startswith(("https://", "http://")):
            links.append(text)
    return _unique(links)[:limit]


def _record_needs_realtime_enrichment(record: dict[str, Any]) -> bool:
    """Return whether a local exact-ID hit lacks core customer-facing facts."""

    severity = str(record.get("severity") or "UNKNOWN").strip().upper()
    try:
        normalization_version = int(record.get("normalization_version") or 0)
    except (TypeError, ValueError):
        normalization_version = 0
    return any(
        (
            normalization_version < _RECORD_NORMALIZATION_VERSION,
            severity in {"", "UNKNOWN"},
            record.get("cvss_score") is None,
            not str(record.get("summary") or record.get("title") or "").strip(),
            not _public_reference_links(record),
        )
    )


def _extract_advisory_code_snippets(text: str, limit: int = 3) -> tuple[list[str], list[str]]:
    """Extract non-exploit code blocks embedded in advisory descriptions.

    Some advisory records include markdown examples that show the vulnerable
    call site, affected API usage, or patched usage. We
    surface only those factual code blocks. We do not synthesize snippets here.
    """

    vulnerable: list[str] = []
    fixed: list[str] = []
    for match in re.finditer(r"```[a-zA-Z0-9_+.-]*\s*\n(.*?)```", text or "", flags=re.DOTALL):
        snippet = _normalize_code_snippet(match.group(1))
        if snippet and _looks_like_vulnerable_code_snippet(snippet):
            context = text[max(0, match.start() - 360): match.start()].lower()
            if _looks_like_fixed_code_context(context):
                fixed.append(snippet)
            else:
                vulnerable.append(snippet)
        if len(vulnerable) >= limit and len(fixed) >= limit:
            break
    return _unique(vulnerable)[:limit], _unique(fixed)[:limit]


def _extract_vulnerable_code_snippets(text: str, limit: int = 3) -> list[str]:
    return _extract_advisory_code_snippets(text, limit=limit)[0]


def _extract_fixed_code_snippets(text: str, limit: int = 3) -> list[str]:
    return _extract_advisory_code_snippets(text, limit=limit)[1]


def _enrich_records_with_reference_patches(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fetch source patches only from explicit GitHub commit references."""

    enriched = [deepcopy(record) for record in records]
    candidates: list[tuple[int, str]] = []
    seen_urls: set[str] = set()
    for index, record in enumerate(enriched):
        if record.get("code_snippets") and record.get("fixed_code_snippets"):
            continue
        for reference in [*record.get("references", []), *record.get("reference_links", [])]:
            url = _github_commit_api_url(str(reference or ""))
            if url and url not in seen_urls:
                candidates.append((index, url))
                seen_urls.add(url)
            if len(candidates) >= _PATCH_ENRICHMENT_MAX_COMMITS:
                break
        if len(candidates) >= _PATCH_ENRICHMENT_MAX_COMMITS:
            break
    if not candidates:
        return enriched

    executor = ThreadPoolExecutor(max_workers=min(len(candidates), _PATCH_ENRICHMENT_MAX_COMMITS))
    try:
        futures = {
            executor.submit(_fetch_github_commit_patch_snippets, url): (index, url)
            for index, url in candidates
        }
        completed, _timed_out = _collect_futures_with_budget(futures, _PATCH_ENRICHMENT_BUDGET_SECONDS)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    for (index, _url), outcome in completed:
        if isinstance(outcome, Exception) or not isinstance(outcome, tuple):
            continue
        vulnerable, fixed = outcome
        enriched[index]["code_snippets"] = _unique(
            [*enriched[index].get("code_snippets", []), *vulnerable]
        )[:3]
        enriched[index]["fixed_code_snippets"] = _unique(
            [*enriched[index].get("fixed_code_snippets", []), *fixed]
        )[:3]
    for record in enriched:
        context = str(record.get("summary") or record.get("title") or "")
        record["code_snippets"] = _rank_code_snippets(record.get("code_snippets", []), context)[:3]
        record["fixed_code_snippets"] = _rank_code_snippets(record.get("fixed_code_snippets", []), context)[:3]
    return enriched


def _github_commit_api_url(reference: str) -> str:
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commit/([0-9a-fA-F]{7,40})(?:[/?#].*)?",
        reference.strip(),
    )
    if not match:
        return ""
    owner, repository, commit = match.groups()
    return f"https://api.github.com/repos/{owner}/{repository}/commits/{commit}"


def _fetch_github_commit_patch_snippets(url: str) -> tuple[list[str], list[str]]:
    with httpx.Client(timeout=_PATCH_ENRICHMENT_BUDGET_SECONDS, follow_redirects=True) as client:
        response = client.get(url, headers=default_headers(auth="secondary"))
        response.raise_for_status()
        payload = response.json()
    return _patch_snippets_from_commit_payload(payload)


def _patch_snippets_from_commit_payload(payload: dict[str, Any], limit: int = 3) -> tuple[list[str], list[str]]:
    vulnerable: list[str] = []
    fixed: list[str] = []
    for file in payload.get("files") or []:
        if not isinstance(file, dict):
            continue
        filename = str(file.get("filename") or "")
        patch = str(file.get("patch") or "")
        if not patch or not _safe_source_patch_file(filename):
            continue
        for hunk in re.split(r"(?=^@@)", patch, flags=re.MULTILINE):
            if not hunk.startswith("@@"):
                continue
            old_lines: list[str] = []
            new_lines: list[str] = []
            has_deleted = False
            has_added = False
            for line in hunk.splitlines()[1:]:
                if line.startswith("\\ No newline"):
                    continue
                if line.startswith("-") and not line.startswith("---"):
                    old_lines.append(line[1:])
                    has_deleted = True
                elif line.startswith("+") and not line.startswith("+++"):
                    new_lines.append(line[1:])
                    has_added = True
                elif line.startswith(" "):
                    value = line[1:]
                    old_lines.append(value)
                    new_lines.append(value)
            if not has_added and not has_deleted:
                continue
            old_snippet = _normalize_code_snippet("\n".join(old_lines))
            new_snippet = _normalize_code_snippet("\n".join(new_lines))
            if has_deleted and old_snippet and _looks_like_vulnerable_code_snippet(old_snippet):
                vulnerable.append(old_snippet)
            if has_added and new_snippet and _looks_like_vulnerable_code_snippet(new_snippet):
                fixed.append(new_snippet)
            if len(vulnerable) >= limit and len(fixed) >= limit:
                return _unique(vulnerable)[:limit], _unique(fixed)[:limit]
    return _unique(vulnerable)[:limit], _unique(fixed)[:limit]


def _safe_source_patch_file(filename: str) -> bool:
    lowered = filename.lower()
    blocked_segments = {"test", "tests", "spec", "specs", "poc", "pocs", "exploit", "exploits", "fixtures"}
    if any(segment in blocked_segments for segment in Path(lowered).parts):
        return False
    if any(marker in Path(lowered).name for marker in ("poc", "exploit", "payload")):
        return False
    return Path(lowered).suffix in {
        ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx",
        ".kt", ".kts", ".m", ".mm", ".php", ".py", ".rb", ".rs", ".scala", ".swift",
        ".ts", ".tsx", ".xml", ".yaml", ".yml",
    }


def _rank_code_snippets(snippets: list[str], context: str) -> list[str]:
    context_tokens = {
        token.lower()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", context)
        if token.lower() not in {
            "affected", "allows", "attacker", "fixed", "issue", "library", "prior", "remote",
            "this", "version", "versions", "vulnerability", "with",
        }
    }
    indexed = list(enumerate(_unique(snippets)))

    def score(item: tuple[int, str]) -> tuple[int, int]:
        index, snippet = item
        lowered = snippet.lower()
        matches = sum(1 for token in context_tokens if token in lowered)
        return matches, -index

    indexed.sort(key=score, reverse=True)
    return [snippet for _index, snippet in indexed]


def _normalize_code_snippet(value: str, max_chars: int = 1400) -> str:
    lines = [line.rstrip() for line in str(value or "").strip().splitlines()]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    snippet = "\n".join(lines).strip()
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars].rstrip() + "\n..."
    return snippet


def _looks_like_vulnerable_code_snippet(snippet: str) -> bool:
    lowered = snippet.lower()
    if len(snippet.strip()) < 12:
        return False
    exploit_markers = [
        "metasploit",
        "reverse shell",
        "bind shell",
        "nc -e",
        "bash -i",
        "powershell -enc",
        "msfconsole",
        "exploit(",
        "payload",
        "shellcode",
        "calc.exe",
        "/bin/sh",
        "/bin/bash",
    ]
    if any(marker in lowered for marker in exploit_markers):
        return False
    code_markers = [
        "function ",
        "class ",
        "def ",
        "import ",
        "require(",
        "const ",
        "let ",
        "var ",
        "public ",
        "private ",
        "if ",
        "return ",
        "{",
        "}",
        "(",
        ")",
        ";",
        "=",
    ]
    return any(marker in lowered for marker in code_markers)


def _looks_like_fixed_code_context(context: str) -> bool:
    fixed_markers = [
        "fixed",
        "fix:",
        "fix ",
        "patch",
        "patched",
        "after",
        "correct",
        "safe",
        "remediation",
        "mitigation",
        "upgrade",
        "修复",
        "修补",
        "补丁",
        "安全写法",
        "修复后",
        "正确写法",
    ]
    vulnerable_markers = [
        "vulnerable",
        "before",
        "affected",
        "bad",
        "unsafe",
        "insecure",
        "易受攻击",
        "漏洞代码",
        "修复前",
        "错误写法",
    ]
    if any(marker in context for marker in fixed_markers):
        return True
    if any(marker in context for marker in vulnerable_markers):
        return False
    return False


def _join_limited(values: list[Any], limit: int = 4) -> str:
    items = [str(value).strip() for value in values if str(value).strip()]
    if len(items) > limit:
        return "、".join(items[:limit]) + f" 等 {len(items)} 项"
    return "、".join(items)


def _contains_cjk(value: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", value))


def _fixed_commit_facts(text: str) -> list[str]:
    hashes = re.findall(
        r"(?:fixed|patched|resolved|修复|修补)[^\n。]{0,40}?commit\s+([0-9a-f]{7,40})\b",
        str(text or ""),
        flags=re.IGNORECASE,
    )
    return [f"修复提交 {value.lower()}" for value in _unique(hashes)]


def _github_record(item: dict[str, Any]) -> dict[str, Any]:
    ghsa_id = str(item.get("ghsa_id") or "").upper()
    cve_id = str(item.get("cve_id") or "").upper()
    affected, fixed = _github_version_facts(item)
    description = str(item.get("description") or item.get("summary") or "")
    vulnerable_snippets, fixed_snippets = _extract_advisory_code_snippets(description)
    components = []
    for vulnerability in item.get("vulnerabilities") or []:
        package = vulnerability.get("package") or {}
        name = str(package.get("name") or "").strip()
        if not name:
            continue
        first_patched = vulnerability.get("first_patched_version") or {}
        patched = first_patched.get("identifier") if isinstance(first_patched, dict) else first_patched
        components.append(
            {
                "name": name,
                "ecosystem": str(package.get("ecosystem") or "generic"),
                "affected": [str(vulnerability.get("vulnerable_version_range") or "")] if vulnerability.get("vulnerable_version_range") else [],
                "fixed": [str(patched)] if patched else [],
            }
        )
    cwes: list[str] = []
    for value in item.get("cwes") or []:
        if isinstance(value, dict):
            cwe = str(value.get("cwe_id") or value.get("id") or "").upper()
        else:
            cwe = str(value or "").upper()
        if cwe.startswith("CWE-"):
            cwes.append(cwe)
    return {
        "id": cve_id or ghsa_id,
        "title": item.get("summary") or cve_id or ghsa_id,
        "severity": str(item.get("severity") or "UNKNOWN").upper(),
        "cvss_score": _github_cvss_score(item),
        "cvss_vector": str((item.get("cvss") or {}).get("vector_string") or "").strip(),
        "summary": description,
        "affected_versions": affected,
        "fixed_versions": _unique([*fixed, *_fixed_commit_facts(description)]),
        "code_snippets": vulnerable_snippets,
        "fixed_code_snippets": fixed_snippets,
        "aliases": _unique([cve_id, ghsa_id]),
        "cwes": cwes,
        "components": components,
        "references": _unique([str(item.get("html_url") or "")]),
        "published_at": item.get("published_at") or "",
        "updated_at": item.get("updated_at") or now_iso(),
        "provenance": ["github_advisory"],
    }


def _osv_record(item: dict[str, Any]) -> dict[str, Any]:
    aliases = _unique([str(item.get("id") or "").upper(), *[str(alias).upper() for alias in item.get("aliases") or []]])
    primary = next((alias for alias in aliases if alias.startswith("CVE-")), aliases[0] if aliases else "UNKNOWN")
    components: list[dict[str, Any]] = []
    affected_versions: list[str] = []
    fixed_versions: list[str] = []
    for affected in item.get("affected") or []:
        package = affected.get("package") or {}
        name = str(package.get("name") or "").strip()
        ecosystem = str(package.get("ecosystem") or "generic")
        affected_ranges: list[str] = []
        fixed: list[str] = []
        for range_item in affected.get("ranges") or []:
            introduced = ""
            for event in range_item.get("events") or []:
                if event.get("introduced") is not None:
                    introduced = str(event["introduced"])
                if event.get("fixed") is not None:
                    fixed.append(str(event["fixed"]))
                if event.get("last_affected") is not None:
                    affected_ranges.append(f"{introduced or '0'} - {event['last_affected']}")
            if introduced and fixed:
                affected_ranges.extend(f">= {introduced}, < {version}" for version in fixed)
        if name:
            components.append({"name": name, "ecosystem": ecosystem, "affected": _unique(affected_ranges), "fixed": _unique(fixed)})
            affected_versions.extend(f"{ecosystem} / {name}: {value}" for value in affected_ranges)
            fixed_versions.extend(f"{ecosystem} / {name}: {value}" for value in fixed)
    database = item.get("database_specific") or {}
    severity = str(database.get("severity") or "UNKNOWN").upper()
    cvss_vector = next(
        (
            str(entry.get("score") or "").strip()
            for entry in item.get("severity") or []
            if isinstance(entry, dict) and str(entry.get("score") or "").strip().startswith("CVSS:")
        ),
        "",
    )
    references = [str(reference.get("url") or "") for reference in item.get("references") or []]
    details = str(item.get("details") or item.get("summary") or "")
    vulnerable_snippets, fixed_snippets = _extract_advisory_code_snippets(details)
    return {
        "id": primary,
        "title": item.get("summary") or primary,
        "severity": severity,
        "cvss_score": None,
        "cvss_vector": cvss_vector,
        "summary": details,
        "affected_versions": _unique(affected_versions),
        "fixed_versions": _unique([*fixed_versions, *_fixed_commit_facts(details)]),
        "code_snippets": vulnerable_snippets,
        "fixed_code_snippets": fixed_snippets,
        "aliases": aliases,
        "cwes": _unique([str(value).upper() for value in database.get("cwe_ids") or []]),
        "components": components,
        "references": _unique(references),
        "published_at": item.get("published") or "",
        "updated_at": item.get("modified") or now_iso(),
        "provenance": ["osv"],
    }


def _nvd_cwes(cve: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").upper()
            if value.startswith("CWE-"):
                values.append(value)
    return _unique(values)


def _nvd_components(cve: dict[str, Any]) -> list[dict[str, Any]]:
    components: dict[str, dict[str, Any]] = {}
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                parts = str(match.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                vendor = parts[3].replace("_", " ")
                product = parts[4].replace("_", " ")
                if not product or product in {"*", "-"}:
                    continue
                key = f"{vendor}:{product}".lower()
                affected = _nvd_affected_versions({"configurations": [{"nodes": [{"cpeMatch": [match]}]}]})
                entry = components.setdefault(key, {"name": product, "ecosystem": vendor or "cpe", "affected": [], "fixed": []})
                entry["affected"] = _unique([*entry["affected"], *affected])
    for component in _nvd_modern_components(cve):
        key = f"{component.get('ecosystem')}:{component.get('name')}".lower()
        entry = components.setdefault(
            key,
            {
                "name": component.get("name"),
                "ecosystem": component.get("ecosystem") or "generic",
                "affected": [],
                "fixed": [],
            },
        )
        entry["affected"] = _unique([*entry["affected"], *component.get("affected", [])])
        entry["fixed"] = _unique([*entry["fixed"], *component.get("fixed", [])])
    return list(components.values())[:20]


def _nvd_records_from_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in items:
        cve = item.get("cve", {})
        if str(cve.get("vulnStatus") or "").lower() == "rejected":
            continue
        record = _nvd_record(cve, {"collection_name": "realtime"}, None)
        if not record:
            continue
        record.update(
            {
                "aliases": [record["id"]],
                "cwes": _nvd_cwes(cve),
                "components": _nvd_components(cve),
                "provenance": ["nvd"],
            }
        )
        record["fixed_versions"] = _unique(
            [*record.get("fixed_versions", []), *_fixed_commit_facts(record.get("summary") or "")]
        )
        records.append(record)
    return records


def _merge_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    for incoming in records:
        incoming = deepcopy(incoming)
        aliases = {str(value).upper() for value in incoming.get("aliases", []) if value}
        aliases.add(str(incoming.get("id") or "").upper())
        target = next((record for record in clusters if aliases & {str(value).upper() for value in record.get("aliases", [])}), None)
        if target is None:
            incoming["aliases"] = sorted(aliases)
            clusters.append(incoming)
        else:
            _merge_record(target, incoming)
    clusters.sort(key=lambda item: (_SEVERITY_RANK.get(str(item.get("severity") or "UNKNOWN").upper(), 0), str(item.get("updated_at") or "")), reverse=True)
    return clusters


def _records_by_canonical_vulnerability_id(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one dashboard row per vulnerability, keyed by CVE first.

    The dashboard must not count API rows or query attempts. Multiple fixed
    upstream interfaces can return the same vulnerability; the business-facing
    total is the unique CVE count. If a record truly has no CVE alias, GHSA is
    used as a fallback key so the item is still visible.
    """

    grouped: dict[str, dict[str, Any]] = {}
    for record in records:
        key = _canonical_vulnerability_id(record)
        if not key:
            continue
        incoming = deepcopy(record)
        current = grouped.get(key)
        if current is None:
            incoming["id"] = key
            grouped[key] = incoming
            continue
        _merge_record(current, incoming)
        current["id"] = key
    result = list(grouped.values())
    result.sort(key=lambda item: (_SEVERITY_RANK.get(str(item.get("severity") or "UNKNOWN").upper(), 0), str(item.get("updated_at") or "")), reverse=True)
    return result


def _canonical_vulnerability_id(record: dict[str, Any]) -> str:
    values = [record.get("id"), *record.get("aliases", [])]
    for value in values:
        match = CVE_ID.search(str(value or ""))
        if match:
            return match.group(0).upper()
    for value in values:
        match = GHSA_ID.search(str(value or ""))
        if match:
            return match.group(0).upper()
    return str(record.get("id") or "").upper()


def _merge_record(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    target["aliases"] = _unique([*target.get("aliases", []), *incoming.get("aliases", []), incoming.get("id", "")])
    cve = next((value for value in target["aliases"] if str(value).startswith("CVE-")), None)
    if cve:
        target["id"] = cve
    for key in ("affected_versions", "fixed_versions", "code_snippets", "fixed_code_snippets", "cwes", "references", "provenance", "matched_dependencies"):
        target[key] = _unique([*target.get(key, []), *incoming.get(key, [])])
    component_map = {f"{item.get('ecosystem')}:{item.get('name')}".lower(): deepcopy(item) for item in target.get("components", [])}
    for component in incoming.get("components", []):
        key = f"{component.get('ecosystem')}:{component.get('name')}".lower()
        if key not in component_map:
            component_map[key] = deepcopy(component)
        else:
            component_map[key]["affected"] = _unique([*component_map[key].get("affected", []), *component.get("affected", [])])
            component_map[key]["fixed"] = _unique([*component_map[key].get("fixed", []), *component.get("fixed", [])])
    target["components"] = list(component_map.values())
    current_score = target.get("cvss_score")
    incoming_score = incoming.get("cvss_score")
    if incoming_score is not None and (current_score is None or float(incoming_score) > float(current_score)):
        target["cvss_score"] = incoming_score
        if incoming.get("cvss_vector"):
            target["cvss_vector"] = incoming["cvss_vector"]
    elif not target.get("cvss_vector") and incoming.get("cvss_vector"):
        target["cvss_vector"] = incoming["cvss_vector"]
    if _SEVERITY_RANK.get(str(incoming.get("severity") or "UNKNOWN").upper(), 0) > _SEVERITY_RANK.get(str(target.get("severity") or "UNKNOWN").upper(), 0):
        target["severity"] = incoming["severity"]
    for key in ("title", "summary"):
        if not target.get(key) and incoming.get(key):
            target[key] = incoming[key]
    published_values = [str(value) for value in (target.get("published_at"), incoming.get("published_at")) if value]
    if published_values:
        target["published_at"] = min(published_values)
    updated_values = [str(value) for value in (target.get("updated_at"), incoming.get("updated_at")) if value]
    if updated_values:
        target["updated_at"] = max(updated_values)


def _keyword_query(query: str) -> str:
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_.+-]{2,}", query)
    return " ".join(tokens[:8])


def _normalize_dependency_facts(dependencies: list[dict[str, Any]], limit: int = 80) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for dependency in dependencies:
        ecosystem = str(dependency.get("ecosystem") or "").strip()
        name = str(dependency.get("name") or "").strip()
        if not ecosystem or not name:
            continue
        item = {
            "ecosystem": ecosystem,
            "name": name,
            "version": str(dependency.get("version") or "").strip(),
            "source_file": str(dependency.get("source_file") or dependency.get("sourceFile") or "").strip(),
            "source_type": str(dependency.get("source_type") or dependency.get("sourceType") or "").strip(),
            "declaration": str(dependency.get("declaration") or "").strip(),
            "confidence": str(dependency.get("confidence") or "medium").strip(),
        }
        key = f"{item['ecosystem']}|{item['name']}|{item['version']}".lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
        if len(result) >= limit:
            break
    return result


def _is_concrete_dependency_version(value: Any) -> bool:
    version = str(value or "").strip()
    return bool(version) and "${" not in version and version.lower() not in {"unknown", "latest", "release", "*"}


def _record_affects_dependency(record: dict[str, Any], dependency: dict[str, Any]) -> bool:
    version = str(dependency.get("version") or "").strip()
    if not _is_concrete_dependency_version(version):
        return False
    dependency_keys = set(_dependency_component_keys(dependency))
    ranges: list[str] = []
    for component in record.get("components") or []:
        if not isinstance(component, dict):
            continue
        if dependency_keys & set(_dependency_component_keys(component)):
            ranges.extend(str(value).strip() for value in component.get("affected") or [] if str(value).strip())
    if not ranges:
        dependency_name = str(dependency.get("name") or "").lower()
        for value in record.get("affected_versions") or []:
            text = str(value).strip()
            if dependency_name and dependency_name in text.lower() and ":" in text:
                ranges.append(text.split(":", 1)[1].strip())
    return any(_version_in_affected_range(version, affected_range) for affected_range in ranges)


def _version_in_affected_range(version: str, affected_range: str) -> bool:
    current = _comparable_version(version)
    if current is None:
        return False
    value = str(affected_range or "").strip()
    if not value:
        return False
    if value.lower() in {"*", "all", "all versions"}:
        return True
    for alternative in re.split(r"\s*\|\|\s*", value):
        alternative = alternative.strip()
        if not alternative:
            continue
        interval = re.fullmatch(r"^(\[|\()\s*([^,]*)\s*,\s*([^\]\)]*)\s*(\]|\))$", alternative)
        if interval:
            lower = _comparable_version(interval.group(2)) if interval.group(2) else None
            upper = _comparable_version(interval.group(3)) if interval.group(3) else None
            lower_ok = lower is None or current > lower or (interval.group(1) == "[" and current == lower)
            upper_ok = upper is None or current < upper or (interval.group(4) == "]" and current == upper)
            if lower_ok and upper_ok:
                return True
            continue
        between = re.fullmatch(r"\s*([^\s,]+)\s+-\s+([^\s,]+)\s*", alternative)
        if between:
            lower = _comparable_version(between.group(1))
            upper = _comparable_version(between.group(2))
            if lower is not None and upper is not None and lower <= current <= upper:
                return True
            continue
        comparisons = re.findall(r"(<=|>=|<|>|==|=)\s*([^\s,]+)", alternative)
        if comparisons:
            matched = True
            for operator, expected_text in comparisons:
                expected = _comparable_version(expected_text)
                if expected is None:
                    matched = False
                    break
                matched = matched and {
                    "<": current < expected,
                    "<=": current <= expected,
                    ">": current > expected,
                    ">=": current >= expected,
                    "=": current == expected,
                    "==": current == expected,
                }[operator]
            if matched:
                return True
            continue
        exact = _comparable_version(alternative)
        if exact is not None and current == exact:
            return True
    return False


def _comparable_version(value: str) -> Version | None:
    clean = str(value or "").strip().lstrip("vV")
    if not clean:
        return None
    clean = re.sub(r"(?i)[.-](?:release|final|ga)$", "", clean)
    clean = re.sub(r"(?i)-m(\d+)$", r"a\1", clean)
    clean = re.sub(r"(?i)-rc(\d+)$", r"rc\1", clean)
    clean = re.sub(r"(?i)-snapshot$", ".dev0", clean)
    clean = re.sub(r"(?i)[.-]jre\d+$", "", clean)
    try:
        return Version(clean)
    except InvalidVersion:
        return None


def _component_key(ecosystem: Any, name: Any) -> str:
    clean_ecosystem = re.sub(r"\s+", " ", str(ecosystem or "").strip().lower())
    clean_name = re.sub(r"\s+", " ", str(name or "").strip().lower())
    if not clean_ecosystem or not clean_name:
        return ""
    return f"{clean_ecosystem}|{clean_name}"


def _record_component_keys(record: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for component in record.get("components") or []:
        if not isinstance(component, dict):
            continue
        key = _component_key(component.get("ecosystem"), component.get("name"))
        if key:
            keys.append(key)
    for dependency in record.get("matched_dependencies") or []:
        if not isinstance(dependency, dict):
            continue
        keys.extend(_dependency_component_keys(dependency))
    return _unique(keys)


def _dependency_component_keys(dependency: dict[str, Any]) -> list[str]:
    ecosystem = str(dependency.get("ecosystem") or "").strip()
    name = str(dependency.get("name") or "").strip()
    keys = [_component_key(ecosystem, name)]
    if ecosystem.lower() == "maven" and ":" in name:
        group_id, artifact_id = name.split(":", 1)
        keys.append(_component_key(ecosystem, artifact_id))
        keys.append(_component_key(group_id, artifact_id))
    return [key for key in _unique(keys) if key]


def _dependencies_missing_local_hits(dependencies: list[dict[str, Any]], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matched_keys: set[str] = set()
    for record in records:
        matched_keys.update(_record_component_keys(record))
        for dependency in record.get("matched_dependencies") or []:
            if isinstance(dependency, dict):
                matched_keys.update(_dependency_component_keys(dependency))
    missing: list[dict[str, Any]] = []
    for dependency in dependencies:
        dependency_keys = set(_dependency_component_keys(dependency))
        if not dependency_keys or not (dependency_keys & matched_keys):
            missing.append(dependency)
    return missing


def _tag_dependency_record(record: dict[str, Any], dependency: dict[str, Any]) -> dict[str, Any]:
    public_dependency = {
        "ecosystem": str(dependency.get("ecosystem") or ""),
        "name": str(dependency.get("name") or ""),
        "version": str(dependency.get("version") or ""),
        "source_file": str(dependency.get("source_file") or ""),
        "source_type": str(dependency.get("source_type") or ""),
        "declaration": str(dependency.get("declaration") or ""),
        "confidence": str(dependency.get("confidence") or "medium"),
    }
    record["matched_dependencies"] = _unique([*record.get("matched_dependencies", []), public_dependency])
    component_key = f"{public_dependency['ecosystem']}:{public_dependency['name']}".lower()
    components = record.setdefault("components", [])
    if public_dependency["name"] and not any(
        f"{component.get('ecosystem')}:{component.get('name')}".lower() == component_key
        for component in components
        if isinstance(component, dict)
    ):
        components.append(
            {
                "ecosystem": public_dependency["ecosystem"],
                "name": public_dependency["name"],
                "affected": [],
                "fixed": [],
            }
        )
    return record


def _dependency_lookup_error_record(dependency: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"DEPENDENCY-LOOKUP-{abs(hash(str(dependency))) % 100000}",
        "lookup_error": True,
        "matched_dependencies": [_normalize_dependency_facts([dependency])[0]] if _normalize_dependency_facts([dependency]) else [],
        "aliases": [],
        "severity": "UNKNOWN",
        "updated_at": now_iso(),
    }


def _record_identifiers(records: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for record in records:
        values.append(str(record.get("id") or ""))
        values.extend(str(alias or "") for alias in record.get("aliases", []))
    preferred: list[str] = []
    fallback: list[str] = []
    for value in values:
        cve = CVE_ID.search(value)
        if cve:
            preferred.append(cve.group(0).upper())
            continue
        ghsa = GHSA_ID.search(value)
        if ghsa:
            fallback.append(ghsa.group(0).upper())
    return _unique([*preferred, *fallback])


def _nvd_api_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _dashboard_date_range(
    start_value: date | str | None,
    end_value: date | str | None,
) -> tuple[datetime | None, datetime | None]:
    if start_value is None and end_value is None:
        return None, None
    if start_value is None or end_value is None:
        raise ValueError("开始日期和结束日期必须同时提供")

    def as_date(value: date | str) -> date:
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, date):
            return value
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError as exc:
            raise ValueError("日期格式必须为 YYYY-MM-DD") from exc

    start_date = as_date(start_value)
    end_date = as_date(end_value)
    if start_date > end_date:
        raise ValueError("开始日期不能晚于结束日期")
    start = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
    end = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
    return start, end


def _unique(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        if value is None or value == "":
            continue
        key = str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _aggregate_status(statuses: list[dict[str, Any]]) -> str:
    failed = sum(item.get("status") == "failed" for item in statuses)
    if failed == len(statuses) and statuses:
        return "failed"
    if failed:
        return "warning"
    return "completed"


def _dependency_secondary_enrichment_enabled() -> bool:
    return str(os.getenv("SECFLOW_DEPENDENCY_SECONDARY_ENRICHMENT", "")).strip().lower() in {"1", "true", "yes", "on"}


def _dependency_lookup_budget_seconds() -> float:
    return _positive_float_env("SECFLOW_DEPENDENCY_LOOKUP_BUDGET_SECONDS", _DEPENDENCY_LOOKUP_BUDGET_SECONDS, minimum=3.0, maximum=30.0)


def _dependency_total_budget_seconds() -> float:
    return _positive_float_env("SECFLOW_DEPENDENCY_TOTAL_BUDGET_SECONDS", _DEPENDENCY_TOTAL_BUDGET_SECONDS, minimum=0.1, maximum=30.0)


def _dependency_request_timeout_seconds() -> float:
    return _positive_float_env("SECFLOW_DEPENDENCY_REQUEST_TIMEOUT_SECONDS", _DEPENDENCY_REQUEST_TIMEOUT_SECONDS, minimum=2.0, maximum=15.0)


def _dependency_detail_timeout_seconds() -> float:
    return _positive_float_env("SECFLOW_DEPENDENCY_DETAIL_TIMEOUT_SECONDS", _DEPENDENCY_DETAIL_TIMEOUT_SECONDS, minimum=1.0, maximum=8.0)


def _dependency_record_limit() -> int:
    value = os.getenv("SECFLOW_DEPENDENCY_RECORD_LIMIT", "").strip()
    if value.isdigit():
        return max(1, min(int(value), 8))
    return _DEPENDENCY_RECORD_LIMIT


def _dependency_query_limit() -> int:
    value = os.getenv("SECFLOW_DEPENDENCY_QUERY_LIMIT", "").strip()
    if value.isdigit():
        return max(1, min(int(value), 30))
    return _DEPENDENCY_QUERY_LIMIT


def _realtime_query_budget_seconds() -> float:
    return _positive_float_env("SECFLOW_REALTIME_QUERY_BUDGET_SECONDS", _REALTIME_QUERY_BUDGET_SECONDS, minimum=0.1, maximum=30.0)


def _dashboard_refresh_budget_seconds() -> float:
    return _positive_float_env("SECFLOW_DASHBOARD_REFRESH_BUDGET_SECONDS", _DASHBOARD_REFRESH_BUDGET_SECONDS, minimum=1.0, maximum=60.0)


def _osv_batch_budget_seconds() -> float:
    return _positive_float_env("SECFLOW_OSV_BATCH_BUDGET_SECONDS", _OSV_BATCH_BUDGET_SECONDS, minimum=0.1, maximum=30.0)


def _positive_float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, "").strip()
    try:
        value = float(raw) if raw else float(default)
    except ValueError:
        value = float(default)
    return max(minimum, min(value, maximum))


def _public_source_status(statuses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = {source: index for index, source in enumerate(_FIXED_SOURCE_ORDER)}
    result: list[dict[str, Any]] = []
    for index, item in enumerate(sorted(statuses, key=lambda value: order.get(str(value.get("id")), 99)), start=1):
        status = str(item.get("status") or "ready")
        count = int(item.get("count") or item.get("last_count") or 0)
        if status == "success":
            message = "查询完成"
        elif status == "failed":
            message = "查询失败"
        elif status == "warning":
            message = "部分完成"
        else:
            message = "等待查询"
        result.append(
            {
                "id": f"intel_{index}",
                "name": f"情报接口 {index}",
                "kind": "固定接口",
                "enabled": True,
                "status": status,
                "count": count,
                "last_count": count,
                "message": message,
            }
        )
    return result


def _public_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove upstream provenance from records returned to the desktop client."""

    private_keys = {"source", "sources", "provenance", "references", "collection", "collection_name", "provider"}
    result: list[dict[str, Any]] = []
    for record in records:
        item = {key: deepcopy(value) for key, value in record.items() if key not in private_keys}
        item["reference_links"] = _public_reference_links(record)
        result.append(item)
    return result


def _catalog_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize a record for encrypted internal storage without losing facts."""

    item = deepcopy(record)
    item["normalization_version"] = _RECORD_NORMALIZATION_VERSION
    item["references"] = _public_reference_links(item, limit=100)
    item.pop("reference_links", None)
    item.pop("lookup_error", None)
    return item


def _trace(node: str, message: str, status: str = "completed") -> dict[str, Any]:
    return {"node": node, "message": message, "status": status, "time": now_iso()}


intelligence_service = RealtimeIntelligenceService()
