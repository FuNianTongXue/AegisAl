#!/usr/bin/env python3
"""
AegisAl MCP stdio Launcher — Unified entry point for all bundled MCP servers.

Usage:
    python3 mcp_stdio_launcher.py --server <server-id>

Available server IDs:
    code-scan, component-detail, excel, d3-sankey,
    license-scan, sbom-excel, translation,
    report-chart, report-markdown, report-mermaid,
    report-pdf, report-sarif, report-template, report-excel, report-word
"""
from __future__ import annotations

import argparse
import ctypes
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager

# Ensure the project root is on sys.path so `app.*` imports resolve
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _flush_native_streams() -> None:
    if os.name != "posix":
        return
    try:
        libc = ctypes.CDLL(None)
        fflush = libc.fflush
        fflush.argtypes = [ctypes.c_void_p]
        fflush.restype = ctypes.c_int
        fflush(None)
    except (AttributeError, OSError):
        pass


@contextmanager
def _native_stdout_to_stderr() -> Iterator[None]:
    """Keep native-library startup notices out of the MCP JSON-RPC stream."""

    sys.stdout.flush()
    sys.stderr.flush()
    stdout_fd = sys.stdout.fileno()
    saved_stdout = os.dup(stdout_fd)
    try:
        os.dup2(sys.stderr.fileno(), stdout_fd)
        yield
    finally:
        _flush_native_streams()
        os.dup2(saved_stdout, stdout_fd)
        os.close(saved_stdout)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AegisAl MCP stdio Launcher")
    parser.add_argument(
        "--server",
        required=True,
        choices=[
            "code-scan",
            "component-detail",
            "excel",
            "d3-sankey",
            "license-scan",
            "sbom-excel",
            "translation",
            "report-chart",
            "report-markdown",
            "report-mermaid",
            "report-pdf",
            "report-sarif",
            "report-template",
            "report-excel",
            "report-word",
        ],
        help="MCP server to launch",
    )
    args = parser.parse_args(argv)

    server_id = args.server

    # ── code-scan ──────────────────────────────────────────────────────
    if server_id == "code-scan":
        # The Host launches this entry point as an isolated child process.
        from app.mcp.code_scan import code_scan_mcp

        code_scan_mcp.run(transport="stdio")
        return

    # ── component-detail / excel / d3-sankey ───────────────────────────
    if server_id == "component-detail":
        from app.mcp.component_query import detail_mcp
        detail_mcp.run(transport="stdio")
        return

    if server_id == "excel":
        from app.mcp.component_query import excel_mcp
        excel_mcp.run(transport="stdio")
        return

    if server_id == "d3-sankey":
        from app.mcp.component_query import sankey_mcp
        sankey_mcp.run(transport="stdio")
        return

    # ── license-scan ───────────────────────────────────────────────────
    if server_id == "license-scan":
        from app.mcp.license_scan import license_scan_mcp
        license_scan_mcp.run(transport="stdio")
        return

    # ── sbom-excel ──────────────────────────────────────────────────────
    if server_id == "sbom-excel":
        from app.mcp.sbom import sbom_excel_mcp
        sbom_excel_mcp.run(transport="stdio")
        return

    # ── translation ────────────────────────────────────────────────────
    if server_id == "translation":
        from app.mcp.offline_translation import offline_translation_engine

        with _native_stdout_to_stderr():
            offline_translation_engine.warmup()
        from app.mcp.translation import translation_mcp

        translation_mcp.run(transport="stdio")
        return

    # ── report-chart ────────────────────────────────────────────────────
    if server_id == "report-chart":
        from app.mcp.report_charts import report_chart_mcp
        report_chart_mcp.run(transport="stdio")
        return

    # ── report-markdown ────────────────────────────────────────────────
    if server_id == "report-markdown":
        from app.mcp.report_markdown import report_markdown_mcp
        report_markdown_mcp.run(transport="stdio")
        return

    # ── report-mermaid ─────────────────────────────────────────────────
    if server_id == "report-mermaid":
        from app.mcp.report_mermaid import report_mermaid_mcp
        report_mermaid_mcp.run(transport="stdio")
        return

    # ── report-pdf ────────────────────────────────────────────────────
    if server_id == "report-pdf":
        from app.mcp.report_pdf import report_pdf_mcp
        report_pdf_mcp.run(transport="stdio")
        return

    # ── report-sarif ────────────────────────────────────────────────────
    if server_id == "report-sarif":
        from app.mcp.report_sarif import report_sarif_mcp
        report_sarif_mcp.run(transport="stdio")
        return

    # ── report-template ─────────────────────────────────────────
    if server_id == "report-template":
        from app.mcp.report_template import template_mcp
        template_mcp.run(transport="stdio")
        return

    # ── report-excel ───────────────────────────────────────────
    if server_id == "report-excel":
        from app.mcp.report_excel import report_excel_mcp
        report_excel_mcp.run(transport="stdio")
        return

    # ── report-word ────────────────────────────────────────────────────
    if server_id == "report-word":
        from app.mcp.report_word import report_word_mcp
        report_word_mcp.run(transport="stdio")
        return

    parser.error(f"Unknown server: {server_id}")


if __name__ == "__main__":
    main()
