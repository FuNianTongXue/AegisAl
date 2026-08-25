from __future__ import annotations

import os
import sys
import types

from mcp_stdio_launcher import _native_stdout_to_stderr, main


def test_native_stdout_is_redirected_to_stderr(capfd) -> None:
    with _native_stdout_to_stderr():
        os.write(sys.stdout.fileno(), b"native startup notice\n")

    captured = capfd.readouterr()
    assert "native startup notice" not in captured.out
    assert "native startup notice" in captured.err


def test_translation_engine_warms_before_stdio_server(monkeypatch) -> None:
    events: list[str] = []
    engine = types.SimpleNamespace(warmup=lambda: events.append("warmup"))
    server = types.SimpleNamespace(run=lambda *, transport: events.append(f"run:{transport}"))
    monkeypatch.setitem(
        sys.modules,
        "app.mcp.offline_translation",
        types.SimpleNamespace(offline_translation_engine=engine),
    )
    monkeypatch.setitem(
        sys.modules,
        "app.mcp.translation",
        types.SimpleNamespace(translation_mcp=server),
    )

    main(["--server", "translation"])

    assert events == ["warmup", "run:stdio"]
