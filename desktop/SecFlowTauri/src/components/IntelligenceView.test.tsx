// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import { IntelligenceView } from "./IntelligenceView";

beforeEach(() => {
  useAppStore.setState({
    settings: {
      profile: { display_name: "", email: "", department: "", role: "" },
      preferences: { language: "zh-Hans", dark_mode: false, font_size: "default" },
    },
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAppStore.setState({ settings: undefined });
});

describe("IntelligenceView metrics", () => {
  it("renders CISA KEV, public PoC totals, and the seven-day update trend", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [],
      stats: { total: 10_000, critical: 100, high: 900, kev: 1_656, poc: 412 },
      trend: [
        { date: "2026-07-26", count: 18 },
        { date: "2026-07-27", count: 27 },
        { date: "2026-07-28", count: 14 },
        { date: "2026-07-29", count: 31 },
        { date: "2026-07-30", count: 20 },
        { date: "2026-07-31", count: 44 },
        { date: "2026-08-01", count: 36 },
      ],
      catalog_status: "ready",
      catalog_progress: 100,
      catalog_count: 10_000,
      translation_status: "translated",
      translation_progress: 100,
      translation_count: 10_000,
      translation_ready_count: 10_000,
    });

    render(<IntelligenceView />);

    expect(await screen.findByText("1,656")).toBeInTheDocument();
    expect(screen.getByText("412")).toBeInTheDocument();
    expect(screen.getByText("具有公开 PoC")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "近期情报更新趋势" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "近 7 天情报更新趋势" })).toBeInTheDocument();
    expect(screen.getAllByText(/^0[78]\/\d{2}$/)).toHaveLength(7);
    expect(screen.getByRole("table", { name: "最近更新的高风险漏洞情报" })).toBeInTheDocument();
    expect(api.dashboard).toHaveBeenCalledWith("zh-Hans");
    expect(screen.getByText("漏洞目录同步完成")).toBeInTheDocument();
    expect(screen.queryByText(/离线译文/)).not.toBeInTheDocument();
    expect(screen.queryByText("简体中文")).not.toBeInTheDocument();
  });

  it("prefers translated record fields and never renders an English fallback as Chinese", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [{
        id: "CVE-2026-8080",
        title: "Remote validation bypass in OpenSSL",
        title_zh: "OpenSSL 远程验证绕过漏洞",
        severity: "high",
        content_language: "zh-Hans",
        translation_status: "translated",
      }],
      stats: { total: 1, high: 1 },
      catalog_status: "ready",
      catalog_progress: 100,
      catalog_count: 1,
      translation_status: "translated",
      translation_progress: 100,
      translation_count: 1,
      translation_ready_count: 1,
    });

    render(<IntelligenceView />);

    expect(await screen.findByText("OpenSSL 远程验证绕过漏洞")).toBeInTheDocument();
    expect(screen.queryByText("Remote validation bypass in OpenSSL")).not.toBeInTheDocument();
    expect(screen.queryByText("内容状态")).not.toBeInTheDocument();
    expect(screen.queryByText(/离线译文/)).not.toBeInTheDocument();
    expect(screen.queryByText("简体中文")).not.toBeInTheDocument();
  });

  it("does not publish a pending mixed-language title", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [{
        id: "CVE-2026-76008",
        title: "远程 URI 参数 Parsing vulnerability",
        severity: "high",
        content_language: "unknown",
        translation_status: "pending",
      }],
      stats: { total: 1, high: 1 },
      translation_status: "pending",
      translation_count: 1,
      translation_ready_count: 0,
      translation_progress: 0,
    });

    render(<IntelligenceView />);

    expect(await screen.findByText("漏洞内容准备中")).toBeInTheDocument();
    expect(screen.queryByText(/离线译文/)).not.toBeInTheDocument();
    expect(screen.queryByText("远程 URI 参数 Parsing vulnerability")).not.toBeInTheDocument();
  });
});
