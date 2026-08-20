// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import { RecordsView } from "./RecordsView";

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

describe("RecordsView", () => {
  it("labels filters and renders loaded vulnerability records", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [{ id: "CVE-2026-1234", title: "OpenSSL validation issue", severity: "high" }],
      stats: {},
    });

    render(<RecordsView />);

    expect(screen.getByRole("textbox", { name: "搜索漏洞记录" })).toHaveAttribute("name", "vulnerability_query");
    expect(screen.getByRole("combobox", { name: "按严重度筛选" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "CVE-2026-1234" })).toBeInTheDocument();
  });

  it("shows a retry action when loading fails", async () => {
    const request = vi.spyOn(api, "dashboard")
      .mockRejectedValueOnce(new Error("service unavailable"))
      .mockResolvedValueOnce({ records: [], stats: {} });

    render(<RecordsView />);

    expect(await screen.findByRole("alert")).toHaveTextContent("service unavailable");
    fireEvent.click(screen.getByRole("button", { name: "重新加载" }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("没有匹配的漏洞记录")).toBeInTheDocument();
  });

  it("shows Chinese offline translations and hides English fallback prose", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [{
        id: "CVE-2026-2000",
        title: "Remote validation bypass in OpenSSL",
        title_zh: "OpenSSL 远程验证绕过漏洞",
        description: "A remote attacker can bypass certificate validation.",
        description_zh: "远程攻击者可绕过证书验证。",
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

    render(<RecordsView />);

    expect(await screen.findByText("OpenSSL 远程验证绕过漏洞")).toBeInTheDocument();
    expect(screen.getByText("远程攻击者可绕过证书验证。")).toBeInTheDocument();
    expect(screen.queryByText("Remote validation bypass in OpenSSL")).not.toBeInTheDocument();
    expect(screen.queryByText("A remote attacker can bypass certificate validation.")).not.toBeInTheDocument();
    expect(api.dashboard).toHaveBeenCalledWith("zh-Hans");
  });

  it("hides translation implementation labels and pending mixed-language prose", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [{
        id: "CVE-2026-76008",
        title: "远程 URI 参数 Parsing vulnerability",
        summary: "远程攻击者可以 trigger 基于堆栈的缓冲区溢出。",
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

    render(<RecordsView />);

    expect(await screen.findByText("漏洞内容准备中")).toBeInTheDocument();
    expect(screen.getByText("暂无漏洞描述")).toBeInTheDocument();
    expect(screen.queryByText(/离线译文/)).not.toBeInTheDocument();
    expect(screen.queryByText("简体中文")).not.toBeInTheDocument();
    expect(screen.queryByText("远程 URI 参数 Parsing vulnerability")).not.toBeInTheDocument();
    expect(screen.queryByText("远程攻击者可以 trigger 基于堆栈的缓冲区溢出。")).not.toBeInTheDocument();
  });

  it("searches the full catalog by CVE and opens public website details", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [{ id: "CVE-2026-0001", title: "", severity: "low" }],
      stats: { total: 1000 },
    });
    const search = vi.spyOn(api, "vulnerabilities").mockResolvedValue([{
      id: "CVE-2026-98765",
      title: "目标漏洞",
      summary: "目标漏洞的公开网站描述。",
      severity: "critical",
      cvss: 9.8,
      source: "NVD",
      affected_products: ["OpenSSL"],
      affected_versions: ["3.0.x"],
      fixed_versions: ["3.0.18"],
      aliases: ["GHSA-1234-5678-9ABC"],
      references: ["https://security.example.test/advisory/98765"],
      content_language: "zh-Hans",
      translation_status: "translated",
    }]);

    render(<RecordsView />);
    fireEvent.change(screen.getByRole("textbox", { name: "搜索漏洞记录" }), { target: { value: "CVE-2026-98765" } });

    await waitFor(() => expect(search).toHaveBeenCalledWith("zh-Hans", "CVE-2026-98765"));
    expect(await screen.findByRole("heading", { name: "CVE-2026-98765" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "CVE-2026-0001" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "查看 CVE-2026-98765 的网站漏洞信息" }));

    const dialog = screen.getByRole("dialog", { name: "CVE-2026-98765" });
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText("网站漏洞信息")).toBeInTheDocument();
    expect(dialog).toHaveTextContent("目标漏洞的公开网站描述。");
    expect(dialog).toHaveTextContent("NVD");
    expect(dialog).toHaveTextContent("security.example.test");
  });

  it("requests and preserves original content for the English locale", async () => {
    useAppStore.setState({
      settings: {
        profile: { display_name: "", email: "", department: "", role: "" },
        preferences: { language: "en", dark_mode: false, font_size: "default" },
      },
    });
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [{
        id: "CVE-2026-2001",
        title: "中文漏洞标题",
        title_original: "Original OpenSSL vulnerability title",
        description: "中文漏洞描述。",
        description_original: "Original OpenSSL vulnerability description.",
        severity: "medium",
        content_language: "en",
        translation_status: "original",
      }],
      stats: { total: 1, medium: 1 },
      catalog_status: "ready",
      catalog_progress: 100,
      catalog_count: 1,
      translation_status: "not_required",
      translation_progress: 100,
    });

    render(<RecordsView />);

    expect(await screen.findByText("Original OpenSSL vulnerability title")).toBeInTheDocument();
    expect(screen.getByText("Original OpenSSL vulnerability description.")).toBeInTheDocument();
    expect(screen.queryByText("中文漏洞标题")).not.toBeInTheDocument();
    expect(api.dashboard).toHaveBeenCalledWith("en");
  });
});
