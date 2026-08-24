// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import aegisalEmblem from "../assets/aegisal-emblem.png";
import { api } from "../lib/api";
import { saveBinaryArtifact } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import type { ChatTurn } from "../types";
import { ChatMessage } from "./ChatMessage";

vi.mock("../lib/platform", () => ({
  saveBinaryArtifact: vi.fn().mockResolvedValue(undefined),
}));

const baseTurn: ChatTurn = {
  id: "turn-report-1",
  role: "assistant",
  content: "扫描已完成，是否根据本次扫描事实生成完整报告？",
  createdAt: new Date().toISOString(),
  state: "completed",
  result: {
    answer: "",
    interrupt: {
      interrupt_id: "int-1",
      thread_id: "report-thread-1",
      kind: "report_generation_confirmation",
      message: "扫描已完成，是否根据本次扫描事实生成完整报告？",
      question: "扫描已完成，是否根据本次扫描事实生成完整报告？",
      detail: "确认后将生成 Mermaid、Markdown、Word 与 PDF。",
      options: ["confirm", "cancel"],
    },
  } as never,
};

function Harness() {
  const turns = useAppStore((state) => state.turns);
  const turn = turns.find((item) => item.id === baseTurn.id) || turns[0] || baseTurn;
  return <ChatMessage turn={turn} />;
}

describe("ChatMessage report interrupt card", () => {
  beforeEach(() => {
    useAppStore.setState({ userId: "tester", activeSessionId: "session-9", turns: [baseTurn] });
    vi.mocked(saveBinaryArtifact).mockReset().mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("confirms generation, chains to download formats, then shows artifact links", async () => {
    const resume = vi
      .spyOn(api, "resumeReportAction")
      .mockResolvedValueOnce({
        answer: {
          answer: "",
          summary: "报告已生成：demo_20260804.md。",
          artifacts: [],
          interrupt: {
            interrupt_id: "int-2",
            thread_id: "report-thread-1",
            kind: "report_download_confirmation",
            message: "报告已准备好，是否确认下载？",
            formats: ["md", "pdf"],
            options: ["confirm", "cancel"],
          },
        },
      } as never)
      .mockResolvedValueOnce({
        answer: {
          answer: "",
          summary: "下载制品已准备好：demo_20260804.pdf。",
          interrupt: null,
          artifacts: [
            { id: "art-1", file_name: "demo_20260804.pdf", media_type: "application/pdf", download_path: "/api/assistant/artifacts/art-1" },
          ],
        },
      } as never);

    render(<Harness />);

    expect(screen.getByRole("alertdialog", { name: "扫描已完成，是否根据本次扫描事实生成完整报告？" })).toBeInTheDocument();
    const generateButton = screen.getByRole("button", { name: /确认生成报告/ });
    expect(generateButton).toHaveFocus();
    fireEvent.click(generateButton);
    await waitFor(() => expect(resume).toHaveBeenCalledWith(expect.objectContaining({
      thread_id: "report-thread-1",
      interrupt_id: "int-1",
      decision: "confirm",
      user_id: "tester",
      session_id: "session-9",
    })));

    expect(await screen.findByText("报告已生成：demo_20260804.md。")).toBeInTheDocument();
    const raw = vi.spyOn(api, "raw").mockResolvedValue(new Response(new Blob(["demo-pdf"])));
    const pdfButton = await screen.findByRole("button", { name: "PDF" });
    fireEvent.click(pdfButton);

    await waitFor(() => expect(resume).toHaveBeenLastCalledWith(expect.objectContaining({
      interrupt_id: "int-2",
      decision: "confirm",
      format: "pdf",
    })));

    await waitFor(() => expect(raw).toHaveBeenCalledWith("/api/assistant/artifacts/art-1"));
    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalledTimes(1));
    const [savedName, savedBlob] = vi.mocked(saveBinaryArtifact).mock.calls[0];
    expect(savedName).toBe("demo_20260804.pdf");
    expect(savedBlob.size).toBeGreaterThan(0);

    await screen.findByRole("button", { name: /demo_20260804\.pdf/ });
    expect(screen.getByRole("region", { name: "可下载的报告文件" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "MD" })).not.toBeInTheDocument();
  });

  it.each([
    ["component_excel_download_confirmation", "component-catalog-thread-1", "components.xlsx"],
    ["sbom_excel_download_confirmation", "sbom-thread-1", "project-sbom.xlsx"],
  ])("downloads %s from one download action without a second confirmation card", async (kind, threadId, fileName) => {
    const artifact = {
      id: `artifact-${kind}`,
      file_name: fileName,
      media_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      download_path: `/api/assistant/artifacts/artifact-${kind}`,
    };
    const downloadTurn: ChatTurn = {
      ...baseTurn,
      id: `turn-${kind}`,
      content: "Excel 已生成，是否选择目录并下载？",
      result: {
        answer: "",
        artifacts: [artifact],
        interrupt: {
          interrupt_id: `interrupt-${kind}`,
          thread_id: threadId,
          kind,
          message: "Excel 已生成，是否选择目录并下载？",
          question: "Excel 已生成，是否选择目录并下载？",
          options: ["confirm", "cancel"],
        },
      } as never,
    };
    useAppStore.setState({ turns: [downloadTurn] });
    const resume = vi.spyOn(api, "resumeAssistantInterrupt").mockResolvedValue({
      answer: { answer: "", summary: `下载已确认：${fileName}。`, interrupt: null, artifacts: [artifact] },
    } as never);
    const raw = vi.spyOn(api, "raw").mockResolvedValue(new Response(new Blob([fileName])));

    render(<Harness />);

    expect(screen.getByRole("region", { name: "可下载的报告文件" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "确认下载" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: `下载 ${fileName}` }));

    await waitFor(() => expect(resume).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(raw).toHaveBeenCalledWith(artifact.download_path));
    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalledTimes(1));
    expect(vi.mocked(saveBinaryArtifact).mock.calls[0][0]).toBe(fileName);
    expect(await screen.findByRole("region", { name: "可下载的报告文件" })).toBeInTheDocument();
  });

  it("retries a failed artifact fetch without submitting the confirmation twice", async () => {
    const artifact = {
      id: "artifact-retry",
      file_name: "components.xlsx",
      media_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      download_path: "/api/assistant/artifacts/artifact-retry",
    };
    const downloadTurn: ChatTurn = {
      ...baseTurn,
      id: "turn-download-retry",
      result: {
        answer: "",
        artifacts: [artifact],
        interrupt: {
          interrupt_id: "interrupt-download-retry",
          thread_id: "component-catalog-thread-retry",
          kind: "component_excel_download_confirmation",
          message: "Excel 已生成，是否选择目录并下载？",
          options: ["confirm", "cancel"],
        },
      } as never,
    };
    useAppStore.setState({ turns: [downloadTurn] });
    const resume = vi.spyOn(api, "resumeAssistantInterrupt").mockResolvedValue({
      answer: { answer: "", summary: "下载已确认：components.xlsx。", interrupt: null, artifacts: [artifact] },
    } as never);
    const raw = vi.spyOn(api, "raw")
      .mockRejectedValueOnce(new Error("artifact fetch failed"))
      .mockResolvedValueOnce(new Response(new Blob(["retry-ok"])));

    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "下载 components.xlsx" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("artifact fetch failed");

    fireEvent.click(screen.getByRole("button", { name: "重试下载 components.xlsx" }));
    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalledTimes(1));
    expect(resume).toHaveBeenCalledTimes(1);
    expect(raw).toHaveBeenCalledTimes(2);
  });

  it("cancel closes the card without further actions", async () => {
    const resume = vi.spyOn(api, "resumeReportAction").mockResolvedValue({
      answer: { answer: "", summary: "已取消生成报告。", interrupt: null, artifacts: [] },
    } as never);

    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "取消" }));

    await waitFor(() => expect(resume).toHaveBeenCalledWith(expect.objectContaining({ decision: "cancel" })));
    expect(await screen.findByText("已取消生成报告。")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /确认生成报告/ })).not.toBeInTheDocument();
  });

  it("routes sbom interrupts to the assistant resume endpoint with a match label", async () => {
    const sbomTurn: ChatTurn = {
      ...baseTurn,
      id: "turn-sbom-1",
      content: "SBOM 组件清单已生成，是否匹配漏洞情报？",
      result: {
        answer: "",
        interrupt: {
          interrupt_id: "int-sbom-1",
          thread_id: "sbom-thread-1",
          kind: "sbom_vulnerability_match_confirmation",
          question: "SBOM 组件清单已生成，是否匹配漏洞情报？",
          detail: "当前共 8 个组件。",
          options: ["confirm", "cancel"],
        },
      } as never,
    };
    useAppStore.setState({ turns: [sbomTurn] });
    const assistantResume = vi.spyOn(api, "resumeAssistantInterrupt").mockResolvedValue({
      answer: { answer: "", summary: "组件漏洞匹配完成：命中 3 个已知漏洞。", interrupt: null, artifacts: [] },
    } as never);
    const reportResume = vi.spyOn(api, "resumeReportAction");

    render(<Harness />);

    const confirm = screen.getByRole("button", { name: "确认匹配漏洞" });
    expect(screen.queryByRole("button", { name: /确认生成报告/ })).not.toBeInTheDocument();
    fireEvent.click(confirm);

    await waitFor(() => expect(assistantResume).toHaveBeenCalledWith(expect.objectContaining({
      thread_id: "sbom-thread-1",
      interrupt_id: "int-sbom-1",
      decision: "confirm",
      user_id: "tester",
      session_id: "session-9",
    })));
    expect(reportResume).not.toHaveBeenCalled();
    expect(await screen.findByText("组件漏洞匹配完成：命中 3 个已知漏洞。")).toBeInTheDocument();
  });

  it("labels component catalog generation as Excel instead of a generic report", () => {
    useAppStore.setState({
      turns: [{
        ...baseTurn,
        result: {
          answer: "",
          interrupt: {
            interrupt_id: "int-component-1",
            thread_id: "component-catalog-thread-1",
            kind: "component_excel_generation_confirmation",
            question: "组件漏洞清单已查询完成，是否生成 Excel？",
            options: ["confirm", "cancel"],
          },
        } as never,
      }],
    });

    render(<Harness />);

    expect(screen.getByRole("button", { name: "确认生成 Excel" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "确认生成报告" })).not.toBeInTheDocument();
  });
});

describe("ChatMessage user attachment chip", () => {
  afterEach(() => {
    cleanup();
    useAppStore.setState({ settings: undefined });
  });

  it("uses the saved personal-profile avatar to the right of a user message", () => {
    useAppStore.setState({
      userId: "tester",
      settings: {
        preferences: { language: "zh-Hans" },
        profile: {
          display_name: "测试用户",
          email: "tester@example.com",
          department: "SOC",
          role: "安全分析师",
          avatar_available: true,
          avatar_updated_at: "2026-08-06T21:00:00Z",
        },
      } as never,
    });
    const turn: ChatTurn = {
      id: "turn-user-avatar",
      role: "user",
      content: "分析这条安全告警",
      createdAt: new Date().toISOString(),
    };

    render(<ChatMessage turn={turn} />);

    const avatar = document.querySelector<HTMLImageElement>(".chat-user-avatar img");
    expect(avatar).toBeInTheDocument();
    expect(avatar?.src).toContain("/api/settings/profile/avatar");
    expect(avatar?.src).toContain("user_id=tester");
    expect(document.querySelector(".user-turn")?.lastElementChild).toHaveClass("chat-user-avatar");
  });

  it("renders the workspace attachment submitted with the user message", () => {
    const turn: ChatTurn = {
      id: "turn-user-1",
      role: "user",
      content: "检查这个项目的安全状况",
      createdAt: new Date().toISOString(),
      workspace: { name: "log4shell-demo", path: "/Users/test/projects/log4shell-demo" },
    };

    render(<ChatMessage turn={turn} />);

    const chip = document.querySelector(".user-attachment-chip");
    expect(chip).toBeInTheDocument();
    expect(chip).toHaveTextContent("log4shell-demo");
    expect(chip).toHaveAttribute("title", "/Users/test/projects/log4shell-demo");
    expect(screen.getByText("检查这个项目的安全状况")).toBeInTheDocument();
  });

  it("renders no attachment chip for plain user messages", () => {
    const turn: ChatTurn = {
      id: "turn-user-2",
      role: "user",
      content: "什么是 SQL 注入",
      createdAt: new Date().toISOString(),
    };

    render(<ChatMessage turn={turn} />);

    expect(document.querySelector(".user-attachment-chip")).not.toBeInTheDocument();
  });
});

describe("ChatMessage actions", () => {
  afterEach(cleanup);

  it("uses the AegisAl logo for assistant messages at regular and compact sizes", () => {
    const { container, rerender } = render(
      <ChatMessage turn={{ ...baseTurn, result: undefined, content: "回答内容" }} />,
    );

    let mark = container.querySelector(".assistant-gutter .brand-mark");
    expect(mark).toBeInTheDocument();
    expect(mark).toHaveStyle({ width: "32px", height: "32px" });
    expect(mark?.querySelector("img")).toHaveAttribute("src", aegisalEmblem);
    expect(container.querySelector(".assistant-gutter svg")).not.toBeInTheDocument();

    rerender(<ChatMessage compact turn={{ ...baseTurn, result: undefined, content: "回答内容" }} />);
    mark = container.querySelector(".assistant-gutter .brand-mark");
    expect(mark).toHaveStyle({ width: "23px", height: "23px" });
    expect(mark?.querySelector("img")).toHaveAttribute("src", aegisalEmblem);
    expect(container.querySelector(".assistant-gutter svg")).not.toBeInTheDocument();
  });

  it("folds tool request and response into one task row without a duplicate tool list", () => {
    const { container } = render(<ChatMessage turn={{
      ...baseTurn,
      content: "组件漏洞 Excel 已生成。",
      result: { answer: "组件漏洞 Excel 已生成。", provider: "openai", model: "gpt-test" } as never,
      trace: [{
        node: "export_component_vulnerability_catalog",
        title: "生成组件漏洞 Excel",
        status: "completed",
        tool_name: "component_catalog_excel_mcp",
        duration_ms: 1200,
        input: { severity: ["CRITICAL", "HIGH"] },
        output: { record_count: 8579 },
      }],
    }} />);

    const group = screen.getByRole("button", { name: /思考完成/ });
    expect(group).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(group);
    const row = screen.getByRole("button", { name: /生成，组件漏洞 Excel，已完成/ });
    expect(row).toHaveAttribute("aria-expanded", "false");
    expect(container.querySelector(".tool-call")).not.toBeInTheDocument();
    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("请求参数").closest(".bui-tool-row-details-collapse")).toHaveTextContent("CRITICAL");
    expect(screen.getByText("执行结果").closest(".bui-tool-row-details-collapse")).toHaveTextContent("8579");
  });

  it("names icon-only actions and only renders regenerate when it has a handler", () => {
    const onRegenerate = vi.fn();
    render(<ChatMessage turn={{ ...baseTurn, result: undefined, content: "回答内容" }} onRegenerate={onRegenerate} />);

    expect(screen.getByRole("button", { name: "复制" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "重新生成" }));
    expect(onRegenerate).toHaveBeenCalledOnce();
  });

  it("maps legacy brands in displayed and copied prose while preserving Markdown code", async () => {
    const content = [
      "SecFlow 安全智脑",
      "",
      "`secflow:task`",
      "",
      "```text",
      "SECFLOW_DATA_DIR=/tmp/secflow",
      "```",
    ].join("\n");
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });

    render(<ChatMessage turn={{ ...baseTurn, result: undefined, content }} />);

    expect(screen.getByText("AegisAl 神盾")).toBeInTheDocument();
    expect(screen.getByText("secflow:task")).toBeInTheDocument();
    expect(screen.getByText("SECFLOW_DATA_DIR=/tmp/secflow")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "复制" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith([
      "AegisAl 神盾",
      "",
      "`secflow:task`",
      "",
      "```text",
      "SECFLOW_DATA_DIR=/tmp/secflow",
      "```",
    ].join("\n")));
  });

  it("announces compact errors without showing an unusable retry action", () => {
    render(<ChatMessage compact turn={{ ...baseTurn, result: undefined, content: "请求失败", state: "error" }} />);

    expect(screen.getByRole("alert")).toHaveTextContent("处理请求时发生错误");
    expect(screen.queryByRole("button", { name: "重试" })).not.toBeInTheDocument();
  });
});

describe("ChatMessage structured data", () => {
  beforeEach(() => {
    useAppStore.setState({
      settings: { preferences: { language: "zh-Hans" } } as never,
    });
  });

  afterEach(cleanup);

  it("renders a GFM data table with semantic headers inside the reusable scroll surface", () => {
    const content = [
      "以下是确认命中的漏洞：",
      "",
      "| 漏洞编号 | 严重度 | 受影响组件 | 修复版本 |",
      "| --- | --- | --- | --- |",
      "| CVE-2026-8080 | CRITICAL | `openssl` 3.2.0 | 3.2.1 |",
      "| CVE-2026-9090 | HIGH | spring-web 6.1.0 | 6.1.4 |",
    ].join("\n");

    const { container } = render(<ChatMessage turn={{
      ...baseTurn,
      id: "turn-markdown-table",
      content,
      result: undefined,
    }} />);

    const table = screen.getByRole("table");
    expect(table).toHaveClass("structured-data-table");
    expect(table.closest(".structured-data-table-wrap")).toBeInTheDocument();
    expect(screen.getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual([
      "漏洞编号",
      "严重度",
      "受影响组件",
      "修复版本",
    ]);
    for (const header of screen.getAllByRole("columnheader")) {
      expect(header).toHaveAttribute("scope", "col");
    }
    expect(screen.getByRole("cell", { name: "CVE-2026-8080" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "CRITICAL" })).toBeInTheDocument();
    expect(container.querySelector("td code")).toHaveTextContent("openssl");
  });

  it("maps legacy brands in table metadata without rewriting returned row data", () => {
    render(<ChatMessage turn={{
      ...baseTurn,
      id: "turn-branded-table",
      content: "已返回结构化结果。",
      result: {
        answer: "已返回结构化结果。",
        tables: [{
          id: "branded-table",
          title: "SecFlow 漏洞结果",
          caption: "安全智脑数据说明",
          columns: [
            "SecFlow 规则",
            { key: "description", label: "安全智脑说明" },
          ],
          rows: [{ rule_id: "secflow.java.command-injection", description: "安全智脑" }],
        }],
      },
    }} />);

    expect(screen.getByRole("region", { name: "AegisAl 漏洞结果" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "神盾数据说明" })).toBeInTheDocument();
    expect(screen.getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual([
      "AegisAl 规则",
      "神盾说明",
    ]);
    expect(screen.getByRole("cell", { name: "secflow.java.command-injection" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "安全智脑" })).toBeInTheDocument();
  });

  it("keeps links and bilingual long-form values usable inside Markdown table cells", () => {
    render(<ChatMessage turn={{
      ...baseTurn,
      id: "turn-wide-markdown-table",
      content: [
        "| ID | Status | Evidence / 证据 | Reference |",
        "| --- | --- | --- | --- |",
        "| GHSA-demo-0001 | Pending / 待处理 | A deliberately long evidence value that must remain available in the DOM for horizontal overflow | [Advisory](https://example.com/advisories/GHSA-demo-0001) |",
      ].join("\n"),
      result: undefined,
    }} />);

    expect(screen.getByText(/A deliberately long evidence value/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Advisory/ })).toHaveAttribute(
      "href",
      "https://example.com/advisories/GHSA-demo-0001",
    );
    expect(document.querySelector(".structured-data-table-wrap")).toContainElement(screen.getByRole("table"));
  });

  it("maps verified vulnerability records from the assistant payload into the same table UI", () => {
    render(<ChatMessage turn={{
      ...baseTurn,
      id: "turn-structured-records",
      content: "已找到 2 条需要优先处理的漏洞。",
      result: {
        answer: "已找到 2 条需要优先处理的漏洞。",
        records: [
          {
            id: "CVE-2026-8080",
            title: "OpenSSL 证书验证绕过漏洞",
            severity: "CRITICAL",
            cvss_score: 9.8,
            components: [{ name: "openssl", version: "3.2.0" }],
            fixed_versions: ["3.2.1"],
          },
          {
            id: "CVE-2026-9090",
            title: "Spring Web 请求解析漏洞",
            severity: "HIGH",
            components: [{ name: "spring-web", version: "6.1.0" }],
          },
        ],
      },
    }} />);

    const table = screen.getByRole("table", { name: "数据概览" });
    expect(table).toHaveClass("structured-data-table");
    expect(screen.getByRole("cell", { name: "严重" }).querySelector(".structured-data-status-dot")).toBeInTheDocument();
    expect(screen.getByText("openssl @ 3.2.0")).toBeInTheDocument();
    expect(screen.getByText("3.2.1")).toBeInTheDocument();
  });

  it("renders every returned translated vulnerability row and public column in the data overview", () => {
    render(<ChatMessage turn={{
      ...baseTurn,
      id: "turn-full-translated-records",
      content: "已返回译后漏洞数据。",
      result: {
        answer: "已返回译后漏洞数据。",
        total: 8579,
        fields: { "查询开始日期": "2026-01-01", "漏洞数量": "8579" },
        records: [
          {
            id: "CVE-2026-8080",
            title: "Original title",
            title_zh: "证书验证绕过漏洞",
            summary: "Original summary",
            summary_zh: "攻击者可绕过证书校验。",
            severity: "CRITICAL",
            cvss_score: 9.8,
            components: [{ ecosystem: "npm", name: "demo-package", affected: ["< 2.0.0"] }],
            title_original: "Original title",
            summary_original: "Original summary",
            content_language: "zh-Hans",
            translation_status: "translated",
            translation_audit: { tool: "internal-translator" },
          },
          {
            id: "CVE-2026-9090",
            title_zh: "请求解析漏洞",
            aliases: ["GHSA-demo-0001"],
            cwes: ["CWE-20"],
            affected_versions: ["< 6.1.2"],
            fixed_versions: ["6.1.2"],
            reference_links: ["https://example.com/advisories/CVE-2026-9090"],
            published_at: "2026-08-20T00:00:00Z",
          },
        ],
      },
    }} />);

    const table = screen.getByRole("table", { name: "数据概览" });
    const headers = within(table).getAllByRole("columnheader").map((cell) => cell.textContent);
    expect(headers).toEqual(expect.arrayContaining([
      "漏洞编号",
      "漏洞别名",
      "标题",
      "摘要",
      "严重度",
      "CVSS",
      "CWE",
      "受影响组件",
      "受影响版本",
      "修复版本",
      "参考",
      "发布时间",
    ]));
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(screen.getByText("证书验证绕过漏洞")).toBeInTheDocument();
    expect(screen.getByText("请求解析漏洞")).toBeInTheDocument();
    expect(screen.queryByText("Original title")).not.toBeInTheDocument();
    expect(screen.queryByText("查询开始日期")).not.toBeInTheDocument();
    expect(headers).not.toContain("Content Language");
    expect(headers).not.toContain("Translation Audit");
    expect(screen.getByRole("link", { name: "https://example.com/advisories/CVE-2026-9090" })).toBeInTheDocument();
    expect(screen.getByText("显示 2 / 8579 条")).toBeInTheDocument();
  });

  it("shows translated record values first and saves editable cells as a display snapshot", async () => {
    const onResultChange = vi.fn().mockResolvedValue(undefined);
    render(<ChatMessage
      turn={{
        ...baseTurn,
        id: "turn-translated-records",
        content: "已返回翻译后的漏洞记录。",
        result: {
          answer: "已返回翻译后的漏洞记录。",
          records: [{
            id: "CVE-2026-8080",
            title: "Original vulnerability title",
            title_zh: "证书验证绕过漏洞",
            severity: "HIGH",
          }],
        },
      }}
      onResultChange={onResultChange}
    />);

    expect(screen.getByText("证书验证绕过漏洞")).toBeInTheDocument();
    expect(screen.queryByText("Original vulnerability title")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "编辑记录表" }));
    fireEvent.change(screen.getByRole("textbox", { name: "标题，第 1" }), {
      target: { value: "修订后的中文标题" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }));

    await waitFor(() => expect(onResultChange).toHaveBeenCalledOnce());
    expect(onResultChange.mock.calls[0][0].structured_data_edits[0]).toMatchObject({
      id: "assistant-vulnerability-records",
      edited: true,
      rows: [{ id: "CVE-2026-8080", title: "修订后的中文标题", severity: "高危" }],
    });
    expect(screen.getByText("修订后的中文标题")).toBeInTheDocument();
  });

  it("matches translated string headers semantically when object-key order differs", async () => {
    const onResultChange = vi.fn().mockResolvedValue(undefined);
    render(<ChatMessage
      turn={{
        ...baseTurn,
        id: "turn-translated-string-columns",
        content: "已返回翻译后的记录表。",
        result: {
          answer: "已返回翻译后的记录表。",
          tables: [{
            id: "translated-string-columns",
            columns: ["标题", "漏洞编号"],
            rows: [{ id: "CVE-2026-8181", title: "翻译后的漏洞标题" }],
          }],
        },
      }}
      onResultChange={onResultChange}
    />);

    expect(screen.getByRole("cell", { name: "CVE-2026-8181" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "翻译后的漏洞标题" })).toBeInTheDocument();
    expect(screen.getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(["标题", "漏洞编号"]);
    fireEvent.click(screen.getByRole("button", { name: "编辑记录表" }));
    fireEvent.change(screen.getByRole("textbox", { name: "标题，第 1" }), {
      target: { value: "用户修订后的标题" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }));

    await waitFor(() => expect(onResultChange).toHaveBeenCalledOnce());
    expect(onResultChange.mock.calls[0][0].structured_data_edits[0].rows).toEqual([{
      title: "用户修订后的标题",
      id: "CVE-2026-8181",
    }]);
  });

  it("renders structured results without answer text and localizes boolean values", () => {
    render(<ChatMessage turn={{
      ...baseTurn,
      id: "turn-data-only",
      content: "",
      result: {
        answer: "",
        tables: [{
          id: "data-only-table",
          title: "检查结果",
          columns: [
            { key: "name", label: "名称" },
            { key: "enabled", label: "是否启用" },
          ],
          rows: [{ name: "签名校验", enabled: true }],
        }],
      },
    }} />);

    expect(screen.getByRole("table", { name: "检查结果" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "是" })).toBeInTheDocument();
    expect(screen.queryByText("Yes")).not.toBeInTheDocument();
  });

  it("preserves untouched link lists, comma-bearing tags, and object arrays when another cell changes", async () => {
    const onResultChange = vi.fn().mockResolvedValue(undefined);
    const references = "https://example.com/advisories/one\nhttps://example.com/advisories/two";
    const tags = ["ACME, Inc.", "needs review"];
    const components = [{ ecosystem: "npm", name: "demo-package", version: "1.2.3" }];
    render(<ChatMessage
      turn={{
        ...baseTurn,
        id: "turn-lossless-edit",
        content: "已返回可编辑记录。",
        result: {
          answer: "已返回可编辑记录。",
          tables: [{
            id: "lossless-edit-table",
            columns: [
              { key: "title", label: "标题", kind: "text" },
              { key: "references", label: "参考", kind: "link" },
              { key: "tags", label: "标签", kind: "tags" },
              { key: "components", label: "组件", kind: "tags" },
            ],
            rows: [{ title: "原始标题", references, tags, components }],
          }],
        },
      }}
      onResultChange={onResultChange}
    />);

    fireEvent.click(screen.getByRole("button", { name: "编辑记录表" }));
    fireEvent.change(screen.getByRole("textbox", { name: "标题，第 1" }), {
      target: { value: "用户修订标题" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }));

    await waitFor(() => expect(onResultChange).toHaveBeenCalledOnce());
    expect(onResultChange.mock.calls[0][0].structured_data_edits[0].rows[0]).toEqual({
      title: "用户修订标题",
      references,
      tags,
      components,
    });
  });

  it("accepts an edited newline-separated link list", async () => {
    const onResultChange = vi.fn().mockResolvedValue(undefined);
    const nextReferences = "https://example.com/advisories/three\nhttps://example.com/advisories/four";
    render(<ChatMessage
      turn={{
        ...baseTurn,
        id: "turn-edited-link-list",
        content: "已返回参考链接。",
        result: {
          answer: "已返回参考链接。",
          tables: [{
            id: "edited-link-list-table",
            columns: [{ key: "references", label: "参考", kind: "link" }],
            rows: [{ references: "https://example.com/advisories/one\nhttps://example.com/advisories/two" }],
          }],
        },
      }}
      onResultChange={onResultChange}
    />);

    fireEvent.click(screen.getByRole("button", { name: "编辑记录表" }));
    fireEvent.change(screen.getByRole("textbox", { name: "参考，第 1" }), {
      target: { value: nextReferences },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }));

    await waitFor(() => expect(onResultChange).toHaveBeenCalledOnce());
    expect(onResultChange.mock.calls[0][0].structured_data_edits[0].rows[0]).toEqual({
      references: nextReferences,
    });
  });

  it("keeps Markdown tables read-only even when structured result editing is enabled", () => {
    render(<ChatMessage
      turn={{
        ...baseTurn,
        id: "turn-readonly-markdown-table",
        content: [
          "| 漏洞编号 | 标题 |",
          "| --- | --- |",
          "| CVE-2026-8080 | 已翻译标题 |",
        ].join("\n"),
        result: { answer: "", fields: {} },
      }}
      onResultChange={vi.fn()}
    />);

    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "编辑记录表" })).not.toBeInTheDocument();
  });

  it("shows customer-facing result fields while filtering orchestration metadata", () => {
    render(<ChatMessage turn={{
      ...baseTurn,
      id: "turn-structured-fields",
      content: "查询完成。",
      result: {
        answer: "查询完成。",
        fields: {
          "意图": "recent_high_vulnerability_lookup",
          "模型调用状态": "成功",
          "查询开始日期": "2026-08-01",
          "命中漏洞": "12",
        },
      },
    }} />);

    expect(screen.getByRole("table", { name: "数据概览" })).toBeInTheDocument();
    expect(screen.getByText("查询开始日期")).toBeInTheDocument();
    expect(screen.getByText("命中漏洞")).toBeInTheDocument();
    expect(screen.queryByText("模型调用状态")).not.toBeInTheDocument();
    expect(screen.queryByText("recent_high_vulnerability_lookup")).not.toBeInTheDocument();
  });
});
