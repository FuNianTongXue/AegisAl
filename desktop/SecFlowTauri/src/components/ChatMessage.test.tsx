// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

    fireEvent.click(screen.getByRole("button", { name: /确认生成报告/ }));
    await waitFor(() => expect(resume).toHaveBeenCalledWith(expect.objectContaining({
      thread_id: "report-thread-1",
      interrupt_id: "int-1",
      decision: "confirm",
      user_id: "tester",
      session_id: "session-9",
    })));

    expect(await screen.findByText("报告已生成：demo_20260804.md。")).toBeInTheDocument();
    const pdfButton = await screen.findByRole("button", { name: "PDF" });
    fireEvent.click(pdfButton);

    await waitFor(() => expect(resume).toHaveBeenLastCalledWith(expect.objectContaining({
      interrupt_id: "int-2",
      decision: "confirm",
      format: "pdf",
    })));

    const downloadButton = await screen.findByRole("button", { name: /demo_20260804\.pdf/ });
    expect(screen.queryByRole("button", { name: "MD" })).not.toBeInTheDocument();

    // 点击后走 api.raw 取内容并交给原生保存面板（可选路径、可重命名）。
    const raw = vi.spyOn(api, "raw").mockResolvedValue(new Response(new Blob(["demo-pdf"])));
    fireEvent.click(downloadButton);
    await waitFor(() => expect(raw).toHaveBeenCalledWith("/api/assistant/artifacts/art-1"));
    // Response.blob() may come from Node's fetch realm while the test's Blob
    // constructor belongs to jsdom, so an instanceof matcher is not portable.
    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalled());
    const [savedName, savedBlob] = vi.mocked(saveBinaryArtifact).mock.calls[0];
    expect(savedName).toBe("demo_20260804.pdf");
    expect(savedBlob.size).toBeGreaterThan(0);
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
