// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import aegisalEmblem from "../assets/aegisal-emblem.png";
import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { AskResult, InformationItem } from "../types";
import { InformationPanel } from "./InformationPanel";

describe("InformationPanel", () => {
  beforeEach(() => {
    Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: vi.fn() });
    useAppStore.setState({
      activeSessionId: "main-session",
      workspacePath: "/tmp/main-workspace",
      activeTaskId: "main-task",
      turns: [],
      userId: "tester",
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("streams trace and content in a session isolated from the main workspace", async () => {
    let requestBody: Record<string, unknown> | undefined;
    vi.spyOn(api, "streamQuestion").mockImplementation(async (body, callbacks) => {
      requestBody = body;
      callbacks.onTrace({
        node: "security_search_tool",
        title: "检索漏洞情报",
        status: "completed",
        tool_name: "Security MCP",
        input: { query: "近期高危漏洞" },
        output: { matches: 3 },
      });
      callbacks.onContent("已完成检索。");
      return {
        answer: "已完成检索。建议优先检查受影响资产。",
        session_id: String(body.session_id),
        orchestration: { agentic: true },
      } as AskResult;
    });

    const { container } = render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("独立咨询问题"), { target: { value: "查询近期高危漏洞" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    expect(await screen.findByText("已完成检索。建议优先检查受影响资产。")).toBeInTheDocument();
    const assistantMark = container.querySelector(
      ".consultation-conversation .compact-chat.assistant-turn .assistant-gutter .brand-mark",
    );
    expect(assistantMark).toHaveStyle({ width: "23px", height: "23px" });
    expect(assistantMark?.querySelector("img")).toHaveAttribute("src", aegisalEmblem);
    expect(container.querySelector(".consultation-conversation .assistant-gutter svg")).not.toBeInTheDocument();
    expect(screen.getAllByText("Security MCP").length).toBeGreaterThan(0);
    expect(String(requestBody?.session_id)).toMatch(/^information:/);
    expect(requestBody?.user_id).toBe("tester");
    expect(requestBody?.response_language).toBe("zh-Hans");
    expect(requestBody?.intent_hint).toBe("recent_high_vulnerability_lookup");
    const executionSummary = screen.getByRole("button", { name: /思考完成/ });
    await waitFor(() => expect(executionSummary).toHaveAttribute("aria-expanded", "false"));
    fireEvent.click(executionSummary);
    expect(screen.getByRole("button", { name: /检索漏洞情报，已完成/ })).toHaveAttribute("aria-expanded", "false");
    expect(useAppStore.getState().activeSessionId).toBe("main-session");
    expect(useAppStore.getState().workspacePath).toBe("/tmp/main-workspace");
    expect(useAppStore.getState().activeTaskId).toBe("main-task");
    expect(useAppStore.getState().turns).toEqual([]);
  });

  it("persists edited translated tables to the active information session", async () => {
    let informationSession = "";
    vi.spyOn(api, "streamQuestion").mockImplementation(async (body) => {
      informationSession = String(body.session_id);
      return {
        answer: "已返回翻译后的漏洞记录。",
        session_id: informationSession,
        exchange_id: "msg-73",
        tables: [{
          id: "information-findings",
          title: "翻译后的漏洞记录",
          columns: [
            { key: "id", label: "漏洞编号", editable: false },
            { key: "title", label: "标题" },
          ],
          rows: [{ id: "CVE-2026-7373", title: "原中文标题" }],
        }],
      } as AskResult;
    });
    const update = vi.spyOn(api, "updateConversationTableEdits").mockImplementation(
      async (_sessionId, exchangeId, _userId, tables) => ({ exchange_id: exchangeId, tables }),
    );

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("独立咨询问题"), { target: { value: "查询漏洞记录" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    expect(await screen.findByRole("table", { name: "翻译后的漏洞记录" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "编辑记录表" }));
    fireEvent.change(screen.getByRole("textbox", { name: "标题，第 1" }), {
      target: { value: "信息中心修订标题" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }));

    await waitFor(() => expect(update).toHaveBeenCalledWith(
      informationSession,
      "msg-73",
      "tester",
      expect.arrayContaining([
        expect.objectContaining({
          id: "information-findings",
          rows: [{ id: "CVE-2026-7373", title: "信息中心修订标题" }],
        }),
      ]),
    ));
    expect(await screen.findByText("信息中心修订标题")).toBeInTheDocument();
  });

  it("routes ordinary questions directly and clears only the previous short-term session", async () => {
    let requestBody: Record<string, unknown> | undefined;
    const clearSpy = vi.spyOn(api, "clearShortTermSession").mockResolvedValue({
      session_id: "information:test",
      cleared_turn_count: 1,
    });
    vi.spyOn(api, "streamQuestion").mockImplementation(async (body) => {
      requestBody = body;
      return { answer: "应采用分级分类、最小权限和审计留痕。", session_id: String(body.session_id) } as AskResult;
    });

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("独立咨询问题"), { target: { value: "如何保护业务数据" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    expect(await screen.findByText("应采用分级分类、最小权限和审计留痕。")).toBeInTheDocument();
    expect(requestBody?.intent_hint).toBe("information_consultation");
    const previousSession = String(requestBody?.session_id);
    fireEvent.click(screen.getByRole("button", { name: "新建独立咨询" }));
    expect(clearSpy).toHaveBeenCalledWith(previousSession, "tester");
  });

  it("aborts only the active consultation request", async () => {
    let requestSignal: AbortSignal | undefined;
    vi.spyOn(api, "streamQuestion").mockImplementation((_body, _callbacks, signal) => {
      requestSignal = signal;
      return new Promise<AskResult>((_resolve, reject) => {
        signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      });
    });

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("独立咨询问题"), { target: { value: "分析告警" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));
    fireEvent.click(await screen.findByRole("button", { name: "停止生成" }));

    expect(requestSignal?.aborted).toBe(true);
    expect((await screen.findAllByText("已停止本次咨询。")).length).toBeGreaterThan(0);
    await waitFor(() => expect(screen.getByRole("button", { name: "发送" })).toBeInTheDocument());
  });

  it("renders consultation turns in batches of 60 and resets the window for a new consultation", async () => {
    vi.spyOn(api, "clearShortTermSession").mockResolvedValue({
      session_id: "information:test",
      cleared_turn_count: 62,
    });
    vi.spyOn(api, "streamQuestion").mockImplementation(async (body) => ({
      answer: `回答 ${String(body.question).split(" ").at(-1)}`,
      session_id: String(body.session_id),
    } as AskResult));

    render(<InformationPanel open onClose={vi.fn()} />);
    const textbox = screen.getByLabelText("独立咨询问题");
    const sendExchanges = async (prefix: string) => {
      for (let index = 1; index <= 31; index += 1) {
        fireEvent.change(textbox, { target: { value: `${prefix} ${index}` } });
        fireEvent.click(screen.getByRole("button", { name: "发送" }));
        await waitFor(() => expect(screen.getByRole("button", { name: "发送" })).toBeInTheDocument());
      }
    };

    await sendExchanges("首轮问题");

    const log = screen.getByRole("log", { name: "咨询对话记录" });
    expect(log).toHaveAttribute("aria-live", "off");
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(60);
    expect(screen.queryByText("首轮问题 1")).not.toBeInTheDocument();
    expect(screen.queryByText("回答 1")).not.toBeInTheDocument();
    expect(screen.getByText("首轮问题 2")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "显示更早消息" }));
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(62);
    expect(screen.getByText("首轮问题 1")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "显示更早消息" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "新建独立咨询" }));
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(0);
    await sendExchanges("次轮问题");
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(60);
    expect(screen.queryByText("次轮问题 1")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "显示更早消息" })).toBeInTheDocument();
  }, 15_000);

  it("keeps the existing security feed available as a separate view", async () => {
    vi.spyOn(api, "information").mockResolvedValue({
      items: [{
        id: "feed-1",
        title: "供应链安全通告",
        source_name: "AegisAl",
        published_at: "2026-08-01T10:00:00+08:00",
        translation_status: "failed",
        translation_message: "离线翻译暂不可用，请稍后重试。",
      } as InformationItem & { translation_status: string; translation_message: string }],
    });

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", { name: "资讯" }));

    expect(await screen.findByText("供应链安全通告")).toBeInTheDocument();
    expect(screen.queryByText(/离线翻译暂不可用/)).not.toBeInTheDocument();
    expect(api.information).toHaveBeenCalledOnce();
  });

  it("maps a legacy product-owned feed source at the display boundary", async () => {
    vi.spyOn(api, "information").mockResolvedValue({
      items: [{
        id: "legacy-brand-feed",
        title: "SecFlow 安全智脑历史来源安全通告",
        source_name: "SecFlow",
        published_at: "2026-08-01T10:00:00+08:00",
      }],
    });

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", { name: "资讯" }));

    expect(await screen.findByText("AegisAl 神盾历史来源安全通告")).toBeInTheDocument();
    expect(screen.queryByText(/SecFlow 安全智脑/)).not.toBeInTheDocument();
    expect(screen.getByText(/AegisAl ·/)).toBeInTheDocument();
    expect(screen.queryByText(/SecFlow ·/)).not.toBeInTheDocument();
  });

  it("loads feed artwork through the local image proxy with a source-logo fallback", async () => {
    vi.spyOn(api, "information").mockResolvedValue({
      items: [{
        id: "feed/cover-1",
        title: "带封面的安全资讯",
        source_id: "source/logo-1",
        source_name: "AegisAl",
        image_url: "https://remote.example/blocked-by-csp.png",
      }],
    });

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", { name: "资讯" }));

    await waitFor(() => expect(document.querySelector("img.information-image")).not.toBeNull());
    const articleImage = document.querySelector<HTMLImageElement>("img.information-image")!;
    expect(articleImage).toHaveAttribute(
      "src",
      `${api.baseUrl}/api/information/images/feed%2Fcover-1`,
    );
    expect(articleImage.getAttribute("src")).not.toContain("remote.example");

    fireEvent.error(articleImage);
    await waitFor(() => expect(document.querySelector("img.source-image")).not.toBeNull());
    const sourceImage = document.querySelector<HTMLImageElement>("img.source-image")!;
    expect(sourceImage).toHaveAttribute(
      "src",
      `${api.baseUrl}/api/information/source-images/source%2Flogo-1`,
    );

    fireEvent.error(sourceImage);
    expect(await screen.findByText("A")).toHaveClass("source-logo");
  });

  it("can render as the native status-item window without changing consultation behavior", () => {
    render(<InformationPanel open onClose={vi.fn()} variant="window" />);

    expect(screen.getByLabelText("独立信息咨询")).toHaveClass("information-panel", "windowed");
    expect(screen.getByText("信息中心").closest("header")).not.toHaveAttribute("data-tauri-drag-region");
    expect(screen.getByLabelText("独立咨询问题")).toBeInTheDocument();
  });
});
