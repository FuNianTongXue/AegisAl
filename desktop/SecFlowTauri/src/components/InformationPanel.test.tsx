// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { AskResult } from "../types";
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

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("独立咨询问题"), { target: { value: "查询近期高危漏洞" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    expect(await screen.findByText("已完成检索。建议优先检查受影响资产。")).toBeInTheDocument();
    expect(screen.getAllByText("Security MCP").length).toBeGreaterThan(0);
    expect(String(requestBody?.session_id)).toMatch(/^information:/);
    expect(requestBody?.user_id).toBe("tester");
    expect(requestBody?.response_language).toBe("zh-Hans");
    expect(requestBody?.intent_hint).toBe("recent_high_vulnerability_lookup");
    expect(screen.getByRole("button", { name: /思考过程/ })).toHaveAttribute("aria-expanded", "false");
    expect(useAppStore.getState().activeSessionId).toBe("main-session");
    expect(useAppStore.getState().workspacePath).toBe("/tmp/main-workspace");
    expect(useAppStore.getState().activeTaskId).toBe("main-task");
    expect(useAppStore.getState().turns).toEqual([]);
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
    expect(await screen.findByText("已停止本次咨询。")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "发送" })).toBeInTheDocument());
  });

  it("keeps the existing security feed available as a separate view", async () => {
    vi.spyOn(api, "information").mockResolvedValue({
      items: [{ id: "feed-1", title: "供应链安全通告", source_name: "SecFlow", published_at: "2026-08-01T10:00:00+08:00" }],
    });

    render(<InformationPanel open onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", { name: "资讯" }));

    expect(await screen.findByText("供应链安全通告")).toBeInTheDocument();
    expect(api.information).toHaveBeenCalledOnce();
  });

  it("loads feed artwork through the local image proxy with a source-logo fallback", async () => {
    vi.spyOn(api, "information").mockResolvedValue({
      items: [{
        id: "feed/cover-1",
        title: "带封面的安全资讯",
        source_id: "source/logo-1",
        source_name: "SecFlow",
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
    expect(await screen.findByText("S")).toHaveClass("source-logo");
  });

  it("can render as the native status-item window without changing consultation behavior", () => {
    render(<InformationPanel open onClose={vi.fn()} variant="window" />);

    expect(screen.getByLabelText("独立信息咨询")).toHaveClass("information-panel", "windowed");
    expect(screen.getByText("信息中心").closest("header")).not.toHaveAttribute("data-tauri-drag-region");
    expect(screen.getByLabelText("独立咨询问题")).toBeInTheDocument();
  });
});
