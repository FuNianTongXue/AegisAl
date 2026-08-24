// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  BeautifulApprovalCard,
  BeautifulLoadingState,
  BeautifulThinkingTrigger,
  BeautifulToolChips,
  BeautifulToolChipTrigger,
} from "./BeautifulUI";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("Beautiful UI adapters", () => {
  it("renders an accessible pixel loading state with elapsed time", () => {
    vi.useFakeTimers();
    render(<BeautifulLoadingState label="正在分析" showElapsed />);
    expect(screen.getByRole("status", { name: "正在分析" })).toBeInTheDocument();
    expect(document.querySelectorAll(".bui-pixel-grid i")).toHaveLength(9);
    act(() => vi.advanceTimersByTime(1200));
    expect(screen.getByText("1.0s")).toBeInTheDocument();
  });

  it("keeps reasoning and tool disclosures keyboard-compatible", () => {
    const toggleThinking = vi.fn();
    const toggleTool = vi.fn();
    render(<>
      <BeautifulThinkingTrigger running expanded={false} title="思考过程" description="持续了 1 秒" onToggle={toggleThinking} />
      <BeautifulToolChipTrigger state="completed" name="CVE Search" meta="0.4s" open={false} onToggle={toggleTool} />
    </>);
    fireEvent.click(screen.getByRole("button", { name: /思考过程/ }));
    fireEvent.click(screen.getByRole("button", { name: /CVE Search/ }));
    expect(toggleThinking).toHaveBeenCalledOnce();
    expect(toggleTool).toHaveBeenCalledOnce();
  });

  it("preserves alert dialog semantics for approval flows", () => {
    render(<BeautifulApprovalCard label="确认操作"><button>确认</button></BeautifulApprovalCard>);
    expect(screen.getByRole("alertdialog", { name: "确认操作" })).toBeInTheDocument();
  });

  it("keeps the tool group and individual rows collapsed until requested", () => {
    render(<BeautifulToolChips summary="1 次工具调用，2 条消息" items={[
      {
        id: "query",
        state: "completed",
        action: "查询",
        actionKind: "query",
        chip: "组件漏洞目录",
        meta: "1.2s",
        statusLabel: "已完成",
        details: [{ label: "执行说明", content: "已查询 8,579 条漏洞" }],
      },
      {
        id: "export",
        state: "running",
        action: "生成",
        actionKind: "generate",
        chip: "组件漏洞 Excel",
        meta: "持续 6 秒",
        statusLabel: "运行中",
        details: [{ label: "执行说明", content: "正在流式写入工作簿" }],
      },
    ]} />);

    const group = screen.getByRole("button", { name: "1 次工具调用，2 条消息" });
    expect(group).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: /查询，组件漏洞目录，已完成/ })).not.toBeInTheDocument();

    fireEvent.click(group);
    const query = screen.getByRole("button", { name: /查询，组件漏洞目录，已完成/ });
    const exportRow = screen.getByRole("button", { name: /生成，组件漏洞 Excel，运行中/ });
    expect(group).toHaveAttribute("aria-expanded", "true");
    expect(query).toHaveAttribute("aria-expanded", "false");
    expect(exportRow).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(query);
    expect(query).toHaveAttribute("aria-expanded", "true");
    expect(exportRow).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(group);
    expect(group).toHaveAttribute("aria-expanded", "false");
    expect(query).toHaveAttribute("tabindex", "-1");
  });

  it("renders real file diffs in a body portal and preserves long chip labels", () => {
    render(<BeautifulToolChips
      summary="1 次工具调用，1 条消息"
      items={[{
        id: "write",
        state: "completed",
        action: "生成",
        actionKind: "generate",
        chip: "特别长的组件漏洞导出文件名称用于验证紧凑布局不会撑破父容器.xlsx",
        statusLabel: "已完成",
        details: [{ label: "执行结果", content: "写入完成" }],
      }]}
      diffs={[{
        id: "report",
        file: "component-vulnerability-report.ts",
        additions: 13,
        deletions: 2,
        lines: [{ text: "const severity = HIGH", tone: "add" }],
      }]}
    />);

    fireEvent.click(screen.getByRole("button", { name: "1 次工具调用，1 条消息" }));
    const chip = screen.getByTitle("特别长的组件漏洞导出文件名称用于验证紧凑布局不会撑破父容器.xlsx");
    expect(chip).toHaveClass("bui-tool-row-chip");
    const diff = screen.getByRole("button", { name: /component-vulnerability-report.ts，新增 13 行，删除 2 行/ });
    fireEvent.focus(diff);
    expect(screen.getByRole("tooltip")).toHaveTextContent("const severity = HIGH");
  });
});
