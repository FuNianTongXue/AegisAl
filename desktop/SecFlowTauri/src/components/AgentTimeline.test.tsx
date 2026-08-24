// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { AgentTimeline } from "./AgentTimeline";

afterEach(cleanup);

describe("AgentTimeline", () => {
  it("keeps a running direct-model trace compact by default until the user opens it", () => {
    const { container } = render(
      <AgentTimeline
        running
        trace={[{ node: "call_llm", status: "running", message: "正在生成回答" }]}
      />,
    );

    const group = screen.getByRole("button", { name: /正在思考 call llm/ });
    expect(group).toHaveAttribute("aria-expanded", "false");
    expect(container.querySelector(".bui-tool-row-trigger")).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("正在生成回答").closest(".bui-tool-row-details-collapse")).toHaveAttribute("aria-hidden", "true");

    fireEvent.click(group);
    expect(group).toHaveAttribute("aria-expanded", "true");
    expect(document.querySelector(".thinking-state-body")).not.toHaveAttribute("inert");
    const row = screen.getByRole("button", { name: /执行，call llm，运行中/ });
    expect(row).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(group);
    expect(group).toHaveAttribute("aria-expanded", "false");
    expect(document.querySelector(".thinking-state-body")).toHaveAttribute("inert");
  });

  it("honors explicit live auto-expand and returns the completed timeline to its compact summary", () => {
    const { rerender } = render(
      <AgentTimeline
        running
        autoExpand
        trace={[{ node: "call_llm", status: "running", message: "正在生成回答" }]}
      />,
    );

    expect(screen.getByRole("button", { name: /正在思考 call llm/ })).toHaveAttribute("aria-expanded", "true");

    rerender(
      <AgentTimeline
        running={false}
        autoExpand
        trace={[{ node: "call_llm", status: "completed", message: "回答生成完成" }]}
      />,
    );

    const completed = screen.getByRole("button", { name: /思考完成/ });
    expect(completed).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(completed);
    expect(completed).toHaveAttribute("aria-expanded", "true");
  });

  it("keeps future plan nodes visible while merging completed events", () => {
    render(
      <AgentTimeline
        running
        plan={[
          { node: "inspect_workspace", title: "检查项目范围", status: "completed" },
          { node: "taint_analysis", title: "还原跨方法污点路径", status: "pending" },
        ]}
        events={[
          {
            sequence: 1,
            type: "node.completed",
            node: "inspect_workspace",
            status: "completed",
            message: "项目范围已确认",
            time: "2026-08-01T10:00:00+08:00",
          },
        ]}
      />,
    );

    const group = screen.getByRole("button", { name: /正在思考 综合分析中/ });
    expect(group).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(group);
    expect(screen.getByRole("list", { name: "执行过程" })).toBeInTheDocument();

    const completedRow = screen.getByRole("button", { name: /分析，检查项目范围，已完成/ });
    const pendingRow = screen.getByRole("button", { name: /分析，还原跨方法污点路径，等待中/ });
    expect(completedRow).toHaveAttribute("aria-expanded", "false");
    expect(pendingRow).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(completedRow);
    expect(completedRow).toHaveAttribute("aria-expanded", "true");
    expect(pendingRow).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("项目范围已确认").closest(".bui-tool-row-details-collapse")).toHaveAttribute("aria-hidden", "false");
  });

  it("renders a leftover running step as cancelled once the task is stopped", () => {
    render(
      <AgentTimeline
        running={false}
        events={[
          {
            sequence: 1,
            type: "node.completed",
            node: "detect_languages",
            status: "completed",
            message: "项目语言识别完成：Java、Python。",
            time: "2026-08-04T20:00:05+08:00",
          },
          {
            sequence: 2,
            type: "node.progress",
            node: "scan_java",
            status: "running",
            message: "Java 语义扫描仍在执行：共 3575 个文件，已运行 35 秒。",
            time: "2026-08-04T20:00:40+08:00",
          },
          {
            sequence: 3,
            type: "task.cancelled",
            node: "cancel",
            status: "warning",
            message: "任务已由用户停止。",
            time: "2026-08-04T20:00:41+08:00",
          },
        ]}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /思考完成/ }));
    const item = screen.getByRole("button", { name: /分析，scan java，已停止/ }).closest(".bui-tool-row");
    expect(item).toHaveClass("bui-status-cancelled");
    expect(item?.querySelector(".spin")).toBeNull();
  });

  it("renders an explicit node.cancelled terminal event as cancelled", () => {
    render(
      <AgentTimeline
        running={false}
        events={[
          {
            sequence: 1,
            type: "node.cancelled",
            node: "scan_java",
            status: "cancelled",
            message: "该步骤已随用户停止而终止。",
            time: "2026-08-04T20:00:41+08:00",
          },
        ]}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /思考完成/ }));
    const item = screen.getByRole("button", { name: /分析，scan java，已停止/ }).closest(".bui-tool-row");
    expect(item).toHaveClass("bui-status-cancelled");
    expect(screen.getByText("该步骤已随用户停止而终止。")).toBeInTheDocument();
    expect(item?.querySelector(".spin")).toBeNull();
  });

  it("maps legacy branded trace labels without changing the stored tool call", () => {
    const trace = [{
      node: "code_scan_mcp",
      title: "SecFlow 代码扫描",
      status: "completed" as const,
      message: "安全智脑正在校验 SecFlow 输出",
      tool_name: "SecFlow Code Scan MCP",
      error: "SecFlow 回退失败：安全智脑未响应",
    }];
    render(
      <AgentTimeline
        trace={trace}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /思考完成/ }));
    const row = screen.getByRole("button", { name: /AegisAl 代码扫描，已完成/ });
    expect(row).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /SecFlow 代码扫描/ })).not.toBeInTheDocument();
    fireEvent.click(row);
    expect(screen.getAllByText("AegisAl Code Scan MCP")).toHaveLength(2);
    expect(screen.getByText("神盾正在校验 AegisAl 输出")).toBeInTheDocument();
    expect(screen.getByText("AegisAl 回退失败：神盾未响应")).toBeInTheDocument();
    expect(trace[0].message).toBe("安全智脑正在校验 SecFlow 输出");
    expect(trace[0].error).toBe("SecFlow 回退失败：安全智脑未响应");
  });
});
