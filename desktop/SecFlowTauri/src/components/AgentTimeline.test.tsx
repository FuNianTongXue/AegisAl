// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { AgentTimeline } from "./AgentTimeline";

afterEach(cleanup);

describe("AgentTimeline", () => {
  it("keeps a running direct-model trace collapsed until the user opens it", () => {
    render(
      <AgentTimeline
        running
        autoExpand={false}
        trace={[{ node: "call_llm", status: "running", message: "正在生成回答" }]}
      />,
    );

    const heading = screen.getByRole("button", { name: /思考过程/ });
    expect(heading).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("正在生成回答").closest(".timeline-collapse")).toHaveAttribute("aria-hidden", "true");

    fireEvent.click(heading);
    expect(heading).toHaveAttribute("aria-expanded", "true");
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

    expect(screen.getByText("检查项目范围")).toBeInTheDocument();
    expect(screen.getByText("项目范围已确认")).toBeInTheDocument();
    expect(screen.getByText("还原跨方法污点路径")).toBeInTheDocument();
    expect(screen.getByText("思考过程")).toBeInTheDocument();
    expect(screen.getByText(/持续了 0 秒/)).toBeInTheDocument();

    const heading = screen.getByRole("button", { name: /思考过程/ });
    expect(heading).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(heading);
    expect(heading).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("检查项目范围").closest(".timeline-collapse")).toHaveAttribute("aria-hidden", "false");
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

    const item = screen.getByText("scan java").closest("li");
    expect(item).toHaveClass("cancelled");
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

    const item = screen.getByText("scan java").closest("li");
    expect(item).toHaveClass("cancelled");
    expect(screen.getByText("该步骤已随用户停止而终止。")).toBeInTheDocument();
    expect(item?.querySelector(".spin")).toBeNull();
  });
});
