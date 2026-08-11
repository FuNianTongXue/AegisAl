// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { useAppStore } from "../store/appStore";
import type { AgentTask } from "../types";
import { InspectorPanel } from "./InspectorPanel";

describe("InspectorPanel execution plan", () => {
  beforeEach(() => {
    useAppStore.setState({
      activeTaskId: "",
      tasks: [],
      turns: [],
      health: undefined,
    });
  });

  afterEach(cleanup);

  it("renders and updates the latest assistant trace", () => {
    useAppStore.setState({
      turns: [{
        id: "assistant-trace",
        role: "assistant",
        content: "",
        createdAt: "2026-08-06T08:00:00Z",
        state: "streaming",
        trace: [{
          node: "supervisor_agent",
          title: "Supervisor 规划报告任务",
          status: "running",
          message: "正在规划报告任务",
        }],
      }],
    });

    render(<InspectorPanel />);
    expect(screen.getAllByText("Supervisor 规划报告任务").length).toBeGreaterThan(0);
    expect(screen.getByText("正在规划报告任务")).toBeInTheDocument();

    act(() => {
      useAppStore.getState().updateTurn("assistant-trace", {
        state: "completed",
        trace: [{
          node: "supervisor_agent",
          title: "Supervisor 规划报告任务",
          status: "completed",
          message: "规划完成",
        }],
      });
    });
    expect(screen.getByText("规划完成")).toBeInTheDocument();
  });

  it("merges task plans with their latest execution events", () => {
    const task = {
      id: "scan-task",
      objective: "扫描项目",
      workspace_path: "/Users/test/project",
      workspace_name: "project",
      user_id: "analyst",
      status: "running",
      current_node: "static_rule_scan",
      languages: ["python"],
      plan: [{ node: "static_rule_scan", title: "静态规则扫描", status: "running" }],
      events: [{
        sequence: 1,
        type: "node.running",
        node: "static_rule_scan",
        status: "running",
        message: "正在检查安全规则",
        time: "2026-08-06T08:00:00Z",
      }],
      report_ready: false,
      created_at: "2026-08-06T08:00:00Z",
      updated_at: "2026-08-06T08:00:00Z",
    } as AgentTask;
    useAppStore.setState({ activeTaskId: task.id, tasks: [task] });

    render(<InspectorPanel />);
    expect(screen.getAllByText("静态规则扫描").length).toBeGreaterThan(0);
    expect(screen.getByText("正在检查安全规则")).toBeInTheDocument();
  });
});
