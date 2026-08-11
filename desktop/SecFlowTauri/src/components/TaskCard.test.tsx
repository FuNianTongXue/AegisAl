// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { saveBinaryArtifact } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import type { AgentTask } from "../types";
import { TaskCard } from "./TaskCard";

vi.mock("../lib/platform", () => ({
  saveBinaryArtifact: vi.fn(),
}));

const completedTask = (): AgentTask => ({
  id: "task-report-1",
  objective: "扫描这个代码的漏洞",
  workspace_path: "/Users/test/kafka",
  workspace_name: "kafka",
  user_id: "analyst",
  status: "completed",
  current_node: "compose_result",
  languages: ["java"],
  plan: [],
  events: [],
  result: { finding_count: 2 },
  report_ready: true,
  report_decision: "pending",
  run_number: 1,
  created_at: "2026-08-01T10:00:00+08:00",
  updated_at: "2026-08-01T10:00:00+08:00",
});

describe("TaskCard report confirmation", () => {
  beforeEach(() => {
    const task = completedTask();
    useAppStore.setState({ userId: "analyst", tasks: [task], activeTaskId: task.id });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("immediately exposes Report Agent progress and prevents duplicate confirmation", async () => {
    let finish!: (task: AgentTask) => void;
    vi.spyOn(api, "decideReport").mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    vi.spyOn(api, "task").mockImplementation(async () => useAppStore.getState().tasks[0]);
    const task = completedTask();
    render(<TaskCard task={task} />);

    fireEvent.click(screen.getByRole("button", { name: /确认生成报告/ }));

    expect(await screen.findByRole("button", { name: /Report Agent 生成中/ })).toBeDisabled();
    expect(screen.getByText("报告生成中")).toBeInTheDocument();
    expect(screen.getByText("Report Agent")).toBeInTheDocument();
    expect(api.decideReport).toHaveBeenCalledTimes(1);

    finish({ ...task, report_decision: "generated", report: { id: "report-1", title: "报告", created_at: task.updated_at } });
    await waitFor(() => expect(screen.queryByRole("button", { name: /Report Agent 生成中/ })).not.toBeInTheDocument());
    expect(api.decideReport).toHaveBeenCalledTimes(1);
  });

  it("renders matched vulnerability alerts with severity chips", () => {
    const task: AgentTask = {
      ...completedTask(),
      result: {
        finding_count: 2,
        dependency_count: 2,
        vulnerability_count: 3,
        vulnerabilities: [
          { id: "CVE-2021-44228", severity: "CRITICAL", summary: "Log4Shell" },
          { id: "CVE-2021-45046", severity: "CRITICAL", summary: "Log4j RCE" },
          { id: "CVE-2026-34480", severity: "HIGH", summary: "XmlLayout" },
        ],
      },
    };
    useAppStore.setState({ tasks: [task], activeTaskId: task.id });
    render(<TaskCard task={task} />);

    expect(screen.getByText("漏洞命中")).toBeInTheDocument();
    expect(screen.getByText("3", { selector: ".metric-danger strong" })).toBeInTheDocument();
    expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument();
    expect(screen.getByText("CVE-2021-45046")).toBeInTheDocument();
    expect(screen.queryByText("等 3 个已知漏洞")).not.toBeInTheDocument();
  });

  it("immediately enters cancelling state, clears stale metrics, and prevents duplicate stops", async () => {
    const runningTask: AgentTask = {
      ...completedTask(),
      status: "running",
      current_node: "scan_java",
      languages: ["java"],
      plan: [{ node: "scan_java", status: "running" }],
      result: { finding_count: 9, dependency_count: 7 },
      report_ready: false,
      report_decision: "unavailable",
    };
    let finish!: (task: AgentTask) => void;
    vi.spyOn(api, "taskMutation").mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    useAppStore.setState({ tasks: [runningTask], activeTaskId: runningTask.id });
    render(<TaskCard task={runningTask} />);

    fireEvent.click(screen.getByRole("button", { name: /停止分析/ }));

    const stopButton = await screen.findByRole("button", { name: /停止中/ });
    expect(stopButton).toBeDisabled();
    expect(screen.getByText("停止中", { selector: ".status-chip" })).toBeInTheDocument();
    expect(screen.getByText("识别中")).toBeInTheDocument();
    expect(screen.getByText("漏洞命中")).toBeInTheDocument();
    expect(screen.getAllByText("0")).toHaveLength(3);
    fireEvent.click(stopButton);
    expect(api.taskMutation).toHaveBeenCalledTimes(1);

    finish({ ...runningTask, status: "cancelled", languages: [], plan: [], result: undefined });
    await waitFor(() => expect(screen.queryByRole("button", { name: /停止中/ })).not.toBeInTheDocument());
  });

  it("downloads Excel directly and all report formats as one ZIP decision", async () => {
    const task: AgentTask = {
      ...completedTask(),
      report_decision: "generated",
      report: { id: "report-1", title: "安全报告", created_at: completedTask().updated_at },
    };
    useAppStore.setState({ tasks: [task], activeTaskId: task.id });
    vi.spyOn(api, "decideReportDownload").mockResolvedValue({
      task,
      artifact: {
        id: "report-artifact-bundle",
        file_name: "SecFlow-report-1-bundle.zip",
        download_path: "/api/assistant/artifacts/report-artifact-bundle",
      },
    });
    vi.spyOn(api, "raw").mockResolvedValue(new Response(new Blob(["bundle"])));

    render(<TaskCard task={task} />);
    fireEvent.change(screen.getByLabelText("报告格式"), { target: { value: "all" } });
    fireEvent.click(screen.getByRole("button", { name: /确认下载/ }));

    await waitFor(() => expect(api.decideReportDownload).toHaveBeenCalledWith(task.id, "analyst", true, "all"));
    expect(api.decideReportDownload).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalled());
    expect(vi.mocked(saveBinaryArtifact).mock.calls[0][0]).toBe("SecFlow-report-1-bundle.zip");
  });
});
