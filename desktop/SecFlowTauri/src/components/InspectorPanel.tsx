import { Activity, Cpu, Database, HardDrive, Network } from "lucide-react";

import { brandDisplayText } from "../branding";
import { useAppStore } from "../store/appStore";
import type { AgentTask, TraceItem } from "../types";

type ExecutionStep = {
  node: string;
  title: string;
  message: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
};

export function InspectorPanel() {
  const state = useAppStore();
  const activeTask = state.tasks.find((item) => item.id === state.activeTaskId);
  const latestAssistantTurn = [...state.turns].reverse().find((turn) => turn.role === "assistant");
  const turnTask = latestAssistantTurn?.task
    ? state.tasks.find((item) => item.id === latestAssistantTurn.task?.id) || latestAssistantTurn.task
    : undefined;
  const task = turnTask || (!latestAssistantTurn?.trace?.length ? activeTask : undefined);
  const steps = task ? taskExecutionSteps(task) : traceExecutionSteps(latestAssistantTurn?.trace || []);
  const running = latestAssistantTurn?.state === "streaming" || Boolean(task && ["queued", "running", "cancelling"].includes(task.status));
  const currentStep = steps.find((step) => step.status === "running") || steps.at(-1);
  const online = Boolean(state.health?.ok);

  return (
    <aside className="inspector-panel" aria-label="Agent 执行状态">
      <section className="inspector-section">
        <h3><Activity size={14} />运行状态</h3>
        <div className="runtime-grid">
          <span><Cpu /><small>控制面</small><strong>{online ? "正常" : "连接中"}</strong></span>
          <span><Network /><small>任务 Worker</small><strong>{state.health?.task_execution.running_workers || 0}</strong></span>
          <span><Database /><small>事件存储</small><strong>SQLite WAL</strong></span>
          <span><HardDrive /><small>数据边界</small><strong>本机</strong></span>
        </div>
      </section>
      <section className="inspector-section process-section">
        <h3>进程</h3>
        <div className="process-row"><span className={running ? "live-dot" : "idle-dot"} /><div><strong>{brandDisplayText(currentStep?.title || task?.current_node) || "等待任务"}</strong><small>{running ? "running" : currentStep ? statusLabel(currentStep.status) : "idle"}</small></div></div>
        <div className="process-row"><span className={online ? "live-dot" : "idle-dot"} /><div><strong>FastAPI Control</strong><small>{online ? "HTTP + SSE" : "连接中"}</small></div></div>
      </section>
    </aside>
  );
}

function taskExecutionSteps(task: AgentTask): ExecutionStep[] {
  const eventsByNode = new Map(task.events
    .filter((event) => event.node && !event.type.startsWith("task."))
    .map((event) => [event.node, event]));
  const nodes = [...new Set([...task.plan.map((step) => step.node), ...eventsByNode.keys()])];
  return nodes.map((node) => {
    const planned = task.plan.find((step) => step.node === node);
    const event = eventsByNode.get(node);
    return {
      node,
      title: planned?.title || humanizeNode(node),
      message: event?.message || "",
      status: normalizeStatus(event?.status || planned?.status || "pending"),
    };
  });
}

function traceExecutionSteps(trace: TraceItem[]): ExecutionStep[] {
  return trace.map((item) => ({
    node: item.node,
    title: item.title || humanizeNode(item.node),
    message: item.message || "",
    status: normalizeStatus(item.status),
  }));
}

function normalizeStatus(status: string): ExecutionStep["status"] {
  if (["completed", "success", "warning"].includes(status)) return "completed";
  if (["failed", "error"].includes(status)) return "failed";
  if (["running", "started"].includes(status)) return "running";
  if (status === "cancelled") return "cancelled";
  return "pending";
}

const statusLabel = (status: ExecutionStep["status"]) => ({
  pending: "等待执行",
  running: "执行中",
  completed: "已完成",
  failed: "执行失败",
  cancelled: "已停止",
}[status]);

const humanizeNode = (node: string) => node.replace(/[._]/g, " ");
