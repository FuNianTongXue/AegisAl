import { useEffect, useMemo, useRef, useState } from "react";

import { brandDisplayText } from "../branding";
import type { AgentPlanStep, AgentTaskEvent, TraceItem } from "../types";
import { ThinkingState } from "./ThinkingState";
import {
  BeautifulToolChips,
  type BeautifulFileDiff,
  type BeautifulStatus,
  type BeautifulTaskDetail,
  type BeautifulToolAction,
  type BeautifulToolRowItem,
} from "./beautiful-ui/BeautifulUI";

export function AgentTimeline({
  trace = [],
  events = [],
  plan = [],
  running = false,
  autoExpand = false,
}: {
  trace?: TraceItem[];
  events?: AgentTaskEvent[];
  plan?: AgentPlanStep[];
  running?: boolean;
  autoExpand?: boolean;
}) {
  const startedAt = useRef(Date.now());
  const [elapsedMs, setElapsedMs] = useState(0);
  const steps = useMemo(() => normalizeSteps(trace, events, plan, !running), [events, plan, running, trace]);
  const measuredDuration = steps.reduce((total, step) => total + step.durationMs, 0) || elapsedMs;
  useEffect(() => {
    if (!running) {
      setElapsedMs(Date.now() - startedAt.current);
      return;
    }
    const tick = () => setElapsedMs(Date.now() - startedAt.current);
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [running]);
  const visibleSteps = running && !steps.some((item) => item.status === "running")
    ? [...steps, {
        node: "compose_result",
        title: "综合分析中",
        message: "正在固化证据和结论",
        status: "running",
        durationMs: 0,
        toolName: "",
        input: undefined,
        output: undefined,
        error: "",
        fileDiffs: [],
      }]
    : steps;
  if (!visibleSteps.length) return null;

  const items: BeautifulToolRowItem[] = visibleSteps.map((step, index) => {
    const state = taskRowStatus(step.status);
    const { action, actionKind } = stepAction(step);
    const meta = [
      step.toolName,
      step.status === "running" ? formatWorkingTime(elapsedMs) : step.durationMs ? formatDuration(step.durationMs) : "",
    ].filter(Boolean).join(" · ");
    return {
      id: `${step.node}:${index}`,
      state,
      action,
      actionKind,
      chip: stepChip(step.title, action),
      meta,
      statusLabel: statusLabel(state),
      details: stepDetails(step),
    };
  });
  const toolCallCount = visibleSteps.filter((step) => Boolean(step.toolName)).length;
  const messageCount = visibleSteps.filter((step) => Boolean(step.message?.trim())).length;
  const summary = toolCallCount || messageCount
    ? `${toolCallCount} 次工具调用，${messageCount} 条消息`
    : `${items.length} 个执行步骤`;
  const diffs = uniqueFileDiffs(visibleSteps.flatMap((step) => step.fileDiffs));
  const activeStep = visibleSteps.find((step) => step.status === "running");
  const activity = activeStep ? `${activeStep.title}${activeStep.toolName ? ` · ${activeStep.toolName}` : ""}` : undefined;

  return (
    <section className={`agent-timeline bui-task-timeline ${running ? "running" : "completed"}`} aria-label="思考过程">
      <ThinkingState
        running={running}
        elapsedMs={running ? elapsedMs : measuredDuration}
        stepCount={items.length}
        activity={activity}
        autoExpand={autoExpand}
      >
        <BeautifulToolChips items={items} summary={summary} label="执行过程" diffs={diffs} defaultOpen showSummary={false} />
      </ThinkingState>
    </section>
  );
}

function normalizeSteps(trace: TraceItem[], events: AgentTaskEvent[], plan: AgentPlanStep[], settled = false) {
  if (events.length) {
    const byNode = new Map<string, AgentTaskEvent>();
    events.forEach((event) => {
      if (event.node && !event.type.startsWith("task.")) byNode.set(event.node, event);
    });
    const orderedNodes = [...new Set([...plan.map((step) => step.node), ...byNode.keys()])];
    return orderedNodes.map((node) => {
      const planned = plan.find((step) => step.node === node);
      const event = byNode.get(node);
      const status = normalizeStatus(event?.status || planned?.status || "pending");
      return {
        node,
        title: brandDisplayText(planned?.title || nodeTitle(node)),
        message: brandDisplayText(event?.message),
        // 任务已终止（停止/失败）时，事件流里残留的 running 步骤降级为 cancelled，
        // 避免扫描已被停止后时间线仍一直转圈。
        status: settled && status === "running" ? "cancelled" : status,
        durationMs: numericField(event?.data, "duration_ms"),
        toolName: brandDisplayText(stringField(event?.data, "tool_name") || (node.includes("mcp") ? "MCP" : "")),
        input: event?.data?.input,
        output: event?.data?.output,
        error: brandDisplayText(stringField(event?.data, "error")),
        fileDiffs: uniqueFileDiffs([
          ...extractFileDiffs(event?.data),
          ...extractFileDiffs(event?.data?.output),
        ]),
      };
    });
  }
  if (plan.length) return plan.map((step) => ({
    node: step.node,
    title: brandDisplayText(step.title || nodeTitle(step.node)),
    message: "",
    status: normalizeStatus(step.status),
    durationMs: 0,
    toolName: brandDisplayText(step.node.includes("mcp") ? "MCP" : ""),
    input: undefined,
    output: undefined,
    error: "",
    fileDiffs: [],
  }));
  return trace.map((item) => ({
    node: item.node,
    title: brandDisplayText(item.title || nodeTitle(item.node)),
    message: brandDisplayText(item.message),
    status: normalizeStatus(item.status),
    durationMs: item.duration_ms || 0,
    toolName: brandDisplayText(item.tool_name || presentationField(item, "tool_name") || (item.node.includes("mcp") ? "MCP" : "")),
    input: item.input ?? item.presentation?.input,
    output: item.output ?? item.presentation?.output,
    error: brandDisplayText(item.error || presentationField(item, "error")),
    fileDiffs: uniqueFileDiffs([
      ...extractFileDiffs(item.presentation),
      ...extractFileDiffs(item.output),
    ]),
  }));
}

type TimelineStep = ReturnType<typeof normalizeSteps>[number];

function stepDetails(step: TimelineStep): BeautifulTaskDetail[] {
  const details: BeautifulTaskDetail[] = [{
    label: "执行说明",
    content: <span dir="auto">{step.message || nodeDescription(step.node)}</span>,
  }];
  if (step.toolName) details.push({ label: "执行工具", meta: step.toolName });
  if (step.durationMs) details.push({ label: "耗时", meta: formatDuration(step.durationMs) });
  if (step.input !== undefined) details.push({ label: "请求参数", content: <TraceValue value={step.input} /> });
  if (step.output !== undefined) details.push({ label: "执行结果", content: <TraceValue value={step.output} /> });
  if (step.error) details.push({ label: "错误信息", content: <span dir="auto">{step.error}</span>, tone: "error" });
  return details;
}

function TraceValue({ value }: { value: unknown }) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return <span dir="auto">{value}</span>;
    try {
      return <pre>{JSON.stringify(JSON.parse(trimmed), null, 2)}</pre>;
    } catch {
      return <span dir="auto">{value}</span>;
    }
  }
  let serialized = "";
  try {
    serialized = JSON.stringify(value, null, 2);
  } catch {
    serialized = String(value);
  }
  return <pre>{serialized}</pre>;
}

function stepAction(step: TimelineStep): { action: string; actionKind: BeautifulToolAction } {
  const source = `${step.node} ${step.title}`.toLocaleLowerCase();
  if (/(query|search|查询|检索)/.test(source)) return { action: "查询", actionKind: "query" };
  if (/(export|generate|render|生成|导出|渲染)/.test(source)) return { action: "生成", actionKind: "generate" };
  if (/(verify|validate|核验|验证|确认)/.test(source)) return { action: "验证", actionKind: "verify" };
  if (/(translation|translate|翻译)/.test(source)) return { action: "翻译", actionKind: "translate" };
  if (/(plan|supervisor|规划)/.test(source)) return { action: "规划", actionKind: "plan" };
  if (/(scan|analysis|analyze|detect|inspect|分析|扫描|检查|识别)/.test(source)) return { action: "分析", actionKind: "analyze" };
  if (step.toolName) return { action: "调用工具", actionKind: "execute" };
  return { action: "执行", actionKind: "execute" };
}

function stepChip(title: string, action: string) {
  const compact = title.replace(new RegExp(`^${action}\\s*`), "").trim();
  return compact || title;
}

function extractFileDiffs(value: unknown): BeautifulFileDiff[] {
  const record = objectValue(value);
  if (!record) return [];
  const source = ["file_changes", "fileChanges", "changed_files", "changedFiles", "diffs"]
    .map((key) => record[key])
    .find(Array.isArray);
  if (!Array.isArray(source)) return [];
  return source.flatMap((candidate, index) => {
    const item = objectValue(candidate);
    if (!item) return [];
    const file = firstString(item, ["file", "path", "file_name", "fileName", "name"]);
    if (!file) return [];
    const additions = firstNumber(item, ["additions", "added", "add"]);
    const deletions = firstNumber(item, ["deletions", "deleted", "del"]);
    const lines = extractDiffLines(item.lines ?? item.diff_lines ?? item.patch);
    return [{
      id: `${file}:${index}`,
      file,
      additions,
      deletions,
      ...(lines.length ? { lines } : {}),
    }];
  });
}

function extractDiffLines(value: unknown): NonNullable<BeautifulFileDiff["lines"]> {
  const source = typeof value === "string" ? value.split("\n") : Array.isArray(value) ? value : [];
  return source.flatMap((candidate) => {
    if (typeof candidate === "string") {
      const tone = candidate.startsWith("+") && !candidate.startsWith("+++")
        ? "add"
        : candidate.startsWith("-") && !candidate.startsWith("---")
          ? "delete"
          : "context";
      return [{ text: candidate.replace(/^[+-]/, ""), tone } as const];
    }
    const item = objectValue(candidate);
    const text = item ? firstString(item, ["text", "content", "line"]) : "";
    if (!item || !text) return [];
    const rawTone = firstString(item, ["tone", "type", "kind"]);
    const tone = ["add", "added", "addition"].includes(rawTone)
      ? "add"
      : ["delete", "deleted", "deletion", "remove", "removed"].includes(rawTone)
        ? "delete"
        : "context";
    return [{ text, tone }];
  });
}

function uniqueFileDiffs(items: BeautifulFileDiff[]) {
  return [...new Map(items.map((item) => [item.file, item])).values()];
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function firstString(value: Record<string, unknown>, keys: string[]) {
  const item = keys.map((key) => value[key]).find((candidate) => typeof candidate === "string");
  return typeof item === "string" ? item : "";
}

function firstNumber(value: Record<string, unknown>, keys: string[]) {
  const item = keys.map((key) => Number(value[key])).find((candidate) => Number.isFinite(candidate));
  return item ?? 0;
}

function stringField(value: AgentTaskEvent["data"], key: string) {
  const item = value?.[key];
  return typeof item === "string" ? item : "";
}

function numericField(value: AgentTaskEvent["data"], key: string) {
  const item = Number(value?.[key] || 0);
  return Number.isFinite(item) ? item : 0;
}

function presentationField(item: TraceItem, key: string) {
  const value = item.presentation?.[key];
  return typeof value === "string" ? value : "";
}

function normalizeStatus(status: string) {
  if (["completed", "success", "warning"].includes(status)) return "completed";
  if (["failed", "error"].includes(status)) return "failed";
  if (["running", "started"].includes(status)) return "running";
  if (status === "cancelled") return "cancelled";
  return "pending";
}

const taskRowStatus = (status: string): BeautifulStatus => status === "failed" ? "error" : status as BeautifulStatus;
const statusLabel = (status: BeautifulStatus) => ({
  pending: "等待中",
  running: "运行中",
  completed: "已完成",
  error: "失败",
  cancelled: "已停止",
})[status];

const titles: Record<string, string> = {
  inspect_workspace: "检查项目范围",
  detect_languages: "识别语言与框架",
  static_rule_scan: "运行静态安全规则",
  code_scan_mcp: "调用代码扫描 MCP",
  semantic_analysis: "构建 AST / CFG / DFG",
  taint_analysis: "还原跨方法污点路径",
  dependency_scan: "分析依赖与许可",
  verify_findings: "验证漏洞证据",
  compose_result: "固化扫描结果",
  supervisor_agent: "Supervisor 规划报告任务",
  report_agent: "Report Agent",
  result_aggregator_agent: "汇总 Agent 执行结果",
  translation_agent: "翻译结构化回复",
  plan_assistant_intent: "规划请求意图",
  validate_component_catalog_plan: "验证组件漏洞查询计划",
  query_component_vulnerability_catalog: "查询组件漏洞目录",
  "component_catalog.d3_sankey_mcp": "生成组件关联图",
  export_component_vulnerability_catalog: "生成组件漏洞 Excel",
  report_capability_subgraph: "准备报告数据",
  "report.interrupt_generate": "确认报告生成",
  "report.scan_json": "核验扫描结果 JSON",
  "report.translation_agent": "翻译报告 JSON",
  "report.sarif_mcp": "生成 SARIF 污点路径",
  "report.chart_mcp": "生成报告图表数据",
  "report.prepare_draft": "准备报告事实草稿",
  "report.mermaid_mcp": "渲染漏洞关系图",
  "report.markdown_mcp": "生成 Markdown 报告",
  "report.word_mcp": "生成 Word 报告",
  "report.pdf_mcp": "生成 PDF 报告",
  "report.persist": "保存报告制品",
  "report.interrupt_download": "等待确认下载",
  sbom_capability_subgraph: "生成 SBOM 清单",
};

const nodeTitle = (node: string) => titles[node] || node.replaceAll("_", " ");
const nodeDescription = (node: string) => (node.includes("scan") ? "安全工具正在处理项目证据" : "LangGraph 节点执行完成");
const formatDuration = (value: number) => value < 1000 ? `${value}ms` : `${(value / 1000).toFixed(1)}s`;
const formatWorkingTime = (value: number) => `${Math.max(0, Math.floor(value / 1000))} 秒`;
