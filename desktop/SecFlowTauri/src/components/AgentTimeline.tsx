import { BrainCircuit, Check, ChevronDown, Circle, LoaderCircle, Square, Wrench, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { AgentPlanStep, AgentTaskEvent, TraceItem } from "../types";

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
  const [expanded, setExpanded] = useState(running && autoExpand);
  const startedAt = useRef(Date.now());
  const [elapsedMs, setElapsedMs] = useState(0);
  const steps = useMemo(() => normalizeSteps(trace, events, plan, !running), [events, plan, running, trace]);
  const measuredDuration = steps.reduce((total, step) => total + step.durationMs, 0) || elapsedMs;
  useEffect(() => {
    if (running && autoExpand) setExpanded(true);
  }, [autoExpand, running]);
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
  if (!steps.length && !running) return null;

  return (
    <section className={`agent-timeline ${running ? "running" : "completed"}`}>
      <button className="timeline-heading" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded}>
        <span className="timeline-pulse">{running ? <LoaderCircle size={15} className="spin" /> : <BrainCircuit size={15} />}</span>
        <span className="timeline-summary">
          <strong>思考过程</strong>
          <small>{running ? `持续了 ${formatWorkingTime(elapsedMs)}` : `持续了 ${formatWorkingTime(measuredDuration)}`}</small>
        </span>
        <ChevronDown size={15} className={expanded ? "" : "rotated"} />
      </button>
      <div className={`timeline-collapse ${expanded ? "expanded" : ""}`} aria-hidden={!expanded}>
        <div className="timeline-collapse-inner">
          <ol className="timeline-list">
            {steps.map((step, index) => (
              <li key={`${step.node}:${index}`} className={step.status} style={{ animationDelay: `${Math.min(index, 8) * 45}ms` }}>
                <span className="timeline-marker">{statusIcon(step.status)}</span>
                <span className="timeline-line" />
                <div><strong>{step.title}</strong><small>{step.message || nodeDescription(step.node)}</small></div>
                {step.durationMs ? <time>{formatDuration(step.durationMs)}</time> : null}
                {step.toolName ? <span className="tool-badge"><Wrench size={11} />{step.toolName}</span> : null}
              </li>
            ))}
            {running && !steps.some((item) => item.status === "running") ? (
              <li className="running timeline-stream-in"><span className="timeline-marker">{statusIcon("running")}</span><div><strong>综合分析中</strong><small>正在固化证据和结论</small></div></li>
            ) : null}
          </ol>
        </div>
      </div>
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
        title: planned?.title || nodeTitle(node),
        message: event?.message,
        // 任务已终止（停止/失败）时，事件流里残留的 running 步骤降级为 cancelled，
        // 避免扫描已被停止后时间线仍一直转圈。
        status: settled && status === "running" ? "cancelled" : status,
        durationMs: numericField(event?.data, "duration_ms"),
        toolName: stringField(event?.data, "tool_name") || (node.includes("mcp") ? "MCP" : ""),
      };
    });
  }
  if (plan.length) return plan.map((step) => ({
    node: step.node,
    title: step.title || nodeTitle(step.node),
    message: "",
    status: normalizeStatus(step.status),
    durationMs: 0,
    toolName: step.node.includes("mcp") ? "MCP" : "",
  }));
  return trace.map((item) => ({
    node: item.node,
    title: item.title || nodeTitle(item.node),
    message: item.message,
    status: normalizeStatus(item.status),
    durationMs: item.duration_ms || 0,
    toolName: item.tool_name || presentationField(item, "tool_name") || (item.node.includes("mcp") ? "MCP" : ""),
  }));
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

function statusIcon(status: string) {
  if (status === "completed") return <Check size={12} />;
  if (status === "failed") return <X size={12} />;
  if (status === "running") return <LoaderCircle size={12} className="spin" />;
  if (status === "cancelled") return <Square size={12} />;
  return <Circle size={8} />;
}

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
