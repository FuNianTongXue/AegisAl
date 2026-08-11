import { Check, Download, FileText, LoaderCircle, RotateCcw, Square, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../lib/api";
import { useI18n } from "../i18n";
import { saveBinaryArtifact } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import type { AgentTask } from "../types";
import { AgentTimeline } from "./AgentTimeline";

export function TaskCard({ task: initialTask, showExecutionDetails = true }: { task: AgentTask; showExecutionDetails?: boolean }) {
  const { locale } = useI18n();
  const [format, setFormat] = useState("pdf");
  const [downloading, setDownloading] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  const userId = useAppStore((state) => state.userId);
  const replaceTask = useAppStore((state) => state.replaceTask);
  const task = useAppStore((state) => state.tasks.find((item) => item.id === initialTask.id)) || initialTask;
  const reportGenerating = reporting || task.report_decision === "generating";
  const scanRunning = ["queued", "running", "cancelling"].includes(task.status);
  const running = scanRunning || reportGenerating;
  const findings = Array.isArray(task.result?.findings)
    ? task.result.findings.length
    : Number(task.result?.finding_count || task.result?.total_findings || 0);
  const dependencies = Array.isArray(task.result?.dependencies) ? task.result.dependencies.length : Number(task.result?.dependency_count || 0);
  const vulnerabilities = Number(task.result?.vulnerability_count || 0);
  const vulnerabilityHits = (Array.isArray(task.result?.vulnerabilities) ? task.result.vulnerabilities : [])
    .filter((item) => item && typeof item === "object")
    .slice(0, 3) as Array<{ id?: string; severity?: string; summary?: string }>;

  useEffect(() => {
    if (!reporting) return;
    let active = true;
    let timer = 0;
    const refresh = async () => {
      try {
        const snapshot = await api.task(task.id, userId);
        if (!active) return;
        replaceTask(snapshot);
        if (snapshot.report_decision === "generating") {
          timer = window.setTimeout(() => void refresh(), 500);
        }
      } catch {
        if (active) timer = window.setTimeout(() => void refresh(), 1000);
      }
    };
    timer = window.setTimeout(() => void refresh(), 250);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [reporting, replaceTask, task.id, userId]);

  const download = async () => {
    setDownloading(true);
    setDownloadError("");
    try {
      // A single backend decision prepares either one requested format or one
      // verified ZIP bundle for all formats. Reusing the same interrupt once
      // per format consumed it after the first request and made Excel/the
      // remaining downloads fail with an expired-interrupt error.
      const result = await api.decideReportDownload(task.id, userId, true, format);
      replaceTask(result.task);
      const artifact = result.artifact || {};
      const path = String(artifact.download_path || "");
      if (!path) throw new Error(`${format === "all" ? "全部格式" : format.toUpperCase()} 报告缺少下载地址。`);
      const response = await api.raw(path);
      const fallbackName = format === "all" ? `${task.workspace_name}-reports.zip` : `${task.workspace_name}.${format}`;
      await saveBinaryArtifact(String(artifact.file_name || fallbackName), await response.blob());
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : String(error));
    } finally {
      setDownloading(false);
    }
  };

  const decideReport = async (generate: boolean) => {
    setDownloadError("");
    setReporting(true);
    const sequence = Math.max(0, ...task.events.map((event) => event.sequence)) + 1;
    replaceTask({
      ...task,
      report_decision: "generating",
      events: [
        ...task.events,
        {
          sequence,
          type: "report.agent.started",
          node: "report_agent",
          status: "running",
          message: "正在将固定扫描事实交给 Report Agent。",
          data: { agent_id: "report_agent" },
          time: new Date().toISOString(),
        },
      ],
    });
    try {
      replaceTask(await api.decideReport(task.id, userId, generate, locale));
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : String(error));
      try {
        replaceTask(await api.task(task.id, userId));
      } catch {
        // Keep the actionable report error when the refresh also fails.
      }
    } finally {
      setReporting(false);
    }
  };

  const cancelScan = async () => {
    if (cancelling || task.status === "cancelling") return;
    setCancelling(true);
    setDownloadError("");
    replaceTask({
      ...task,
      status: "cancelling",
      current_node: "cancel",
      languages: [],
      plan: [],
      result: undefined,
      report_ready: false,
      report_decision: "unavailable",
      report: undefined,
      error: "",
    });
    try {
      replaceTask(await api.taskMutation(task.id, "cancel", userId));
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : String(error));
      try {
        replaceTask(await api.task(task.id, userId));
      } catch {
        // Keep the cancellation error when the status refresh also fails.
      }
    } finally {
      setCancelling(false);
    }
  };

  return (
    <section className={`task-card task-${task.status}`}>
      <header>
        <span className="task-state-icon">{reportGenerating ? <LoaderCircle size={15} className="spin" /> : taskIcon(task.status)}</span>
        <div><strong>{task.workspace_name}</strong><small>{task.objective}</small></div>
        <span className="status-chip">{reportGenerating ? "报告生成中" : statusLabel(task.status)}</span>
      </header>
      <div className="task-metrics">
        <span><small>语言</small><strong>{task.languages.join(" / ") || "识别中"}</strong></span>
        <span><small>已验证风险</small><strong>{findings}</strong></span>
        <span><small>依赖组件</small><strong>{dependencies}</strong></span>
        <span className={vulnerabilities > 0 ? "metric-danger" : ""}><small>漏洞命中</small><strong>{vulnerabilities}</strong></span>
        <span><small>执行轮次</small><strong>{task.run_number || 1}</strong></span>
      </div>
      {vulnerabilityHits.length > 0 ? (
        <div className="vulnerability-hits">
          {vulnerabilityHits.map((hit) => (
            <span key={hit.id} className={`vulnerability-chip severity-${String(hit.severity || "").toLowerCase()}`}>
              <TriangleAlert size={12} />{hit.id}<small>{hit.severity}</small>
            </span>
          ))}
          {vulnerabilities > vulnerabilityHits.length ? <small className="vulnerability-more">等 {vulnerabilities} 个已知漏洞</small> : null}
        </div>
      ) : null}
      {showExecutionDetails ? <AgentTimeline events={task.events} plan={task.plan} running={running} /> : null}
      {task.error ? <p className="task-error"><TriangleAlert size={14} />{task.error}</p> : null}
      {downloadError ? <p className="task-error"><TriangleAlert size={14} />{downloadError}</p> : null}
      <footer>
        {scanRunning ? <button className="secondary" disabled={cancelling || task.status === "cancelling"} onClick={() => void cancelScan()}>{cancelling || task.status === "cancelling" ? <LoaderCircle size={14} className="spin" /> : <Square size={14} />}{cancelling || task.status === "cancelling" ? "停止中" : "停止分析"}</button> : null}
        {["failed", "cancelled"].includes(task.status) ? <button className="secondary" onClick={() => void api.taskMutation(task.id, "resume", userId).then(replaceTask)}><RotateCcw size={14} />重新扫描</button> : null}
        {task.report_ready && task.report_decision === "pending" ? (
          <>
            <button className="secondary" disabled={reporting} onClick={() => void decideReport(false)}>暂不生成</button>
            <button className="primary" disabled={reporting} onClick={() => void decideReport(true)}><FileText size={14} />确认生成报告</button>
          </>
        ) : null}
        {task.report_decision === "generating" ? <button className="primary" disabled><LoaderCircle size={14} className="spin" />Report Agent 生成中</button> : null}
        {task.report ? (
          <div className="download-control">
            <select value={format} onChange={(event) => setFormat(event.target.value)} aria-label="报告格式">
              <option value="pdf">PDF</option><option value="html">HTML</option><option value="docx">Word</option><option value="xlsx">Excel</option><option value="md">Markdown</option><option value="all">全部格式</option>
            </select>
            <button className="primary" disabled={downloading} onClick={() => void download()}>{downloading ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}确认下载</button>
          </div>
        ) : null}
      </footer>
    </section>
  );
}

function taskIcon(status: string) {
  if (status === "completed") return <Check size={15} />;
  if (["failed", "interrupted"].includes(status)) return <TriangleAlert size={15} />;
  return <LoaderCircle size={15} className={["running", "cancelling"].includes(status) ? "spin" : ""} />;
}

const statusLabel = (status: string) => ({ queued: "排队中", running: "扫描中", completed: "已完成", failed: "失败", interrupted: "等待确认", cancelled: "已停止", cancelling: "停止中" }[status] || status);
