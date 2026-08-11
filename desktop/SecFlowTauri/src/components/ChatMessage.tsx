import { Check, Copy, Download, ExternalLink, FileText, FolderOpen, LoaderCircle, RefreshCcw, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { useI18n } from "../i18n";
import { api } from "../lib/api";
import { saveBinaryArtifact } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import type { AssistantArtifact, AssistantInterrupt, ChatTurn, EvidenceSource, TraceItem } from "../types";
import { AgentTimeline } from "./AgentTimeline";
import { MermaidBlock } from "./MermaidBlock";
import { ProfileAvatar } from "./ProfileAvatar";
import { TaskCard } from "./TaskCard";
import { ToolCall } from "./ToolCall";

export function ChatMessage({
  turn,
  onRegenerate,
  compact = false,
  autoExpandThinking,
  showExecutionDetails = true,
}: {
  turn: ChatTurn;
  onRegenerate?: () => void;
  compact?: boolean;
  autoExpandThinking?: boolean;
  showExecutionDetails?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const sources = turn.result?.evidence_sources || turn.result?.sources || [];
  const toolCalls = useMemo(() => (turn.trace || []).filter(isToolTrace), [turn.trace]);
  const running = turn.state === "streaming";
  const interrupt = turn.result?.interrupt;
  const artifacts = (turn.result?.artifacts || []).filter((item) => item.download_path);
  const profile = useAppStore((state) => state.settings?.profile);
  const userId = useAppStore((state) => state.userId);

  if (turn.role === "user") {
    return (
      <article className={`chat-turn user-turn ${compact ? "compact-chat" : ""}`}>
        <div className="user-turn-body">
          {turn.workspace ? (
            <div className="user-turn-chips">
              <span className="user-attachment-chip" title={turn.workspace.path}>
                <FolderOpen size={12} />
                <strong>{turn.workspace.name}</strong>
                <small>{turn.workspace.path}</small>
              </span>
            </div>
          ) : null}
          <div className="user-bubble">{turn.content}</div>
        </div>
        <ProfileAvatar profile={profile} userId={userId} className="chat-user-avatar" />
      </article>
    );
  }

  return (
    <article className={`chat-turn assistant-turn ${turn.state || "completed"} ${compact ? "compact-chat" : ""}`}>
      <div className="assistant-gutter"><span><ShieldCheck size={16} /></span></div>
      <div className="assistant-content">
        {!running && turn.result ? <AssistantMeta turn={turn} toolCalls={toolCalls} /> : null}
        {showExecutionDetails ? <AgentTimeline trace={turn.trace} running={running} autoExpand={autoExpandThinking ?? false} /> : null}
        {turn.task ? <TaskCard task={turn.task} showExecutionDetails={showExecutionDetails} /> : null}
        {running && !turn.content ? <ResponseSkeleton /> : null}
        {turn.content ? (
          <div className={`markdown-body ${running ? "stream-active" : ""}`}>
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                a: ({ children, href }) => <a href={href} target="_blank" rel="noreferrer">{children}<ExternalLink size={11} /></a>,
                code: ({ className, children }) => {
                  const language = /language-(\w+)/.exec(className || "")?.[1];
                  const value = String(children).replace(/\n$/, "");
                  if (language === "mermaid") return <MermaidBlock code={value} />;
                  return className ? <CodeBlock language={language || "code"} code={value} /> : <code>{children}</code>;
                },
              }}
            >
              {turn.content}
            </ReactMarkdown>
            {running ? <span className="stream-caret" /> : null}
          </div>
        ) : null}
        {showExecutionDetails && toolCalls.length ? <ToolCalls items={toolCalls} /> : null}
        {!running && interrupt ? <ReportActionCard turn={turn} interrupt={interrupt} /> : null}
        {artifacts.length ? <ArtifactDownloads items={artifacts} /> : null}
        {sources.length ? <Sources sources={sources} /> : null}
        {!compact && !running && turn.state !== "error" ? (
          <div className="message-actions">
            <button title="复制" onClick={() => void navigator.clipboard.writeText(turn.content).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1200); })}>{copied ? <Check /> : <Copy />}</button>
            <button title="重新生成" onClick={onRegenerate}><RefreshCcw /></button>
          </div>
        ) : null}
        {turn.state === "error" ? <div className="message-error"><span>处理请求时发生错误。</span><button onClick={onRegenerate}><RefreshCcw size={13} />重试</button></div> : null}
      </div>
    </article>
  );
}

function AssistantMeta({ turn, toolCalls }: { turn: ChatTurn; toolCalls: TraceItem[] }) {
  const result = turn.result;
  if (!result) return null;
  const mcpCount = toolCalls.filter((item) => item.node.includes("mcp") || item.tool_name?.toLowerCase().includes("mcp")).length;
  const elapsedMs = Number(result.elapsed_ms || (turn.trace || []).reduce((total, item) => total + Number(item.duration_ms || 0), 0));
  const tokenCount = Number(result.usage?.total_tokens || result.token_usage || 0);
  const model = [result.provider, result.model].filter(Boolean).join(" / ") || (isAgenticTurn(turn) ? "Security Agent" : "Direct Model");
  return (
    <div className="assistant-meta" aria-label="回答运行信息">
      <strong>{elapsedMs ? `已工作 ${formatElapsed(elapsedMs)}` : "已完成"}</strong>
      <span>{model}</span>
      <span>{toolCalls.length} Tools</span>
      {mcpCount ? <span>{mcpCount} MCP</span> : null}
      {tokenCount ? <span>{tokenCount.toLocaleString("zh-CN")} Tokens</span> : null}
    </div>
  );
}

function CodeBlock({ language, code }: { language: string; code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="code-block-wrap">
      <header><span>{language}</span><button onClick={() => void navigator.clipboard.writeText(code).then(() => setCopied(true))}>{copied ? <Check /> : <Copy />}</button></header>
      <pre className="code-block"><code>{code}</code></pre>
    </div>
  );
}

function ToolCalls({ items }: { items: TraceItem[] }) {
  return <section className="tool-calls"><h4>工具调用 <span>{items.length}</span></h4>{items.map((item, index) => <ToolCall key={`${item.node}:${index}`} item={item} />)}</section>;
}

function Sources({ sources }: { sources: EvidenceSource[] }) {
  return (
    <details className="sources-panel">
      <summary>参考来源 <span>{sources.length}</span></summary>
      <ol>{sources.map((source, index) => <li key={source.id || `${source.title}:${index}`}><a href={source.url} target="_blank" rel="noreferrer"><span>{index + 1}</span><strong>{source.title}</strong><small>{source.source || safeHost(source.url)}</small></a></li>)}</ol>
    </details>
  );
}

function ResponseSkeleton() {
  return <div className="response-skeleton" aria-label="正在生成"><span /><span /><span /><span /></div>;
}

/** Action card for report-generation / report-download interrupts on chat turns. */
function ReportActionCard({ turn, interrupt }: { turn: ChatTurn; interrupt: AssistantInterrupt }) {
  const { t, locale } = useI18n();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const threadId = String(interrupt.thread_id || "");
  const question = interrupt.question || interrupt.message || "";
  const detail = interrupt.detail || "";
  const formats = (interrupt.formats || []).filter(Boolean);
  const isDownload = interrupt.kind === "report_download_confirmation" || formats.length > 0;
  if (!threadId) return null;

  const decide = async (decision: "confirm" | "cancel", format?: string) => {
    setBusy(true);
    setError("");
    try {
      const state = useAppStore.getState();
      const payload = {
        thread_id: threadId,
        interrupt_id: interrupt.interrupt_id,
        decision,
        ...(format ? { format } : {}),
        // Authorize with the session/user that owns this interrupt card.
        // Falling back to the currently-active session caused 404s when the
        // user clicked a card while another conversation was selected.
        user_id: String(interrupt.user_id || state.userId),
        session_id: String(interrupt.session_id || state.activeSessionId || "default"),
        response_language: locale,
      };
      // The unified assistant endpoint routes report-*, sbom-*, and
      // component-catalog-* threads to their owning graph; the report-only
      // endpoint would 409 for non-report interrupts.
      const outcome = threadId.startsWith("report-")
        ? await api.resumeReportAction(payload)
        : await api.resumeAssistantInterrupt(payload);
      const answer = (outcome.answer || outcome) as ChatTurn["result"];
      useAppStore.getState().updateTurn(turn.id, {
        content: String(answer?.summary || answer?.answer || turn.content),
        result: { ...(turn.result || {}), ...(answer || {}) } as ChatTurn["result"],
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const confirmLabel = {
    sbom_vulnerability_match_confirmation: t("确认匹配漏洞"),
    sbom_excel_generation_confirmation: t("确认生成 Excel"),
    sbom_excel_download_confirmation: t("确认下载"),
    component_excel_generation_confirmation: t("确认生成 Excel"),
    component_excel_download_confirmation: t("确认下载"),
  }[String(interrupt.kind || "")] || t("确认生成报告");

  return (
    <div className="report-action-card">
      {question ? <strong>{question}</strong> : null}
      {detail ? <p>{detail}</p> : null}
      <div className="report-action-buttons">
        {isDownload && formats.length > 1 ? (
          <button className="primary" disabled={busy} onClick={() => void decide("confirm", "all")}>
            {busy ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}
            {t("全部格式 ZIP")}
          </button>
        ) : null}
        {isDownload
          ? formats.map((format) => (
              <button key={format} className="primary" disabled={busy} onClick={() => void decide("confirm", format)}>
                {busy ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}
                {format.toUpperCase()}
              </button>
            ))
          : (
              <button className="primary" disabled={busy} onClick={() => void decide("confirm")}>
                {busy ? <LoaderCircle size={14} className="spin" /> : <FileText size={14} />}
                {confirmLabel}
              </button>
            )}
        <button className="secondary" disabled={busy} onClick={() => void decide("cancel")}>{t("取消")}</button>
      </div>
      {error ? <div className="message-error"><span>{error}</span></div> : null}
    </div>
  );
}

/** Download actions for generated report artifacts on chat turns. */
function ArtifactDownloads({ items }: { items: AssistantArtifact[] }) {
  const [pending, setPending] = useState("");
  const [error, setError] = useState("");

  // Route through the native save panel (Tauri) so the user can choose the
  // destination directory and rename the file; a bare <a download> inside the
  // webview silently drops the file into the default download location.
  const download = async (item: AssistantArtifact) => {
    const path = String(item.download_path || "");
    const fileName = String(item.file_name || "report");
    if (!path) return;
    setPending(path);
    setError("");
    try {
      const response = await api.raw(path);
      await saveBinaryArtifact(fileName, await response.blob());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setPending("");
    }
  };

  return (
    <div className="report-artifacts">
      {items.map((item) => (
        <button key={item.id || item.download_path} disabled={Boolean(pending)} onClick={() => void download(item)}>
          {pending === String(item.download_path) ? <LoaderCircle size={13} className="spin" /> : <Download size={13} />}
          <span>{item.file_name}</span>
        </button>
      ))}
      {error ? <div className="message-error"><span>{error}</span></div> : null}
    </div>
  );
}

const isToolTrace = (item: TraceItem) => Boolean(
  item.tool_name
  || item.input
  || item.output
  || item.node.includes("mcp")
  || item.node.includes("tool")
  || item.presentation?.kind === "tool_call",
);
const isAgenticTurn = (turn: ChatTurn) => {
  if (turn.task) return true;
  const orchestration = turn.result?.orchestration;
  if (orchestration && typeof orchestration === "object" && "agentic" in orchestration) {
    return orchestration.agentic === true;
  }
  return (turn.trace || []).some((item) => item.node.endsWith("_agent") || item.node === "supervisor_agent");
};
const safeHost = (url?: string) => { try { return url ? new URL(url).hostname : ""; } catch { return ""; } };
const formatElapsed = (value: number) => value < 1000 ? `${Math.round(value)}ms` : `${(value / 1000).toFixed(1)}s`;
