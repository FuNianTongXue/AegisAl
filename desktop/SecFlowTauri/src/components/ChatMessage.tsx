import { Check, Copy, Download, ExternalLink, FileText, FolderOpen, LoaderCircle, RefreshCcw } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { clientLocaleTag, useI18n } from "../i18n";
import { brandDisplayText, brandMarkdownDisplayText, remarkBrandDisplayText } from "../branding";
import { api } from "../lib/api";
import { saveBinaryArtifact } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import type { AskResult, AssistantInterrupt, ChatTurn, EvidenceSource, TraceItem } from "../types";
import { AgentTimeline } from "./AgentTimeline";
import { AssistantResultData } from "./AssistantResultData";
import { BrandMark } from "./BrandMark";
import { MermaidBlock } from "./MermaidBlock";
import { ProfileAvatar } from "./ProfileAvatar";
import { MarkdownDataCell, MarkdownDataHeaderCell, MarkdownDataTable } from "./StructuredDataTable";
import { TaskCard } from "./TaskCard";
import { BeautifulApprovalCard } from "./beautiful-ui/BeautifulUI";
import { DownloadRecommendationCard } from "./beautiful-ui/DownloadRecommendationCard";

export function ChatMessage({
  turn,
  onRegenerate,
  compact = false,
  autoExpandThinking,
  showExecutionDetails = true,
  onResultChange,
}: {
  turn: ChatTurn;
  onRegenerate?: () => void;
  compact?: boolean;
  autoExpandThinking?: boolean;
  showExecutionDetails?: boolean;
  onResultChange?: (result: AskResult) => void | Promise<void>;
}) {
  const { t, locale } = useI18n();
  const [copied, setCopied] = useState(false);
  const sources = turn.result?.evidence_sources || turn.result?.sources || [];
  const toolCalls = useMemo(() => (turn.trace || []).filter(isToolTrace), [turn.trace]);
  const running = turn.state === "streaming";
  const interrupt = turn.result?.interrupt;
  const artifacts = (turn.result?.artifacts || []).filter((item) => item.download_path);
  const awaitingDownloadConfirmation = isDownloadInterrupt(interrupt);
  const legacyExcelDownloadInterrupt = isExcelDownloadInterrupt(interrupt);
  const legacyExcelDownloadKey = legacyExcelDownloadInterrupt
    ? `${String(interrupt?.thread_id || "")}:${String(interrupt?.interrupt_id || "")}`
    : "";
  const legacyExcelDownloadRef = useRef<{
    key: string;
    result: ChatTurn["result"] | null;
    applied: boolean;
  }>({ key: legacyExcelDownloadKey, result: null, applied: false });
  if (legacyExcelDownloadRef.current.key !== legacyExcelDownloadKey) {
    legacyExcelDownloadRef.current = { key: legacyExcelDownloadKey, result: null, applied: false };
  }
  const canBridgeLegacyExcelDownload = legacyExcelDownloadInterrupt && artifacts.length > 0;
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
                <strong dir="auto">{turn.workspace.name}</strong>
                <small dir="auto">{turn.workspace.path}</small>
              </span>
            </div>
          ) : null}
          <div className="user-bubble" dir="auto">{turn.content}</div>
        </div>
        <ProfileAvatar profile={profile} userId={userId} className="chat-user-avatar" />
      </article>
    );
  }

  return (
    <article className={`chat-turn assistant-turn ${turn.state || "completed"} ${compact ? "compact-chat" : ""}`}>
      <div className="assistant-gutter"><BrandMark size={compact ? 23 : 32} /></div>
      <div className="assistant-content">
        {!running && turn.result ? <AssistantMeta turn={turn} toolCalls={toolCalls} /> : null}
        {showExecutionDetails && !turn.task ? <AgentTimeline trace={turn.trace} running={running} autoExpand={autoExpandThinking ?? false} /> : null}
        {turn.task ? <TaskCard task={turn.task} showExecutionDetails={showExecutionDetails} /> : null}
        {turn.content || (!running && turn.result) ? (
          <div className={`markdown-body ${running ? "stream-active" : ""}`}>
            {turn.content ? (
              <ReactMarkdown
                remarkPlugins={[remarkGfm, remarkBrandDisplayText]}
                components={{
                  a: ({ children, href }) => <a href={href} target="_blank" rel="noreferrer">{children}<ExternalLink size={11} /></a>,
                  table: ({ children }) => <MarkdownDataTable label={t("数据表格，可横向滚动")}>{children}</MarkdownDataTable>,
                  th: ({ node: _node, children, ...props }) => <MarkdownDataHeaderCell {...props}>{children}</MarkdownDataHeaderCell>,
                  td: ({ node: _node, children, ...props }) => <MarkdownDataCell {...props}>{children}</MarkdownDataCell>,
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
            ) : null}
            {!running ? (
              <AssistantResultData
                result={turn.result}
                content={turn.content}
                onResultChange={onResultChange}
              />
            ) : null}
            {running ? <span className="stream-caret" /> : null}
          </div>
        ) : null}
        {!running && interrupt && (!legacyExcelDownloadInterrupt || !canBridgeLegacyExcelDownload)
          ? <ReportActionCard turn={turn} interrupt={interrupt} />
          : null}
        {artifacts.length && (!awaitingDownloadConfirmation || canBridgeLegacyExcelDownload) ? (
          <DownloadRecommendationCard
            items={artifacts}
            onDownload={canBridgeLegacyExcelDownload
              ? async (artifact) => {
                  let answer = legacyExcelDownloadRef.current.result;
                  let downloadArtifact = artifact;
                  if (!answer) {
                    const session = useAppStore.getState();
                    answer = await resumeAction(
                      {
                        thread_id: String(interrupt?.thread_id || ""),
                        interrupt_id: String(interrupt?.interrupt_id || ""),
                        decision: "confirm",
                        user_id: String(interrupt?.user_id || session.userId),
                        session_id: String(interrupt?.session_id || session.activeSessionId || "default"),
                        response_language: locale,
                      },
                      String(interrupt?.thread_id || ""),
                    );
                    downloadArtifact = (answer?.artifacts || []).find((item) => item.download_path) || artifact;
                    legacyExcelDownloadRef.current.result = answer;
                  }
                  const path = String(downloadArtifact.download_path || "");
                  if (!path) throw new Error(t("下载制品尚未准备好，请重试。"));
                  const response = await api.raw(path);
                  const saved = await saveBinaryArtifact(
                    brandDisplayText(downloadArtifact.file_name || artifact.file_name) || "Excel",
                    await response.blob(),
                  );
                  if (saved === false) return false;
                  if (answer && !legacyExcelDownloadRef.current.applied) {
                    legacyExcelDownloadRef.current.applied = true;
                    applyActionResult(turn, answer);
                  }
                  return true;
                }
              : undefined}
          />
        ) : null}
        {sources.length ? <Sources sources={sources} /> : null}
        {!compact && !running && turn.state !== "error" ? (
          <div className="message-actions">
            <button type="button" title={t("复制")} aria-label={t("复制")} onClick={() => void navigator.clipboard.writeText(brandMarkdownDisplayText(turn.content)).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1200); })}>{copied ? <Check /> : <Copy />}</button>
            {onRegenerate ? <button type="button" title={t("重新生成")} aria-label={t("重新生成")} onClick={onRegenerate}><RefreshCcw /></button> : null}
          </div>
        ) : null}
        {turn.state === "error" ? <div className="message-error" role="alert"><span>{t("处理请求时发生错误。")}</span>{onRegenerate ? <button type="button" onClick={onRegenerate}><RefreshCcw size={13} />{t("重试")}</button> : null}</div> : null}
      </div>
    </article>
  );
}

function AssistantMeta({ turn, toolCalls }: { turn: ChatTurn; toolCalls: TraceItem[] }) {
  const { locale } = useI18n();
  const result = turn.result;
  if (!result) return null;
  const mcpCount = toolCalls.filter((item) => item.node.includes("mcp") || item.tool_name?.toLowerCase().includes("mcp")).length;
  const elapsedMs = Number(result.elapsed_ms || (turn.trace || []).reduce((total, item) => total + Number(item.duration_ms || 0), 0));
  const tokenCount = Number(result.usage?.total_tokens || result.token_usage || 0);
  const model = [result.provider, result.model].filter(Boolean).join(" / ") || (isAgenticTurn(turn) ? "Security Agent" : "Direct Model");
  return (
    <div className="assistant-meta" aria-label="回答运行信息">
      <strong>{elapsedMs ? `已工作 ${formatElapsed(elapsedMs)}` : "已完成"}</strong>
      <span translate="no">{model}</span>
      <span>{toolCalls.length} Tools</span>
      {mcpCount ? <span>{mcpCount} MCP</span> : null}
      {tokenCount ? <span>{new Intl.NumberFormat(clientLocaleTag(locale)).format(tokenCount)} Tokens</span> : null}
    </div>
  );
}

function CodeBlock({ language, code }: { language: string; code: string }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  return (
    <div className="code-block-wrap">
      <header><span translate="no">{language}</span><button type="button" title={t("复制代码")} aria-label={t("复制代码")} onClick={() => void navigator.clipboard.writeText(code).then(() => setCopied(true))}>{copied ? <Check /> : <Copy />}</button></header>
      <pre className="code-block"><code>{code}</code></pre>
    </div>
  );
}

function Sources({ sources }: { sources: EvidenceSource[] }) {
  return (
    <details className="sources-panel">
      <summary>参考来源 <span>{sources.length}</span></summary>
      <ol>{sources.map((source, index) => <li key={source.id || `${source.title}:${index}`}><a href={source.url} target="_blank" rel="noreferrer"><span>{index + 1}</span><strong>{brandDisplayText(source.title)}</strong><small>{brandDisplayText(source.source) || safeHost(source.url)}</small></a></li>)}</ol>
    </details>
  );
}

/** Action card for report-generation / report-download interrupts on chat turns. */
function ReportActionCard({ turn, interrupt }: { turn: ChatTurn; interrupt: AssistantInterrupt }) {
  const { t, locale } = useI18n();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const titleId = useId();
  const detailId = useId();
  const firstAction = useRef<HTMLButtonElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  const threadId = String(interrupt.thread_id || "");
  const question = brandDisplayText(interrupt.question || interrupt.message || "");
  const detail = brandDisplayText(interrupt.detail || "");
  const formats = (interrupt.formats || []).filter(Boolean);
  const isDownload = isDownloadInterrupt(interrupt);
  const [resolvedDownload, setResolvedDownload] = useState<ChatTurn["result"] | null>(null);

  useEffect(() => {
    if (!threadId) return;
    previouslyFocused.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    return () => {
      if (previouslyFocused.current?.isConnected) previouslyFocused.current.focus();
    };
  }, [threadId]);

  useEffect(() => {
    if (threadId) firstAction.current?.focus();
  }, [interrupt.interrupt_id, threadId]);

  if (!threadId) return null;

  const decide = async (decision: "confirm" | "cancel", format?: string) => {
    setBusy(true);
    setError("");
    try {
      if (decision === "cancel" && resolvedDownload) {
        applyActionResult(turn, resolvedDownload);
        return;
      }
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
      const answer = resolvedDownload || await resumeAction(payload, threadId);
      if (decision === "confirm" && isDownload) {
        const artifact = (answer?.artifacts || []).find((item) => item.download_path);
        if (!artifact) throw new Error(t("下载制品尚未准备好，请重试。"));
        if (!resolvedDownload) setResolvedDownload(answer);
        const response = await api.raw(String(artifact.download_path));
        const saved = await saveBinaryArtifact(brandDisplayText(artifact.file_name) || "report", await response.blob());
        if (saved === false) return;
      }
      applyActionResult(turn, answer);
      setResolvedDownload(null);
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
    <BeautifulApprovalCard
      className="report-action-card"
      busy={busy}
      labelledBy={question ? titleId : undefined}
      label={question ? undefined : confirmLabel}
      describedBy={detail ? detailId : undefined}
    >
      {question ? <strong id={titleId}>{question}</strong> : null}
      {detail ? <p id={detailId}>{detail}</p> : null}
      <div className="report-action-buttons">
        {isDownload && formats.length > 1 ? (
          <button ref={firstAction} type="button" className="primary" disabled={busy} onClick={() => void decide("confirm", "all")}>
            {busy ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}
            {t("全部格式 ZIP")}
          </button>
        ) : null}
        {isDownload && formats.length
          ? formats.map((format, index) => (
              <button ref={formats.length === 1 && index === 0 ? firstAction : undefined} key={format} type="button" className="primary" disabled={busy} onClick={() => void decide("confirm", format)}>
                {busy ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}
                {format.toUpperCase()}
              </button>
            ))
          : (
              <button ref={firstAction} type="button" className="primary" disabled={busy} onClick={() => void decide("confirm")}>
                {busy ? <LoaderCircle size={14} className="spin" /> : isDownload ? <Download size={14} /> : <FileText size={14} />}
                {confirmLabel}
              </button>
            )}
        <button type="button" className="secondary" disabled={busy} onClick={() => void decide("cancel")}>{t("取消")}</button>
      </div>
      {error ? <div className="message-error" role="alert"><span>{brandDisplayText(error)}</span></div> : null}
    </BeautifulApprovalCard>
  );
}

const DOWNLOAD_INTERRUPT_KINDS = new Set([
  "report_download_confirmation",
]);
const EXCEL_DOWNLOAD_INTERRUPT_KINDS = new Set([
  "component_excel_download_confirmation",
  "sbom_excel_download_confirmation",
]);

function isDownloadInterrupt(interrupt?: AssistantInterrupt) {
  return Boolean(interrupt && DOWNLOAD_INTERRUPT_KINDS.has(String(interrupt.kind || "")));
}

function isExcelDownloadInterrupt(interrupt?: AssistantInterrupt) {
  return Boolean(interrupt && EXCEL_DOWNLOAD_INTERRUPT_KINDS.has(String(interrupt.kind || "")));
}

async function resumeAction(
  payload: Parameters<typeof api.resumeAssistantInterrupt>[0],
  threadId: string,
) {
  const outcome = threadId.startsWith("report-")
    ? await api.resumeReportAction(payload)
    : await api.resumeAssistantInterrupt(payload);
  return (outcome.answer || outcome) as ChatTurn["result"];
}

function applyActionResult(turn: ChatTurn, answer: ChatTurn["result"]) {
  useAppStore.getState().updateTurn(turn.id, {
    content: String(answer?.summary || answer?.answer || turn.content),
    result: { ...(turn.result || {}), ...(answer || {}) } as ChatTurn["result"],
  });
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
