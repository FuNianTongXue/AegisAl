import { Bot, Bug, FileCheck2, FolderSearch2, PackageSearch, Shield, Sparkles, X } from "lucide-react";
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";

import { useActiveTaskStream, waitForBackendReady } from "../hooks/useBackend";
import { useI18n } from "../i18n";
import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { AgentTask, AskResult, ChatTurn, TraceItem, WorkspaceActionResult } from "../types";
import { ChatMessage } from "./ChatMessage";
import { InformationCenterMark } from "./InformationCenterMark";
import { KineticGrid } from "./KineticGrid";
import { PromptComposer } from "./PromptComposer";

/** Slash commands that unambiguously specify a scan type or are non-scan actions. */
const EXPLICIT_COMMANDS = ["/cve", "/report", "/scan", "/sbom", "/code-review"];
/** Verbs that explicitly ask to scan/audit the selected workspace. */
const SCAN_VERB = /(扫描|检查|排查|检测|审查|审计|分析|评估|渗透|看看|scan|audit|inspect|check|review|analy[sz]e|assess|pentest)/i;
/** "项目/代码" combined with "漏洞/风险" also implies a project scan request. */
const PROJECT_RISK =
  /((项目|代码|工程|仓库|repo(sitory)?)[^。！？\n]{0,20}(漏洞|风险|安全问题|隐患)|(漏洞|风险|安全问题|隐患)[^。！？\n]{0,20}(项目|代码|工程|仓库|repo(sitory)?))/i;
/** Report generation/download wording. */
const REPORT_WORD = /(报告|report)/i;
/** References to an already-completed scan whose facts a report request builds on. */
const COMPLETED_SCAN_REF = /(刚才|上次|上一次|已完成|本次|结果)/;
const TURN_BATCH_SIZE = 60;

export function AssistantWorkspace({ visible = true }: { visible?: boolean }) {
  const state = useAppStore();
  const { locale, t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [pendingQuestion, setPendingQuestion] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);
  const scroll = useRef<HTMLDivElement>(null);
  const conversation = useRef<HTMLDivElement>(null);
  const conversationLog = useRef<HTMLDivElement>(null);
  const nearBottom = useRef(true);
  const prependAnchor = useRef<{ element: Element; top: number } | null>(null);
  const [visibleTurnCount, setVisibleTurnCount] = useState(TURN_BATCH_SIZE);
  const firstVisibleTurnIndex = Math.max(0, state.turns.length - visibleTurnCount);
  const visibleTurns = state.turns.slice(firstVisibleTurnIndex);
  const latestAssistant = [...state.turns].reverse().find((turn) => turn.role === "assistant");
  const assistantStatus = latestAssistant?.state === "streaming"
    ? t("正在生成回答…")
    : latestAssistant?.state === "error"
      ? t("回答生成失败，可以重试。")
      : latestAssistant?.result?.interrupt
        ? t("需要确认后继续。")
        : latestAssistant
          ? t("回答已生成。")
          : "";

  useEffect(() => {
    setVisibleTurnCount(TURN_BATCH_SIZE);
    prependAnchor.current = null;
    nearBottom.current = true;
    conversationLog.current?.setAttribute("aria-live", "polite");
  }, [state.activeSessionId, state.activeTaskId]);

  useEffect(() => {
    if (state.turns.length) return;
    setVisibleTurnCount(TURN_BATCH_SIZE);
    prependAnchor.current = null;
    nearBottom.current = true;
    conversationLog.current?.setAttribute("aria-live", "polite");
  }, [state.turns.length]);

  useLayoutEffect(() => {
    const anchor = prependAnchor.current;
    const target = scroll.current;
    if (anchor && target && anchor.element.isConnected) {
      target.scrollTop += anchor.element.getBoundingClientRect().top - anchor.top;
    }
    prependAnchor.current = null;
    const log = conversationLog.current;
    if (!log || log.getAttribute("aria-live") !== "off") return;
    const frame = window.requestAnimationFrame(() => {
      if (log.isConnected) log.setAttribute("aria-live", "polite");
    });
    return () => window.cancelAnimationFrame(frame);
  }, [visibleTurnCount]);

  useActiveTaskStream(useCallback((task: AgentTask) => {
    // Match by turn id (legacy `task:<id>`) or by the attached task so live
    // progress still reaches turns created from the submitted-placeholder flow.
    const target = state.turns.find((turn) => turn.id === `task:${task.id}` || turn.task?.id === task.id);
    if (target) state.updateTurn(target.id, { task, state: task.status === "failed" ? "error" : "completed" });
  }, [state]));

  useEffect(() => {
    if (!nearBottom.current) return;
    const frame = window.requestAnimationFrame(() => {
      scrollToBottom(scroll.current);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [state.turns]);

  useEffect(() => {
    const target = conversation.current;
    if (!target || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      if (nearBottom.current) scrollToBottom(scroll.current);
    });
    observer.observe(target);
    return () => observer.disconnect();
  }, []);

  const needsScanTypeConfirm = useCallback((input: string, workspace: string): boolean => {
    if (!workspace) return false;
    const trimmed = input.trim();
    if (EXPLICIT_COMMANDS.some((cmd) => trimmed.toLowerCase().startsWith(cmd))) return false;
    const asksReport = REPORT_WORD.test(trimmed);
    const asksScan = SCAN_VERB.test(trimmed);
    // Report requests go straight to the report capability: "生成报告" never scans,
    // and "把刚才的扫描结果生成报告" builds on completed scan facts rather than
    // starting a new scan. Turning them into scan-type prompts breaks reporting.
    if (asksReport && (!asksScan || COMPLETED_SCAN_REF.test(trimmed))) return false;
    // Only genuine scan/analysis requests need the scan-type confirmation;
    // QA, follow-ups and other objectives route directly to the assistant planner.
    return asksScan || PROJECT_RISK.test(trimmed);
  }, []);

  const executeSend = useCallback(async (
    question: string,
    displayContent?: string,
    attachment?: { path: string; name: string } | null,
    intentHint?: "component_vulnerability_catalog",
  ) => {
    const createdAt = new Date().toISOString();
    const userTurn: ChatTurn = {
      id: crypto.randomUUID(),
      role: "user",
      content: displayContent || question,
      createdAt,
      ...(attachment ? { workspace: { name: attachment.name, path: attachment.path } } : {}),
    };
    state.appendTurn(userTurn);
    state.set({ view: "assistant", inspectorOpen: true });
    setBusy(true);
    controller.current = new AbortController();

    // The window becomes interactive before the packaged Python sidecar is
    // fully listening. If the user submits during that short cold-start gap,
    // share the bootstrap readiness probe instead of failing the first request
    // with a misleading "service unavailable" message.
    if (!useAppStore.getState().health?.ok) {
      try {
        const health = await waitForBackendReady();
        useAppStore.getState().set({ health });
      } catch (error) {
        state.appendTurn({
          id: crypto.randomUUID(),
          role: "assistant",
          content: userFacingAssistantError(error),
          createdAt: new Date().toISOString(),
          state: "error",
          trace: [],
        });
        controller.current = null;
        setBusy(false);
        return;
      }
    }

    // 附件优先于会话项目：本条消息显式附带的项目即本次提交的目标项目。
    const effectiveWorkspace = attachment?.path || state.workspacePath;
    if (attachment) {
      // 提交后项目上下文并入会话（顶栏与后续路由），输入区附件随即消耗。
      state.set({ workspacePath: attachment.path, workspaceName: attachment.name });
    }
    const activeTask = state.tasks.find((task) => task.id === state.activeTaskId);
    const activeTaskMatchesWorkspace = Boolean(
      activeTask && (!effectiveWorkspace || activeTask.workspace_path === effectiveWorkspace),
    );
    const viaTask = Boolean(state.activeTaskId && activeTaskMatchesWorkspace);
    const viaWorkspace = !viaTask && Boolean(effectiveWorkspace);
    // Task/workspace actions are non-streaming calls that can take seconds while the
    // backend plans intent and creates the scan task. Append an immediate thinking
    // placeholder so the user sees the objective was submitted and has entered the
    // analysis pipeline; it is updated in place once the result arrives.
    const pendingId = crypto.randomUUID();
    if (viaTask || viaWorkspace) {
      state.appendTurn({
        id: pendingId,
        role: "assistant",
        // Execution progress is rendered in the inspector; the conversation
        // keeps only the response placeholder until the final answer arrives.
        content: "",
        createdAt,
        state: "streaming",
        trace: [submitTraceItem("running", createdAt, t("已提交项目目标，正在进入分析流程…"))],
      });
    }
    try {
      if (viaTask) {
        const result = await api.taskAction(state.activeTaskId as string, question, state.userId, state.activeSessionId || "default", locale);
        handleWorkspaceResult(result, pendingId);
      } else if (viaWorkspace) {
        const result = await api.workspaceAction(question, effectiveWorkspace as string, state.userId, state.activeSessionId || "default", locale);
        handleWorkspaceResult(result, pendingId);
      } else {
        await streamQuestion(question, intentHint);
      }
    } catch (error) {
      if (!controller.current?.signal.aborted) {
        if (viaTask || viaWorkspace) {
          state.updateTurn(pendingId, { content: String(error), state: "error" });
        } else {
          // Streaming questions update their existing assistant turn in
          // streamQuestion.  Keeping error handling there prevents a blank
          // "正在生成" turn plus a second, duplicate error bubble.
      }
      }
    } finally {
      controller.current = null;
      setBusy(false);
    }
  }, [state, locale, t]);

  const confirmScanType = useCallback((type: "code" | "sbom" | "full") => {
    if (!pendingQuestion) return;
    const prefixes: Record<string, string> = {
      code: "请仅执行代码安全扫描（不包含SBOM）：",
      sbom: "请仅执行SBOM扫描和许可证识别（不包含代码漏洞扫描）：",
      full: "请执行完整安全扫描（代码安全扫描 + SBOM生成 + 许可证识别）：",
    };
    const enriched = `${prefixes[type]}${pendingQuestion}`;
    setPendingQuestion(null);
    // 确认扫描类型即真正提交：读取仍保留在输入区的附件并随消息一并消耗。
    const attachment = useAppStore.getState().composerAttachment;
    if (attachment) useAppStore.getState().set({ composerAttachmentLeaving: true });
    // Send the enriched instruction but keep the user's original wording visible.
    void executeSend(enriched, pendingQuestion, attachment);
  }, [pendingQuestion, executeSend]);

  const cancelScanTypeConfirm = useCallback(() => {
    setPendingQuestion(null);
  }, []);

  const send = useCallback((
    question: string,
    attachment: { path: string; name: string } | null,
    intentHint?: "component_vulnerability_catalog",
  ): boolean => {
    const effectiveWorkspace = attachment?.path || state.workspacePath;
    if (needsScanTypeConfirm(question, effectiveWorkspace)) {
      // 扫描类型确认期间保留附件 chip，待确认后随确认动作一并提交。
      setPendingQuestion(question);
      return false;
    }
    if (attachment) state.set({ composerAttachmentLeaving: true });
    void executeSend(question, undefined, attachment, intentHint);
    return true;
  }, [needsScanTypeConfirm, executeSend, state]);

  const streamQuestion = async (question: string, intentHint?: "component_vulnerability_catalog") => {
    const id = crypto.randomUUID();
    let content = "";
    let trace: TraceItem[] = [];
    let pending = "";
    let flushTimer = 0;
    state.appendTurn({ id, role: "assistant", content: "", createdAt: new Date().toISOString(), state: "streaming", trace: [] });
    const flush = () => {
      if (!pending) return;
      content += pending;
      pending = "";
      state.updateTurn(id, { content, trace: [...trace] });
    };
    try {
      const result = await api.streamQuestion(
        {
          question,
          user_id: state.userId,
          session_id: state.activeSessionId || undefined,
          response_language: locale,
          ...(intentHint ? { intent_hint: intentHint } : {}),
        },
        {
          onTrace: (item) => {
            trace = upsertTrace(trace, item);
            state.updateTurn(id, { trace: [...trace] });
          },
          onContent: (delta) => {
            pending += delta;
            if (!flushTimer) flushTimer = window.setTimeout(() => { flushTimer = 0; flush(); }, 50);
          },
        },
        controller.current?.signal,
      );
      if (flushTimer) window.clearTimeout(flushTimer);
      flushTimer = 0;
      flush();
      const agentTask = result.agent_task as AgentTask | undefined;
      if (agentTask) {
        state.replaceTask(agentTask);
        state.updateTurn(id, { content: result.answer || content || t("项目任务已进入安全分析队列。"), result, trace: result.trace || trace, task: agentTask, state: "completed" });
        return;
      }
      state.updateTurn(id, { content: result.answer || content, result, trace: result.trace || trace, state: "completed" });
      if (result.session_id) state.set({ activeSessionId: result.session_id });
      void api.conversations(state.userId).then((conversations) => state.set({ conversations }));
    } catch (error) {
      if (!controller.current?.signal.aborted) {
        state.updateTurn(id, {
          content: userFacingAssistantError(error),
          trace: [...trace],
          state: "error",
        });
      }
    } finally {
      if (flushTimer) window.clearTimeout(flushTimer);
    }
  };

  const handleWorkspaceResult = (result: WorkspaceActionResult, pendingId: string) => {
    const task = result.task;
    const answer = result.answer?.answer || result.answer?.summary;
    const submitted = submitTraceItem("completed", undefined, t("已提交项目目标，已进入分析流程。"));
    if (task) {
      state.replaceTask(task);
      // Follow-up messages (e.g. report requests) must route to this task so the
      // backend's deterministic task-action routes (report, rescan) apply.
      state.set({ activeTaskId: task.id });
      state.updateTurn(pendingId, {
        content: answer || t("项目任务已进入安全分析队列。"),
        task,
        state: "completed",
        trace: [
          submitted,
          {
            id: "scan-task-created",
            node: "scan_task_created",
            status: "completed",
            message: t("扫描任务已创建，正在后台执行，进度会实时更新。"),
          },
        ],
      });
    } else {
      const resolved = result.answer;
      state.updateTurn(pendingId, {
        content: resolved?.answer || resolved?.summary || t("任务已处理。"),
        result: resolved,
        trace: [submitted, ...(resolved?.trace || [])],
        state: "completed",
      });
    }
  };

  const stop = () => {
    controller.current?.abort();
    const streaming = [...state.turns].reverse().find((turn) => turn.role === "assistant" && turn.state === "streaming");
    if (streaming) state.updateTurn(streaming.id, { content: streaming.content || t("已停止本次分析。"), state: "completed" });
    if (state.activeTaskId) void api.taskMutation(state.activeTaskId, "cancel", state.userId).then(state.replaceTask);
    setBusy(false);
  };

  const showEarlierTurns = () => {
    const firstVisibleTurn = conversation.current?.querySelector(".chat-turn");
    prependAnchor.current = firstVisibleTurn
      ? { element: firstVisibleTurn, top: firstVisibleTurn.getBoundingClientRect().top }
      : null;
    nearBottom.current = false;
    conversationLog.current?.setAttribute("aria-live", "off");
    setVisibleTurnCount((current) => Math.min(state.turns.length, current + TURN_BATCH_SIZE));
  };

  return (
    <section
      className="assistant-workspace"
      aria-hidden={!visible}
      style={visible ? undefined : { display: "none" }}
    >
      <div
        className="conversation-scroll"
        ref={scroll}
        onScroll={(event) => {
          const target = event.currentTarget;
          nearBottom.current = target.scrollHeight - target.scrollTop - target.clientHeight < 180;
        }}
      >
        <div
          className="conversation-column"
          ref={conversation}
        >
          {firstVisibleTurnIndex ? (
            <button type="button" className="secondary" style={LOAD_EARLIER_BUTTON_STYLE} onClick={showEarlierTurns}>
              {t("显示更早消息")}
            </button>
          ) : null}
          <div
            ref={conversationLog}
            role="log"
            aria-live="polite"
            aria-relevant="additions"
            aria-label={t("安全分析对话")}
          >
            {!state.turns.length && !pendingQuestion ? (
              <AssistantEmptyState
                onPrompt={(prompt, intentHint) => void send(
                  prompt,
                  useAppStore.getState().composerAttachment,
                  intentHint,
                )}
              />
            ) : null}
            {visibleTurns.map((turn, index) => {
              const absoluteIndex = firstVisibleTurnIndex + index;
              const previous = turn.role === "assistant" ? previousUserTurn(state.turns, absoluteIndex) : undefined;
              return (
                <ChatMessage
                  key={turn.id}
                  turn={turn}
                  showExecutionDetails={false}
                  onRegenerate={previous ? () => void send(previous.content, null) : undefined}
                />
              );
            })}
            {pendingQuestion ? (
              <ScanTypeConfirm
                question={pendingQuestion}
                onConfirm={confirmScanType}
                onCancel={cancelScanTypeConfirm}
              />
            ) : null}
          </div>
        </div>
      </div>
      <div role="status" aria-live="polite" aria-atomic="true" style={VISUALLY_HIDDEN_STYLE}>{assistantStatus}</div>
      {state.turns.length && !pendingQuestion ? (
        <div className="composer-suggestions">
          <button type="button" disabled={busy} onClick={() => void send(t("完整扫描这个项目并汇总风险"), null)}><Shield size={14} /><span>{t("完整扫描这个项目并汇总风险")}</span></button>
          <button type="button" disabled={busy} onClick={() => void send(t("生成 SBOM 软件物料清单 Excel"), null)}><FileCheck2 size={14} /><span>{t("生成 SBOM 软件物料清单 Excel")}</span></button>
          <button type="button" disabled={busy} onClick={() => void send(t("匹配组件漏洞情报并给出修复建议"), null)}><Bug size={14} /><span>{t("匹配组件漏洞情报并给出修复建议")}</span></button>
        </div>
      ) : null}
      <PromptComposer busy={busy} onSubmit={(value, attachment) => send(value, attachment)} onStop={stop} />
    </section>
  );
}

function scrollToBottom(target: HTMLDivElement | null) {
  if (!target) return;
  if (typeof target.scrollTo === "function") {
    target.scrollTo({ top: target.scrollHeight, behavior: "auto" });
    return;
  }
  target.scrollTop = target.scrollHeight;
}

function upsertTrace(items: TraceItem[], next: TraceItem) {
  const identity = next.id || next.node;
  return [...items.filter((item) => (item.id || item.node) !== identity), next];
}

function previousUserTurn(turns: ChatTurn[], assistantIndex: number) {
  for (let index = assistantIndex - 1; index >= 0; index -= 1) {
    if (turns[index]?.role === "user") return turns[index];
  }
  return undefined;
}

/** Builds the immediate "objective submitted" timeline step for non-streaming actions. */
function submitTraceItem(status: "running" | "completed", startedAt: string | undefined, message: string): TraceItem {
  return {
    id: "submit-objective",
    node: "submit_objective",
    status,
    message,
    ...(startedAt ? { started_at: startedAt } : {}),
  };
}

/** Inline confirmation card that asks the user to choose a scan type. */
function ScanTypeConfirm({
  question,
  onConfirm,
  onCancel,
}: {
  question: string;
  onConfirm: (type: "code" | "sbom" | "full") => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const headingId = useId();
  const questionId = useId();
  const firstAction = useRef<HTMLButtonElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previouslyFocused.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    firstAction.current?.focus();
    return () => {
      if (previouslyFocused.current?.isConnected) previouslyFocused.current.focus();
    };
  }, []);

  return (
    <div
      className="scan-type-confirm"
      role="alertdialog"
      aria-live="assertive"
      aria-labelledby={headingId}
      aria-describedby={questionId}
    >
      <div className="scan-type-confirm-header">
        <span id={headingId}>{t("请选择本次扫描的类型：")}</span>
        <button type="button" className="scan-type-cancel-icon" onClick={onCancel} title={t("取消")} aria-label={t("取消")}>
          <X size={16} />
        </button>
      </div>
      <p id={questionId} className="scan-type-question">{question}</p>
      <div className="scan-type-options">
        <button ref={firstAction} type="button" className="scan-type-btn scan-type-code" onClick={() => onConfirm("code")}>
          <Shield size={16} />
          <span>{t("代码扫描")}</span>
        </button>
        <button type="button" className="scan-type-btn scan-type-sbom" onClick={() => onConfirm("sbom")}>
          <PackageSearch size={16} />
          <span>{t("SBOM扫描")}</span>
        </button>
        <button type="button" className="scan-type-btn scan-type-full" onClick={() => onConfirm("full")}>
          <Sparkles size={16} />
          <span>{t("完整扫描")}</span>
        </button>
      </div>
    </div>
  );
}

const VISUALLY_HIDDEN_STYLE = {
  position: "absolute",
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: "hidden",
  clip: "rect(0, 0, 0, 0)",
  whiteSpace: "nowrap",
  border: 0,
} as const;

const LOAD_EARLIER_BUTTON_STYLE = {
  display: "block",
  minHeight: 32,
  margin: "0 auto 24px",
  padding: "0 12px",
  borderRadius: 5,
  cursor: "pointer",
} as const;

function AssistantEmptyState({
  onPrompt,
}: {
  onPrompt: (prompt: string, intentHint?: "component_vulnerability_catalog") => void;
}) {
  const { t } = useI18n();
  const suggestions = [
    { icon: <FolderSearch2 />, title: t("扫描代码项目"), prompt: t("对我选择的项目进行完整代码安全扫描"), intentHint: undefined },
    {
      icon: <Shield />,
      title: t("查询最新漏洞"),
      prompt: t("查询本月严重和高危组件漏洞"),
      intentHint: "component_vulnerability_catalog" as const,
    },
    { icon: <Bot />, title: t("导出 SBOM"), prompt: t("导出项目 SBOM、许可和漏洞匹配清单"), intentHint: undefined },
  ];
  return (
    <KineticGrid className="assistant-empty assistant-kinetic-stage">
      <InformationCenterMark className="empty-icon" size={56} />
      <h1>{t("今天需要分析什么？")}</h1>
      <p>{t("安全问答、项目扫描、SBOM 和报告将由模型理解目标后选择对应 Agent。")}</p>
      <div className="empty-suggestions">{suggestions.map((item) => <button key={item.title} onClick={() => onPrompt(item.prompt, item.intentHint)}>{item.icon}<span><strong>{item.title}</strong><small>{item.prompt}</small></span></button>)}</div>
    </KineticGrid>
  );
}

function userFacingAssistantError(error: unknown): string {
  const message = (error instanceof Error ? error.message : String(error || "")).trim();
  if (/database is locked|database is busy|SQLITE_BUSY/i.test(message)) {
    return "本地漏洞库正在更新，请稍后重试。";
  }
  if (/failed to fetch|load failed|networkerror|connection refused/i.test(message)) {
    return "本机安全服务暂时不可用，请刷新本机服务后重试。";
  }
  return message || "查询漏洞情报失败，请稍后重试。";
}
