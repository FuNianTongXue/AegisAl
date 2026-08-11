import {
  ArrowUp,
  ExternalLink,
  MessageSquareText,
  Newspaper,
  RefreshCcw,
  ShieldCheck,
  Square,
  SquarePen,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api } from "../lib/api";
import { useI18n } from "../i18n";
import { useAppStore } from "../store/appStore";
import type { ChatTurn, InformationItem, TraceItem } from "../types";
import { ChatMessage } from "./ChatMessage";
import { InformationCenterMark } from "./InformationCenterMark";

type PanelMode = "consultation" | "feed";
type InformationPanelVariant = "floating" | "window";

export function InformationPanel({
  open,
  onClose,
  variant = "floating",
}: {
  open: boolean;
  onClose: () => void;
  variant?: InformationPanelVariant;
}) {
  const userId = useAppStore((state) => state.userId);
  const { locale } = useI18n();
  const [mode, setMode] = useState<PanelMode>("consultation");
  const [sessionId, setSessionId] = useState(createConsultationSession);
  const sessionIdRef = useRef(sessionId);
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [items, setItems] = useState<InformationItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [feedError, setFeedError] = useState("");
  const controller = useRef<AbortController | null>(null);
  const activeTurnId = useRef("");
  const scroll = useRef<HTMLDivElement>(null);
  const conversation = useRef<HTMLDivElement>(null);
  const nearBottom = useRef(true);

  useEffect(() => {
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  useEffect(() => () => {
    controller.current?.abort();
    void api.clearShortTermSession(sessionIdRef.current, userId).catch(() => undefined);
  }, [userId]);

  useEffect(() => {
    if (!open || mode !== "feed" || items.length) return;
    setLoading(true);
    setFeedError("");
    void api.information()
      .then((result) => setItems(sortItems(result.items)))
      .catch((error) => setFeedError(String(error)))
      .finally(() => setLoading(false));
  }, [items.length, mode, open]);

  useEffect(() => {
    if (!open || mode !== "consultation" || !nearBottom.current) return;
    const frame = window.requestAnimationFrame(() => {
      scroll.current?.scrollTo({ top: scroll.current.scrollHeight, behavior: "auto" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [mode, open, turns]);

  useEffect(() => {
    const target = conversation.current;
    if (!open || mode !== "consultation" || !target || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      if (nearBottom.current) scroll.current?.scrollTo({ top: scroll.current.scrollHeight, behavior: "auto" });
    });
    observer.observe(target);
    return () => observer.disconnect();
  }, [mode, open]);

  if (!open) return null;

  const updateTurn = (id: string, patch: Partial<ChatTurn>) => {
    setTurns((current) => current.map((turn) => turn.id === id ? { ...turn, ...patch } : turn));
  };

  const send = async (question: string) => {
    const clean = question.trim();
    if (!clean || busy) return;
    const intentHint = isRecentHighVulnerabilityLookup(clean)
      ? "recent_high_vulnerability_lookup"
      : "information_consultation";
    const assistantId = crypto.randomUUID();
    const activeController = new AbortController();
    let content = "";
    let pending = "";
    let trace: TraceItem[] = [];
    let flushTimer = 0;
    const flush = () => {
      if (!pending) return;
      content += pending;
      pending = "";
      updateTurn(assistantId, { content, trace: [...trace] });
    };

    nearBottom.current = true;
    setValue("");
    setTurns((current) => [
      ...current,
      { id: crypto.randomUUID(), role: "user", content: clean, createdAt: new Date().toISOString() },
      { id: assistantId, role: "assistant", content: "", createdAt: new Date().toISOString(), state: "streaming", trace: [] },
    ]);
    setBusy(true);
    controller.current = activeController;
    activeTurnId.current = assistantId;

    try {
      const result = await api.streamQuestion(
        {
          question: clean,
          user_id: userId,
          session_id: sessionId,
          response_language: locale,
          intent_hint: intentHint,
        },
        {
          onTrace: (item) => {
            if (activeController.signal.aborted) return;
            trace = upsertTrace(trace, item);
            updateTurn(assistantId, { trace: [...trace] });
          },
          onContent: (delta) => {
            if (activeController.signal.aborted) return;
            pending += delta;
            if (!flushTimer) {
              flushTimer = window.setTimeout(() => {
                flushTimer = 0;
                flush();
              }, 50);
            }
          },
        },
        activeController.signal,
      );
      if (flushTimer) window.clearTimeout(flushTimer);
      flushTimer = 0;
      flush();
      updateTurn(assistantId, {
        content: result.answer || content,
        result,
        trace: result.trace || trace,
        state: "completed",
      });
      if (result.session_id) setSessionId(result.session_id);
    } catch (error) {
      if (!activeController.signal.aborted) {
        updateTurn(assistantId, {
          content: content || `咨询请求失败：${error instanceof Error ? error.message : String(error)}`,
          trace: [...trace],
          state: "error",
        });
      }
    } finally {
      if (flushTimer) window.clearTimeout(flushTimer);
      if (controller.current === activeController) controller.current = null;
      if (activeTurnId.current === assistantId) activeTurnId.current = "";
      setBusy(false);
    }
  };

  const stop = () => {
    controller.current?.abort();
    const id = activeTurnId.current;
    if (id) {
      setTurns((current) => current.map((turn) => turn.id === id
        ? { ...turn, content: turn.content || "已停止本次咨询。", state: "completed" }
        : turn));
    }
    setBusy(false);
  };

  const startNewConsultation = () => {
    controller.current?.abort();
    controller.current = null;
    activeTurnId.current = "";
    setBusy(false);
    setTurns([]);
    setValue("");
    const previousSession = sessionIdRef.current;
    void api.clearShortTermSession(previousSession, userId).catch(() => undefined);
    const nextSession = createConsultationSession();
    sessionIdRef.current = nextSession;
    setSessionId(nextSession);
    nearBottom.current = true;
  };

  const refresh = async () => {
    setRefreshing(true);
    setFeedError("");
    try {
      const result = await api.refreshInformation();
      setItems(sortItems(result.items));
    } catch (error) {
      setFeedError(String(error));
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <aside id="information-panel" className={`information-panel ${variant === "window" ? "windowed" : ""}`} aria-label="独立信息咨询">
      <header>
        <span><MessageSquareText size={16} /><strong>信息中心</strong></span>
        <div>
          {mode === "consultation" ? (
            <button title="新建独立咨询" aria-label="新建独立咨询" onClick={startNewConsultation}><SquarePen size={15} /></button>
          ) : (
            <button title="刷新最新资讯" aria-label="刷新最新资讯" onClick={() => void refresh()} disabled={refreshing}><RefreshCcw size={15} className={refreshing ? "spin" : ""} /></button>
          )}
          <button title="关闭" aria-label="关闭" onClick={onClose}><X size={16} /></button>
        </div>
      </header>
      <div className="information-tabs" role="tablist" aria-label="信息中心视图">
        <button role="tab" aria-selected={mode === "consultation"} className={mode === "consultation" ? "active" : ""} onClick={() => setMode("consultation")}><MessageSquareText size={14} />咨询</button>
        <button role="tab" aria-selected={mode === "feed"} className={mode === "feed" ? "active" : ""} onClick={() => setMode("feed")}><Newspaper size={14} />资讯</button>
      </div>
      {mode === "consultation" ? (
        <div className="consultation-view">
          <div
            className="consultation-scroll"
            ref={scroll}
            aria-live="polite"
            onScroll={(event) => {
              const target = event.currentTarget;
              nearBottom.current = target.scrollHeight - target.scrollTop - target.clientHeight < 100;
            }}
          >
            <div className="consultation-conversation" ref={conversation}>
              {!turns.length ? <ConsultationEmpty onPrompt={(prompt) => void send(prompt)} /> : turns.map((turn) => <ChatMessage key={turn.id} turn={turn} compact autoExpandThinking={false} />)}
            </div>
          </div>
          <div className="consultation-composer">
            <textarea
              rows={2}
              value={value}
              placeholder="询问漏洞、告警或处置建议"
              aria-label="独立咨询问题"
              disabled={busy}
              onChange={(event) => setValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  void send(value);
                }
              }}
            />
            {busy ? (
              <button className="consultation-stop" title="停止生成" aria-label="停止生成" onClick={stop}><Square size={11} /></button>
            ) : (
              <button className="consultation-send" title="发送" aria-label="发送" disabled={!value.trim()} onClick={() => void send(value)}><ArrowUp size={16} /></button>
            )}
            <small><ShieldCheck size={12} />仅当前会话短期记忆</small>
          </div>
        </div>
      ) : (
        <div className="information-feed">
          {loading && !items.length ? <InformationSkeleton /> : null}
          {feedError && !items.length ? <p className="information-error">资讯加载失败：{feedError}</p> : null}
          {items.slice(0, 20).map((item, index) => (
            <a className="information-entry" style={{ animationDelay: `${Math.min(index, 8) * 35}ms` }} key={item.id} href={item.url} target="_blank" rel="noreferrer">
              <InformationImage item={item} />
              <span><strong>{item.title}</strong><small>{item.source_name || "安全情报"} · {formatTime(item.published_at)}</small></span>
              <ExternalLink size={12} />
            </a>
          ))}
        </div>
      )}
    </aside>
  );
}

function ConsultationEmpty({ onPrompt }: { onPrompt: (prompt: string) => void }) {
  const prompts = ["分析这条安全告警", "查询近期高危漏洞", "给出处置优先级建议"];
  return (
    <div className="consultation-empty">
      <InformationCenterMark className="consultation-brand-mark" size={38} />
      <strong>SecFlow 安全咨询</strong>
      <div>{prompts.map((prompt) => <button key={prompt} onClick={() => onPrompt(prompt)}>{prompt}</button>)}</div>
    </div>
  );
}

function InformationImage({ item }: { item: InformationItem }) {
  const [stage, setStage] = useState<"article" | "source" | "fallback">(
    item.image_url ? "article" : item.source_id ? "source" : "fallback",
  );
  if (stage === "article") {
    return (
      <img
        className="information-image"
        src={api.informationImageUrl(item.id)}
        alt=""
        loading="lazy"
        onError={() => setStage(item.source_id ? "source" : "fallback")}
      />
    );
  }
  if (stage === "source" && item.source_id) {
    return (
      <img
        className="information-image source-image"
        src={api.informationSourceImageUrl(item.source_id)}
        alt=""
        loading="lazy"
        onError={() => setStage("fallback")}
      />
    );
  }
  return <span className="source-logo">{(item.source_name || "S").slice(0, 1)}</span>;
}

function InformationSkeleton() {
  return <div className="information-skeleton" aria-label="正在加载安全资讯">{Array.from({ length: 6 }, (_, index) => <span key={index}><i /><b /><b /></span>)}</div>;
}

function upsertTrace(items: TraceItem[], next: TraceItem) {
  const identity = next.id || next.node;
  return [...items.filter((item) => (item.id || item.node) !== identity), next];
}

function createConsultationSession() {
  return `information:${crypto.randomUUID()}`;
}

const sortItems = (items: InformationItem[]) => [...items].sort((left, right) => new Date(right.published_at || 0).getTime() - new Date(left.published_at || 0).getTime());
const formatTime = (value?: string) => value ? new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(value)) : "刚刚";

function isRecentHighVulnerabilityLookup(question: string) {
  const text = question.trim().toLowerCase();
  return /(?:查询|查找|搜索|获取|列出|有哪些|find|show|list|get|query|search)/i.test(text)
    && /(?:近期|最近|近\s*\d+\s*天|本周|recent|latest)/i.test(text)
    && /(?:高危|严重|high|critical)/i.test(text)
    && /(?:漏洞|cve|vulnerab)/i.test(text);
}
