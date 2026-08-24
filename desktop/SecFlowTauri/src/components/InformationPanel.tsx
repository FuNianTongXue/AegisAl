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
import { useEffect, useLayoutEffect, useRef, useState } from "react";

import { clientLocaleTag, type ClientLocale, useI18n } from "../i18n";
import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { AskResult, ChatTurn, InformationItem, TraceItem } from "../types";
import { ChatMessage } from "./ChatMessage";
import { InformationCenterMark } from "./InformationCenterMark";
import { BRAND_NAME_EN, brandDisplayText } from "../branding";

type PanelMode = "consultation" | "feed";
type InformationPanelVariant = "floating" | "window";
const TURN_BATCH_SIZE = 60;

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
  const { locale, t } = useI18n();
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
  const [announcement, setAnnouncement] = useState("");
  const controller = useRef<AbortController | null>(null);
  const activeTurnId = useRef("");
  const scroll = useRef<HTMLDivElement>(null);
  const conversation = useRef<HTMLDivElement>(null);
  const nearBottom = useRef(true);
  const prependAnchor = useRef<{ element: Element; top: number } | null>(null);
  const [visibleTurnCount, setVisibleTurnCount] = useState(TURN_BATCH_SIZE);
  const firstVisibleTurnIndex = Math.max(0, turns.length - visibleTurnCount);
  const visibleTurns = turns.slice(firstVisibleTurnIndex);

  useEffect(() => {
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  useEffect(() => () => {
    controller.current?.abort();
    void api.clearShortTermSession(sessionIdRef.current, userId).catch(() => undefined);
  }, [userId]);

  useEffect(() => {
    if (!open || mode !== "feed") return;
    let cancelled = false;
    setLoading(true);
    setFeedError("");
    setItems([]);
    void (async () => {
      try {
        let result = await api.information(false, locale);
        if (!cancelled) setItems(sortItems(result.items));
        if (result.refreshing) {
          result = await api.refreshInformation(locale);
          if (!cancelled) setItems(sortItems(result.items));
        }
      } catch (error) {
        if (!cancelled) setFeedError(String(error));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [locale, mode, open]);

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

  useLayoutEffect(() => {
    const anchor = prependAnchor.current;
    const target = scroll.current;
    if (anchor && target && anchor.element.isConnected) {
      target.scrollTop += anchor.element.getBoundingClientRect().top - anchor.top;
    }
    prependAnchor.current = null;
  }, [visibleTurnCount]);

  if (!open) return null;

  const updateTurn = (id: string, patch: Partial<ChatTurn>) => {
    setTurns((current) => current.map((turn) => turn.id === id ? { ...turn, ...patch } : turn));
  };

  const saveStructuredData = async (turn: ChatTurn, nextResult: AskResult) => {
    const targetSessionId = String(nextResult.session_id || sessionIdRef.current || "").trim();
    const exchangeId = String(nextResult.exchange_id || "").trim();
    const tables = nextResult.structured_data_edits || [];
    if (!targetSessionId || !exchangeId || !tables.length) {
      throw new Error(t("当前记录尚未同步到会话，请稍后重试"));
    }
    const saved = await api.updateConversationTableEdits(
      targetSessionId,
      exchangeId,
      userId,
      tables,
    );
    updateTurn(turn.id, {
      result: {
        ...nextResult,
        session_id: targetSessionId,
        exchange_id: saved.exchange_id || exchangeId,
        structured_data_edits: saved.tables,
      },
    });
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
    setAnnouncement(t("正在生成咨询回答…"));
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
      setAnnouncement(t("咨询回答已完成。"));
      if (result.session_id) setSessionId(result.session_id);
    } catch (error) {
      if (!activeController.signal.aborted) {
        updateTurn(assistantId, {
          content: content || `咨询请求失败：${error instanceof Error ? error.message : String(error)}`,
          trace: [...trace],
          state: "error",
        });
        setAnnouncement(t("咨询请求失败，请检查连接后重试。"));
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
    setAnnouncement(t("已停止本次咨询。"));
  };

  const startNewConsultation = () => {
    controller.current?.abort();
    controller.current = null;
    activeTurnId.current = "";
    setBusy(false);
    setTurns([]);
    setVisibleTurnCount(TURN_BATCH_SIZE);
    prependAnchor.current = null;
    setValue("");
    const previousSession = sessionIdRef.current;
    void api.clearShortTermSession(previousSession, userId).catch(() => undefined);
    const nextSession = createConsultationSession();
    sessionIdRef.current = nextSession;
    setSessionId(nextSession);
    nearBottom.current = true;
  };

  const showEarlierTurns = () => {
    const firstVisibleTurn = conversation.current?.querySelector(".chat-turn");
    prependAnchor.current = firstVisibleTurn
      ? { element: firstVisibleTurn, top: firstVisibleTurn.getBoundingClientRect().top }
      : null;
    nearBottom.current = false;
    setVisibleTurnCount((current) => Math.min(turns.length, current + TURN_BATCH_SIZE));
  };

  const refresh = async () => {
    setRefreshing(true);
    setFeedError("");
    try {
      const result = await api.refreshInformation(locale);
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
        <span><MessageSquareText size={16} aria-hidden="true" /><h2 id="information-panel-title">信息中心</h2></span>
        <div>
          {mode === "consultation" ? (
            <button title="新建独立咨询" aria-label="新建独立咨询" onClick={startNewConsultation}><SquarePen size={15} /></button>
          ) : (
            <button title="刷新最新资讯" aria-label="刷新最新资讯" onClick={() => void refresh()} disabled={refreshing}><RefreshCcw size={15} className={refreshing ? "spin" : ""} /></button>
          )}
          <button title="关闭" aria-label="关闭" onClick={onClose}><X size={16} /></button>
        </div>
      </header>
      <div className="information-tabs" role="tablist" aria-label="信息中心视图" onKeyDown={(event) => { if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return; event.preventDefault(); const next = mode === "consultation" ? "feed" : "consultation"; setMode(next); document.getElementById(`information-tab-${next}`)?.focus(); }}>
        <button id="information-tab-consultation" role="tab" aria-controls="information-consultation-panel" aria-selected={mode === "consultation"} tabIndex={mode === "consultation" ? 0 : -1} className={mode === "consultation" ? "active" : ""} onClick={() => setMode("consultation")}><MessageSquareText size={14} aria-hidden="true" />咨询</button>
        <button id="information-tab-feed" role="tab" aria-controls="information-feed-panel" aria-selected={mode === "feed"} tabIndex={mode === "feed" ? 0 : -1} className={mode === "feed" ? "active" : ""} onClick={() => setMode("feed")}><Newspaper size={14} aria-hidden="true" />资讯</button>
      </div>
      <span className="sr-only" role="status" aria-live="polite">{announcement}</span>
      {mode === "consultation" ? (
        <div id="information-consultation-panel" className="consultation-view" role="tabpanel" aria-labelledby="information-tab-consultation">
          <div
            className="consultation-scroll"
            ref={scroll}
            onScroll={(event) => {
              const target = event.currentTarget;
              nearBottom.current = target.scrollHeight - target.scrollTop - target.clientHeight < 100;
            }}
          >
            <div className="consultation-conversation" ref={conversation}>
              {firstVisibleTurnIndex ? (
                <button type="button" className="secondary" style={LOAD_EARLIER_BUTTON_STYLE} onClick={showEarlierTurns}>
                  {t("显示更早消息")}
                </button>
              ) : null}
              <div role="log" aria-live="off" aria-label="咨询对话记录">
                {!turns.length ? <ConsultationEmpty onPrompt={(prompt) => void send(prompt)} /> : visibleTurns.map((turn) => (
                  <ChatMessage
                    key={turn.id}
                    turn={turn}
                    compact
                    autoExpandThinking={false}
                    onResultChange={turn.role === "assistant" && turn.result
                      ? (result) => saveStructuredData(turn, result)
                      : undefined}
                  />
                ))}
              </div>
            </div>
          </div>
          <div className="consultation-composer">
            <textarea
              rows={2}
              value={value}
              placeholder="例如：分析这条安全告警并给出处置建议…"
              aria-label="独立咨询问题"
              name="information_question"
              autoComplete="off"
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
        <div id="information-feed-panel" className="information-feed" role="tabpanel" aria-labelledby="information-tab-feed">
          {loading && !items.length ? <InformationSkeleton /> : null}
          {feedError && !items.length ? <div className="information-error" role="alert"><span>资讯加载失败：{brandDisplayText(feedError)}</span><button className="secondary" onClick={() => void refresh()}>重新加载</button></div> : null}
          {items.slice(0, 20).map((item, index) => (
            <a className="information-entry" style={{ animationDelay: `${Math.min(index, 8) * 35}ms` }} key={item.id} href={item.url} target="_blank" rel="noreferrer">
              <InformationImage item={item} />
              <span>
                <strong>{brandDisplayText(item.title)}</strong>
                <small>
                  {brandDisplayText(item.source_name) || "安全情报"} · {formatTime(item.published_at, locale)}
                </small>
              </span>
              <ExternalLink size={12} />
            </a>
          ))}
        </div>
      )}
    </aside>
  );
}

const LOAD_EARLIER_BUTTON_STYLE = {
  display: "block",
  minHeight: 30,
  margin: "0 auto 16px",
  padding: "0 10px",
  borderRadius: 5,
  cursor: "pointer",
} as const;

function ConsultationEmpty({ onPrompt }: { onPrompt: (prompt: string) => void }) {
  const prompts = ["分析这条安全告警", "查询近期高危漏洞", "给出处置优先级建议"];
  return (
    <div className="consultation-empty">
      <InformationCenterMark className="consultation-brand-mark" size={38} />
      <strong>{BRAND_NAME_EN} 安全咨询</strong>
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
        width={46}
        height={46}
        loading="lazy"
        onError={() => setStage(item.source_id ? "source" : "fallback")}
      />
    );
  }
  if (stage === "source" && item.source_id) {
    return (
      <img
        className="information-image source-image"
        src={api.informationSourceImageUrl(item.source_id, item.source_image_version)}
        alt=""
        width={46}
        height={46}
        loading="lazy"
        onError={() => setStage("fallback")}
      />
    );
  }
  return <span className="source-logo">{(brandDisplayText(item.source_name) || "S").slice(0, 1)}</span>;
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
const formatTime = (value: string | undefined, locale: ClientLocale) => {
  if (!value) return "刚刚";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "-";
  return new Intl.DateTimeFormat(clientLocaleTag(locale), { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(parsed);
};

function isRecentHighVulnerabilityLookup(question: string) {
  const text = question.trim().toLowerCase();
  return /(?:查询|查找|搜索|获取|列出|有哪些|find|show|list|get|query|search)/i.test(text)
    && /(?:近期|最近|近\s*\d+\s*天|本周|recent|latest)/i.test(text)
    && /(?:高危|严重|high|critical)/i.test(text)
    && /(?:漏洞|cve|vulnerab)/i.test(text);
}
