import {
  AlertCircle,
  BadgeCheck,
  BrainCircuit,
  Check,
  ChevronDown,
  Circle,
  FileOutput,
  Languages,
  ListChecks,
  LoaderCircle,
  Play,
  Search,
  Sparkles,
  Square,
  Wrench,
} from "lucide-react";
import { useEffect, useId, useState, type PropsWithChildren, type ReactNode, type SyntheticEvent } from "react";
import { createPortal } from "react-dom";

import "./beautiful-ui.css";

export type BeautifulStatus = "pending" | "running" | "completed" | "error" | "cancelled";

export interface BeautifulTaskDetail {
  label: string;
  meta?: string;
  content?: ReactNode;
  tone?: "default" | "error";
}

export type BeautifulToolAction = "analyze" | "execute" | "generate" | "plan" | "query" | "translate" | "verify";

export interface BeautifulToolRowItem {
  id: string;
  state: BeautifulStatus;
  action: string;
  actionKind: BeautifulToolAction;
  chip: string;
  meta?: string;
  statusLabel: string;
  details: BeautifulTaskDetail[];
}

export interface BeautifulFileDiff {
  id: string;
  file: string;
  additions: number;
  deletions: number;
  lines?: Array<{ text: string; tone: "add" | "delete" | "context" }>;
}

export function BeautifulLoadingState({
  label,
  detail,
  compact = false,
  showElapsed = false,
  className = "",
}: {
  label: string;
  detail?: string;
  compact?: boolean;
  showElapsed?: boolean;
  className?: string;
}) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!showElapsed) return;
    const startedAt = Date.now();
    const tick = () => setElapsed(Date.now() - startedAt);
    tick();
    // The elapsed label is informational. Updating once per second keeps it
    // useful during a slow sidecar cold start without re-rendering at 10 fps.
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [showElapsed]);

  return (
    <div
      className={`bui-loading-state ${compact ? "compact" : ""} ${className}`.trim()}
      role="status"
      aria-live="polite"
      aria-label={label}
    >
      <PixelGrid />
      <span className="bui-loading-copy">
        <strong>{label}</strong>
        {detail ? <small>{detail}</small> : null}
      </span>
      {showElapsed ? <time>{(elapsed / 1000).toFixed(1)}s</time> : null}
    </div>
  );
}

export function BeautifulThinkingTrigger({
  running,
  expanded,
  title,
  description,
  onToggle,
}: {
  running: boolean;
  expanded: boolean;
  title: string;
  description: string;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      className="timeline-heading bui-thinking-trigger"
      onClick={onToggle}
      aria-expanded={expanded}
    >
      <span className={`timeline-pulse bui-thinking-mark ${running ? "running" : "settled"}`} aria-hidden="true">
        {running ? <PixelGrid miniature /> : <Sparkles size={15} />}
      </span>
      <span className="timeline-summary">
        <strong>{title}</strong>
        <small>{description}</small>
      </span>
      <ChevronDown size={15} className={expanded ? "" : "rotated"} aria-hidden="true" />
    </button>
  );
}

export function BeautifulToolChipTrigger({
  state,
  name,
  meta,
  open,
  onToggle,
}: {
  state: Exclude<BeautifulStatus, "pending" | "cancelled">;
  name: string;
  meta: string;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <button type="button" className="bui-tool-chip-trigger" onClick={onToggle} aria-expanded={open}>
      <span className={`bui-tool-chip-state ${state}`} aria-hidden="true">
        {state === "running" ? <LoaderCircle className="spin" /> : state === "error" ? <AlertCircle /> : <Check />}
      </span>
      <Wrench size={14} aria-hidden="true" />
      <strong>{name}</strong>
      <small>{meta}</small>
      <ChevronDown size={14} className={open ? "" : "rotated"} aria-hidden="true" />
    </button>
  );
}

export function BeautifulToolChips({
  items,
  summary,
  label = "执行过程",
  diffs = [],
  defaultOpen = false,
  showSummary = true,
}: {
  items: BeautifulToolRowItem[];
  summary: string;
  label?: string;
  diffs?: BeautifulFileDiff[];
  defaultOpen?: boolean;
  showSummary?: boolean;
}) {
  const componentId = useId();
  const contentId = `${componentId}-content`;
  const [groupOpen, setGroupOpen] = useState(defaultOpen);
  const [openRows, setOpenRows] = useState<Set<string>>(() => new Set());
  const [preview, setPreview] = useState<{
    diff: BeautifulFileDiff;
    x: number;
    top?: number;
    bottom?: number;
  } | null>(null);

  useEffect(() => {
    if (!preview) return;
    const close = () => setPreview(null);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [preview]);

  const toggleRow = (id: string) => {
    setOpenRows((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const openPreview = (diff: BeautifulFileDiff) => (event: SyntheticEvent<HTMLElement>) => {
    if (!diff.lines?.length) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const previewHeight = 38 + diff.lines.length * 20;
    const fitsBelow = rect.bottom + 6 + previewHeight <= window.innerHeight - 12;
    setPreview({
      diff,
      x: Math.max(12, Math.min(rect.left, window.innerWidth - 300)),
      ...(fitsBelow ? { top: rect.bottom + 6 } : { bottom: window.innerHeight - rect.top + 6 }),
    });
  };

  const closePreview = (id: string) => () => {
    setPreview((current) => current?.diff.id === id ? null : current);
  };

  return (
    <div className="bui-tool-chips">
      {showSummary ? (
        <button
          type="button"
          className="bui-tool-chips-summary"
          aria-expanded={groupOpen}
          aria-controls={contentId}
          onClick={() => setGroupOpen((current) => !current)}
        >
          <ChevronDown aria-hidden="true" />
          <span>{summary}</span>
        </button>
      ) : null}

      <div
        id={contentId}
        className={`bui-tool-chips-collapse ${groupOpen ? "open" : ""}`}
        aria-hidden={!groupOpen}
      >
        <div className="bui-tool-chips-collapse-inner">
          <div className="bui-tool-chips-list" role="list" aria-label={label}>
            {items.map((item, index) => {
              const open = openRows.has(item.id);
              const detailsId = `${componentId}-details-${index}`;
              const hasDetails = item.details.length > 0;
              return (
                <div
                  key={item.id}
                  className={`bui-tool-row bui-status-${item.state} ${open ? "open" : ""}`}
                  role="listitem"
                  style={{ "--bui-row-delay": `${Math.min(index, 8) * 55}ms` } as React.CSSProperties}
                >
                  <button
                    type="button"
                    className="bui-tool-row-trigger"
                    aria-label={`${item.action}，${item.chip}，${item.statusLabel}${item.meta ? `，${item.meta}` : ""}`}
                    aria-expanded={hasDetails ? open : undefined}
                    aria-controls={hasDetails ? detailsId : undefined}
                    disabled={!hasDetails}
                    tabIndex={groupOpen ? undefined : -1}
                    onClick={() => toggleRow(item.id)}
                  >
                    <ToolRowIcon kind={item.actionKind} state={item.state} open={open} />
                    <span className="bui-tool-row-action">{item.action}</span>
                    <span className="bui-tool-row-chip" title={item.chip}>
                      <span dir="auto">{item.chip}</span>
                      {item.meta ? <small>{item.meta}</small> : null}
                    </span>
                  </button>
                  {hasDetails ? (
                    <div id={detailsId} className="bui-tool-row-details-collapse" aria-hidden={!open}>
                      <div className="bui-tool-row-details-collapse-inner">
                        <div className="bui-tool-row-details">
                          {item.details.map((detail, detailIndex) => (
                            <div
                              key={`${detail.label}:${detailIndex}`}
                              className={`bui-tool-row-detail ${detail.tone === "error" ? "error" : ""}`}
                              style={{ "--bui-detail-delay": `${50 + Math.min(detailIndex, 6) * 45}ms` } as React.CSSProperties}
                            >
                              <div>
                                <strong>{detail.label}</strong>
                                {detail.content ? <div>{detail.content}</div> : null}
                              </div>
                              {detail.meta ? <small>{detail.meta}</small> : null}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>

          {diffs.length ? (
            <div className="bui-file-diffs" aria-label="文件变更">
              {diffs.map((diff, index) => {
                const previewOpen = preview?.diff.id === diff.id;
                const previewId = `${componentId}-diff-${index}`;
                return (
                  <span key={diff.id} className="bui-file-diff-anchor">
                    <button
                      type="button"
                      className="bui-file-diff-chip"
                      aria-label={`${diff.file}，新增 ${diff.additions} 行，删除 ${diff.deletions} 行`}
                      aria-describedby={previewOpen ? previewId : undefined}
                      tabIndex={groupOpen ? undefined : -1}
                      onMouseEnter={openPreview(diff)}
                      onMouseLeave={closePreview(diff.id)}
                      onFocus={openPreview(diff)}
                      onBlur={closePreview(diff.id)}
                    >
                      <span title={diff.file}>{diff.file}</span>
                      <b>+{diff.additions}</b>
                      {diff.deletions ? <em>-{diff.deletions}</em> : null}
                    </button>
                  </span>
                );
              })}
            </div>
          ) : null}
        </div>
      </div>

      {preview && typeof document !== "undefined" ? createPortal(
        <div
          id={`${componentId}-diff-${diffs.findIndex((item) => item.id === preview.diff.id)}`}
          className="bui-file-diff-preview"
          role="tooltip"
          style={{ left: preview.x, top: preview.top, bottom: preview.bottom }}
        >
          <header>
            <span>{preview.diff.file}</span>
            <small><b>+{preview.diff.additions}</b>{preview.diff.deletions ? <em>-{preview.diff.deletions}</em> : null}</small>
          </header>
          <div>
            {preview.diff.lines?.map((line, index) => (
              <code key={`${index}:${line.text}`} className={line.tone}>
                <i>{line.tone === "add" ? "+" : line.tone === "delete" ? "-" : " "}</i>
                <span>{line.text}</span>
              </code>
            ))}
          </div>
        </div>,
        document.body,
      ) : null}
    </div>
  );
}

function ToolRowIcon({
  kind,
  state,
  open,
}: {
  kind: BeautifulToolAction;
  state: BeautifulStatus;
  open: boolean;
}) {
  const ActionIcon = {
    analyze: BrainCircuit,
    execute: Play,
    generate: FileOutput,
    plan: ListChecks,
    query: Search,
    translate: Languages,
    verify: BadgeCheck,
  }[kind];
  const StateIcon = state === "running"
    ? LoaderCircle
    : state === "error"
      ? AlertCircle
      : state === "cancelled"
        ? Square
        : state === "pending"
          ? Circle
          : ActionIcon;

  return (
    <span className={`bui-tool-row-icon ${state}`} aria-hidden="true">
      <StateIcon className={`bui-tool-row-action-icon ${state === "running" ? "spin" : ""}`} />
      <ChevronDown className="bui-tool-row-chevron" style={{ rotate: open ? "0deg" : "-90deg" }} />
    </span>
  );
}

export function BeautifulTaskRow({
  state,
  icon,
  title,
  description,
  meta,
}: {
  state: BeautifulStatus;
  icon: ReactNode;
  title: string;
  description: string;
  meta: string;
}) {
  return (
    <header className={`bui-task-row bui-status-${state}`}>
      <span className="task-state-icon bui-task-state" aria-hidden="true">{icon}</span>
      <div><strong>{title}</strong><small>{description}</small></div>
      <span className="status-chip">{meta}</span>
    </header>
  );
}

export function BeautifulEmptyState({
  title,
  detail,
  query,
  className = "",
}: {
  title: string;
  detail?: string;
  query?: string;
  className?: string;
}) {
  return (
    <div className={`bui-empty-state ${className}`.trim()} role="status">
      <span className="bui-empty-icon" aria-hidden="true"><Search size={18} /></span>
      <strong>{title}</strong>
      {query ? <code>{query}</code> : null}
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

export function BeautifulApprovalCard({
  children,
  className = "",
  busy = false,
  label,
  labelledBy,
  describedBy,
}: PropsWithChildren<{
  className?: string;
  busy?: boolean;
  label?: string;
  labelledBy?: string;
  describedBy?: string;
}>) {
  return (
    <div
      className={`bui-approval-card ${className}`.trim()}
      role="alertdialog"
      aria-live="assertive"
      aria-busy={busy || undefined}
      aria-label={label}
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
    >
      <span className="bui-approval-signal" aria-hidden="true"><Circle /><Circle /><Circle /></span>
      {children}
    </div>
  );
}

function PixelGrid({ miniature = false }: { miniature?: boolean }) {
  return (
    <span className={`bui-pixel-grid ${miniature ? "miniature" : ""}`} aria-hidden="true">
      {Array.from({ length: 9 }, (_, index) => (
        <i key={index} style={{ "--bui-cell": index } as React.CSSProperties} />
      ))}
    </span>
  );
}
