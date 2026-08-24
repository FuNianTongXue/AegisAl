import { useEffect, useRef, useState, type PropsWithChildren } from "react";

import { BeautifulThinkingTrigger } from "./beautiful-ui/BeautifulUI";

/**
 * A stateful shell for the execution trace. The trace itself remains owned by
 * AgentTimeline; this component only gives the stream a readable beginning,
 * middle, and settled state. The detail body starts compact so a long-running
 * answer does not push the response out of view; users can open it on demand.
 */
export function ThinkingState({
  running,
  elapsedMs,
  stepCount,
  activity,
  autoExpand = false,
  children,
}: PropsWithChildren<{
  running: boolean;
  elapsedMs: number;
  stepCount: number;
  activity?: string;
  autoExpand?: boolean;
}>) {
  const [expanded, setExpanded] = useState(running && autoExpand);
  const automaticallyExpanded = useRef(running && autoExpand);
  const seconds = Math.max(0, elapsedMs) / 1000;
  const description = running
    ? `${activity || "正在整理证据和上下文"}${seconds >= 1 ? ` · ${seconds.toFixed(1)} 秒` : ""}`
    : `用时 ${seconds.toFixed(1)} 秒 · ${stepCount} 个执行步骤`;

  useEffect(() => {
    if (running && autoExpand) {
      automaticallyExpanded.current = true;
      setExpanded(true);
      return;
    }
    if (!running && automaticallyExpanded.current) {
      automaticallyExpanded.current = false;
      setExpanded(false);
    }
  }, [autoExpand, running]);

  const toggleExpanded = () => {
    // A direct user choice takes precedence over the automatic live-progress
    // preference, including when the task settles on the next render.
    automaticallyExpanded.current = false;
    setExpanded((current) => !current);
  };

  return (
    <div className={`thinking-state ${running ? "running" : "settled"}`}>
      <BeautifulThinkingTrigger
        running={running}
        expanded={expanded}
        title={running ? "正在思考" : "思考完成"}
        description={description}
        onToggle={toggleExpanded}
      />
      <div
        className={`thinking-state-body ${expanded ? "open" : ""}`}
        aria-hidden={!expanded}
        inert={!expanded}
      >
        <div className="thinking-state-body-inner">{children}</div>
      </div>
    </div>
  );
}
