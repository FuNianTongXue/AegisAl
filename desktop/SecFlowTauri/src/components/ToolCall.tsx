import { useState } from "react";

import { brandDisplayText } from "../branding";
import type { TraceItem } from "../types";
import { BeautifulToolChipTrigger } from "./beautiful-ui/BeautifulUI";

export function ToolCall({ item }: { item: TraceItem }) {
  const [open, setOpen] = useState(false);
  const state = item.status === "failed" ? "error" : item.status === "running" ? "running" : "completed";
  const presentation = item.presentation?.kind === "tool_call" ? item.presentation : undefined;
  const toolName = brandDisplayText(item.tool_name || stringValue(presentation?.tool_name) || item.title || item.node);
  const input = item.input || objectValue(presentation?.input);
  const output = item.output || presentation?.output;
  const error = brandDisplayText(item.error || stringValue(presentation?.error));
  return (
    <div className={`tool-call ${state} tool-stream-in`}>
      <BeautifulToolChipTrigger
        state={state}
        name={toolName}
        meta={item.duration_ms ? `${(item.duration_ms / 1000).toFixed(1)}s` : stateLabel(state)}
        open={open}
        onToggle={() => setOpen((value) => !value)}
      />
      <div className={`tool-call-collapse ${open ? "expanded" : ""}`} aria-hidden={!open}>
        <div className="tool-call-collapse-inner">
          <div className="tool-call-content">
            {input ? <JsonBlock label="Request" value={input} /> : null}
            {output ? <JsonBlock label="Response" value={output} /> : null}
            {error ? <p className="tool-error">{error}</p> : null}
          </div>
        </div>
      </div>
    </div>
  );
}

function JsonBlock({ label, value }: { label: string; value: unknown }) {
  return <div><strong className="tool-json-heading">{label}</strong><pre>{JSON.stringify(value, null, 2)}</pre></div>;
}

const stateLabel = (state: string) => state === "error" ? "执行失败" : state === "running" ? "运行中" : "已完成";
const stringValue = (value: unknown) => typeof value === "string" ? value : "";
const objectValue = (value: unknown) => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
