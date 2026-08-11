import { Archive, Bot, FileSearch, FolderOpen, Search, Settings, ShieldCheck, Sparkles } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { chooseProjectDirectory, openNewTaskWindow } from "../lib/platform";
import { useAppStore, type WorkspaceView } from "../store/appStore";

const commands: Array<{ id: string; label: string; hint: string; icon: React.ReactNode; view?: WorkspaceView; action?: "project" | "new" }> = [
  { id: "new", label: "新建安全任务", hint: "开始新的 Agent 对话", icon: <Sparkles />, action: "new" },
  { id: "project", label: "打开代码项目", hint: "选择本机项目目录", icon: <FolderOpen />, action: "project" },
  { id: "intelligence", label: "查看漏洞情报", hint: "最新 CVE、KEV 和利用状态", icon: <ShieldCheck />, view: "intelligence" },
  { id: "records", label: "查询漏洞库", hint: "搜索结构化漏洞记录", icon: <FileSearch />, view: "records" },
  { id: "archive", label: "打开归档", hint: "历史任务和对话", icon: <Archive />, view: "archive" },
  { id: "settings", label: "打开设置", hint: "资料、模型和外观", icon: <Settings />, view: "settings" },
];

export function CommandPalette() {
  const state = useAppStore();
  const [query, setQuery] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const visible = useMemo(() => commands.filter((item) => `${item.label} ${item.hint}`.toLowerCase().includes(query.toLowerCase())), [query]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); state.set({ commandOpen: !state.commandOpen }); }
      if (event.key === "Escape") state.set({ commandOpen: false });
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [state]);

  useEffect(() => { if (state.commandOpen) window.setTimeout(() => input.current?.focus(), 30); }, [state.commandOpen]);
  if (!state.commandOpen) return null;

  const run = async (command: (typeof commands)[number]) => {
    if (command.action === "new") await openNewTaskWindow();
    if (command.action === "project") {
      const path = await chooseProjectDirectory();
      if (path) state.selectWorkspace(path);
    }
    if (command.view) state.set({ view: command.view });
    state.set({ commandOpen: false });
  };

  return (
    <div className="palette-backdrop" onMouseDown={() => state.set({ commandOpen: false })}>
      <div className="command-palette" onMouseDown={(event) => event.stopPropagation()}>
        <header><Search size={17} /><input ref={input} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索任务、项目或命令" /><kbd>ESC</kbd></header>
        <div className="command-results"><label>命令</label>{visible.map((command) => <button key={command.id} onClick={() => void run(command)}>{command.icon}<span><strong>{command.label}</strong><small>{command.hint}</small></span></button>)}{!visible.length ? <p><Bot size={18} />没有匹配的命令</p> : null}</div>
      </div>
    </div>
  );
}
