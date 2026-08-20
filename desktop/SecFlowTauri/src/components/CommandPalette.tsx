import { Archive, Bot, FileSearch, FolderOpen, Search, Settings, ShieldCheck, Sparkles } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { useI18n } from "../i18n";
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
  const { t } = useI18n();
  const [query, setQuery] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const backdrop = useRef<HTMLDivElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const visible = useMemo(() => commands.filter((item) => `${item.label} ${item.hint}`.toLowerCase().includes(query.toLowerCase())), [query]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const current = useAppStore.getState();
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        const activeModal = document.querySelector<HTMLElement>('[aria-modal="true"]');
        event.preventDefault();
        if (activeModal && !backdrop.current?.contains(activeModal)) return;
        current.set({ commandOpen: !current.commandOpen });
      }
      if (event.key === "Escape" && current.commandOpen) {
        event.preventDefault();
        current.set({ commandOpen: false });
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    if (!state.commandOpen) return;
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setQuery("");
    input.current?.focus();
    const restoreBackground = backdrop.current ? isolateBackground(backdrop.current) : () => undefined;
    const trap = (event: KeyboardEvent) => {
      if (event.key === "Tab" && dialog.current) trapFocus(event, dialog.current);
    };
    document.addEventListener("keydown", trap);
    return () => {
      document.removeEventListener("keydown", trap);
      restoreBackground();
      if (previouslyFocused?.isConnected) previouslyFocused.focus();
    };
  }, [state.commandOpen]);

  if (!state.commandOpen) return null;

  const run = async (command: (typeof commands)[number]) => {
    if (command.action === "new") await openNewTaskWindow();
    if (command.action === "project") {
      const path = await chooseProjectDirectory();
      if (path) state.openProjectForTask(path);
    }
    if (command.view) state.set({ view: command.view });
    state.set({ commandOpen: false });
  };

  const focusResult = (index: number) => {
    const buttons = dialog.current?.querySelectorAll<HTMLButtonElement>(".command-results button");
    if (!buttons?.length) return;
    buttons[(index + buttons.length) % buttons.length]?.focus();
  };

  return (
    <div
      className="palette-backdrop"
      ref={backdrop}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) state.set({ commandOpen: false });
      }}
    >
      <div
        ref={dialog}
        className="command-palette"
        role="dialog"
        aria-modal="true"
        aria-label={t("命令")}
      >
        <header>
          <Search size={17} aria-hidden="true" />
          <input
            id="command-palette-query"
            ref={input}
            type="search"
            name="command-query"
            autoComplete="off"
            aria-label={t("搜索命令")}
            aria-controls="command-palette-results"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") { event.preventDefault(); focusResult(0); }
              if (event.key === "ArrowUp") { event.preventDefault(); focusResult(-1); }
              if (event.key === "Enter" && visible[0]) { event.preventDefault(); void run(visible[0]); }
            }}
            placeholder={`${t("搜索任务、项目或命令")}…`}
          />
          <kbd>ESC</kbd>
        </header>
        <div id="command-palette-results" className="command-results">
          <label htmlFor="command-palette-query">{t("命令")}</label>
          {visible.map((command, index) => (
            <button
              key={command.id}
              type="button"
              onClick={() => void run(command)}
              onKeyDown={(event) => {
                if (event.key === "ArrowDown") { event.preventDefault(); focusResult(index + 1); }
                if (event.key === "ArrowUp") { event.preventDefault(); focusResult(index - 1); }
                if (event.key === "Home") { event.preventDefault(); focusResult(0); }
                if (event.key === "End") { event.preventDefault(); focusResult(-1); }
              }}
            >
              {command.icon}
              <span><strong>{t(command.label)}</strong><small>{t(command.hint)}</small></span>
            </button>
          ))}
          {!visible.length ? <p role="status"><Bot size={18} aria-hidden="true" />{t("没有匹配的命令")}</p> : null}
        </div>
      </div>
    </div>
  );
}

const FOCUSABLE = [
  "button:not([disabled])",
  "[href]",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function trapFocus(event: KeyboardEvent, container: HTMLElement) {
  const focusable = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((element) => !element.hidden);
  if (!focusable.length) {
    event.preventDefault();
    container.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const active = document.activeElement;
  if (event.shiftKey && (active === first || !container.contains(active))) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

function isolateBackground(layer: HTMLElement) {
  const siblings = Array.from(layer.parentElement?.children || [])
    .filter((element): element is HTMLElement => element instanceof HTMLElement && element !== layer)
    .map((element) => ({
      element,
      inert: element.inert,
      ariaHidden: element.getAttribute("aria-hidden"),
    }));
  siblings.forEach(({ element }) => {
    element.inert = true;
    element.setAttribute("aria-hidden", "true");
  });
  return () => siblings.forEach(({ element, inert, ariaHidden }) => {
    element.inert = inert;
    if (ariaHidden === null) element.removeAttribute("aria-hidden");
    else element.setAttribute("aria-hidden", ariaHidden);
  });
}
