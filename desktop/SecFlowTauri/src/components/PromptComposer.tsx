import { ArrowUp, BrainCircuit, Check, ChevronDown, FolderOpen, Plus, Settings2, Square, X } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";

import { useI18n } from "../i18n";
import { api } from "../lib/api";
import { modelOptionsFor, normalizedReasoningEffort, reasoningDescription, reasoningLabel, reasoningOptionsFor } from "../lib/modelControls";
import { chooseProjectDirectory, listenForProjectDirectoryDrop } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import type { ReasoningEffort } from "../types";

const commands = [
  { value: "/scan", label: "完整代码扫描", hint: "AST / CFG / DFG / 污点" },
  { value: "/sbom", label: "导出 SBOM", hint: "依赖、许可与漏洞匹配" },
  { value: "/cve", label: "查询漏洞情报", hint: "NVD / GHSA / KEV" },
  { value: "/report", label: "生成安全报告", hint: "PDF / HTML / Word / Excel / MD" },
  { value: "/code-review", label: "代码安全审查", hint: "证据与修复建议" },
];

/** 附件 chip 退出动画时长（与 styles.css 中 .workspace-chip-shell.leaving 的过渡一致）。 */
const CHIP_EXIT_MS = 190;

export function PromptComposer({
  busy,
  onSubmit,
  onStop,
}: {
  busy: boolean;
  /** 返回 false 表示消息被拦截（如扫描类型确认），附件应保留等待确认；其余情况附件随消息一并消耗。 */
  onSubmit: (value: string, attachment: { path: string; name: string } | null) => boolean | void;
  onStop: () => void;
}) {
  const [value, setValue] = useState("");
  const [focused, setFocused] = useState(false);
  const [dropActive, setDropActive] = useState(false);
  const [dropError, setDropError] = useState("");
  const [modelMenu, setModelMenu] = useState<"model" | "reasoning" | null>(null);
  const [modelBusy, setModelBusy] = useState(false);
  const [modelError, setModelError] = useState("");
  const textarea = useRef<HTMLTextAreaElement>(null);
  const modelControl = useRef<HTMLDivElement>(null);
  const modelTrigger = useRef<HTMLButtonElement>(null);
  const reasoningTrigger = useRef<HTMLButtonElement>(null);
  const modelMenuPanel = useRef<HTMLDivElement>(null);
  const menuInitialFocus = useRef<"selected" | "first" | "last">("selected");
  const modelMenuId = useId();
  const state = useAppStore();
  const { t } = useI18n();
  const attachment = state.composerAttachment;
  const suggestions = useMemo(() => value.startsWith("/") ? commands.filter((command) => command.value.startsWith(value.split(/\s/)[0])) : [], [value]);
  const modelOptions = useMemo(() => modelOptionsFor(state.llm), [state.llm]);
  const reasoningOptions = useMemo(() => reasoningOptionsFor(state.llm), [state.llm]);
  const currentReasoning = normalizedReasoningEffort(state.llm || {}, state.llm?.reasoning_effort);
  const promptLabel = t(state.turns.length
    ? "提出后续修改要求"
    : attachment || state.workspacePath
      ? "描述需要对该项目执行的安全任务"
      : "描述需要完成的安全任务");

  useEffect(() => {
    if (!modelMenu) return;
    const activeMenu = modelMenu;
    focusMenuItem(modelMenuPanel.current, menuInitialFocus.current);
    const dismiss = (event: PointerEvent) => {
      if (!modelControl.current?.contains(event.target as Node)) setModelMenu(null);
    };
    const dismissOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      setModelMenu(null);
      (activeMenu === "model" ? modelTrigger.current : reasoningTrigger.current)?.focus();
    };
    document.addEventListener("pointerdown", dismiss);
    document.addEventListener("keydown", dismissOnEscape);
    return () => {
      document.removeEventListener("pointerdown", dismiss);
      document.removeEventListener("keydown", dismissOnEscape);
    };
  }, [modelMenu]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listenForProjectDirectoryDrop({
      onActive: (active) => { if (!disposed) setDropActive(active); },
      onDrop: (path) => {
        if (disposed) return;
        attachProject(path);
      },
      onError: (message) => { if (!disposed) setDropError(String(message)); },
    }).then((stop) => {
      if (disposed) stop();
      else unlisten = stop;
    }).catch((error) => {
      if (!disposed) setDropError(String(error));
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 附件被标记消耗（发送成功 / 手动移除）后，播放退出动画再真正卸载 chip。
  const attachmentLeaving = state.composerAttachmentLeaving;
  useEffect(() => {
    if (!attachmentLeaving) return;
    const timer = window.setTimeout(() => {
      useAppStore.getState().set({ composerAttachment: null, composerAttachmentLeaving: false });
    }, CHIP_EXIT_MS);
    return () => window.clearTimeout(timer);
  }, [attachmentLeaving]);

  const attachProject = (path: string) => {
    setDropError("");
    state.set({
      composerAttachment: { path, name: path.split(/[\\/]/).filter(Boolean).pop() || path },
      composerAttachmentLeaving: false,
    });
    textarea.current?.focus();
  };

  const dismissAttachment = () => {
    if (!attachment || state.composerAttachmentLeaving) return;
    state.set({ composerAttachmentLeaving: true });
  };

  const submit = () => {
    const clean = value.trim();
    if (!clean || busy) return;
    const consumed = onSubmit(clean, attachment);
    setValue("");
    // 被扫描类型确认拦截时保留附件，待用户确认后随确认动作一并提交。
    if (consumed !== false && attachment) dismissAttachment();
  };

  const chooseProject = async () => {
    const path = await chooseProjectDirectory();
    if (!path) return;
    attachProject(path);
  };

  const openModelMenu = (menu: "model" | "reasoning", initialFocus: "selected" | "first" | "last" = "selected") => {
    menuInitialFocus.current = initialFocus;
    if (modelMenu === menu) {
      focusMenuItem(modelMenuPanel.current, initialFocus);
      return;
    }
    setModelMenu(menu);
  };

  const toggleModelMenu = (menu: "model" | "reasoning") => {
    if (modelMenu === menu) {
      setModelMenu(null);
      return;
    }
    openModelMenu(menu);
  };

  const handleTriggerKeyDown = (event: React.KeyboardEvent, menu: "model" | "reasoning") => {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    event.preventDefault();
    openModelMenu(menu, event.key === "ArrowDown" ? "first" : "last");
  };

  const handleMenuKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Tab") {
      event.preventDefault();
      const trigger = modelMenu === "model" ? modelTrigger.current : reasoningTrigger.current;
      setModelMenu(null);
      focusAdjacentTabStop(trigger, event.shiftKey);
      return;
    }
    const items = menuItems(event.currentTarget);
    if (!items.length) return;
    const currentIndex = items.indexOf(document.activeElement as HTMLElement);
    let targetIndex: number | null = null;
    if (event.key === "ArrowDown") targetIndex = currentIndex < 0 ? 0 : (currentIndex + 1) % items.length;
    if (event.key === "ArrowUp") targetIndex = currentIndex < 0 ? items.length - 1 : (currentIndex - 1 + items.length) % items.length;
    if (event.key === "Home") targetIndex = 0;
    if (event.key === "End") targetIndex = items.length - 1;
    if (targetIndex === null) return;
    event.preventDefault();
    items[targetIndex]?.focus();
  };

  const saveModelPatch = async (patch: Partial<NonNullable<typeof state.llm>>) => {
    if (!state.llm || modelBusy) return;
    setModelBusy(true);
    setModelError("");
    try {
      const result = await api.saveLlmConfig(state.userId, { ...state.llm, ...patch });
      useAppStore.getState().set({ llm: result });
      const trigger = modelMenu === "model" ? modelTrigger.current : reasoningTrigger.current;
      setModelMenu(null);
      trigger?.focus();
    } catch (error) {
      setModelError(error instanceof Error ? error.message : String(error));
    } finally {
      setModelBusy(false);
    }
  };

  const chooseModel = (model: string) => {
    if (!state.llm || model === state.llm.model) {
      setModelMenu(null);
      modelTrigger.current?.focus();
      return;
    }
    const target = { ...state.llm, model, reasoning_options: undefined };
    void saveModelPatch({
      model,
      reasoning_effort: normalizedReasoningEffort(target, state.llm.reasoning_effort),
    });
  };

  const chooseReasoning = (reasoning_effort: ReasoningEffort) => {
    if (reasoning_effort === currentReasoning) {
      setModelMenu(null);
      reasoningTrigger.current?.focus();
      return;
    }
    void saveModelPatch({ reasoning_effort });
  };

  return (
    <div className="composer-zone">
      {suggestions.length ? (
        <div className="command-suggestions">
          {suggestions.map((command) => <button key={command.value} onClick={() => { setValue(`${command.value} `); textarea.current?.focus(); }}><code>{command.value}</code><span><strong>{t(command.label)}</strong><small>{t(command.hint)}</small></span></button>)}
        </div>
      ) : null}
      {attachment ? (
        <div className={`workspace-chip-shell ${state.composerAttachmentLeaving ? "leaving" : ""}`}>
          <div>
            <div className="workspace-chip">
              <FolderOpen size={14} />
              <span><strong>{attachment.name}</strong><small>{attachment.path}</small></span>
              <button type="button" aria-label={t("移除项目附件")} title={t("移除项目附件")} onClick={dismissAttachment}><X size={13} /></button>
            </div>
          </div>
        </div>
      ) : null}
      <div className={`prompt-composer ${focused ? "focused" : ""} ${dropActive ? "drop-active" : ""} ${modelMenu ? "model-menu-open" : ""}`}>
        {dropActive ? <div className="project-drop-indicator"><FolderOpen size={18} /><span>{t("松开以关联整个项目")}</span></div> : null}
        <textarea
          ref={textarea}
          name="assistant-prompt"
          autoComplete="off"
          aria-label={promptLabel}
          value={value}
          rows={3}
          placeholder={`${promptLabel}…`}
          onChange={(event) => setValue(event.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); submit(); }
          }}
        />
        <footer>
          <div className="composer-tools composer-context-tools">
            <button type="button" title={t("添加代码项目")} aria-label={t("添加上下文")} onClick={() => void chooseProject()}><Plus size={18} /></button>
          </div>
          <div className="composer-submit-tools">
            <div className="model-control" ref={modelControl}>
              <div className={`model-control-trigger ${modelMenu ? "open" : ""}`}>
                <button
                  ref={modelTrigger}
                  className="model-selector"
                  type="button"
                  aria-haspopup="menu"
                  aria-expanded={modelMenu === "model"}
                  aria-controls={modelMenu === "model" ? modelMenuId : undefined}
                  title={t("选择模型")}
                  onClick={() => toggleModelMenu("model")}
                  onKeyDown={(event) => handleTriggerKeyDown(event, "model")}
                  disabled={!state.llm || modelBusy}
                >
                  <span>{state.llm?.model || (state.health?.ok ? t("选择模型") : t("模型接入中…"))}</span>
                  <ChevronDown size={13} />
                </button>
                {state.llm ? <span className="model-control-divider" aria-hidden="true" /> : null}
                {state.llm ? (
                  <button
                    ref={reasoningTrigger}
                    className="reasoning-selector"
                    type="button"
                    aria-haspopup="menu"
                    aria-expanded={modelMenu === "reasoning"}
                    aria-controls={modelMenu === "reasoning" ? modelMenuId : undefined}
                    aria-label={t("选择推理强度")}
                    title={t("选择推理强度")}
                    onClick={() => toggleModelMenu("reasoning")}
                    onKeyDown={(event) => handleTriggerKeyDown(event, "reasoning")}
                    disabled={modelBusy}
                  >
                    <BrainCircuit size={14} />
                    <span>{t(reasoningLabel(currentReasoning))}</span>
                    <ChevronDown size={12} />
                  </button>
                ) : null}
              </div>
              {modelMenu ? (
                <div
                  id={modelMenuId}
                  ref={modelMenuPanel}
                  className="model-control-menu"
                  role="menu"
                  aria-label={modelMenu === "model" ? t("选择模型") : t("选择推理强度")}
                  onKeyDown={handleMenuKeyDown}
                >
                  <div className="model-control-menu-title">
                    <span>{modelMenu === "model" ? t("当前模型") : t("推理强度")}</span>
                    {modelBusy ? <small>{t("正在更新模型")}</small> : null}
                  </div>
                  {modelMenu === "model" ? modelOptions.map((model) => (
                    <button key={model} type="button" role="menuitemradio" tabIndex={-1} aria-checked={state.llm?.model === model} onClick={() => chooseModel(model)} disabled={modelBusy}>
                      <span><strong>{model}</strong><small>{model.includes("reasoner") || model.includes("thinking") ? t("深度推理模型") : t("通用模型")}</small></span>
                      {state.llm?.model === model ? <Check size={15} /> : null}
                    </button>
                  )) : reasoningOptions.map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      role="menuitemradio"
                      tabIndex={-1}
                      aria-checked={currentReasoning === option.value}
                      aria-disabled={modelBusy || Boolean(option.fixed)}
                      onClick={() => { if (!option.fixed) chooseReasoning(option.value); }}
                      disabled={modelBusy}
                    >
                      <span><strong>{t(reasoningLabel(option.value))}</strong><small>{option.fixed ? t("当前模型的固定模式") : t(reasoningDescription(option.value))}</small></span>
                      {currentReasoning === option.value ? <Check size={15} /> : null}
                    </button>
                  ))}
                  {modelMenu === "model" ? <button type="button" role="menuitem" tabIndex={-1} className="model-control-manage" onClick={() => { setModelMenu(null); state.set({ view: "settings" }); }}><Settings2 size={14} /><span><strong>{t("管理模型接入")}</strong></span></button> : null}
                  {modelError ? <p role="alert">{modelError}</p> : null}
                </div>
              ) : null}
            </div>
            {busy ? <button type="button" className="stop-button" onClick={onStop}><Square size={12} /><span>{t("停止")}</span></button> : <button type="button" className="send-button" disabled={!value.trim()} onClick={submit} title={t("发送")} aria-label={t("发送")}><ArrowUp size={18} /></button>}
          </div>
        </footer>
      </div>
      {dropError ? <div className="project-drop-error" role="alert">{dropError}</div> : null}
    </div>
  );
}

const MENU_ITEM_SELECTOR = '[role="menuitemradio"], [role="menuitem"]';
const TAB_STOP_SELECTOR = [
  'button:not([disabled]):not([tabindex="-1"])',
  '[href]:not([tabindex="-1"])',
  'input:not([disabled]):not([tabindex="-1"])',
  'select:not([disabled]):not([tabindex="-1"])',
  'textarea:not([disabled]):not([tabindex="-1"])',
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function menuItems(container: HTMLElement | null) {
  if (!container) return [];
  return Array.from(container.querySelectorAll<HTMLElement>(MENU_ITEM_SELECTOR))
    .filter((item) => !(item instanceof HTMLButtonElement && item.disabled));
}

function focusMenuItem(container: HTMLElement | null, initial: "selected" | "first" | "last") {
  const items = menuItems(container);
  if (!items.length) return;
  const selected = items.find((item) => item.getAttribute("aria-checked") === "true");
  const target = initial === "first"
    ? items[0]
    : initial === "last"
      ? items[items.length - 1]
      : selected || items[0];
  target?.focus();
}

function focusAdjacentTabStop(origin: HTMLElement | null, backwards: boolean) {
  if (!origin) return;
  const stops = Array.from(document.querySelectorAll<HTMLElement>(TAB_STOP_SELECTOR))
    .filter((element) => !element.hidden && !element.closest("[inert]"));
  const index = stops.indexOf(origin);
  if (index < 0) return;
  const target = stops[index + (backwards ? -1 : 1)];
  target?.focus();
}
