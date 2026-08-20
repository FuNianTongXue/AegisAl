import {
  ArrowLeft,
  ChevronDown,
  CircleHelp,
  Command,
  Folder,
  MoreHorizontal,
  PanelRight,
  RefreshCcw,
  Search,
  Wifi,
  WifiOff,
} from "lucide-react";

import { useI18n } from "../i18n";
import { chooseProjectDirectory, openNewTaskWindow } from "../lib/platform";
import { handleWindowDrag } from "../lib/windowDrag";
import { useAppStore } from "../store/appStore";

export function Topbar({ onRefresh }: { onRefresh: () => void }) {
  const state = useAppStore();
  const { t } = useI18n();
  const connected = state.health?.ok;
  const activeTask = state.tasks.find((task) => task.id === state.activeTaskId);
  const latestUserTurn = [...state.turns].reverse().find((turn) => turn.role === "user");
  const taskTitle = activeTask?.objective || latestUserTurn?.content || t("新建安全任务");

  const chooseWorkspace = async () => {
    const path = await chooseProjectDirectory();
    if (!path) return;
    state.selectWorkspace(path);
  };

  if (state.view === "assistant") {
    return (
      <header className="topbar zcode-topbar" data-tauri-drag-region onMouseDown={handleWindowDrag}>
        <div className="topbar-history" aria-label={t("任务导航")}>
          <button aria-label={t("后退")} title={t("返回任务主页")} disabled={!state.turns.length && !state.activeTaskId} onClick={state.returnToTaskHome}><ArrowLeft size={17} /></button>
        </div>
        <div className="topbar-task" data-tauri-drag-region>
          <strong data-tauri-drag-region title={taskTitle}>{taskTitle}</strong>
          <button className="topbar-project" onClick={() => void chooseWorkspace()} title={t("选择代码项目")}><Folder size={15} /><span>{state.workspaceName || "default"}</span><ChevronDown size={13} /></button>
          <details className="topbar-overflow">
            <summary aria-label={t("更多任务操作")} title={t("更多任务操作")}><MoreHorizontal size={17} /></summary>
            <div className="context-menu">
              <button onClick={() => void openNewTaskWindow()}>{t("新建任务")}</button>
              <button onClick={() => state.set({ commandOpen: true })}>{t("搜索命令")}</button>
              <button onClick={() => state.set({ view: "settings" })}>{t("打开设置")}</button>
            </div>
          </details>
        </div>
        <div className="topbar-actions">
          <span className={`connection-state connection-state-icon ${connected ? "online" : "offline"}`} role="status" aria-live="polite" aria-label={connected ? t("{count} 个 Worker 正常", { count: state.health?.task_execution.running_workers || 0 }) : t("正在连接本机服务")} title={connected ? t("{count} 个 Worker 正常", { count: state.health?.task_execution.running_workers || 0 }) : t("正在连接本机服务")}>{connected ? <Wifi size={14} aria-hidden="true" /> : <WifiOff size={14} aria-hidden="true" />}</span>
          <button aria-label={t("帮助与命令")} title={t("帮助与命令")} onClick={() => state.set({ commandOpen: true })}><CircleHelp size={17} /></button>
          <button aria-label={t("刷新本机服务")} title={t("刷新本机服务")} onClick={onRefresh}><RefreshCcw size={16} /></button>
          <button aria-label={t("Agent 执行面板")} aria-pressed={state.inspectorOpen} title={t("Agent 执行面板")} className={state.inspectorOpen ? "active" : ""} onClick={() => state.set({ inspectorOpen: !state.inspectorOpen })}><PanelRight size={17} /></button>
        </div>
      </header>
    );
  }

  return (
    <header className="topbar" data-tauri-drag-region onMouseDown={handleWindowDrag}>
      <div className="topbar-title" data-tauri-drag-region>
        <strong data-tauri-drag-region>{viewTitle(state.view, t)}</strong>
        {state.workspaceName ? <span data-tauri-drag-region>{state.workspaceName}</span> : null}
      </div>
      <div className="topbar-actions">
        <button className="command-trigger" onClick={() => state.set({ commandOpen: true })}><Search size={14} /><span>{t("搜索或执行命令")}</span><kbd><Command size={11} /> K</kbd></button>
        <span className={`connection-state ${connected ? "online" : "offline"}`} role="status" aria-live="polite" aria-label={connected ? t("本机服务正常") : t("正在连接本机服务")} title={connected ? t("本机服务正常") : t("正在连接本机服务")}>{connected ? <Wifi size={14} aria-hidden="true" /> : <WifiOff size={14} aria-hidden="true" />}{state.health?.task_execution.running_workers || 0} Worker</span>
        <button aria-label={t("刷新")} title={t("刷新")} onClick={onRefresh}><RefreshCcw size={16} /></button>
        <button aria-label={t("执行面板")} aria-pressed={state.inspectorOpen} title={t("执行面板")} className={state.inspectorOpen ? "active" : ""} onClick={() => state.set({ inspectorOpen: !state.inspectorOpen })}><PanelRight size={16} /></button>
      </div>
    </header>
  );
}

const viewTitle = (view: string, t: (source: string) => string) => t(({ assistant: "安全分析", intelligence: "漏洞情报", records: "漏洞库", settings: "设置", archive: "归档" }[view] || "安全分析"));
