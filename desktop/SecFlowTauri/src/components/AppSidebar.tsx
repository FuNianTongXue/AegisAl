import {
  Archive,
  ChevronDown,
  FileSearch,
  FolderKanban,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Trash2,
  Workflow,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { clientLocaleTag, type ClientLocale, useI18n } from "../i18n";
import { api } from "../lib/api";
import { openNewTaskWindow } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import type { AgentTask, ConversationSummary } from "../types";
import { BrandMark } from "./BrandMark";
import { ProfileAvatar } from "./ProfileAvatar";

const HISTORY_PAGE_SIZE = 40;

export function AppSidebar() {
  const [projectsOpen, setProjectsOpen] = useState(true);
  const [historyOpen, setHistoryOpen] = useState(true);
  const [openingSessionId, setOpeningSessionId] = useState("");
  const [conversationError, setConversationError] = useState("");
  const [visibleConversationCount, setVisibleConversationCount] = useState(HISTORY_PAGE_SIZE);
  const conversationRequest = useRef(0);
  const state = useAppStore();
  const { locale, t } = useI18n();
  const projects = useMemo(() => groupProjects(state.tasks), [state.tasks]);

  useEffect(() => {
    setVisibleConversationCount(HISTORY_PAGE_SIZE);
  }, [state.conversations]);

  const cancelConversationOpen = () => {
    conversationRequest.current += 1;
    setOpeningSessionId("");
    setConversationError("");
  };

  const openTask = (task: AgentTask) => {
    cancelConversationOpen();
    state.set({
      view: "assistant",
      activeTaskId: task.id,
      activeSessionId: "",
      workspacePath: task.workspace_path,
      workspaceName: task.workspace_name,
      composerAttachment: null,
      composerAttachmentLeaving: false,
      turns: [{
        id: `task:${task.id}`,
        role: "assistant",
        content: task.objective,
        createdAt: task.updated_at,
        state: task.status === "failed" ? "error" : "completed",
        task,
      }],
    });
  };

  const openConversation = async (conversation: ConversationSummary) => {
    const sessionId = conversation.session_id || conversation.id;
    const requestId = ++conversationRequest.current;
    setOpeningSessionId(sessionId);
    setConversationError("");
    state.set({
      view: "assistant",
      activeSessionId: sessionId,
      activeTaskId: "",
      workspacePath: "",
      workspaceName: "",
      composerAttachment: null,
      composerAttachmentLeaving: false,
      turns: [],
    });
    try {
      const detail = await api.conversation(sessionId, state.userId);
      if (conversationRequest.current !== requestId) return;
      const current = useAppStore.getState();
      const conversationStillExists = current.conversations.some((item) => (
        item.id === conversation.id || (item.session_id || item.id) === sessionId
      ));
      if (!conversationStillExists || current.activeSessionId !== sessionId || current.turns.length > 0) return;
      state.set({
        turns: detail.exchanges.flatMap((exchange) => {
          // Newer backends persist the complete structured answer as
          // `answer_payload`; older desktop data used `result`.
          const result = exchange.answer_payload || exchange.result;
          return [
            { id: `${exchange.id}:user`, role: "user" as const, content: exchange.question, createdAt: exchange.created_at || detail.updated_at },
            {
              id: `${exchange.id}:assistant`,
              role: "assistant" as const,
              content: exchange.answer,
              createdAt: exchange.created_at || detail.updated_at,
              result,
              trace: result?.trace,
              state: "completed" as const,
            },
          ];
        }),
      });
    } catch (error) {
      if (conversationRequest.current !== requestId) return;
      const current = useAppStore.getState();
      if (current.activeSessionId !== sessionId || current.turns.length > 0) return;
      const message = error instanceof Error && error.message ? error.message : t("无法加载对话");
      setConversationError(`${t("无法加载对话")}：${message}`);
      state.set({ activeSessionId: "", turns: [] });
    } finally {
      if (conversationRequest.current === requestId) setOpeningSessionId("");
    }
  };

  return (
    <aside className="app-sidebar" aria-label={t("项目与任务导航")}>
      <div className="sidebar-spacer" data-tauri-drag-region>
        <button
          className="sidebar-collapse-button"
          aria-label={t(state.sidebarOpen ? "收起侧边栏" : "展开侧边栏")}
          title={t(state.sidebarOpen ? "收起侧边栏" : "展开侧边栏")}
          onClick={() => state.set({ sidebarOpen: !state.sidebarOpen })}
        >
          {state.sidebarOpen ? <PanelLeftClose size={16} /> : <PanelLeftOpen size={16} />}
        </button>
      </div>
      <div className="sidebar-brand">
        <BrandMark />
        <strong>安全智脑</strong>
      </div>
      <button className="sidebar-command primary" aria-label={t("新建任务")} onClick={() => void openNewTaskWindow()}>
        <Plus size={17} />
        <span>{t("新建任务")}</span>
        <kbd>⌘ N</kbd>
      </button>

      <nav className="sidebar-shortcuts" aria-label={t("功能入口")}>
        <button aria-label={t("搜索")} onClick={() => state.set({ commandOpen: true })}>
          <Search size={17} />
          <span>{t("搜索")}</span>
          <kbd>⌘ K</kbd>
        </button>
        <button aria-label={t("漏洞情报")} className={state.view === "intelligence" ? "active" : ""} onClick={() => { cancelConversationOpen(); state.set({ view: "intelligence" }); }}>
          <ShieldCheck size={17} />
          <span>{t("漏洞情报")}</span>
        </button>
        <button aria-label={t("漏洞库")} className={state.view === "records" ? "active" : ""} onClick={() => { cancelConversationOpen(); state.set({ view: "records" }); }}>
          <FileSearch size={17} />
          <span>{t("漏洞库")}</span>
        </button>
      </nav>

      <div className="sidebar-view-switch" role="group" aria-label={t("导航视图")}>
        <button
          aria-label={t("项目")}
          aria-pressed={state.sidebarView === "projects"}
          className={state.sidebarView === "projects" ? "active" : ""}
          onClick={() => {
            cancelConversationOpen();
            setVisibleConversationCount(HISTORY_PAGE_SIZE);
            state.set({ sidebarView: "projects" });
          }}
        >
          <FolderKanban size={14} /><span>{t("项目")}</span>
        </button>
        <button
          aria-label={t("任务")}
          aria-pressed={state.sidebarView === "tasks"}
          className={state.sidebarView === "tasks" ? "active" : ""}
          onClick={() => {
            cancelConversationOpen();
            setVisibleConversationCount(HISTORY_PAGE_SIZE);
            state.returnToTaskHome();
          }}
        >
          <Workflow size={14} /><span>{t("任务")}</span>
        </button>
      </div>

      <div className="sidebar-scroll">
        {state.sidebarView === "projects" ? (
          <SidebarSection title={t("项目")} open={projectsOpen} onToggle={() => setProjectsOpen((value) => !value)} icon={<FolderKanban size={14} />}>
            {projects.length ? (
              projects.map((project) => (
                <div className="project-group" key={project.path}>
                  <div className="project-title"><span>{project.name}</span><small>{project.tasks.length}</small></div>
                  {project.tasks.slice(0, 8).map((task) => (
                    <ItemMenu
                      key={task.id}
                      title={task.objective}
                      meta={taskStatusLabel(task.status, t)}
                      active={state.activeTaskId === task.id}
                      onOpen={() => openTask(task)}
                      onArchive={() => void api.archiveTask(task.id, state.userId, true).then(() => state.set({ tasks: state.tasks.filter((item) => item.id !== task.id) }))}
                      onDelete={() => {
                        if (!window.confirm(t("确定删除任务“{name}”？此操作无法撤销。", { name: task.objective }))) return;
                        void api.deleteTask(task.id, state.userId).then(() => state.removeTask(task.id));
                      }}
                    />
                  ))}
                </div>
              ))
            ) : <p className="sidebar-empty">{t("尚未打开项目")}</p>}
          </SidebarSection>
        ) : (
          <SidebarSection title={t("任务")} open={historyOpen} onToggle={() => setHistoryOpen((value) => !value)}>
            {state.conversations.length ? state.conversations.slice(0, visibleConversationCount).map((conversation) => (
              <ItemMenu
                key={conversation.id}
                title={conversation.title || conversation.preview || t("未命名对话")}
                meta={formatRelative(conversation.updated_at, locale, t)}
                active={state.activeSessionId === (conversation.session_id || conversation.id)}
                busy={openingSessionId === (conversation.session_id || conversation.id)}
                onOpen={() => void openConversation(conversation)}
                onArchive={() => void api.archiveConversation(conversation.session_id || conversation.id, state.userId, true).then(() => state.set({ conversations: state.conversations.filter((item) => item.id !== conversation.id) }))}
                onDelete={() => {
                  const sessionId = conversation.session_id || conversation.id;
                  if (!window.confirm(t("确定删除对话“{name}”？此操作无法撤销。", { name: conversation.title || conversation.preview || t("未命名对话") }))) return;
                  void api.deleteConversation(sessionId, state.userId).then(() => state.removeConversation(sessionId, conversation.id));
                }}
              />
            )) : <p className="sidebar-empty">{t("暂无历史任务")}</p>}
            {state.conversations.length > visibleConversationCount ? (
              <button
                type="button"
                className="archive-entry"
                aria-label={t("显示更多")}
                onClick={() => setVisibleConversationCount((count) => Math.min(count + HISTORY_PAGE_SIZE, state.conversations.length))}
              >
                <span>{t("显示更多")}</span>
                <small aria-hidden="true">{state.conversations.length - visibleConversationCount}</small>
              </button>
            ) : null}
            {conversationError ? <p className="sidebar-empty" role="alert">{conversationError}</p> : null}
          </SidebarSection>
        )}

        <button className="archive-entry" aria-label={t("归档")} onClick={() => { cancelConversationOpen(); state.set({ view: "archive" }); }}>
          <Archive size={15} /><span>{t("归档")}</span><small>{state.archivedTasks.length + state.archivedConversations.length}</small>
        </button>
      </div>

      <div className="sidebar-footer">
        <button className="user-footer" aria-label={t("用户资料")} onClick={() => { cancelConversationOpen(); state.set({ view: "settings" }); }}>
          <ProfileAvatar profile={state.settings?.profile} userId={state.userId} className="user-footer-avatar" />
          <span><strong>{state.settings?.profile.display_name || t("本机用户")}</strong><small>{state.llm?.model || t("连接使用")}</small></span>
        </button>
        <button className="sidebar-settings" aria-label={t("设置")} title={t("设置")} onClick={() => { cancelConversationOpen(); state.set({ view: "settings" }); }}><Settings size={17} /></button>
      </div>
    </aside>
  );
}

function SidebarSection({ title, open, onToggle, icon, children }: React.PropsWithChildren<{ title: string; open: boolean; onToggle: () => void; icon?: React.ReactNode }>) {
  return (
    <section className="sidebar-section">
      <button className="section-heading" onClick={onToggle} aria-expanded={open}>
        {icon}<span>{title}</span><ChevronDown size={14} className={open ? "" : "rotated"} />
      </button>
      {open && <div className="section-content">{children}</div>}
    </section>
  );
}

function ItemMenu({ title, meta, active, busy = false, onOpen, onArchive, onDelete }: { title: string; meta: string; active: boolean; busy?: boolean; onOpen: () => void; onArchive: () => void; onDelete: () => void }) {
  const { t } = useI18n();
  return (
    <div className={`sidebar-item ${active ? "active" : ""}`}>
      <button className="item-main" onClick={onOpen} disabled={busy} aria-busy={busy || undefined}><span>{title}</span><small>{busy ? t("正在加载…") : meta}</small></button>
      <details className="item-menu">
        <summary aria-label={t("更多操作")}><MoreHorizontal size={14} /></summary>
        <div className="context-menu">
          <button onClick={onArchive}><Archive size={14} />{t("归档")}</button>
          <button className="danger" onClick={onDelete}><Trash2 size={14} />{t("删除")}</button>
        </div>
      </details>
    </div>
  );
}

function groupProjects(tasks: AgentTask[]) {
  const grouped = new Map<string, AgentTask[]>();
  tasks.forEach((task) => grouped.set(task.workspace_path, [...(grouped.get(task.workspace_path) || []), task]));
  return [...grouped.entries()].map(([path, items]) => ({ path, name: items[0]?.workspace_name || path.split("/").pop() || path, tasks: items }));
}

const taskStatusLabel = (status: string, t: (source: string) => string) => t(({ queued: "排队", running: "分析中", completed: "完成", failed: "失败", cancelled: "已停止" }[status] || status));

function formatRelative(value: string, locale: ClientLocale, t: (source: string) => string) {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return value;

  const delta = timestamp - Date.now();
  const absoluteDelta = Math.abs(delta);
  if (absoluteDelta < 60_000) return t("刚刚");

  const [divisor, unit]: [number, Intl.RelativeTimeFormatUnit] = absoluteDelta < 3_600_000
    ? [60_000, "minute"]
    : absoluteDelta < 86_400_000
      ? [3_600_000, "hour"]
      : [86_400_000, "day"];
  return new Intl.RelativeTimeFormat(clientLocaleTag(locale), { numeric: "auto" }).format(Math.round(delta / divisor), unit);
}
