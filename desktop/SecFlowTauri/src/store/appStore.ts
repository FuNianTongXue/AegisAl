import { create } from "zustand";
import { persist } from "zustand/middleware";

import type {
  AgentTask,
  ChatTurn,
  ConversationSummary,
  HealthSnapshot,
  LlmConfig,
  SettingsSnapshot,
} from "../types";

export type WorkspaceView = "assistant" | "intelligence" | "records" | "settings" | "archive";
export type SidebarView = "projects" | "tasks";

interface AppState {
  userId: string;
  view: WorkspaceView;
  theme: "light" | "dark" | "system";
  fontScale: number;
  sidebarOpen: boolean;
  sidebarView: SidebarView;
  inspectorOpen: boolean;
  commandOpen: boolean;
  bootstrapReady: boolean;
  bootstrapError?: string;
  initialSetupRequired: boolean;
  workspacePath: string;
  workspaceName: string;
  /** 输入区待提交的项目附件：跟随下一次发送一并提交并消耗，不做持久化。 */
  composerAttachment: { path: string; name: string } | null;
  /** 附件 chip 退出动画标记：置位后由输入区在动画结束后清空附件。 */
  composerAttachmentLeaving: boolean;
  activeTaskId: string;
  activeSessionId: string;
  health?: HealthSnapshot;
  settings?: SettingsSnapshot;
  llm?: LlmConfig;
  tasks: AgentTask[];
  archivedTasks: AgentTask[];
  conversations: ConversationSummary[];
  archivedConversations: ConversationSummary[];
  turns: ChatTurn[];
  set: (patch: Partial<AppState>) => void;
  selectWorkspace: (path: string) => void;
  openProjectForTask: (path: string) => void;
  replaceTask: (task: AgentTask) => void;
  removeTask: (taskId: string) => void;
  removeConversation: (sessionId: string, conversationId?: string) => void;
  appendTurn: (turn: ChatTurn) => void;
  updateTurn: (id: string, patch: Partial<ChatTurn>) => void;
  returnToTaskHome: () => void;
  resetConversation: () => void;
}

type PersistedAppState = Pick<AppState, "userId" | "theme" | "fontScale" | "sidebarOpen" | "inspectorOpen">;

export const useAppStore = create<AppState>()(
  persist<AppState, [], [], PersistedAppState>(
    (set) => ({
      userId: "default",
      view: "assistant",
      theme: "system",
      fontScale: 1,
      sidebarOpen: true,
      sidebarView: "tasks",
      inspectorOpen: false,
      commandOpen: false,
      bootstrapReady: false,
      bootstrapError: undefined,
      initialSetupRequired: false,
      workspacePath: "",
      workspaceName: "",
      composerAttachment: null,
      composerAttachmentLeaving: false,
      activeTaskId: "",
      activeSessionId: "",
      tasks: [],
      archivedTasks: [],
      conversations: [],
      archivedConversations: [],
      turns: [],
      set: (patch) => set(patch),
      selectWorkspace: (path) =>
        set({
          view: "assistant",
          workspacePath: path,
          workspaceName: workspaceNameFromPath(path),
          activeTaskId: "",
        }),
      openProjectForTask: (path) => {
        const name = workspaceNameFromPath(path);
        set({
          view: "assistant",
          sidebarView: "tasks",
          activeTaskId: "",
          activeSessionId: "",
          workspacePath: path,
          workspaceName: name,
          composerAttachment: { path, name },
          composerAttachmentLeaving: false,
          turns: [],
        });
      },
      replaceTask: (task) =>
        set((state) => ({
          tasks: [task, ...state.tasks.filter((item) => item.id !== task.id)],
          activeTaskId: task.id,
        })),
      removeTask: (taskId) =>
        set((state) => {
          const deletingActiveTask = state.activeTaskId === taskId;
          return {
            tasks: state.tasks.filter((item) => item.id !== taskId),
            archivedTasks: state.archivedTasks.filter((item) => item.id !== taskId),
            activeTaskId: deletingActiveTask ? "" : state.activeTaskId,
            activeSessionId: deletingActiveTask ? "" : state.activeSessionId,
            workspacePath: deletingActiveTask ? "" : state.workspacePath,
            workspaceName: deletingActiveTask ? "" : state.workspaceName,
            composerAttachment: deletingActiveTask ? null : state.composerAttachment,
            composerAttachmentLeaving: deletingActiveTask ? false : state.composerAttachmentLeaving,
            turns: deletingActiveTask
              ? []
              : state.turns.filter((turn) => turn.task?.id !== taskId && turn.id !== `task:${taskId}`),
            view: deletingActiveTask ? "assistant" : state.view,
          };
        }),
      removeConversation: (sessionId, conversationId = sessionId) =>
        set((state) => {
          const matchesConversation = (item: ConversationSummary) => (
            item.id === conversationId || (item.session_id || item.id) === sessionId
          );
          const deletingActiveConversation = (
            state.activeSessionId === sessionId || state.activeSessionId === conversationId
          );
          return {
            conversations: state.conversations.filter((item) => !matchesConversation(item)),
            archivedConversations: state.archivedConversations.filter((item) => !matchesConversation(item)),
            activeSessionId: deletingActiveConversation ? "" : state.activeSessionId,
            activeTaskId: deletingActiveConversation ? "" : state.activeTaskId,
            workspacePath: deletingActiveConversation ? "" : state.workspacePath,
            workspaceName: deletingActiveConversation ? "" : state.workspaceName,
            composerAttachment: deletingActiveConversation ? null : state.composerAttachment,
            composerAttachmentLeaving: deletingActiveConversation ? false : state.composerAttachmentLeaving,
            turns: deletingActiveConversation ? [] : state.turns,
            view: deletingActiveConversation ? "assistant" : state.view,
          };
        }),
      appendTurn: (turn) => set((state) => ({ turns: [...state.turns, turn] })),
      updateTurn: (id, patch) =>
        set((state) => ({
          turns: state.turns.map((turn) => (turn.id === id ? { ...turn, ...patch } : turn)),
        })),
      returnToTaskHome: () =>
        set({
          view: "assistant",
          sidebarView: "tasks",
          // Returning to the task landing page is navigation, not task
          // creation.  Leave the session empty so the next submitted prompt
          // can receive its backend-issued session without creating a ghost
          // history item merely by clicking the sidebar tab.
          activeSessionId: "",
          activeTaskId: "",
          workspacePath: "",
          workspaceName: "",
          composerAttachment: null,
          composerAttachmentLeaving: false,
          turns: [],
        }),
      resetConversation: () =>
        set({
          view: "assistant",
          sidebarView: "tasks",
          // Every newly-created task window receives its own durable session.
          // This keeps project/task history in long-term memory without
          // collapsing unrelated windows into the legacy `default` session.
          activeSessionId: createTaskSessionId(),
          activeTaskId: "",
          workspacePath: "",
          workspaceName: "",
          composerAttachment: null,
          composerAttachmentLeaving: false,
          turns: [],
        }),
    }),
    {
      name: "secflow-desktop-state-v1",
      partialize: (state) => ({
        userId: state.userId,
        theme: state.theme,
        fontScale: state.fontScale,
        sidebarOpen: state.sidebarOpen,
        inspectorOpen: state.inspectorOpen,
      }),
      version: 2,
      migrate: (persistedState) => {
        const persisted = persistedState as Partial<AppState>;
        return {
          userId: persisted.userId || "default",
          theme: persisted.theme || "system",
          fontScale: persisted.fontScale || 1,
          sidebarOpen: persisted.sidebarOpen ?? true,
          inspectorOpen: persisted.inspectorOpen ?? false,
        };
      },
      merge: (persistedState, currentState) => ({
        ...currentState,
        ...(persistedState as PersistedAppState),
        // Active identifiers are only meaningful together with backend detail
        // or in-memory turns. Always start on the recoverable task home and
        // let the backend catalogs repopulate navigable task history.
        view: "assistant",
        sidebarView: "tasks",
        activeTaskId: "",
        activeSessionId: "",
        workspacePath: "",
        workspaceName: "",
        composerAttachment: null,
        composerAttachmentLeaving: false,
        turns: [],
      }),
    },
  ),
);

function createTaskSessionId() {
  const id = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `task:${id}`;
}

function workspaceNameFromPath(path: string) {
  return path.split(/[\\/]/).filter(Boolean).pop() || path;
}
