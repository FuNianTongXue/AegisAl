import { useCallback, useEffect, useRef } from "react";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { AgentTask, AgentTaskEvent, HealthSnapshot } from "../types";

// First launch may require Gatekeeper, Rosetta or antivirus to inspect the
// bundled Python runtime. Do not turn a healthy but slow cold start into a
// permanent trial-lock screen.
const BACKEND_READY_TIMEOUT_MS = 120_000;
let backendReadyRequest: Promise<HealthSnapshot> | null = null;

export function useBackendBootstrap() {
  const userId = useAppStore((state) => state.userId);
  const set = useAppStore((state) => state.set);

  const refresh = useCallback(async () => {
    set({ bootstrapError: undefined });
    try {
      const health = await waitForBackendReady();
      set({ health });

      // Model access and user settings are startup-critical. Publish each result
      // as soon as it arrives instead of making them wait for task history and
      // archive queries, which may touch much larger SQLite result sets.
      const critical = await Promise.allSettled([
        api.settings(userId),
        api.llmConfig(userId),
      ] as const);
      const failure = critical.find((result) => result.status === "rejected");
      if (failure?.status === "rejected") throw failure.reason;
      const settings = critical[0].status === "fulfilled" ? critical[0].value : undefined;
      const llm = critical[1].status === "fulfilled" ? critical[1].value : undefined;
      set({
        ...(settings ? { settings } : {}),
        ...(llm ? { llm } : {}),
        bootstrapReady: true,
        bootstrapError: undefined,
        initialSetupRequired: Boolean(
          settings
          && llm
          && (!settings.profile.updated_at || !llm.configured),
        ),
      });

      logBootstrapFailures(await Promise.allSettled([
        api.tasks(userId).then((tasks) => set({ tasks })),
        api.tasks(userId, true).then((archivedTasks) => set({ archivedTasks })),
        api.conversations(userId).then((conversations) => set({ conversations })),
        api.conversations(userId, true).then((archivedConversations) => set({ archivedConversations })),
      ]));
    } catch (error) {
      console.error("SecFlow bootstrap failed", error);
      // StrictMode and explicit refreshes can overlap. A successful caller
      // must not be replaced by a late failure from an older startup attempt.
      if (useAppStore.getState().bootstrapReady) set({ bootstrapError: undefined });
      else set({ bootstrapReady: false, bootstrapError: errorMessage(error) });
    }
  }, [set, userId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return refresh;
}

/** Shares the cold-start probe between bootstrap and an early user submit. */
export function waitForBackendReady(): Promise<HealthSnapshot> {
  if (!backendReadyRequest) {
    backendReadyRequest = retryHealth().finally(() => {
      backendReadyRequest = null;
    });
  }
  return backendReadyRequest;
}

async function retryHealth() {
  let lastError: unknown;
  const deadline = Date.now() + BACKEND_READY_TIMEOUT_MS;
  for (let attempt = 0; Date.now() < deadline; attempt += 1) {
    try {
      return await api.health();
    } catch (error) {
      lastError = error;
      // A local sidecar usually becomes reachable within a few seconds. A
      // short capped backoff removes nearly a full second of avoidable delay
      // without creating meaningful load while the process is still starting.
      const delay = Math.min(50 + attempt * 10, 250);
      await new Promise((resolve) => window.setTimeout(resolve, delay));
    }
  }
  throw lastError;
}

function logBootstrapFailures(results: PromiseSettledResult<unknown>[]) {
  results.forEach((result) => {
    if (result.status === "rejected") console.error("SecFlow bootstrap request failed", result.reason);
  });
}

function errorMessage(error: unknown) {
  if (error instanceof Error && error.message.trim()) return error.message;
  return String(error || "本机服务暂时无法连接");
}

export function useActiveTaskStream(onTerminal?: (task: AgentTask) => void) {
  const taskId = useAppStore((state) => state.activeTaskId);
  const reportDecision = useAppStore((state) => state.tasks.find((task) => task.id === taskId)?.report_decision || "");
  const userId = useAppStore((state) => state.userId);
  const replaceTask = useAppStore((state) => state.replaceTask);
  const lastSequence = useRef(0);
  const terminalHandler = useRef(onTerminal);

  useEffect(() => {
    terminalHandler.current = onTerminal;
  }, [onTerminal]);

  useEffect(() => {
    if (!taskId) return;
    const controller = new AbortController();
    const applyEvent = (event: AgentTaskEvent) => {
      lastSequence.current = Math.max(lastSequence.current, event.sequence);
      const current = useAppStore.getState().tasks.find((task) => task.id === taskId);
      if (!current) return;
      replaceTask({
        ...current,
        current_node: event.node || current.current_node,
        status: terminalStatus(event.type) || (
          event.status === "failed" && !event.type.startsWith("report.") ? "failed" : current.status
        ),
        events: [...current.events.filter((item) => item.sequence !== event.sequence), event].sort(
          (left, right) => left.sequence - right.sequence,
        ),
      });
      if (event.type.startsWith("task.") && ["task.completed", "task.failed", "task.cancelled", "task.interrupted"].includes(event.type)) {
        void api.task(taskId, userId).then((task) => {
          replaceTask(task);
          terminalHandler.current?.(task);
        });
      }
    };

    const run = async () => {
      let failures = 0;
      while (!controller.signal.aborted) {
        try {
          const snapshot = await api.task(taskId, userId);
          replaceTask(snapshot);
          lastSequence.current = Math.max(0, ...(snapshot.events || []).map((event) => event.sequence));
          if (isTerminal(snapshot.status) && snapshot.report_decision !== "generating") {
            terminalHandler.current?.(snapshot);
            return;
          }
          await api.streamTaskEvents(taskId, userId, lastSequence.current, applyEvent, controller.signal);
          failures = 0;
        } catch (error) {
          if (controller.signal.aborted) return;
          failures += 1;
          console.error("Task SSE disconnected", error);
        }
        const delay = [1000, 2000, 5000][Math.min(failures, 3) - 1] || 1000;
        await new Promise((resolve) => window.setTimeout(resolve, delay));
      }
    };
    void run();
    return () => controller.abort();
  }, [replaceTask, reportDecision, taskId, userId]);
}

const terminalStatus = (type: string) => ({
  "task.completed": "completed",
  "task.failed": "failed",
  "task.cancelled": "cancelled",
  "task.interrupted": "interrupted",
}[type] || "");

export const isTerminal = (status: string) => ["completed", "failed", "cancelled", "interrupted"].includes(status);
