// @vitest-environment jsdom

import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import { useBackendBootstrap, waitForBackendReady } from "./useBackend";

describe("backend cold-start bootstrap", () => {
  beforeEach(() => {
    useAppStore.setState({
      userId: "default",
      health: undefined,
      settings: undefined,
      llm: undefined,
      tasks: [],
      archivedTasks: [],
      conversations: [],
      archivedConversations: [],
    });
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("publishes model configuration before slow task-history queries finish", async () => {
    const never = new Promise<never>(() => {});
    vi.spyOn(api, "health").mockResolvedValue({ ok: true } as never);
    vi.spyOn(api, "settings").mockResolvedValue({ profile: {} } as never);
    vi.spyOn(api, "llmConfig").mockResolvedValue({ model: "deepseek-chat", enabled: true } as never);
    vi.spyOn(api, "tasks").mockReturnValue(never);
    vi.spyOn(api, "conversations").mockReturnValue(never);

    renderHook(() => useBackendBootstrap());

    await waitFor(() => expect(useAppStore.getState().llm?.model).toBe("deepseek-chat"));
    expect(useAppStore.getState().health?.ok).toBe(true);
    expect(useAppStore.getState().tasks).toEqual([]);
  });

  it("shares one fast readiness retry between concurrent startup callers", async () => {
    vi.useFakeTimers();
    const health = vi.spyOn(api, "health")
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValue({ ok: true } as never);

    const first = waitForBackendReady();
    const second = waitForBackendReady();
    expect(second).toBe(first);

    await vi.advanceTimersByTimeAsync(50);
    await expect(first).resolves.toMatchObject({ ok: true });
    expect(health).toHaveBeenCalledTimes(2);
  });
});
