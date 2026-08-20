// @vitest-environment jsdom

import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import { useBackendBootstrap, waitForBackendReady } from "./useBackend";

describe("backend cold-start bootstrap", () => {
  beforeEach(() => {
    useAppStore.setState({
      userId: "default",
      bootstrapReady: false,
      bootstrapError: undefined,
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

  it("publishes a startup error and succeeds when the user retries", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(api, "health").mockResolvedValue({ ok: true } as never);
    vi.spyOn(api, "settings")
      .mockRejectedValueOnce(new Error("设置服务不可用"))
      .mockResolvedValue({ profile: { updated_at: "2026-08-06T08:00:00Z" } } as never);
    vi.spyOn(api, "llmConfig").mockResolvedValue({ model: "deepseek-chat", configured: true } as never);
    vi.spyOn(api, "tasks").mockResolvedValue([]);
    vi.spyOn(api, "conversations").mockResolvedValue([]);

    const { result } = renderHook(() => useBackendBootstrap());

    await waitFor(() => expect(useAppStore.getState().bootstrapError).toBe("设置服务不可用"));
    expect(useAppStore.getState().bootstrapReady).toBe(false);

    await act(async () => { await result.current(); });

    await waitFor(() => expect(useAppStore.getState().bootstrapReady).toBe(true));
    expect(useAppStore.getState().bootstrapError).toBeUndefined();
  });
});
