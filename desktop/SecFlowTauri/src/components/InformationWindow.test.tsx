// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { INFORMATION_APPEARANCE_EVENT } from "../lib/appearance";
import { useAppStore } from "../store/appStore";
import { InformationWindow } from "./InformationWindow";

const tauriEvents = vi.hoisted(() => ({
  handlers: new Map<string, (event: { payload: unknown }) => void>(),
  listen: vi.fn(async (event: string, handler: (event: { payload: unknown }) => void) => {
    tauriEvents.handlers.set(event, handler);
    return () => tauriEvents.handlers.delete(event);
  }),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: tauriEvents.listen,
  emitTo: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../lib/platform", () => ({
  isTauri: () => true,
}));

describe("InformationWindow appearance synchronization", () => {
  beforeEach(() => {
    localStorage.clear();
    tauriEvents.handlers.clear();
    tauriEvents.listen.mockClear();
    Object.defineProperty(HTMLElement.prototype, "scrollTo", {
      configurable: true,
      value: vi.fn(),
    });
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: false }),
    });
    Object.defineProperty(window, "requestAnimationFrame", {
      configurable: true,
      value: (callback: FrameRequestCallback) => window.setTimeout(() => callback(0), 0),
    });
    useAppStore.setState({ userId: "tester", theme: "dark", fontScale: 1.12 });
    vi.spyOn(api, "clearShortTermSession").mockResolvedValue({
      session_id: "information:test",
      cleared_turn_count: 0,
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    delete document.documentElement.dataset.theme;
    delete document.documentElement.dataset.secflowWindow;
    delete document.body.dataset.secflowWindow;
    document.documentElement.style.removeProperty("--font-scale");
  });

  it("updates immediately when the main window emits a new appearance", async () => {
    render(<InformationWindow />);

    await waitFor(() => expect(tauriEvents.handlers.has(INFORMATION_APPEARANCE_EVENT)).toBe(true));
    expect(document.documentElement.dataset.theme).toBe("dark");

    act(() => {
      tauriEvents.handlers.get(INFORMATION_APPEARANCE_EVENT)?.({
        payload: { theme: "light", fontScale: 0.9 },
      });
    });

    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
    expect(document.documentElement.style.getPropertyValue("--font-scale")).toBe("0.9");
    expect(useAppStore.getState()).toMatchObject({ theme: "light", fontScale: 0.9 });
  });

  it("rehydrates persisted appearance whenever the native window opens", async () => {
    render(<InformationWindow />);
    await waitFor(() => expect(tauriEvents.handlers.has("secflow:information-opened")).toBe(true));
    localStorage.setItem("secflow-desktop-state-v1", JSON.stringify({
      state: {
        userId: "tester",
        theme: "light",
        fontScale: 0.9,
        sidebarOpen: true,
        inspectorOpen: false,
      },
      version: 2,
    }));

    act(() => {
      tauriEvents.handlers.get("secflow:information-opened")?.({ payload: undefined });
    });

    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
    expect(document.documentElement.style.getPropertyValue("--font-scale")).toBe("0.9");
  });
});
