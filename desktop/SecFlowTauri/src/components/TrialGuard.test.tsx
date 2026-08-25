// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { waitForBackendReady } from "../hooks/useBackend";
import { api } from "../lib/api";
import { restartLocalBackend } from "../lib/backendRecovery";
import { TrialGuard } from "./TrialGuard";

vi.mock("../hooks/useBackend", () => ({ waitForBackendReady: vi.fn() }));
vi.mock("../lib/backendRecovery", () => ({ restartLocalBackend: vi.fn() }));

describe("TrialGuard", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_SECFLOW_TRIAL_BUILD", "1");
    vi.mocked(waitForBackendReady).mockResolvedValue({
      ok: true,
      service: "secflow",
      contract_version: "test",
      task_execution: { mode: "test", configured_workers: 2, running_workers: 2 },
    });
    vi.mocked(restartLocalBackend).mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("shows the remaining time for an active seven-day trial", async () => {
    vi.spyOn(api, "trialStatus").mockResolvedValue({
      enabled: true,
      usable: true,
      state: "active",
      durationHours: 168,
      secondsRemaining: 6 * 86400,
      message: "7 天试用版可用。",
    });

    render(<TrialGuard />);

    expect(await screen.findByText("7 天试用 · 剩余 6 天")).toBeInTheDocument();
  });

  it("uses the backend duration for an active fourteen-day trial", async () => {
    vi.spyOn(api, "trialStatus").mockResolvedValue({
      enabled: true,
      usable: true,
      state: "active",
      durationHours: 336,
      secondsRemaining: 13 * 86400,
      message: "14 天试用版可用。",
    });

    render(<TrialGuard />);

    expect(await screen.findByText("14 天试用 · 剩余 13 天")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveAccessibleName("14 天试用状态");
  });

  it("fails closed when a trial client reaches a non-trial backend", async () => {
    vi.spyOn(api, "trialStatus").mockResolvedValue({
      enabled: false,
      usable: true,
      state: "disabled",
      durationHours: 336,
      secondsRemaining: null,
      message: "当前版本未启用限时试用。",
    });

    render(<TrialGuard />);

    expect(await screen.findByRole("alertdialog", { name: "神盾试用版不可用" })).toHaveTextContent(
      "当前版本未启用限时试用",
    );
  });

  it("fails closed without destroying local data when authorization is invalid", async () => {
    vi.spyOn(api, "trialStatus").mockResolvedValue({
      enabled: true,
      usable: false,
      state: "tampered",
      durationHours: 168,
      secondsRemaining: 0,
      message: "试用授权状态无效或已被修改，核心功能已停用。",
    });

    render(<><button type="button">Background action</button><TrialGuard /></>);
    const background = screen.getByRole("button", { name: "Background action" });
    background.focus();

    const blocker = await screen.findByRole("alertdialog", { name: "神盾试用版不可用" });
    expect(blocker).toHaveTextContent("核心功能已停用");
    expect(blocker).toHaveFocus();
    expect(background).toHaveAttribute("aria-hidden", "true");
    expect(background.inert).toBe(true);
    expect(screen.getByText(/用户数据未被修改/)).toBeInTheDocument();
  });

  it("does not misclassify a sidecar connection failure as authorization damage", async () => {
    vi.mocked(waitForBackendReady)
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValue({
        ok: true,
        service: "secflow",
        contract_version: "test",
        task_execution: { mode: "test", configured_workers: 2, running_workers: 2 },
      });
    vi.spyOn(api, "trialStatus").mockResolvedValue({
      enabled: true,
      usable: true,
      state: "active",
      durationHours: 168,
      secondsRemaining: 5 * 86400,
      message: "7 天试用版可用。",
    });

    render(<><button type="button">Background action</button><TrialGuard /></>);
    const background = screen.getByRole("button", { name: "Background action" });
    background.focus();

    const serviceAlert = await screen.findByRole("alertdialog", { name: "本地安全服务正在恢复" });
    expect(serviceAlert).toHaveTextContent("不代表试用授权或用户数据已损坏");
    expect(serviceAlert).not.toHaveTextContent("安装正式授权版本");
    expect(screen.getByRole("button", { name: "重新连接" })).toHaveFocus();
    expect(background.inert).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "重新连接" }));

    expect(await screen.findByText("7 天试用 · 剩余 5 天")).toBeInTheDocument();
    expect(background.inert).not.toBe(true);
    expect(background).not.toHaveAttribute("aria-hidden");
    expect(waitForBackendReady).toHaveBeenCalledTimes(2);
    expect(restartLocalBackend).toHaveBeenCalledTimes(1);
  });
});
