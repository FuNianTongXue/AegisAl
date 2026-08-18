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

  it("fails closed without destroying local data when authorization is invalid", async () => {
    vi.spyOn(api, "trialStatus").mockResolvedValue({
      enabled: true,
      usable: false,
      state: "tampered",
      durationHours: 168,
      secondsRemaining: 0,
      message: "试用授权状态无效或已被修改，核心功能已停用。",
    });

    render(<TrialGuard />);

    expect(await screen.findByRole("alert", { name: "试用授权不可用" })).toHaveTextContent("核心功能已停用");
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

    render(<TrialGuard />);

    const serviceAlert = await screen.findByRole("alert", { name: "本地安全服务不可用" });
    expect(serviceAlert).toHaveTextContent("不代表试用授权或用户数据已损坏");
    expect(serviceAlert).not.toHaveTextContent("安装正式授权版本");

    fireEvent.click(screen.getByRole("button", { name: "重新连接" }));

    expect(await screen.findByText("7 天试用 · 剩余 5 天")).toBeInTheDocument();
    expect(waitForBackendReady).toHaveBeenCalledTimes(2);
    expect(restartLocalBackend).toHaveBeenCalledTimes(1);
  });
});
