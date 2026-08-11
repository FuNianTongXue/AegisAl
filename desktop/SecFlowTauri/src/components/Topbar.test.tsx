// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Topbar } from "./Topbar";

describe("Topbar", () => {
  afterEach(() => {
    cleanup();
    delete (window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
  });

  it("removes the consultation entry from the titlebar in the browser shell", () => {
    render(<Topbar onRefresh={vi.fn()} />);

    expect(screen.queryByRole("button", { name: "独立信息咨询" })).not.toBeInTheDocument();
    expect(document.querySelector(".information-trigger")).toBeNull();
  });

  it("removes the consultation entry from the Tauri titlebar (menu bar status item only)", () => {
    Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });

    render(<Topbar onRefresh={vi.fn()} />);

    expect(screen.queryByRole("button", { name: "独立信息咨询" })).not.toBeInTheDocument();
    expect(document.querySelector(".information-trigger")).toBeNull();
  });

  it("keeps the refresh action working", () => {
    const onRefresh = vi.fn();
    render(<Topbar onRefresh={onRefresh} />);

    fireEvent.click(screen.getByTitle("刷新本机服务"));
    expect(onRefresh).toHaveBeenCalledOnce();
  });
});
