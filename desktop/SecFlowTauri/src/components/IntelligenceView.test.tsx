// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { IntelligenceView } from "./IntelligenceView";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("IntelligenceView metrics", () => {
  it("renders CISA KEV, public PoC totals, and the seven-day update trend", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [],
      stats: { total: 10_000, critical: 100, high: 900, kev: 1_656, poc: 412 },
      trend: [
        { date: "2026-07-26", count: 18 },
        { date: "2026-07-27", count: 27 },
        { date: "2026-07-28", count: 14 },
        { date: "2026-07-29", count: 31 },
        { date: "2026-07-30", count: 20 },
        { date: "2026-07-31", count: 44 },
        { date: "2026-08-01", count: 36 },
      ],
      catalog_status: "ready",
    });

    render(<IntelligenceView />);

    expect(await screen.findByText("1,656")).toBeInTheDocument();
    expect(screen.getByText("412")).toBeInTheDocument();
    expect(screen.getByText("具有公开 PoC")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "近期情报更新趋势" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "近 7 天情报更新趋势" })).toBeInTheDocument();
    expect(screen.getAllByText(/^0[78]-\d{2}$/)).toHaveLength(7);
  });
});
