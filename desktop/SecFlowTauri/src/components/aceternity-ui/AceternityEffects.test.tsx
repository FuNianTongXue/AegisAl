// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AceternityGlowingCard, AceternitySparklesStage } from "./AceternityEffects";

afterEach(cleanup);

describe("Aceternity-inspired local effects", () => {
  it("renders deterministic decorative sparkles outside the accessibility tree", () => {
    render(<AceternitySparklesStage>安全分析</AceternitySparklesStage>);

    const stage = screen.getByTestId("aceternity-sparkles-stage");
    expect(stage.querySelectorAll(".aceternity-sparkles > i")).toHaveLength(34);
    expect(stage.querySelector(".aceternity-sparkles")).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByText("安全分析")).toBeInTheDocument();
  });

  it("keeps the glowing card keyboard-accessible and clickable", () => {
    const onClick = vi.fn();
    render(<AceternityGlowingCard onClick={onClick}>查询最新漏洞</AceternityGlowingCard>);

    const button = screen.getByRole("button", { name: "查询最新漏洞" });
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();
    expect(button).toHaveAttribute("type", "button");
  });

  it("moves the pointer glow without forcing a synchronous layout read", () => {
    render(<AceternityGlowingCard>扫描项目</AceternityGlowingCard>);
    const card = screen.getByRole("button", { name: "扫描项目" });
    const readLayout = vi.spyOn(card, "getBoundingClientRect");

    fireEvent.pointerMove(card, { offsetX: 38, offsetY: 24 });

    expect(readLayout).not.toHaveBeenCalled();
  });
});
