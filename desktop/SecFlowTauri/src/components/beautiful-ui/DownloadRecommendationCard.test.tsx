// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../../lib/api";
import { saveBinaryArtifact } from "../../lib/platform";
import { useAppStore } from "../../store/appStore";
import type { AssistantArtifact } from "../../types";
import { DownloadRecommendationCard } from "./DownloadRecommendationCard";

vi.mock("../../lib/platform", () => ({
  saveBinaryArtifact: vi.fn(),
}));

const artifacts: AssistantArtifact[] = [
  {
    id: "artifact-pdf",
    file_name: "AegisAl-security-report.pdf",
    media_type: "application/pdf",
    size: 4_812_345,
    sha256: "a".repeat(64),
    download_path: "/api/assistant/artifacts/artifact-pdf",
  },
  {
    id: "artifact-xlsx",
    file_name: "AegisAl-findings.xlsx",
    media_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    size: 38_400,
    download_path: "/api/assistant/artifacts/artifact-xlsx",
  },
];

describe("DownloadRecommendationCard", () => {
  beforeEach(() => {
    useAppStore.setState({
      settings: {
        preferences: { language: "zh-Hans", dark_mode: false, font_size: "default" },
        profile: { display_name: "测试用户", email: "test@example.com", department: "SOC", role: "安全分析师" },
      },
    });
    vi.mocked(saveBinaryArtifact).mockReset().mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("switches among prepared artifact formats and saves the selected file", async () => {
    const raw = vi.spyOn(api, "raw").mockResolvedValue(new Response(new Blob(["xlsx"]), { status: 200 }));

    render(<DownloadRecommendationCard items={artifacts} />);

    expect(screen.getByRole("region", { name: "可下载的报告文件" })).toBeInTheDocument();
    expect(screen.getByTitle("AegisAl-security-report.pdf")).toBeInTheDocument();
    const alternatives = screen.getByRole("button", { name: "其他格式" });
    expect(alternatives).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(alternatives);
    const excel = screen.getByRole("button", { name: "Excel，AegisAl-findings.xlsx" });
    fireEvent.click(excel);

    expect(screen.getByRole("button", { name: "下载 AegisAl-findings.xlsx" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "下载 AegisAl-findings.xlsx" }));

    await waitFor(() => expect(raw).toHaveBeenCalledWith("/api/assistant/artifacts/artifact-xlsx"));
    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalledTimes(1));
    expect(vi.mocked(saveBinaryArtifact).mock.calls[0][0]).toBe("AegisAl-findings.xlsx");
    expect(await screen.findByRole("button", { name: "再次下载 AegisAl-findings.xlsx" })).toBeInTheDocument();
    expect(screen.getByText("已保存")).toBeInTheDocument();
  });

  it("keeps the selected artifact and retries a failed fetch in place", async () => {
    const raw = vi.spyOn(api, "raw")
      .mockRejectedValueOnce(new Error("artifact fetch failed"))
      .mockResolvedValueOnce(new Response(new Blob(["pdf"]), { status: 200 }));

    render(<DownloadRecommendationCard items={[artifacts[0]]} />);
    fireEvent.click(screen.getByRole("button", { name: "下载 AegisAl-security-report.pdf" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("artifact fetch failed");
    const retry = screen.getByRole("button", { name: "重试下载 AegisAl-security-report.pdf" });
    fireEvent.click(retry);

    await waitFor(() => expect(raw).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("button", { name: "再次下载 AegisAl-security-report.pdf" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("returns to the ready state when the native save panel is cancelled", async () => {
    vi.spyOn(api, "raw").mockResolvedValue(new Response(new Blob(["pdf"]), { status: 200 }));
    vi.mocked(saveBinaryArtifact).mockResolvedValue(false);

    render(<DownloadRecommendationCard items={[artifacts[0]]} />);
    fireEvent.click(screen.getByRole("button", { name: "下载 AegisAl-security-report.pdf" }));

    await waitFor(() => expect(saveBinaryArtifact).toHaveBeenCalledTimes(1));
    expect(screen.getByRole("button", { name: "下载 AegisAl-security-report.pdf" })).toBeEnabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("已取消保存")).toBeInTheDocument();
  });

  it("locks format changes while a download is in progress", async () => {
    let finish!: (saved: boolean) => void;
    const onDownload = vi.fn(() => new Promise<boolean>((resolve) => { finish = resolve; }));

    render(<DownloadRecommendationCard items={artifacts} onDownload={onDownload} />);
    fireEvent.click(screen.getByRole("button", { name: "下载 AegisAl-security-report.pdf" }));

    expect(screen.getByRole("button", { name: "正在下载 AegisAl-security-report.pdf" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "其他格式" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "正在下载 AegisAl-security-report.pdf" }));
    expect(onDownload).toHaveBeenCalledTimes(1);

    finish(true);
    expect(await screen.findByRole("button", { name: "再次下载 AegisAl-security-report.pdf" })).toBeEnabled();
  });

  it("honors an explicit recommended artifact and renders nothing without downloads", () => {
    const { rerender } = render(<DownloadRecommendationCard items={artifacts} recommendedId="artifact-xlsx" />);
    expect(screen.getByRole("button", { name: "下载 AegisAl-findings.xlsx" })).toBeInTheDocument();

    rerender(<DownloadRecommendationCard items={[]} />);
    expect(screen.queryByRole("region", { name: "可下载的报告文件" })).not.toBeInTheDocument();
  });
});
