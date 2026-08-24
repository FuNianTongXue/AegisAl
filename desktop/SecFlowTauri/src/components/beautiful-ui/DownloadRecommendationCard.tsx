import {
  Check,
  ChevronDown,
  Download,
  FileArchive,
  FileCode2,
  FileSpreadsheet,
  FileText,
  LoaderCircle,
  RotateCcw,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";

import { clientLocaleTag, useI18n } from "../../i18n";
import { brandDisplayText } from "../../branding";
import { api } from "../../lib/api";
import { saveBinaryArtifact } from "../../lib/platform";
import type { AssistantArtifact } from "../../types";
import "./beautiful-ui.css";

export type DownloadArtifactHandler = (artifact: AssistantArtifact) => Promise<boolean | void>;

export interface DownloadRecommendationCardProps {
  items: AssistantArtifact[];
  recommendedId?: string;
  onDownload?: DownloadArtifactHandler;
  className?: string;
}

type DownloadPhase = "idle" | "downloading" | "saved" | "error";

interface DownloadStatus {
  phase: DownloadPhase;
  error?: string;
}

interface DownloadOption {
  artifact: AssistantArtifact;
  key: string;
}

/** A real artifact picker based on Beautiful UI's recommendation-card pattern. */
export function DownloadRecommendationCard({
  items,
  recommendedId,
  onDownload = downloadPreparedArtifact,
  className = "",
}: DownloadRecommendationCardProps) {
  const { t, locale } = useI18n();
  const drawerId = useId();
  const options = useMemo(() => downloadableOptions(items), [items]);
  const recommended = options.find(({ artifact }) => artifact.id === recommendedId) || options[0];
  const [selectedKey, setSelectedKey] = useState(() => recommended?.key || "");
  const [open, setOpen] = useState(false);
  const [statuses, setStatuses] = useState<Record<string, DownloadStatus>>({});
  const [announcement, setAnnouncement] = useState("");
  const inFlightKey = useRef("");
  const active = options.find((option) => option.key === selectedKey) || recommended;
  const others = options.filter((option) => option.key !== active?.key);
  const pending = Object.values(statuses).some((status) => status.phase === "downloading");

  useEffect(() => {
    if (!recommended) return;
    if (!options.some((option) => option.key === selectedKey)) setSelectedKey(recommended.key);
  }, [options, recommended, selectedKey]);

  if (!active) return null;

  const status = statuses[active.key] || { phase: "idle" as const };
  const format = artifactFormat(active.artifact);
  const activeFileName = brandDisplayText(active.artifact.file_name) || "report";
  const integrityLevel = active.artifact.sha256 ? 3 : active.artifact.size ? 2 : 1;
  const statusLabel = status.phase === "saved"
    ? t("已保存")
    : status.phase === "error"
      ? t("下载失败")
      : status.phase === "downloading"
        ? t("正在下载")
        : active.artifact.sha256
          ? t("校验信息可用")
          : t("文件已准备好");
  const accessibleSeparator = locale === "en" ? ", " : "，";

  const selectOption = (option: DownloadOption) => {
    setSelectedKey(option.key);
    setAnnouncement("");
  };

  const download = async () => {
    if (inFlightKey.current) return;
    inFlightKey.current = active.key;
    const fileName = activeFileName;
    setStatuses((current) => ({ ...current, [active.key]: { phase: "downloading" } }));
    setAnnouncement(`${t("正在下载")} ${fileName}...`);
    try {
      const saved = await onDownload(active.artifact);
      if (saved === false) {
        setStatuses((current) => ({ ...current, [active.key]: { phase: "idle" } }));
        setAnnouncement(t("已取消保存"));
        return;
      }
      setStatuses((current) => ({ ...current, [active.key]: { phase: "saved" } }));
      setAnnouncement(`${fileName} ${t("已保存")}`);
    } catch (reason) {
      const message = brandDisplayText(reason instanceof Error ? reason.message : String(reason));
      setStatuses((current) => ({ ...current, [active.key]: { phase: "error", error: message } }));
      setAnnouncement(`${t("下载失败")}：${message}`);
    } finally {
      inFlightKey.current = "";
    }
  };

  return (
    <section
      className={`bui-download-card ${className}`.trim()}
      role="region"
      aria-label={t("可下载的报告文件")}
      aria-busy={pending || undefined}
    >
      <div className="bui-download-card-body">
        <strong>{t("下载生成的文件")}</strong>
        <div key={active.key} className="bui-download-active-file">
          <span className="bui-download-file-icon" aria-hidden="true">{format.icon}</span>
          <span className="bui-download-file-copy">
            <b dir="auto" title={activeFileName}>{activeFileName}</b>
            <small>
              <span className="bui-download-format">{format.label}</span>
              {active.artifact.size ? <span>{formatBytes(active.artifact.size, clientLocaleTag(locale))}</span> : null}
            </small>
          </span>
        </div>
      </div>

      {others.length ? (
        <div className={`bui-download-drawer ${open ? "open" : ""}`} aria-hidden={!open}>
          <div className="bui-download-drawer-inner">
            <div id={drawerId} className="bui-download-options">
              <small className="bui-download-options-label">{t("其他文件与格式")}</small>
              <div role="list" aria-label={t("其他文件与格式")}>
                {others.map((option) => {
                  const optionFormat = artifactFormat(option.artifact);
                  const optionFileName = brandDisplayText(option.artifact.file_name) || "report";
                  const optionStatus = statuses[option.key]?.phase;
                  const optionStateLabel = optionStatus === "saved"
                    ? t("已保存")
                    : optionStatus === "error"
                      ? t("下载失败")
                      : "";
                  const optionMeta = [
                    optionFormat.label,
                    option.artifact.size ? formatBytes(option.artifact.size, clientLocaleTag(locale)) : "",
                    optionStateLabel,
                  ].filter(Boolean).join(" · ");
                  return (
                    <div key={option.key} className="bui-download-option" role="listitem">
                      <button
                        type="button"
                        disabled={pending}
                        tabIndex={open ? undefined : -1}
                        onClick={() => selectOption(option)}
                        aria-label={[optionFormat.label, optionFileName, optionStateLabel].filter(Boolean).join(accessibleSeparator)}
                      >
                        <ArtifactMeter level={option.artifact.sha256 ? 3 : option.artifact.size ? 2 : 1} phase={optionStatus} />
                        <span className="bui-download-option-name" dir="auto" title={optionFileName}>{optionFileName}</span>
                        <small>{optionMeta}</small>
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {status.phase === "error" ? (
        <div className="bui-download-error" role="alert">
          <TriangleAlert aria-hidden="true" />
          <span><strong>{t("下载失败")}</strong><small>{brandDisplayText(status.error)}</small></span>
        </div>
      ) : null}

      <footer className="bui-download-card-footer">
        <span className="bui-download-readiness">
          <ArtifactMeter level={integrityLevel} phase={status.phase} />
          <span>{statusLabel}</span>
        </span>
        <span className="bui-download-actions">
          {others.length ? (
            <button
              type="button"
              className="secondary"
              aria-expanded={open}
              aria-controls={drawerId}
              disabled={pending}
              onClick={() => setOpen((current) => !current)}
            >
              {t("其他格式")}
              <ChevronDown aria-hidden="true" className={open ? "" : "rotated"} />
            </button>
          ) : null}
          <button
            type="button"
            className={`primary phase-${status.phase}`}
            disabled={pending}
            aria-label={`${downloadActionLabel(status.phase, t)} ${activeFileName}`}
            onClick={() => void download()}
          >
            {status.phase === "downloading"
              ? <LoaderCircle className="spin" aria-hidden="true" />
              : status.phase === "saved"
                ? <Check aria-hidden="true" />
                : status.phase === "error"
                  ? <RotateCcw aria-hidden="true" />
                  : <Download aria-hidden="true" />}
            <span>{downloadActionLabel(status.phase, t)} {format.label}</span>
          </button>
        </span>
      </footer>
      <span className="bui-visually-hidden" role="status" aria-live="polite" aria-atomic="true">{announcement}</span>
    </section>
  );
}

function ArtifactMeter({ level, phase }: { level: number; phase?: DownloadPhase }) {
  return (
    <span className={`bui-download-meter ${phase || "idle"}`} aria-hidden="true">
      {[0, 1, 2].map((bar) => <i key={bar} className={bar < level ? "filled" : ""} />)}
    </span>
  );
}

function downloadActionLabel(phase: DownloadPhase, t: (source: string) => string) {
  if (phase === "downloading") return t("正在下载");
  if (phase === "saved") return t("再次下载");
  if (phase === "error") return t("重试下载");
  return t("下载");
}

async function downloadPreparedArtifact(artifact: AssistantArtifact) {
  const path = String(artifact.download_path || "");
  if (!path) throw new Error("Artifact download path is missing.");
  const response = await api.raw(path);
  return saveBinaryArtifact(brandDisplayText(artifact.file_name) || "report", await response.blob());
}

function downloadableOptions(items: AssistantArtifact[]): DownloadOption[] {
  const seen = new Set<string>();
  return items.flatMap((artifact, index) => {
    if (!artifact?.download_path) return [];
    const baseKey = String(artifact.id || artifact.download_path || `${artifact.file_name}:${artifact.media_type}`);
    const key = seen.has(baseKey) ? `${baseKey}:${index}` : baseKey;
    seen.add(key);
    return [{ artifact, key }];
  });
}

function artifactFormat(artifact: AssistantArtifact): { label: string; icon: ReactNode } {
  const fileName = String(artifact.file_name || "");
  const extension = String(artifact.format || (fileName.includes(".") ? fileName.split(".").pop() : "") || "").toLowerCase();
  const mediaType = String(artifact.media_type || "").toLowerCase();
  if (extension === "pdf" || mediaType.includes("pdf")) return { label: "PDF", icon: <FileText /> };
  if (["xlsx", "xls", "csv"].includes(extension) || mediaType.includes("spreadsheet") || mediaType.includes("excel")) {
    return { label: extension === "csv" ? "CSV" : "Excel", icon: <FileSpreadsheet /> };
  }
  if (["docx", "doc"].includes(extension) || mediaType.includes("wordprocessing")) return { label: "Word", icon: <FileText /> };
  if (["zip", "tar", "gz"].includes(extension) || mediaType.includes("zip")) return { label: "ZIP", icon: <FileArchive /> };
  if (["html", "htm"].includes(extension) || mediaType.includes("html")) return { label: "HTML", icon: <FileCode2 /> };
  if (["md", "markdown"].includes(extension) || mediaType.includes("markdown")) return { label: "Markdown", icon: <FileCode2 /> };
  return { label: extension ? extension.toUpperCase() : "FILE", icon: <FileText /> };
}

function formatBytes(value: number, locale: string) {
  const size = Math.max(0, Number(value) || 0);
  if (size < 1024) return `${new Intl.NumberFormat(locale).format(size)} B`;
  const units = ["KB", "MB", "GB"];
  let amount = size / 1024;
  let unit = units[0];
  for (let index = 1; amount >= 1024 && index < units.length; index += 1) {
    amount /= 1024;
    unit = units[index];
  }
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: amount < 10 ? 1 : 0 }).format(amount)} ${unit}`;
}
