import { Clock3, RefreshCw, ServerCrash, ShieldAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { waitForBackendReady } from "../hooks/useBackend";
import { api } from "../lib/api";
import { restartLocalBackend } from "../lib/backendRecovery";
import type { TrialStatus } from "../types";
import { BRAND_NAME_ZH, brandDisplayText } from "../branding";

export function TrialGuard({ hideActive = false }: { hideActive?: boolean }) {
  const trialBuild = import.meta.env.VITE_SECFLOW_TRIAL_BUILD === "1";
  const [status, setStatus] = useState<TrialStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [retrySequence, setRetrySequence] = useState(0);
  const [checking, setChecking] = useState(false);
  const blocker = useRef<HTMLDivElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const retryButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!trialBuild) return;
    let disposed = false;
    let retryTimer: number | undefined;
    setChecking(true);
    void waitForBackendReady()
      .then(() => api.trialStatus())
      .then((next) => {
        if (!disposed) {
          setLoadError("");
          setStatus(next);
        }
      })
      .catch((error) => {
        if (!disposed) {
          setLoadError(error instanceof Error ? error.message : String(error));
          // A cold sidecar can be delayed by Gatekeeper, Rosetta or antivirus
          // inspection. Keep probing instead of permanently classifying a
          // transient connection failure as a damaged trial authorization.
          retryTimer = window.setTimeout(() => {
            void restartLocalBackend()
              .catch((restartError) => console.error("AegisAl automatic backend restart failed", restartError))
              .finally(() => setRetrySequence((value) => value + 1));
          }, 5_000);
        }
      })
      .finally(() => {
        if (!disposed) setChecking(false);
      });
    return () => {
      disposed = true;
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
    };
  }, [retrySequence, trialBuild]);

  const blockerKind = trialBuild && !status && loadError
    ? "service"
    : trialBuild && status && !status.usable
      ? "license"
      : null;

  useEffect(() => {
    if (!blockerKind) return;
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialog.current?.focus();
    const restoreBackground = blocker.current ? isolateBackground(blocker.current) : () => undefined;
    const trap = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        event.stopPropagation();
        return;
      }
      if (event.key === "Tab" && dialog.current) trapFocus(event, dialog.current);
    };
    document.addEventListener("keydown", trap, true);
    return () => {
      document.removeEventListener("keydown", trap, true);
      restoreBackground();
      if (previouslyFocused?.isConnected) previouslyFocused.focus();
    };
  }, [blockerKind]);

  useEffect(() => {
    if (blockerKind === "service" && !checking) retryButton.current?.focus();
  }, [blockerKind, checking]);

  const retry = () => {
    setLoadError("");
    setStatus(null);
    setChecking(true);
    void restartLocalBackend()
      .catch((error) => console.error("AegisAl local backend restart failed", error))
      .finally(() => setRetrySequence((value) => value + 1));
  };

  if (!trialBuild) return null;
  if (!status && !loadError) {
    return <div className="trial-status-chip loading" role="status"><Clock3 size={14} />正在验证试用授权</div>;
  }
  if (!status) {
    return (
      <div className="trial-blocker service-unavailable" ref={blocker}>
        <div
          ref={dialog}
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="trial-service-title"
          aria-describedby="trial-service-description"
          tabIndex={-1}
        >
          <span><ServerCrash size={24} /></span>
          <h2 id="trial-service-title">本地安全服务正在恢复</h2>
          <p id="trial-service-description">暂时无法连接本机分析服务。这不代表试用授权或用户数据已损坏。</p>
          <button ref={retryButton} type="button" className="trial-retry-button" onClick={retry} disabled={checking}>
            <RefreshCw size={15} className={checking ? "spinning" : ""} />
            {checking ? "正在重新连接" : "重新连接"}
          </button>
          <small>客户端会自动继续尝试。若多次失败，请重启应用并检查安全软件是否拦截了本地 sidecar。</small>
        </div>
      </div>
    );
  }
  if (!status.usable) {
    return (
      <div className="trial-blocker" ref={blocker}>
        <div
          ref={dialog}
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="trial-license-title"
          aria-describedby="trial-license-description trial-license-guidance"
          tabIndex={-1}
        >
          <span><ShieldAlert size={24} /></span>
          <h2 id="trial-license-title">{BRAND_NAME_ZH}试用版不可用</h2>
          <p id="trial-license-description">{brandDisplayText(status?.message || loadError) || "无法验证本机试用授权。"}</p>
          <small id="trial-license-guidance">应用和用户数据未被修改。请安装正式授权版本或联系管理员。</small>
        </div>
      </div>
    );
  }
  if (hideActive) return null;
  return (
    <div className="trial-status-chip" role="status" aria-label="七天试用状态">
      <Clock3 size={14} />7 天试用 · {remainingLabel(status.secondsRemaining)}
    </div>
  );
}

function remainingLabel(seconds: number | null | undefined) {
  const safe = Math.max(0, Number(seconds || 0));
  if (safe >= 86400) return `剩余 ${Math.ceil(safe / 86400)} 天`;
  if (safe >= 3600) return `剩余 ${Math.ceil(safe / 3600)} 小时`;
  return `剩余 ${Math.ceil(safe / 60)} 分钟`;
}

const FOCUSABLE = [
  "button:not([disabled])",
  "[href]",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function trapFocus(event: KeyboardEvent, container: HTMLElement) {
  const focusable = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((element) => !element.hidden);
  if (!focusable.length) {
    event.preventDefault();
    container.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const active = document.activeElement;
  if (event.shiftKey && (active === first || !container.contains(active))) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

function isolateBackground(layer: HTMLElement) {
  const siblings = Array.from(layer.parentElement?.children || [])
    .filter((element): element is HTMLElement => element instanceof HTMLElement && element !== layer)
    .map((element) => ({
      element,
      inert: element.inert,
      ariaHidden: element.getAttribute("aria-hidden"),
    }));
  siblings.forEach(({ element }) => {
    element.inert = true;
    element.setAttribute("aria-hidden", "true");
  });
  return () => siblings.forEach(({ element, inert, ariaHidden }) => {
    element.inert = inert;
    if (ariaHidden === null) element.removeAttribute("aria-hidden");
    else element.setAttribute("aria-hidden", ariaHidden);
  });
}
