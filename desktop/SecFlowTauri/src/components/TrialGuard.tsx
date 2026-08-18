import { Clock3, RefreshCw, ServerCrash, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";

import { waitForBackendReady } from "../hooks/useBackend";
import { api } from "../lib/api";
import { restartLocalBackend } from "../lib/backendRecovery";
import type { TrialStatus } from "../types";

export function TrialGuard({ hideActive = false }: { hideActive?: boolean }) {
  const trialBuild = import.meta.env.VITE_SECFLOW_TRIAL_BUILD === "1";
  const [status, setStatus] = useState<TrialStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [retrySequence, setRetrySequence] = useState(0);
  const [checking, setChecking] = useState(false);

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
              .catch((restartError) => console.error("SecFlow automatic backend restart failed", restartError))
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

  const retry = () => {
    setLoadError("");
    setStatus(null);
    setChecking(true);
    void restartLocalBackend()
      .catch((error) => console.error("SecFlow local backend restart failed", error))
      .finally(() => setRetrySequence((value) => value + 1));
  };

  if (!trialBuild) return null;
  if (!status && !loadError) {
    return <div className="trial-status-chip loading" role="status"><Clock3 size={14} />正在验证试用授权</div>;
  }
  if (!status) {
    return (
      <div className="trial-blocker service-unavailable" role="alert" aria-label="本地安全服务不可用">
        <div>
          <span><ServerCrash size={24} /></span>
          <h2>本地安全服务正在恢复</h2>
          <p>暂时无法连接本机分析服务。这不代表试用授权或用户数据已损坏。</p>
          <button type="button" className="trial-retry-button" onClick={retry} disabled={checking}>
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
      <div className="trial-blocker" role="alert" aria-label="试用授权不可用">
        <div>
          <span><ShieldAlert size={24} /></span>
          <h2>安全智脑试用版不可用</h2>
          <p>{status?.message || loadError || "无法验证本机试用授权。"}</p>
          <small>应用和用户数据未被修改。请安装正式授权版本或联系管理员。</small>
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
