import { Clock3, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";

import { waitForBackendReady } from "../hooks/useBackend";
import { api } from "../lib/api";
import type { TrialStatus } from "../types";

export function TrialGuard({ hideActive = false }: { hideActive?: boolean }) {
  const trialBuild = import.meta.env.VITE_SECFLOW_TRIAL_BUILD === "1";
  const [status, setStatus] = useState<TrialStatus | null>(null);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    if (!trialBuild) return;
    let disposed = false;
    void waitForBackendReady()
      .then(() => api.trialStatus())
      .then((next) => {
        if (!disposed) setStatus(next);
      })
      .catch((error) => {
        if (!disposed) setLoadError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      disposed = true;
    };
  }, [trialBuild]);

  if (!trialBuild) return null;
  if (!status && !loadError) {
    return <div className="trial-status-chip loading" role="status"><Clock3 size={14} />正在验证试用授权</div>;
  }
  if (!status || !status.usable) {
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
