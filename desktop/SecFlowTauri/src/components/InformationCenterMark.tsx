import { Sparkles } from "lucide-react";

/** Shared SecFlow mark used by both the workspace and Information Center. */
export function InformationCenterMark({
  size = 44,
  className = "",
}: {
  size?: number;
  className?: string;
}) {
  return (
    <span
      className={`information-center-mark ${className}`.trim()}
      style={{ width: size, height: size }}
      role="img"
      aria-label="SecFlow 信息中心标识"
    >
      <span className="information-center-mark-halo" aria-hidden="true" />
      <Sparkles aria-hidden="true" />
    </span>
  );
}
