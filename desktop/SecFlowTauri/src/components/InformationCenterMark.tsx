import aegisalEmblem from "../assets/aegisal-emblem.png";
import { BRAND_NAME_EN } from "../branding";

/** Shared AegisAl mark used by both the workspace and Information Center. */
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
      aria-label={`${BRAND_NAME_EN} 信息中心标识`}
    >
      <img src={aegisalEmblem} alt="" draggable="false" />
    </span>
  );
}
