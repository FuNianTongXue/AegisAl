import aegisalEmblem from "../assets/aegisal-emblem.png";

export function BrandMark({ size = 28 }: { size?: number }) {
  return (
    <span className="brand-mark" style={{ width: size, height: size }} aria-hidden="true">
      <img src={aegisalEmblem} alt="" draggable="false" />
    </span>
  );
}
