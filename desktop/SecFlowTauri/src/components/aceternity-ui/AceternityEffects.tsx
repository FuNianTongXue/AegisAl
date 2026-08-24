import {
  type ButtonHTMLAttributes,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
  useEffect,
  useRef,
} from "react";

import "./aceternity-effects.css";

type SparkleStyle = CSSProperties & {
  "--spark-x": string;
  "--spark-y": string;
  "--spark-size": string;
  "--spark-delay": string;
  "--spark-duration": string;
  "--spark-opacity": number;
};

const SPARKLES = Array.from({ length: 34 }, (_, index): SparkleStyle => ({
  "--spark-x": `${4 + ((index * 37) % 92)}%`,
  "--spark-y": `${5 + ((index * 53) % 84)}%`,
  "--spark-size": `${index % 7 === 0 ? 3 : index % 3 === 0 ? 2 : 1}px`,
  "--spark-delay": `${-((index * 0.37) % 4.8).toFixed(2)}s`,
  "--spark-duration": `${3.2 + (index % 6) * 0.58}s`,
  "--spark-opacity": 0.24 + (index % 5) * 0.12,
}));

export function AceternitySparklesStage({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`aceternity-sparkles-stage ${className}`.trim()}
      data-testid="aceternity-sparkles-stage"
    >
      <span className="aceternity-lamp-glow" aria-hidden="true" />
      <span className="aceternity-shine-line" aria-hidden="true" />
      <span className="aceternity-sparkles" aria-hidden="true">
        {SPARKLES.map((style, index) => (
          <i key={index} style={style} />
        ))}
      </span>
      <div className="aceternity-stage-content">{children}</div>
    </section>
  );
}

export function AceternityGlowingCard({
  children,
  className = "",
  onPointerMove,
  onPointerLeave,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  const glowFrame = useRef<number | null>(null);
  const pendingGlow = useRef<{ target: HTMLButtonElement; x: number; y: number } | null>(null);

  useEffect(() => () => {
    if (glowFrame.current !== null) window.cancelAnimationFrame(glowFrame.current);
  }, []);

  const moveGlow = (event: ReactPointerEvent<HTMLButtonElement>) => {
    pendingGlow.current = {
      target: event.currentTarget,
      x: event.nativeEvent.offsetX,
      y: event.nativeEvent.offsetY,
    };
    if (glowFrame.current === null) {
      const applyGlow = () => {
        glowFrame.current = null;
        const glow = pendingGlow.current;
        if (!glow) return;
        glow.target.style.setProperty("--glow-x", `${glow.x}px`);
        glow.target.style.setProperty("--glow-y", `${glow.y}px`);
      };
      if (typeof window.requestAnimationFrame === "function") {
        glowFrame.current = window.requestAnimationFrame(applyGlow);
      } else {
        applyGlow();
      }
    }
    onPointerMove?.(event);
  };
  const resetGlow = (event: ReactPointerEvent<HTMLButtonElement>) => {
    pendingGlow.current = null;
    if (glowFrame.current !== null) {
      window.cancelAnimationFrame(glowFrame.current);
      glowFrame.current = null;
    }
    event.currentTarget.style.removeProperty("--glow-x");
    event.currentTarget.style.removeProperty("--glow-y");
    onPointerLeave?.(event);
  };

  return (
    <button
      {...props}
      type={props.type ?? "button"}
      className={`aceternity-glowing-card ${className}`.trim()}
      onPointerMove={moveGlow}
      onPointerLeave={resetGlow}
    >
      <span className="aceternity-card-glow" aria-hidden="true" />
      <span className="aceternity-card-sheen" aria-hidden="true" />
      <span className="aceternity-card-content">{children}</span>
    </button>
  );
}
