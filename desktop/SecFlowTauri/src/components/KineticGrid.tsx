import { type ReactNode, useEffect, useRef } from "react";

interface Ripple {
  x: number;
  y: number;
  startedAt: number;
}

/**
 * Lightweight pointer-warped dot field inspired by 21st.dev's Kinetic Grid.
 * It intentionally uses the browser canvas directly so the welcome screen does
 * not pull a large animation runtime into the desktop bundle.
 */
export function KineticGrid({ children, className = "" }: { children: ReactNode; className?: string }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    const canvas = canvasRef.current;
    if (!host || !canvas || navigator.userAgent.toLowerCase().includes("jsdom")) return;

    let context: CanvasRenderingContext2D | null = null;
    try {
      context = canvas.getContext("2d");
    } catch {
      return;
    }
    if (!context) return;
    const drawing = context;
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    const pointer = { x: 0, y: 0, active: false };
    const ripples: Ripple[] = [];
    let width = 1;
    let height = 1;
    let frame = 0;
    let accent = "#0ba3c4";

    const readAccent = () => {
      accent = getComputedStyle(host).getPropertyValue("--kinetic-accent").trim() || "#0ba3c4";
    };
    const resize = () => {
      const bounds = host.getBoundingClientRect();
      width = Math.max(1, bounds.width);
      height = Math.max(1, bounds.height);
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      drawing.setTransform(ratio, 0, 0, ratio, 0, 0);
      readAccent();
    };
    const draw = (timestamp: number) => {
      drawing.clearRect(0, 0, width, height);
      const spacing = width < 620 ? 30 : 34;
      const time = timestamp / 1000;
      drawing.fillStyle = accent;
      for (let y = spacing / 2; y < height; y += spacing) {
        for (let x = spacing / 2; x < width; x += spacing) {
          const dx = pointer.x - x;
          const dy = pointer.y - y;
          const distance = Math.hypot(dx, dy) || 1;
          const influence = pointer.active ? Math.max(0, 1 - distance / 210) ** 2 : 0;
          const drift = reducedMotion ? 0 : Math.sin(time * 0.72 + x * 0.018 + y * 0.014) * 1.25;
          const warpedX = x + dx * influence * 0.18 + drift;
          const warpedY = y + dy * influence * 0.18 + drift * 0.45;
          drawing.globalAlpha = 0.12 + influence * 0.58;
          drawing.beginPath();
          drawing.arc(warpedX, warpedY, 0.8 + influence * 1.7, 0, Math.PI * 2);
          drawing.fill();
        }
      }

      const now = timestamp;
      for (let index = ripples.length - 1; index >= 0; index -= 1) {
        const age = (now - ripples[index].startedAt) / 1000;
        if (age > 1.25) {
          ripples.splice(index, 1);
          continue;
        }
        drawing.globalAlpha = (1 - age / 1.25) * 0.45;
        drawing.strokeStyle = accent;
        drawing.lineWidth = 1.2;
        drawing.beginPath();
        drawing.arc(ripples[index].x, ripples[index].y, 18 + age * 150, 0, Math.PI * 2);
        drawing.stroke();
      }
      drawing.globalAlpha = 1;
      if (!reducedMotion) frame = window.requestAnimationFrame(draw);
    };
    const localPoint = (event: PointerEvent) => {
      const bounds = host.getBoundingClientRect();
      return { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
    };
    const onPointerMove = (event: PointerEvent) => {
      const point = localPoint(event);
      pointer.x = point.x;
      pointer.y = point.y;
      pointer.active = true;
    };
    const onPointerLeave = () => { pointer.active = false; };
    const onPointerDown = (event: PointerEvent) => {
      const point = localPoint(event);
      ripples.push({ ...point, startedAt: performance.now() });
    };

    resize();
    draw(performance.now());
    const resizeObserver = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(resize);
    resizeObserver?.observe(host);
    const themeObserver = new MutationObserver(readAccent);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    host.addEventListener("pointermove", onPointerMove);
    host.addEventListener("pointerleave", onPointerLeave);
    host.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("resize", resize);
    return () => {
      window.cancelAnimationFrame(frame);
      resizeObserver?.disconnect();
      themeObserver.disconnect();
      host.removeEventListener("pointermove", onPointerMove);
      host.removeEventListener("pointerleave", onPointerLeave);
      host.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <div ref={hostRef} className={`kinetic-grid ${className}`.trim()} data-testid="kinetic-grid">
      <canvas ref={canvasRef} className="kinetic-grid-canvas" aria-hidden="true" />
      <span className="kinetic-grid-scan" aria-hidden="true" />
      {children}
    </div>
  );
}
