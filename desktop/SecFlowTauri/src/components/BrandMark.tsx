export function BrandMark({ size = 28 }: { size?: number }) {
  return (
    <span className="brand-mark" style={{ width: size, height: size }} aria-hidden="true">
      <svg viewBox="0 0 24 24" focusable="false">
        <path className="brand-shield" d="M12 2.8 19 5.7v5.5c0 4.7-2.8 7.7-7 10-4.2-2.3-7-5.3-7-10V5.7L12 2.8Z" />
        <path className="brand-star" d="m12 7.1 1.18 2.39 2.64.38-1.91 1.86.45 2.63L12 13.12l-2.36 1.24.45-2.63-1.91-1.86 2.64-.38L12 7.1Z" />
      </svg>
    </span>
  );
}
