import { isTauri } from "./platform";

export type AppearanceTheme = "light" | "dark" | "system";

export interface InformationAppearance {
  theme: AppearanceTheme;
  fontScale: number;
}

export const INFORMATION_APPEARANCE_EVENT = "secflow:appearance-changed";
const INFORMATION_WINDOW_LABEL = "information";
const THEMES = new Set<AppearanceTheme>(["light", "dark", "system"]);

export function applyDocumentAppearance(
  appearance: InformationAppearance,
  locale: string,
) {
  const root = document.documentElement;
  root.dataset.theme = appearance.theme;
  root.lang = locale;
  root.style.setProperty("--font-scale", String(appearance.fontScale));
  const dark = appearance.theme === "dark"
    || (appearance.theme === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
  document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    ?.setAttribute("content", dark ? "#171718" : "#f7f7f6");
}

export function parseInformationAppearance(payload: unknown): InformationAppearance | null {
  if (!payload || typeof payload !== "object") return null;
  const candidate = payload as Partial<InformationAppearance>;
  if (!THEMES.has(candidate.theme as AppearanceTheme)) return null;
  if (typeof candidate.fontScale !== "number"
    || !Number.isFinite(candidate.fontScale)
    || candidate.fontScale < 0.75
    || candidate.fontScale > 1.5) {
    return null;
  }
  return { theme: candidate.theme as AppearanceTheme, fontScale: candidate.fontScale };
}

export async function emitInformationAppearance(appearance: InformationAppearance) {
  if (!isTauri()) return;
  const { emitTo } = await import("@tauri-apps/api/event");
  await emitTo(INFORMATION_WINDOW_LABEL, INFORMATION_APPEARANCE_EVENT, appearance);
}
