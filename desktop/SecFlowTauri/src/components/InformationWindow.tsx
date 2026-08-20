import { useEffect, useLayoutEffect } from "react";

import { useI18n } from "../i18n";
import { isTauri } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import { InformationPanel } from "./InformationPanel";

export function InformationWindow() {
  const theme = useAppStore((state) => state.theme);
  const fontScale = useAppStore((state) => state.fontScale);
  const { locale } = useI18n();

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.lang = locale;
    root.style.setProperty("--font-scale", String(fontScale));
    const dark = theme === "dark" || (theme === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
    document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute("content", dark ? "#171718" : "#fafbfd");
  }, [fontScale, locale, theme]);

  useLayoutEffect(() => {
    document.documentElement.dataset.secflowWindow = "information";
    document.body.dataset.secflowWindow = "information";
    return () => {
      delete document.documentElement.dataset.secflowWindow;
      delete document.body.dataset.secflowWindow;
    };
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let cleanup: (() => void) | undefined;

    void import("@tauri-apps/api/event")
      .then(({ listen }) => listen("secflow:information-opened", () => {
        window.requestAnimationFrame(() => {
          document.querySelector<HTMLTextAreaElement>("[aria-label='独立咨询问题']")?.focus();
        });
      }))
      .then((unlisten) => {
        if (disposed) {
          unlisten();
          return;
        }
        cleanup = unlisten;
      })
      .catch((error) => console.error("Failed to bind information window events", error));

    return () => {
      disposed = true;
      cleanup?.();
    };
  }, []);

  return (
    <main className="information-window-shell" aria-label="信息中心">
      <h1 className="sr-only">信息中心</h1>
      <InformationPanel open onClose={() => void hideInformationWindow()} variant="window" />
    </main>
  );
}

async function hideInformationWindow() {
  if (!isTauri()) return;
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  await getCurrentWindow().hide();
}
