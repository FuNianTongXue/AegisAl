import { useEffect, useLayoutEffect } from "react";

import { isTauri } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import { InformationPanel } from "./InformationPanel";

export function InformationWindow() {
  const theme = useAppStore((state) => state.theme);
  const fontScale = useAppStore((state) => state.fontScale);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.style.setProperty("--font-scale", String(fontScale));
  }, [fontScale, theme]);

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
    <div className="information-window-shell">
      <InformationPanel open onClose={() => void hideInformationWindow()} variant="window" />
    </div>
  );
}

async function hideInformationWindow() {
  if (!isTauri()) return;
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  await getCurrentWindow().hide();
}
