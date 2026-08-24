import { useEffect, useLayoutEffect } from "react";

import { useI18n } from "../i18n";
import {
  applyDocumentAppearance,
  INFORMATION_APPEARANCE_EVENT,
  parseInformationAppearance,
} from "../lib/appearance";
import { isTauri } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import { InformationPanel } from "./InformationPanel";

export function InformationWindow() {
  const theme = useAppStore((state) => state.theme);
  const fontScale = useAppStore((state) => state.fontScale);
  const { locale } = useI18n();

  useEffect(() => {
    applyDocumentAppearance({ theme, fontScale }, locale);
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
    const cleanups: Array<() => void> = [];

    void import("@tauri-apps/api/event")
      .then(async ({ listen }) => {
        const opened = await listen("secflow:information-opened", () => {
          void Promise.resolve(useAppStore.persist.rehydrate())
            .catch((error) => console.error("Failed to refresh information window appearance", error))
            .finally(() => {
              window.requestAnimationFrame(() => {
                document.querySelector<HTMLTextAreaElement>("[aria-label='独立咨询问题']")?.focus();
              });
            });
        });
        if (disposed) {
          opened();
          return;
        }
        cleanups.push(opened);

        const appearanceChanged = await listen<unknown>(INFORMATION_APPEARANCE_EVENT, ({ payload }) => {
          const appearance = parseInformationAppearance(payload);
          if (appearance) useAppStore.getState().set(appearance);
        });
        if (disposed) {
          appearanceChanged();
          return;
        }
        cleanups.push(appearanceChanged);
      })
      .catch((error) => console.error("Failed to bind information window events", error));

    return () => {
      disposed = true;
      cleanups.splice(0).forEach((cleanup) => cleanup());
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
