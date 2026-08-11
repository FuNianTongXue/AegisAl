import { useEffect } from "react";

import { AppSidebar } from "./components/AppSidebar";
import { ArchiveView } from "./components/ArchiveView";
import { AssistantWorkspace } from "./components/AssistantWorkspace";
import { CommandPalette } from "./components/CommandPalette";
import { InspectorPanel } from "./components/InspectorPanel";
import { IntelligenceView } from "./components/IntelligenceView";
import { RecordsView } from "./components/RecordsView";
import { SettingsView } from "./components/SettingsView";
import { Topbar } from "./components/Topbar";
import { InformationWindow } from "./components/InformationWindow";
import { InitialSetupView } from "./components/InitialSetupView";
import { BrandMark } from "./components/BrandMark";
import { TrialGuard } from "./components/TrialGuard";
import { useBackendBootstrap } from "./hooks/useBackend";
import { useI18n } from "./i18n";
import { isTauri } from "./lib/platform";
import { useAppStore } from "./store/appStore";

export default function App() {
  const informationWindow = new URLSearchParams(window.location.search).get("secflowWindow") === "information";
  return (
    <>
      {informationWindow ? <InformationWindow /> : <MainApp />}
      <TrialGuard hideActive={informationWindow} />
    </>
  );
}

function MainApp() {
  const refreshBackend = useBackendBootstrap();
  const state = useAppStore();
  const { locale } = useI18n();

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = state.theme;
    root.lang = locale;
    root.style.setProperty("--font-scale", String(state.fontScale));
  }, [locale, state.fontScale, state.theme]);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let cleanup: (() => void) | undefined;

    void import("@tauri-apps/api/event")
      .then(({ listen }) => listen("secflow:open-settings", () => {
        useAppStore.getState().set({ view: "settings" });
      }))
      .then((unlisten) => {
        if (disposed) {
          unlisten();
          return;
        }
        cleanup = unlisten;
      })
      .catch((error) => console.error("Failed to bind native menu events", error));

    return () => {
      disposed = true;
      cleanup?.();
    };
  }, []);

  if (!state.bootstrapReady) {
    return <div className="startup-loading"><BrandMark size={44} /><strong>安全智脑</strong><span>正在初始化本机服务…</span></div>;
  }

  if (state.initialSetupRequired) {
    return <InitialSetupView />;
  }

  return (
    <>
      {/* Settings used to replace this entire tree. That unmounted the active
          report card and aborted the task SSE subscription, so returning to
          the task made an in-flight graph look interrupted. Keep the shell
          alive for every primary view and only hide it while settings is open. */}
      <div
        className={`app-shell assistant-shell ${state.sidebarOpen ? "" : "sidebar-collapsed"}`}
        aria-hidden={state.view === "settings"}
        style={state.view === "settings" ? { display: "none" } : undefined}
      >
        <AppSidebar />
        <div className="app-main">
          <Topbar onRefresh={() => void refreshBackend()} />
          <div className={`workspace-frame ${state.inspectorOpen && state.view === "assistant" ? "with-inspector" : ""}`}>
            <main className="workspace-content">
              {/* Keep the active workspace mounted while visiting every other
                  feature. Its local action state and SSE connection then keep
                  running instead of being recreated from an interrupt snapshot. */}
              <AssistantWorkspace visible={state.view === "assistant"} />
              {state.view === "intelligence" ? <IntelligenceView /> : null}
              {state.view === "records" ? <RecordsView /> : null}
              {state.view === "archive" ? <ArchiveView /> : null}
            </main>
            {state.inspectorOpen && state.view === "assistant" ? <InspectorPanel /> : null}
          </div>
        </div>
      </div>
      {state.view === "settings" ? <SettingsView onBack={() => state.set({ view: "assistant" })} /> : null}
      <CommandPalette />
    </>
  );
}
