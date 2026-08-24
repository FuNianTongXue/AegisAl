import { useEffect, useState } from "react";

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
import { BeautifulLoadingState } from "./components/beautiful-ui/BeautifulUI";
import { useBackendBootstrap } from "./hooks/useBackend";
import { useI18n } from "./i18n";
import { applyDocumentAppearance, emitInformationAppearance } from "./lib/appearance";
import { isTauri } from "./lib/platform";
import { useAppStore } from "./store/appStore";
import { BRAND_NAME_ZH, brandDisplayText } from "./branding";

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
  const copy = interfaceCopy(locale);

  useEffect(() => {
    applyDocumentAppearance({ theme: state.theme, fontScale: state.fontScale }, locale);
  }, [locale, state.fontScale, state.theme]);

  useEffect(() => {
    void emitInformationAppearance({ theme: state.theme, fontScale: state.fontScale })
      .catch((error) => console.error("Failed to sync information window appearance", error));
  }, [state.fontScale, state.theme]);

  useEffect(() => {
    const url = new URL(window.location.href);
    url.searchParams.set("view", state.view);
    if (state.activeSessionId) url.searchParams.set("session", state.activeSessionId);
    else url.searchParams.delete("session");
    if (state.activeTaskId) url.searchParams.set("task", state.activeTaskId);
    else url.searchParams.delete("task");
    const nextUrl = `${url.pathname}${url.search}${url.hash}`;
    const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (nextUrl !== currentUrl) window.history.replaceState(window.history.state, "", nextUrl);
  }, [state.activeSessionId, state.activeTaskId, state.view]);

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
    return (
      <>
        <SkipLink label={copy.skip} />
        <main id="main-content" tabIndex={-1} className="startup-loading" aria-busy={!state.bootstrapError}>
          <BrandMark size={44} />
          <strong>{BRAND_NAME_ZH}</strong>
          {state.bootstrapError ? (
            <>
              <span role="alert">
                {copy.bootstrapFailed}
                <small style={{ display: "block", marginTop: 4 }}>{brandDisplayText(state.bootstrapError)}</small>
              </span>
              <button type="button" className="primary" onClick={() => void refreshBackend()}>{copy.retry}</button>
            </>
          ) : <BeautifulLoadingState label={copy.initializing} compact showElapsed />}
        </main>
      </>
    );
  }

  if (state.initialSetupRequired) {
    return (
      <>
        <SkipLink label={copy.skip} />
        <div id="main-content" tabIndex={-1} style={{ width: "100%", height: "100%" }}><InitialSetupView /></div>
      </>
    );
  }

  return (
    <>
      <SkipLink label={copy.skip} />
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
            <main id={state.view === "settings" ? undefined : "main-content"} tabIndex={-1} className="workspace-content">
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
      {state.view === "settings" ? (
        <div id="main-content" tabIndex={-1} style={{ width: "100%", height: "100%" }}>
          <SettingsView onBack={() => state.set({ view: "assistant" })} />
        </div>
      ) : null}
      <CommandPalette />
    </>
  );
}

function SkipLink({ label }: { label: string }) {
  const [focused, setFocused] = useState(false);
  return (
    <a
      href="#main-content"
      onClick={(event) => {
        const target = document.getElementById("main-content");
        if (!target) return;
        event.preventDefault();
        target.focus();
      }}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      style={{
        position: "fixed",
        insetInlineStart: 8,
        top: focused ? 8 : -80,
        zIndex: 10_000,
        padding: "8px 12px",
        border: "1px solid var(--border)",
        borderRadius: 4,
        background: "var(--surface-raised)",
        color: "var(--text)",
      }}
    >
      {label}
    </a>
  );
}

function interfaceCopy(locale: string) {
  if (locale === "en") return {
    skip: "Skip to main content",
    initializing: "Initializing the local service…",
    bootstrapFailed: "The local service could not be initialized.",
    retry: "Retry",
  };
  if (locale === "zh-Hant") return {
    skip: "跳至主要內容",
    initializing: "正在初始化本機服務…",
    bootstrapFailed: "無法初始化本機服務。",
    retry: "重試",
  };
  return {
    skip: "跳到主要内容",
    initializing: "正在初始化本机服务…",
    bootstrapFailed: "本机服务初始化失败。",
    retry: "重试",
  };
}
