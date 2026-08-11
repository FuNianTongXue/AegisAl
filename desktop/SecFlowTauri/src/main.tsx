import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import "./styles.css";
import { useAppStore } from "./store/appStore";

// Task windows share the durable user/project catalog, but must always begin
// with a blank active conversation. Reset before React paints so an existing
// task from the main window never flashes in the newly-created window.
if (new URLSearchParams(window.location.search).get("secflowWindow") === "task") {
  useAppStore.getState().resetConversation();
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
