import { invoke } from "@tauri-apps/api/core";

export async function restartLocalBackend(): Promise<boolean> {
  if (!("__TAURI_INTERNALS__" in window)) return false;
  await invoke("restart_backend");
  return true;
}
