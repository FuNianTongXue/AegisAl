export const isTauri = () => "__TAURI_INTERNALS__" in window;

export async function openExternalUrl(url: string) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("仅允许打开公开网页链接。");
  }
  if (isTauri()) {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(parsed.toString());
    return;
  }
  window.open(parsed.toString(), "_blank", "noopener,noreferrer");
}

/** Open a clean task workspace without replacing the task in this window. */
export async function openNewTaskWindow() {
  if (!isTauri()) {
    const url = new URL(window.location.href);
    url.search = "";
    url.searchParams.set("secflowWindow", "task");
    url.searchParams.set("taskWindowId", crypto.randomUUID());
    window.open(url.toString(), "_blank", "noopener,noreferrer");
    return;
  }
  const { invoke } = await import("@tauri-apps/api/core");
  await invoke<string>("open_task_window");
}

export type ProjectDropHandlers = {
  onActive: (active: boolean) => void;
  onDrop: (path: string) => void;
  onError: (message: string) => void;
};

export async function chooseProjectDirectory() {
  if (!isTauri()) {
    try {
      return window.prompt("输入本机项目绝对路径", "") || null;
    } catch {
      return null;
    }
  }
  const { open } = await import("@tauri-apps/plugin-dialog");
  const selected = await open({ directory: true, multiple: false, title: "选择需要分析的代码项目" });
  return typeof selected === "string" ? selected : null;
}

export async function validateProjectDirectory(path: string) {
  const cleanPath = path.trim();
  if (!cleanPath) throw new Error("未检测到可用的项目目录。");
  if (!isTauri()) return cleanPath;
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<string>("validate_project_directory", { path: cleanPath });
}

export async function listenForProjectDirectoryDrop(handlers: ProjectDropHandlers) {
  if (!isTauri()) return () => undefined;
  const { getCurrentWebview } = await import("@tauri-apps/api/webview");
  return getCurrentWebview().onDragDropEvent((event) => {
    if (event.payload.type === "enter" || event.payload.type === "over") {
      handlers.onActive(true);
      return;
    }
    handlers.onActive(false);
    if (event.payload.type !== "drop") return;
    const paths = event.payload.paths;
    void (async () => {
      for (const path of paths) {
        try {
          handlers.onDrop(await validateProjectDirectory(path));
          return;
        } catch {
          // Continue until a directory is found when files and a project are dropped together.
        }
      }
      handlers.onError("请拖入一个完整的项目目录，不能只拖入单个文件。");
    })();
  });
}

export async function saveBinaryArtifact(fileName: string, content: Blob) {
  if (!isTauri()) {
    const url = URL.createObjectURL(content);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
    return true;
  }
  const { save } = await import("@tauri-apps/plugin-dialog");
  const destination = await save({ defaultPath: fileName });
  if (!destination) return false;
  const { writeFile } = await import("@tauri-apps/plugin-fs");
  await writeFile(destination, new Uint8Array(await content.arrayBuffer()));
  return true;
}

export async function saveBinaryArtifacts(items: Array<{ fileName: string; content: Blob }>) {
  if (!items.length) return;
  if (!isTauri()) {
    for (const item of items) await saveBinaryArtifact(item.fileName, item.content);
    return;
  }
  const { open } = await import("@tauri-apps/plugin-dialog");
  const directory = await open({ directory: true, multiple: false, title: "选择报告保存目录" });
  if (typeof directory !== "string") return;
  const [{ writeFile }, { join }] = await Promise.all([
    import("@tauri-apps/plugin-fs"),
    import("@tauri-apps/api/path"),
  ]);
  for (const item of items) {
    await writeFile(await join(directory, item.fileName), new Uint8Array(await item.content.arrayBuffer()));
  }
}
