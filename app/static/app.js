const state = {
  userId: localStorage.getItem("secflowUserId") || "windows-local-user",
  sessionId: localStorage.getItem("secflowSessionId") || newSessionId(),
  workspacePath: "",
  tasks: [],
  conversations: [],
  taskFilter: "active",
  conversationArchived: false,
  activeTaskId: null,
  pollToken: 0,
  trialTimer: null,
  trialDeadline: 0,
  activeInterrupt: null,
};

localStorage.setItem("secflowUserId", state.userId);
localStorage.setItem("secflowSessionId", state.sessionId);

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function newSessionId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `session-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function queryPath(path, params = {}) {
  const url = new URL(path, window.location.origin);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
  });
  return `${url.pathname}${url.search}`;
}

async function api(path, options = {}) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), options.timeout || 180000);
  try {
    const response = await fetch(path, {
      method: options.method || "GET",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal,
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 403 && payload.data?.trial) renderTrial(payload.data.trial);
      const detail = typeof payload.detail === "string" ? payload.detail : payload.detail?.[0]?.msg;
      throw new Error(detail || payload.message || `HTTP ${response.status}`);
    }
    return payload.data;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("请求超时，请检查本机服务或模型连接。");
    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}

function showToast(message, type = "") {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = `toast ${type}`.trim();
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.add("hidden"), 4200);
}

function setView(view) {
  const copy = {
    assistant: ["新建任务", "安全分析、代码扫描、组件查询和报告生成由模型按语义选择能力。"],
    tasks: ["任务", "查看扫描状态、证据、归档和报告确认。"],
    settings: ["设置", "资料和模型配置按当前本机用户隔离保存。"],
  };
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `${view}View`));
  $("#viewTitle").textContent = copy[view][0];
  $("#viewSubtitle").textContent = copy[view][1];
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("secflowTheme", theme);
}

function toggleTheme() {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
}

async function loadTrial() {
  renderTrial(await api("/api/trial/status"));
}

function renderTrial(trial) {
  const banner = $("#trialBanner");
  if (!trial?.enabled) {
    banner.classList.add("hidden");
    $("#trialCountdown").textContent = "无限期";
    $("#trialBlocked").classList.add("hidden");
    return;
  }
  banner.classList.remove("hidden");
  $("#trialMessage").textContent = trial.message || "7 天试用版可用。";
  if (!trial.usable) {
    $("#trialBlockedMessage").textContent = trial.message || "7 天试用期已结束。";
    $("#trialBlocked").classList.remove("hidden");
    $("#trialCountdown").textContent = "已停用";
    return;
  }
  $("#trialBlocked").classList.add("hidden");
  state.trialDeadline = performance.now() + Math.max(0, Number(trial.secondsRemaining || 0)) * 1000;
  updateTrialCountdown();
  if (state.trialTimer) window.clearInterval(state.trialTimer);
  state.trialTimer = window.setInterval(updateTrialCountdown, 1000);
}

function updateTrialCountdown() {
  const seconds = Math.max(0, Math.ceil((state.trialDeadline - performance.now()) / 1000));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  $("#trialCountdown").textContent = `${days} 天 ${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
  if (seconds === 0) loadTrial().catch(() => {});
}

async function loadRuntime() {
  try {
    const runtime = await api(queryPath("/api/system/runtime", { user_id: state.userId }));
    const llm = runtime.llm || {};
    const memory = runtime.memory || {};
    $("#runtimeStatus").textContent = `${llm.configured ? "模型可用" : "模型未配置"} · 长期记忆 ${memory.historyCount || 0} 条`;
    $("#activeModel").textContent = llm.configured ? llm.model || "模型可用" : "模型未配置";
  } catch (error) {
    $("#runtimeStatus").textContent = error.message;
  }
}

async function chooseWorkspace() {
  try {
    if (!window.pywebview?.api?.select_workspace) {
      throw new Error("当前运行方式不支持原生目录选择，请从打包后的 Windows 客户端打开。");
    }
    const selected = await window.pywebview.api.select_workspace();
    if (!selected?.path) return;
    state.activeTaskId = null;
    state.workspacePath = selected.path;
    $("#workspaceName").textContent = selected.name || selected.path;
    $("#workspaceChip").classList.remove("hidden");
    $("#composerHint").textContent = "项目意图将由模型判断";
    $("#question").focus();
  } catch (error) {
    showToast(error.message, "error");
  }
}

function clearWorkspace() {
  state.activeTaskId = null;
  state.workspacePath = "";
  $("#workspaceChip").classList.add("hidden");
  $("#composerHint").textContent = "普通问答";
}

function clearConversationView() {
  $("#conversation").innerHTML = `
    <div class="empty-state">
      <span class="empty-mark">S</span>
      <h2>今天需要分析什么？</h2>
      <p>可以直接提问，也可以选择一个代码项目后描述扫描、SBOM 或报告目标。</p>
    </div>`;
}

function ensureConversationStarted() {
  $(".empty-state", $("#conversation"))?.remove();
}

function appendMessage(role, content, options = {}) {
  ensureConversationStarted();
  const id = options.id || `message-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const article = document.createElement("article");
  article.id = id;
  article.className = `message ${role}`;
  article.innerHTML = `
    <div class="message-avatar">${role === "user" ? "用" : "S"}</div>
    <div class="message-body">
      ${options.meta ? `<div class="message-meta">${options.meta}</div>` : ""}
      <div class="message-content">${renderText(content)}</div>
      <div class="message-extra"></div>
    </div>`;
  $("#conversation").appendChild(article);
  if (options.scroll !== false) scrollConversation();
  return article;
}

function renderInlineMarkdown(value) {
  const tokens = [];
  const token = (html) => {
    const marker = `\u0000SECFLOW_INLINE_${tokens.length}\u0000`;
    tokens.push(html);
    return marker;
  };
  let source = String(value || "");
  source = source.replace(/`([^`\n]+)`/g, (_, code) => token(`<code>${escapeHtml(code)}</code>`));
  source = source.replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, label, url) => (
    token(`<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(label)}</a>`)
  ));
  let rendered = escapeHtml(source)
    .replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^_\n]+)__/g, "<strong>$1</strong>");
  rendered = rendered.replace(/\u0000SECFLOW_INLINE_(\d+)\u0000/g, (_, index) => tokens[Number(index)] || "");
  return rendered;
}

function renderMarkdownTable(lines) {
  const cells = (line) => line.trim().replace(/^\||\|$/g, "").split("|").map((item) => item.trim());
  const rows = lines.map(cells);
  const header = rows.shift() || [];
  rows.shift();
  return `<div class="markdown-table-wrap"><table class="markdown-table"><thead><tr>${header.map((cell) => `<th>${renderInlineMarkdown(cell)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${renderInlineMarkdown(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function renderText(value) {
  const lines = String(value || "").replace(/\r\n?/g, "\n").split("\n");
  const output = [];
  let paragraph = [];
  let listType = "";
  let listItems = [];

  const flushParagraph = () => {
    if (paragraph.length) output.push(`<p>${paragraph.map(renderInlineMarkdown).join("<br>")}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (listItems.length) output.push(`<${listType}>${listItems.map((item) => `<li>${renderInlineMarkdown(item)}</li>`).join("")}</${listType}>`);
    listType = "";
    listItems = [];
  };

  for (let index = 0; index < lines.length;) {
    const line = lines[index];
    const stripped = line.trim();
    const fence = stripped.match(/^```([\w+-]*)$/);
    if (fence) {
      flushParagraph();
      flushList();
      const code = [];
      index += 1;
      while (index < lines.length && !lines[index].trim().startsWith("```")) code.push(lines[index++]);
      if (index < lines.length) index += 1;
      output.push(`<pre class="code-block" data-language="${escapeHtml(fence[1] || "")}">${escapeHtml(code.join("\n"))}</pre>`);
      continue;
    }
    if (stripped.startsWith("|") && index + 1 < lines.length && /^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*$/.test(lines[index + 1])) {
      flushParagraph();
      flushList();
      const tableLines = [line, lines[index + 1]];
      index += 2;
      while (index < lines.length && lines[index].trim().startsWith("|")) tableLines.push(lines[index++]);
      output.push(renderMarkdownTable(tableLines));
      continue;
    }
    const heading = stripped.match(/^(#{1,4})\s+(.+)$/);
    const unordered = stripped.match(/^[-*]\s+(.+)$/);
    const ordered = stripped.match(/^\d+\.\s+(.+)$/);
    if (heading) {
      flushParagraph();
      flushList();
      const level = Math.min(heading[1].length + 1, 5);
      output.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
    } else if (unordered || ordered) {
      flushParagraph();
      const nextType = unordered ? "ul" : "ol";
      if (listType && listType !== nextType) flushList();
      listType = nextType;
      listItems.push((unordered || ordered)[1]);
    } else if (stripped.startsWith("> ")) {
      flushParagraph();
      flushList();
      output.push(`<blockquote>${renderInlineMarkdown(stripped.slice(2))}</blockquote>`);
    } else if (!stripped) {
      flushParagraph();
      flushList();
    } else {
      flushList();
      paragraph.push(line);
    }
    index += 1;
  }
  flushParagraph();
  flushList();
  return output.join("");
}

function scrollConversation() {
  const target = $("#conversation");
  requestAnimationFrame(() => target.scrollTo({ top: target.scrollHeight, behavior: "smooth" }));
}

function renderTrace(trace = []) {
  if (!trace.length) return "";
  return `<div class="trace-list">${trace.map((item) => `
    <div class="trace-item ${escapeHtml(item.status || "pending")}">
      <i></i><span><b>${escapeHtml(nodeLabel(item.node))}</b> · ${escapeHtml(item.message || "")}</span><time>${escapeHtml(item.time || "")}</time>
    </div>`).join("")}</div>`;
}

function nodeLabel(value) {
  const labels = {
    assistant_intent_classifier: "理解任务意图",
    load_memory_context: "读取长期记忆",
    inspect_workspace: "检查项目范围",
    dependency_scan: "解析依赖组件",
    code_scan_mcp: "调用代码扫描 MCP",
    report_capability_subgraph: "生成报告",
    call_llm: "模型综合分析",
    compose_answer: "整理回答",
  };
  return labels[value] || String(value || "执行节点").replaceAll("_", " ");
}

async function submitQuestion(event) {
  event.preventDefault();
  const question = $("#question").value.trim();
  if (!question) return;
  $("#sendButton").disabled = true;
  appendMessage("user", question, { meta: state.workspacePath ? `已选择项目 · ${escapeHtml(state.workspacePath)}` : "" });
  $("#question").value = "";
  try {
    if (state.activeTaskId) {
      await submitTaskAction(state.activeTaskId, question);
    } else if (state.workspacePath) {
      await submitWorkspaceAction(question);
    } else {
      await streamQuestion(question);
    }
    await Promise.all([loadConversations(), loadRuntime()]);
  } catch (error) {
    appendMessage("assistant", `处理失败：${error.message}`);
    showToast(error.message, "error");
  } finally {
    $("#sendButton").disabled = false;
  }
}

async function submitTaskAction(taskId, objective) {
  const pending = appendMessage("assistant", "正在结合已完成的扫描证据理解后续任务...", { meta: "Security Agent · 任务上下文", id: `pending-${Date.now()}` });
  const result = await api(`/api/assistant/tasks/${encodeURIComponent(taskId)}/actions`, {
    method: "POST",
    timeout: 900000,
    body: {
      objective,
      user_id: state.userId,
      session_id: state.sessionId,
      response_language: "zh-Hans",
    },
  });
  pending.remove();
  if (result.kind === "agent_task" && result.task) {
    state.activeTaskId = result.task.id;
    renderTaskInConversation(result.task);
    await loadTasks();
    pollTask(result.task.id);
  } else {
    renderAssistantResult(result.answer || result);
  }
}

async function submitWorkspaceAction(objective) {
  const pending = appendMessage("assistant", "正在理解项目任务并选择分析能力...", { meta: "Security Agent · 语义路由", id: `pending-${Date.now()}` });
  const result = await api("/api/assistant/workspace-actions", {
    method: "POST",
    timeout: 900000,
    body: {
      objective,
      workspace_path: state.workspacePath,
      user_id: state.userId,
      session_id: state.sessionId,
      response_language: "zh-Hans",
    },
  });
  pending.remove();
  if (result.kind === "agent_task" && result.task) {
    renderTaskInConversation(result.task);
    await loadTasks();
    pollTask(result.task.id);
  } else {
    renderAssistantResult(result.answer || result);
  }
}

async function streamQuestion(question) {
  const message = appendMessage("assistant", "", { meta: "Security Agent · 流式分析" });
  const contentTarget = $(".message-content", message);
  const extraTarget = $(".message-extra", message);
  let streamed = "";
  const trace = [];
  const response = await fetch("/api/assistant/questions/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify({ question, top_k: 8, user_id: state.userId, session_id: state.sessionId, response_language: "zh-Hans", attachments: [] }),
  });
  if (!response.ok || !response.body) throw new Error(`模型流式请求失败：HTTP ${response.status}`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult = null;
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const blocks = buffer.split("\n\n");
    buffer = blocks.pop() || "";
    for (const block of blocks) {
      const event = parseSSEBlock(block);
      if (!event) continue;
      if (event.name === "trace") {
        trace.push(event.data);
        extraTarget.innerHTML = renderTrace(trace);
      } else if (event.name === "content") {
        streamed += event.data.delta || "";
        contentTarget.innerHTML = renderText(streamed);
        scrollConversation();
      } else if (event.name === "result") {
        finalResult = event.data;
      } else if (event.name === "error") {
        throw new Error(event.data.message || "模型执行失败");
      }
    }
    if (done) break;
  }
  if (finalResult?.agent_task) {
    message.remove();
    state.activeTaskId = finalResult.agent_task.id;
    renderTaskInConversation(finalResult.agent_task);
    await loadTasks();
    pollTask(finalResult.agent_task.id);
  } else if (finalResult) {
    hydrateAssistantMessage(message, finalResult, trace);
  }
}

function parseSSEBlock(block) {
  let name = "message";
  const data = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) name = line.slice(6).trim();
    if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  if (!data.length) return null;
  try { return { name, data: JSON.parse(data.join("\n")) }; } catch { return null; }
}

function renderAssistantResult(result) {
  const message = appendMessage("assistant", result.summary || "分析已完成。", { meta: modeLabel(result.mode) });
  hydrateAssistantMessage(message, result, result.trace || []);
}

function hydrateAssistantMessage(message, result, trace, shouldScroll = true) {
  $(".message-content", message).innerHTML = renderText(result.summary || "分析已完成。");
  const fields = result.fields || {};
  const card = result.vulnerability_card || {};
  const artifacts = result.artifacts || [];
  const fieldHtml = Object.keys(card).length ? renderFields(card) : renderFields(fields);
  const artifactsHtml = artifacts.length ? `<div class="task-actions">${artifacts.map((item) => `<a class="secondary-button" href="${escapeHtml(item.download_path || "#")}" download>${escapeHtml(item.file_name || "下载文件")}</a>`).join("")}</div>` : "";
  const tools = (result.tool_calls || result.tools || []).length ? `<details class="tool-box"><summary>工具调用</summary><pre>${escapeHtml(JSON.stringify(result.tool_calls || result.tools, null, 2))}</pre></details>` : "";
  $(".message-extra", message).innerHTML = `${renderTrace(trace)}${fieldHtml}${artifactsHtml}${tools}${renderInterrupt(result.interrupt)}`;
  if (result.interrupt) state.activeInterrupt = result.interrupt;
  if (shouldScroll) scrollConversation();
}

function renderFields(fields) {
  const entries = Object.entries(fields || {}).filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (!entries.length) return "";
  return `<div class="answer-fields">${entries.map(([key, value]) => `<div><span>${escapeHtml(key)}</span><b>${escapeHtml(Array.isArray(value) ? value.join("、") : value)}</b></div>`).join("")}</div>`;
}

function renderInterrupt(interrupt) {
  if (!interrupt) return "";
  const formats = interrupt.kind === "report_download_confirmation" ? `<select data-interrupt-format><option value="pdf">PDF</option><option value="docx">Word</option><option value="html">HTML</option><option value="md">Markdown</option></select>` : "";
  return `<div class="tool-box" data-interrupt-thread="${escapeHtml(interrupt.thread_id || "")}" data-interrupt-id="${escapeHtml(interrupt.interrupt_id || "")}"><div class="task-card"><div><h3>${escapeHtml(interrupt.question || "需要人工确认")}</h3><p>${escapeHtml(interrupt.kind || "interrupt")}</p></div><div class="task-actions">${formats}<button data-interrupt="cancel">取消</button><button data-interrupt="confirm">确认</button></div></div></div>`;
}

async function resumeInterrupt(decision, source) {
  const card = source.closest(".tool-box");
  const threadId = card?.dataset.interruptThread || state.activeInterrupt?.thread_id;
  const interruptId = card?.dataset.interruptId || state.activeInterrupt?.interrupt_id || "";
  if (!threadId) return;
  const format = $("[data-interrupt-format]", card)?.value || null;
  const result = await api("/api/assistant/interrupts/resume", {
    method: "POST",
    timeout: 900000,
    body: {
      thread_id: threadId,
      interrupt_id: interruptId,
      decision,
      format,
      user_id: state.userId,
      session_id: state.sessionId,
    },
  });
  state.activeInterrupt = result.interrupt || null;
  renderAssistantResult(result.answer || result);
}

function modeLabel(mode) {
  const labels = { security_knowledge: "安全知识分析", llm_direct: "模型问答", project_sbom_export: "SBOM 分析", component_vulnerability_catalog: "组件漏洞分析", report_action: "报告处理" };
  return labels[mode] || "Security Agent";
}

async function loadTasks() {
  state.tasks = await api(queryPath("/api/agent/tasks", { user_id: state.userId, limit: 50, archived: state.taskFilter === "archived" }));
  renderTaskLists();
}

function renderTaskLists() {
  $("#taskCount").textContent = state.tasks.length;
  const projectList = $("#projectList");
  projectList.classList.toggle("empty-list", !state.tasks.length);
  projectList.innerHTML = state.tasks.length ? state.tasks.slice(0, 14).map((task) => sidebarTask(task)).join("") : "暂无项目";
  const center = $("#taskCenter");
  center.classList.toggle("empty-list", !state.tasks.length);
  center.innerHTML = state.tasks.length ? state.tasks.map((task) => taskCard(task)).join("") : "暂无任务";
}

function sidebarTask(task) {
  return `<div class="sidebar-row" data-task-id="${escapeHtml(task.id)}"><span>${escapeHtml(task.workspace_name || task.objective || "项目")}</span><span class="row-actions"><button data-task-action="archive" title="${state.taskFilter === "archived" ? "恢复" : "归档"}">${state.taskFilter === "archived" ? "&#8634;" : "&#9633;"}</button><button data-task-action="delete" title="删除">&#215;</button></span></div>`;
}

function taskCard(task) {
  const findings = task.result?.total_findings ?? task.result?.finding_count ?? 0;
  return `<article class="task-card" data-task-id="${escapeHtml(task.id)}">
    <div><h3>${escapeHtml(task.workspace_name || task.objective || "代码扫描任务")}</h3><p><span class="status-badge ${escapeHtml(task.status)}">${escapeHtml(statusLabel(task.status))}</span> · ${escapeHtml(task.current_node || "-")} · ${Number(findings)} 条风险</p><p>${escapeHtml(task.objective || "")}</p></div>
    <div class="task-actions"><button data-task-action="open">查看</button>${["queued", "running"].includes(task.status) ? '<button data-task-action="cancel">停止</button>' : ""}<button data-task-action="archive">${state.taskFilter === "archived" ? "恢复" : "归档"}</button><button data-task-action="delete">删除</button></div>
  </article>`;
}

function statusLabel(status) {
  return { queued: "排队中", running: "扫描中", completed: "已完成", failed: "失败", cancelled: "已取消", interrupted: "等待确认" }[status] || status || "未知";
}

function renderTaskInConversation(task) {
  let message = document.getElementById(`task-${task.id}`);
  if (!message) message = appendMessage("assistant", "", { id: `task-${task.id}`, meta: `Security Agent · ${escapeHtml(task.workspace_name || "项目扫描")}` });
  const events = (task.events || []).slice(-14);
  const progress = task.plan?.length ? `${task.plan.filter((step) => step.status === "completed").length}/${task.plan.length}` : "-";
  const findings = Number(task.result?.total_findings ?? task.result?.finding_count ?? 0);
  $(".message-content", message).innerHTML = `<p><b>${escapeHtml(statusLabel(task.status))}</b> · 进度 ${escapeHtml(progress)} · ${findings} 条已确认风险</p><p>${escapeHtml(task.objective || "")}</p>`;
  let controls = "";
  if (task.status === "completed" && task.report_ready && task.report_decision === "pending") {
    controls = `<div class="task-actions"><button data-task-action="rescan" data-task-id="${escapeHtml(task.id)}">重新扫描</button><button data-report-generate="false" data-task-id="${escapeHtml(task.id)}">暂不生成</button><button data-report-generate="true" data-task-id="${escapeHtml(task.id)}">确认生成报告</button></div>`;
  } else if (task.report_decision === "generated" && task.report_interrupt) {
    controls = `<div class="task-actions"><button data-task-action="rescan" data-task-id="${escapeHtml(task.id)}">重新扫描</button><select data-report-format><option value="pdf">PDF</option><option value="docx">Word</option><option value="html">HTML</option><option value="md">Markdown</option></select><button data-report-download data-task-id="${escapeHtml(task.id)}">确认下载</button></div>`;
  } else if (task.status === "failed") {
    controls = `<div class="task-actions"><button data-task-action="resume" data-task-id="${escapeHtml(task.id)}">重新扫描</button></div>`;
  }
  $(".message-extra", message).innerHTML = `${renderTrace(events)}${controls}${task.error ? `<details class="tool-box" open><summary>失败归因</summary><pre>${escapeHtml(task.error)}</pre></details>` : ""}`;
  scrollConversation();
}

async function pollTask(taskId) {
  const token = ++state.pollToken;
  while (token === state.pollToken) {
    const task = await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}`, { user_id: state.userId }));
    renderTaskInConversation(task);
    if (["completed", "failed", "cancelled", "interrupted"].includes(task.status)) {
      await loadTasks();
      return;
    }
    await new Promise((resolve) => window.setTimeout(resolve, 900));
  }
}

async function handleTaskAction(action, taskId) {
  if (action === "open") {
    setView("assistant");
    const task = await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}`, { user_id: state.userId }));
    state.activeTaskId = task.id;
    state.workspacePath = task.workspace_path || "";
    $("#workspaceName").textContent = task.workspace_name || task.workspace_path || "已选择扫描任务";
    $("#workspaceChip").classList.remove("hidden");
    $("#composerHint").textContent = "基于扫描结果追问或重新扫描";
    renderTaskInConversation(task);
    if (["queued", "running"].includes(task.status)) pollTask(task.id);
    return;
  }
  if (action === "delete") {
    if (!window.confirm("确定删除该任务及其执行记录吗？")) return;
    await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}`, { user_id: state.userId }), { method: "DELETE" });
  } else if (action === "archive") {
    await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}/archive`, { user_id: state.userId }), { method: "POST", body: { archived: state.taskFilter !== "archived" } });
  } else if (action === "cancel") {
    await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}/cancel`, { user_id: state.userId }), { method: "POST" });
  } else if (action === "resume") {
    await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}/resume`, { user_id: state.userId }), { method: "POST" });
    pollTask(taskId);
  } else if (action === "rescan") {
    await submitTaskAction(taskId, "重新完整扫描这个项目");
  }
  await loadTasks();
}

async function decideReport(taskId, generate) {
  const task = await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}/report-decision`, { user_id: state.userId }), { method: "POST", timeout: 300000, body: { generate } });
  renderTaskInConversation(task);
  await loadTasks();
}

async function downloadTaskReport(taskId, source) {
  const format = $("[data-report-format]", source.closest(".message-extra"))?.value || "pdf";
  const result = await api(queryPath(`/api/agent/tasks/${encodeURIComponent(taskId)}/report-download-decision`, { user_id: state.userId }), { method: "POST", timeout: 300000, body: { confirm: true, format } });
  if (result.artifact?.download_path) {
    const link = document.createElement("a");
    link.href = result.artifact.download_path;
    link.download = result.artifact.file_name || `SecFlow-report.${format}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast(`已下载 ${result.artifact.file_name}`);
  }
  renderTaskInConversation(result.task);
}

async function loadConversations() {
  state.conversations = await api(queryPath("/api/assistant/conversations", { user_id: state.userId, limit: 30, archived: state.conversationArchived }));
  $("#conversationHeading").textContent = state.conversationArchived ? "已归档对话" : "历史对话";
  $("#toggleArchivedConversations").classList.toggle("active", state.conversationArchived);
  $("#toggleArchivedConversations").title = state.conversationArchived ? "返回历史对话" : "查看已归档对话";
  const list = $("#conversationList");
  list.classList.toggle("empty-list", !state.conversations.length);
  list.innerHTML = state.conversations.length ? state.conversations.map((item) => {
    const sessionId = item.session_id || item.id;
    const archiveLabel = state.conversationArchived ? "恢复" : "归档";
    return `<div class="sidebar-row ${sessionId === state.sessionId ? "active" : ""}" data-session-id="${escapeHtml(sessionId)}"><span>${escapeHtml(item.title || item.preview || item.last_question || "历史对话")}</span><span class="row-actions"><button data-conversation-action="archive" title="${archiveLabel}">${state.conversationArchived ? "&#8634;" : "&#9633;"}</button><button data-conversation-action="delete" title="删除">&#215;</button></span></div>`;
  }).join("") : (state.conversationArchived ? "暂无已归档对话" : "暂无对话");
}

async function openConversation(sessionId) {
  const detail = await api(queryPath(`/api/assistant/conversations/${encodeURIComponent(sessionId)}`, { user_id: state.userId }));
  state.sessionId = sessionId;
  localStorage.setItem("secflowSessionId", state.sessionId);
  state.activeTaskId = null;
  state.workspacePath = "";
  $("#workspaceChip").classList.add("hidden");
  $("#composerHint").textContent = "普通问答";
  clearConversationView();
  const exchanges = detail.exchanges || [];
  const turns = detail.messages || detail.turns || detail.history || [];
  if (exchanges.length || turns.length) {
    $(".empty-state", $("#conversation"))?.remove();
    if (exchanges.length) {
      exchanges.forEach((exchange) => {
        appendMessage("user", exchange.question || "", { scroll: false });
        const payload = exchange.answer_payload || {};
        const message = appendMessage("assistant", exchange.answer || payload.summary || "", { meta: modeLabel(exchange.mode), scroll: false });
        if (Object.keys(payload).length) hydrateAssistantMessage(message, payload, payload.trace || [], false);
      });
    } else {
      turns.forEach((turn) => appendMessage(turn.role === "assistant" ? "assistant" : "user", turn.content || turn.summary || turn.question || "", { scroll: false }));
    }
    const conversation = $("#conversation");
    conversation.scrollTop = conversation.scrollHeight;
  }
  await loadConversations();
  setView("assistant");
}

async function handleConversationAction(action, sessionId) {
  if (action === "delete" && !window.confirm("确定删除该历史对话吗？")) return;
  const path = queryPath(`/api/assistant/conversations/${encodeURIComponent(sessionId)}${action === "archive" ? "/archive" : ""}`, { user_id: state.userId });
  await api(path, action === "archive" ? { method: "POST", body: { archived: !state.conversationArchived } } : { method: "DELETE" });
  if (sessionId === state.sessionId) newConversation();
  await loadConversations();
}

function newConversation() {
  state.sessionId = newSessionId();
  localStorage.setItem("secflowSessionId", state.sessionId);
  state.activeInterrupt = null;
  state.activeTaskId = null;
  state.workspacePath = "";
  state.pollToken += 1;
  $("#workspaceChip").classList.add("hidden");
  $("#composerHint").textContent = "普通问答";
  clearConversationView();
  loadConversations().catch(() => {});
  setView("assistant");
  $("#question").focus();
}

async function loadProfile() {
  const profile = await api(queryPath("/api/settings/profile", { user_id: state.userId }));
  const form = $("#profileForm");
  ["display_name", "email", "phone", "department", "role", "employee_id", "bio"].forEach((name) => { form.elements[name].value = profile[name] || ""; });
  const name = profile.display_name || "本机用户";
  $("#userName").textContent = name;
  $("#userAvatar").textContent = name.slice(0, 1);
}

async function saveProfile(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const body = Object.fromEntries(["display_name", "email", "phone", "department", "role", "employee_id", "bio"].map((name) => [name, form.elements[name].value.trim()]));
  const profile = await api(queryPath("/api/settings/profile", { user_id: state.userId }), { method: "PATCH", body });
  $("#profileStatus").textContent = "资料已保存";
  $("#userName").textContent = profile.display_name;
  $("#userAvatar").textContent = profile.display_name.slice(0, 1);
}

function llmPayload(includeKey = true) {
  const form = $("#llmForm");
  const provider = form.elements.provider.value;
  return {
    provider,
    catalog_provider: null,
    model: form.elements.model.value,
    endpoint: form.elements.endpoint.value.trim() || null,
    api_key: includeKey ? (form.elements.api_key.value.trim() || null) : null,
    enabled: true,
    max_tokens: Number(form.elements.max_tokens.value || 1800),
    temperature: 0.25,
    top_p: 0.9,
    timeout_ms: Number(form.elements.timeout_ms.value || 60000),
    wire_api: provider === "openai" ? "responses" : "chat",
    reasoning_effort: provider === "openai" ? "medium" : null,
    disable_response_storage: provider === "openai" ? true : null,
  };
}

async function loadLLMConfig() {
  const config = await api(queryPath("/api/llm/config", { user_id: state.userId }));
  const form = $("#llmForm");
  form.elements.provider.value = config.provider || "openai";
  form.elements.endpoint.value = config.endpoint || "";
  setModelOptions([config.model || "gpt-5.6"], config.model || "gpt-5.6");
  form.elements.api_key.placeholder = config.has_api_key ? `已保存 ${config.api_key_masked || "密钥"}` : "输入 API Key";
  form.elements.max_tokens.value = config.max_tokens || 1800;
  form.elements.timeout_ms.value = config.timeout_ms || 60000;
  $("#llmStatus").textContent = config.message || "";
  $("#activeModel").textContent = config.configured ? config.model : "模型未配置";
}

function setModelOptions(models, selected) {
  const select = $("#llmForm").elements.model;
  const clean = [...new Set(models.filter(Boolean))];
  select.innerHTML = clean.map((model) => `<option value="${escapeHtml(model)}" ${model === selected ? "selected" : ""}>${escapeHtml(model)}</option>`).join("");
}

async function loadModels() {
  const payload = llmPayload();
  const result = await api(queryPath("/api/llm/models", { user_id: state.userId }), { method: "POST", body: { provider: payload.provider, catalog_provider: payload.catalog_provider, endpoint: payload.endpoint, api_key: payload.api_key, timeout_ms: payload.timeout_ms } });
  const models = (result.models || []).map((item) => typeof item === "string" ? item : item.id || item.name);
  setModelOptions(models.length ? models : [payload.model], payload.model);
  $("#llmStatus").textContent = result.message || `已获取 ${models.length} 个模型`;
}

async function saveLLM(event) {
  event.preventDefault();
  const result = await api(queryPath("/api/llm/config", { user_id: state.userId }), { method: "PATCH", body: llmPayload() });
  $("#llmForm").elements.api_key.value = "";
  $("#llmStatus").textContent = result.message || "模型配置已保存";
  await loadRuntime();
}

async function testLLM() {
  const result = await api(queryPath("/api/llm/test", { user_id: state.userId }), { method: "POST", timeout: 180000, body: llmPayload() });
  $("#llmStatus").textContent = result.message || result.status || "连接测试完成";
}

function bindEvents() {
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => setView(item.dataset.view)));
  $("#themeToggle").addEventListener("click", toggleTheme);
  $("#chooseWorkspace").addEventListener("click", chooseWorkspace);
  $("#clearWorkspace").addEventListener("click", clearWorkspace);
  $("#askForm").addEventListener("submit", submitQuestion);
  $("#newConversation").addEventListener("click", newConversation);
  $("#toggleArchivedConversations").addEventListener("click", async () => {
    state.conversationArchived = !state.conversationArchived;
    await loadConversations();
  });
  $("#refreshTasks").addEventListener("click", () => loadTasks().catch(handleError));
  $("#reloadTaskCenter").addEventListener("click", () => loadTasks().catch(handleError));
  $("#profileForm").addEventListener("submit", (event) => saveProfile(event).catch(handleError));
  $("#llmForm").addEventListener("submit", (event) => saveLLM(event).catch(handleError));
  $("#loadModels").addEventListener("click", () => loadModels().catch(handleError));
  $("#testModel").addEventListener("click", () => testLLM().catch(handleError));
  $$('[data-task-filter]').forEach((button) => button.addEventListener("click", async () => {
    $$('[data-task-filter]').forEach((item) => item.classList.toggle("active", item === button));
    state.taskFilter = button.dataset.taskFilter;
    await loadTasks();
  }));
  document.addEventListener("click", async (event) => {
    const taskAction = event.target.closest("[data-task-action]");
    const reportDecision = event.target.closest("[data-report-generate]");
    const reportDownload = event.target.closest("[data-report-download]");
    const interrupt = event.target.closest("[data-interrupt]");
    const conversationAction = event.target.closest("[data-conversation-action]");
    try {
      if (taskAction) {
        event.stopPropagation();
        const taskId = taskAction.dataset.taskId || taskAction.closest("[data-task-id]")?.dataset.taskId;
        await handleTaskAction(taskAction.dataset.taskAction, taskId);
      } else if (reportDecision) {
        await decideReport(reportDecision.dataset.taskId, reportDecision.dataset.reportGenerate === "true");
      } else if (reportDownload) {
        await downloadTaskReport(reportDownload.dataset.taskId, reportDownload);
      } else if (interrupt) {
        await resumeInterrupt(interrupt.dataset.interrupt, interrupt);
      } else if (conversationAction) {
        event.stopPropagation();
        const sessionId = conversationAction.closest("[data-session-id]")?.dataset.sessionId;
        await handleConversationAction(conversationAction.dataset.conversationAction, sessionId);
      } else {
        const taskRow = event.target.closest("[data-task-id]");
        const conversationRow = event.target.closest("[data-session-id]");
        if (taskRow) await handleTaskAction("open", taskRow.dataset.taskId);
        if (conversationRow) await openConversation(conversationRow.dataset.sessionId);
      }
    } catch (error) { handleError(error); }
  });
}

function handleError(error) {
  showToast(error.message || String(error), "error");
}

async function bootstrap() {
  const savedTheme = localStorage.getItem("secflowTheme");
  applyTheme(savedTheme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  bindEvents();
  const results = await Promise.allSettled([loadTrial(), loadRuntime(), loadProfile(), loadLLMConfig(), loadTasks(), loadConversations()]);
  const failures = results.filter((result) => result.status === "rejected");
  if (failures.length) showToast(`有 ${failures.length} 项本机配置未能读取，请在设置中检查。`, "error");
  $("#question").focus();
}

bootstrap();
