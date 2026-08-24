// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";

import { SecFlowApi } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("model configuration payloads", () => {
  it("normalizes a historical blank reasoning effort when loading and saving", async () => {
    const responseConfig = {
      provider: "openai",
      catalog_provider: "openai",
      endpoint: "https://api.openai.com/v1",
      model: "gpt-5.6-sol",
      wire_api: "responses",
      reasoning_effort: "",
      reasoning_options: [
        { value: "none" },
        { value: "medium" },
        { value: "high" },
      ],
      max_tokens: 1800,
      timeout_ms: 60000,
      enabled: true,
      has_api_key: true,
    };
    const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ data: responseConfig }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new SecFlowApi("http://secflow.test");

    const loaded = await client.llmConfig("default");
    expect(loaded.reasoning_effort).toBe("medium");

    await client.saveLlmConfig("default", { ...loaded, reasoning_effort: "" as never });

    const [, request] = fetchMock.mock.calls[1] as [URL, RequestInit];
    const payload = JSON.parse(String(request.body));
    expect(payload.reasoning_effort).toBe("medium");
  });

  it("sends an explicit API key clear request without inventing a replacement", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        provider: "custom",
        catalog_provider: "custom",
        endpoint: "https://gateway.example/v1",
        model: "third-party-model",
        max_tokens: 1800,
        timeout_ms: 60000,
        enabled: true,
        has_api_key: false,
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await new SecFlowApi("http://secflow.test").saveLlmConfig("default", {
      provider: "custom",
      catalog_provider: "custom",
      endpoint: "https://gateway.example/v1",
      model: "third-party-model",
      max_tokens: 1800,
      timeout_ms: 60000,
      enabled: true,
      clear_api_key: true,
    });

    const [, request] = fetchMock.mock.calls[0] as [URL, RequestInit];
    const payload = JSON.parse(String(request.body));
    expect(payload.clear_api_key).toBe(true);
    expect(payload.api_key).toBeUndefined();
  });
});

describe("dashboard normalization", () => {
  it("maps explicit KEV, PoC, and recent update trend fields", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        vulnerability_count: 10_000,
        known_exploited_count: 1_656,
        poc_count: 412,
        severity: { CRITICAL: 100, HIGH: 900 },
        recent_records: [],
        recent_update_trend: [
          { date: "2026-07-31", count: 44 },
          { date: "2026-08-01", count: 36 },
        ],
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const dashboard = await new SecFlowApi("http://secflow.test").dashboard();

    expect(dashboard.stats.kev).toBe(1_656);
    expect(dashboard.stats.poc).toBe(412);
    expect(dashboard.trend).toEqual([
      { date: "2026-07-31", count: 44 },
      { date: "2026-08-01", count: 36 },
    ]);
  });

  it("shares dashboard requests, reuses the short cache, and bypasses it on refresh", async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({
      data: { vulnerability_count: 10, recent_records: [] },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new SecFlowApi("http://secflow.test");

    await Promise.all([client.dashboard("zh-Hans"), client.dashboard("zh-Hans")]);
    await client.dashboard("zh-Hans");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await client.dashboard("zh-Hans", true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [refreshUrl] = fetchMock.mock.calls[1] as [URL, RequestInit];
    expect(refreshUrl.searchParams.get("refresh")).toBe("true");
  });

  it("sends the requested language and normalizes offline translation progress and localized fields", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        response_language: "zh-Hans",
        vulnerability_count: 20,
        catalog_count: 20,
        catalog_translation: {
          status: "completed",
          target_language: "zh-Hans",
          record_count: 20,
          ready_records: 20,
        },
        recent_records: [{
          id: "CVE-2026-1234",
          title: "OpenSSL validation issue",
          title_zh: "OpenSSL 验证缺陷",
          summary: "A validation issue affects OpenSSL.",
          summary_zh: "OpenSSL 受验证缺陷影响。",
          content_language: "zh-Hans",
          catalog_translation: { status: "translated" },
        }],
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const dashboard = await new SecFlowApi("http://secflow.test").dashboard("zh-Hans");

    const [url] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.searchParams.get("response_language")).toBe("zh-Hans");
    expect(dashboard).toMatchObject({
      response_language: "zh-Hans",
      translation_status: "translated",
      translation_progress: 100,
      translation_count: 20,
      translation_ready_count: 20,
    });
    expect(dashboard.records[0]).toMatchObject({
      title: "OpenSSL 验证缺陷",
      description: "OpenSSL 受验证缺陷影响。",
      content_language: "zh-Hans",
      translation_status: "translated",
    });
  });

  it("keeps original vulnerability content for an English request", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        response_language: "en",
        recent_records: [{
          id: "CVE-2026-4321",
          title: "中文标题",
          title_original: "Original vulnerability title",
          summary: "中文描述。",
          summary_original: "Original vulnerability description.",
          content_language: "en",
          translation_status: "original",
        }],
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const dashboard = await new SecFlowApi("http://secflow.test").dashboard("en");

    const [url] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.searchParams.get("response_language")).toBe("en");
    expect(dashboard.translation_status).toBe("not_required");
    expect(dashboard.records[0]).toMatchObject({
      title: "Original vulnerability title",
      description: "Original vulnerability description.",
      translation_status: "original",
    });
  });

  it("keeps total and ready translation counts distinct for a partial catalog", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        response_language: "zh-Hans",
        vulnerability_count: 20,
        translation_count: 5,
        translation_progress: 25,
        translation_status: "partial",
        catalog_translation: {
          status: "partial",
          record_count: 20,
          ready_records: 5,
        },
        recent_records: [],
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const dashboard = await new SecFlowApi("http://secflow.test").dashboard("zh-Hans");

    expect(dashboard.translation_count).toBe(20);
    expect(dashboard.translation_ready_count).toBe(5);
    expect(dashboard.translation_progress).toBe(25);
    expect(dashboard.translation_status).toBe("pending");
  });

  it("drops pending mixed-language prose from normalized display fields", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        response_language: "zh-Hans",
        recent_records: [{
          id: "CVE-2026-76008",
          title: "远程 URI 参数 Parsing vulnerability",
          summary: "远程攻击者可以 trigger 基于堆栈的缓冲区溢出。",
          content_language: "unknown",
          translation_status: "pending",
        }],
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const dashboard = await new SecFlowApi("http://secflow.test").dashboard("zh-Hans");

    expect(dashboard.records[0]).toMatchObject({
      id: "CVE-2026-76008",
      title: "",
      summary: "",
      description: "",
      translation_status: "pending",
    });
  });

  it("keeps explicit public source facts visible while translation is pending", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        response_language: "zh-Hans",
        recent_records: [{
          id: "CVE-2026-76011",
          title: "Original vulnerability title",
          title_original: "Original vulnerability title",
          summary: "Original public vulnerability description.",
          summary_original: "Original public vulnerability description.",
          content_language: "en",
          translation_status: "pending",
        }],
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const dashboard = await new SecFlowApi("http://secflow.test").dashboard("zh-Hans");

    expect(dashboard.records[0]).toMatchObject({
      title: "Original vulnerability title",
      summary: "Original public vulnerability description.",
      description: "Original public vulnerability description.",
      translation_status: "pending",
    });
  });

  it("does not let a simplified response override a Traditional Chinese request", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: {
        response_language: "zh-Hans",
        translation_status: "completed",
        recent_records: [{
          id: "CVE-2026-76009",
          title: "简体中文漏洞标题",
          summary: "简体中文漏洞描述。",
          content_language: "zh-Hans",
          translation_status: "translated",
        }],
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const dashboard = await new SecFlowApi("http://secflow.test").dashboard("zh-Hant");

    expect(dashboard.response_language).toBe("zh-Hant");
    expect(dashboard.translation_status).toBe("pending");
    expect(dashboard.records[0]).toMatchObject({
      title: "",
      summary: "",
      description: "",
      content_language: "zh-Hans",
      translation_status: "pending",
    });
  });

  it("rejects a forged translated status when the declared record language does not match", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: [{
        id: "CVE-2026-76010",
        title: "Simplified or stale content",
        title_zh_hant: "伪造的译文标题",
        summary: "Stale source summary.",
        summary_zh_hant: "伪造的译文摘要。",
        content_language: "unknown",
        translation_status: "translated",
      }],
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const records = await new SecFlowApi("http://secflow.test").vulnerabilities("zh-Hant");

    expect(records[0]).toMatchObject({
      title: "",
      summary: "",
      description: "",
      content_language: "unknown",
      translation_status: "pending",
    });
  });

  it("passes a CVE query to the full vulnerability catalog endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: { records: [] },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await new SecFlowApi("http://secflow.test").vulnerabilities("zh-Hans", " CVE-2026-98765 ");

    const [url] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.searchParams.get("response_language")).toBe("zh-Hans");
    expect(url.searchParams.get("query")).toBe("CVE-2026-98765");
  });
});

describe("workspace actions", () => {
  it("sends the selected project path with every workspace submission", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: { kind: "assistant", answer: { answer: "ok" }, task: null },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await new SecFlowApi("http://secflow.test").workspaceAction(
      "这个项目存在哪些漏洞",
      "/Users/test/projects/kafka",
      "analyst",
      "session-1",
      "en",
    );

    const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({
      objective: "这个项目存在哪些漏洞",
      workspace_path: "/Users/test/projects/kafka",
      user_id: "analyst",
      session_id: "session-1",
      response_language: "en",
    });
  });

  it("sends translated table snapshots to the selected conversation exchange", async () => {
    const tables = [{
      id: "translated-findings",
      title: "翻译后的漏洞记录",
      columns: [{ key: "id", label: "漏洞编号", editable: false }, { key: "title", label: "标题" }],
      rows: [{ id: "CVE-2026-4242", title: "修订后的中文标题" }],
      edited: true,
    }];
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: { exchange_id: "msg-42", tables },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new SecFlowApi("http://secflow.test").updateConversationTableEdits(
      "translated/session",
      "msg-42",
      "analyst",
      tables,
    );

    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.pathname).toBe("/api/assistant/conversations/translated%2Fsession/exchanges/msg-42/table-edits");
    expect(url.searchParams.get("user_id")).toBe("analyst");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(String(init.body))).toEqual({ tables });
    expect(result.tables[0].rows[0]).toEqual({ id: "CVE-2026-4242", title: "修订后的中文标题" });
  });

  it("encodes avatar upload and removal requests for the selected user", async () => {
    const profile = { display_name: "Analyst", email: "a@example.com", department: "SOC", role: "安全分析师", avatar_available: true };
    const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ data: profile }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new SecFlowApi("http://secflow.test");

    await api.uploadProfileAvatar("analyst", "avatar.png", "iVBORw0KGgo=", "image/png");
    await api.removeProfileAvatar("analyst");

    const [uploadUrl, uploadInit] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(uploadUrl.toString()).toContain("/api/settings/profile/avatar?user_id=analyst");
    expect(uploadInit.method).toBe("POST");
    expect(JSON.parse(String(uploadInit.body))).toEqual({
      file_name: "avatar.png",
      content_base64: "iVBORw0KGgo=",
      content_type: "image/png",
    });
    const [removeUrl, removeInit] = fetchMock.mock.calls[1] as [URL, RequestInit];
    expect(removeUrl.toString()).toContain("/api/settings/profile/avatar?user_id=analyst");
    expect(removeInit.method).toBe("DELETE");
  });
});

describe("LLM configuration", () => {
  it("rejects an HTTP-success response when the model business test failed", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status: "success",
      data: {
        status: "failed",
        configured: false,
        message: "上游模型鉴权失败",
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const api = new SecFlowApi("http://secflow.test");
    await expect(api.testLlmConfig("default", {
      provider: "custom",
      endpoint: "https://carpool.example",
      model: "gpt-5.6-sol",
      max_tokens: 1800,
      timeout_ms: 60000,
      enabled: true,
    })).rejects.toThrow("上游模型鉴权失败");
  });

  it("formats structured FastAPI validation errors as readable text", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      detail: [{ loc: ["body", "model"], msg: "模型 ID 不能为空", type: "value_error" }],
    }), { status: 422, headers: { "Content-Type": "application/json" } })));

    const api = new SecFlowApi("http://secflow.test");
    await expect(api.testLlmConfig("default", {
      provider: "custom",
      endpoint: "http://127.0.0.1:19999",
      model: "",
      max_tokens: 1800,
      timeout_ms: 60000,
      enabled: true,
    })).rejects.toThrow("模型 ID 不能为空");
  });
});
