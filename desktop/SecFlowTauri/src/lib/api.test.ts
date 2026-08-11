// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";

import { SecFlowApi } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
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
