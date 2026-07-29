from __future__ import annotations

import os
import time
from copy import deepcopy
from typing import Any

import httpx

from app.storage import mask_secret, now_iso, store


LOCAL_PROVIDERS = {"ollama", "vllm", "local"}
PROVIDER_DEFAULTS: dict[str, dict[str, Any]] = {
    "openai": {
        "name": "OpenAI",
        "model": "gpt-5.6",
        "endpoint": "https://api.openai.com/v1",
    },
    "claude": {
        "name": "Claude",
        "model": "claude-sonnet-5",
        "endpoint": "https://api.anthropic.com/v1",
    },
    "deepseek": {
        "name": "DeepSeek",
        "model": "deepseek-v4-flash",
        "endpoint": "https://api.deepseek.com/v1",
    },
    "custom": {
        "name": "Sub2API",
        "model": "gpt-5.6-sol",
        "endpoint": "https://carpool.composiastack.com",
        "wire_api": "responses",
        "reasoning_effort": "xhigh",
        "disable_response_storage": True,
    },
}
MODEL_PROVIDER_NAMES = {
    "sub2api": "Sub2API",
    "openai": "OpenAI",
    "claude": "Anthropic",
    "google": "Google Gemini",
    "meta": "Meta Llama",
    "deepseek": "DeepSeek",
    "qwen": "通义千问",
    "ernie": "百度千帆",
    "zhipu": "智谱 AI",
    "spark": "讯飞星火",
    "moonshot": "Kimi",
    "stepfun": "阶跃星辰",
    "custom": "自定义模型",
}
FALLBACK_MODELS: dict[str, list[dict[str, str]]] = {
    "sub2api": [
        {"id": "gpt-5.6-sol", "name": "GPT-5.6 Sol", "description": "自定义网关 Responses 模型"},
    ],
    "openai": [
        {"id": "gpt-5.6", "name": "GPT-5.6", "description": "GPT-5.6 Sol 官方别名"},
        {"id": "gpt-5.6-sol", "name": "GPT-5.6 Sol", "description": "旗舰能力"},
        {"id": "gpt-5.6-terra", "name": "GPT-5.6 Terra", "description": "能力、成本与速度平衡"},
        {"id": "gpt-5.6-luna", "name": "GPT-5.6 Luna", "description": "高吞吐低延迟"},
        {"id": "gpt-5.4", "name": "GPT-5.4", "description": "兼容既有 GPT-5 工作流"},
    ],
    "claude": [
        {"id": "claude-sonnet-5", "name": "Claude Sonnet 5", "description": "速度与能力平衡"},
        {"id": "claude-opus-4-8", "name": "Claude Opus 4.8", "description": "复杂智能体与企业工作"},
        {"id": "claude-fable-5", "name": "Claude Fable 5", "description": "Anthropic 最高能力模型"},
        {"id": "claude-haiku-4-5", "name": "Claude Haiku 4.5", "description": "低延迟轻量模型"},
    ],
    "deepseek": [
        {"id": "deepseek-v4-flash", "name": "DeepSeek V4 Flash", "description": "DeepSeek 官方低延迟模型"},
        {"id": "deepseek-v4-pro", "name": "DeepSeek V4 Pro", "description": "DeepSeek 官方高能力模型"},
    ],
    "google": [
        {"id": "gemini-3.5-flash", "name": "Gemini 3.5 Flash", "description": "稳定版智能体与编码模型"},
        {"id": "gemini-3.1-pro-preview", "name": "Gemini 3.1 Pro", "description": "高级推理预览版"},
        {"id": "gemini-3-flash-preview", "name": "Gemini 3 Flash", "description": "高性价比预览版"},
        {"id": "gemini-3.1-flash-lite", "name": "Gemini 3.1 Flash-Lite", "description": "稳定低成本模型"},
        {"id": "gemini-2.5-pro", "name": "Gemini 2.5 Pro", "description": "复杂推理与编码"},
        {"id": "gemini-2.5-flash", "name": "Gemini 2.5 Flash", "description": "低延迟高吞吐"},
        {"id": "gemini-2.5-flash-lite", "name": "Gemini 2.5 Flash-Lite", "description": "经济型多模态模型"},
    ],
    "qwen": [
        {"id": "qwen3.8-max-preview", "name": "Qwen 3.8 Max Preview", "description": "千问最新预览模型"},
        {"id": "qwen3.7-max", "name": "Qwen 3.7 Max", "description": "高能力文本生成"},
        {"id": "qwen3.7-plus", "name": "Qwen 3.7 Plus", "description": "通用任务与视觉理解"},
        {"id": "qwen3.7-flash", "name": "Qwen 3.7 Flash", "description": "低延迟文本生成"},
    ],
    "zhipu": [
        {"id": "glm-5", "name": "GLM-5", "description": "智谱旗舰文本模型"},
        {"id": "glm-5-turbo", "name": "GLM-5 Turbo", "description": "高吞吐文本模型"},
        {"id": "glm-5.2", "name": "GLM-5.2", "description": "新一代通用模型"},
        {"id": "glm-5.1", "name": "GLM-5.1", "description": "通用推理模型"},
        {"id": "glm-4.7", "name": "GLM-4.7", "description": "稳定通用模型"},
        {"id": "glm-4.7-flash", "name": "GLM-4.7 Flash", "description": "低延迟通用模型"},
    ],
    "moonshot": [
        {"id": "kimi-k3", "name": "Kimi K3", "description": "旗舰编程、知识工作与深度推理"},
        {"id": "kimi-k2.7-code", "name": "Kimi K2.7 Code", "description": "编程与代码智能体"},
        {"id": "kimi-k2.7-code-highspeed", "name": "Kimi K2.7 Code Highspeed", "description": "高速编程模型"},
        {"id": "kimi-k2.6", "name": "Kimi K2.6", "description": "通用对话、智能体与复杂推理"},
        {"id": "kimi-k2.5", "name": "Kimi K2.5", "description": "兼容既有 Kimi 工作流"},
    ],
    "meta": [
        {"id": "llama-3.1-405b-instruct", "name": "Llama 3.1 405B Instruct", "description": "兼容既有 Llama API 配置"},
        {"id": "llama-3.1-70b-instruct", "name": "Llama 3.1 70B Instruct", "description": "兼容既有 Llama API 配置"},
    ],
    "ernie": [
        {"id": "ernie-4.0-turbo-8k", "name": "ERNIE 4.0 Turbo", "description": "千帆文本生成模型"},
        {"id": "ernie-speed-128k", "name": "ERNIE Speed 128K", "description": "长上下文低延迟模型"},
    ],
    "spark": [
        {"id": "generalv3.5", "name": "Spark Max", "description": "星火 Max 文本模型"},
        {"id": "generalv3", "name": "Spark Pro", "description": "星火 Pro 文本模型"},
    ],
    "stepfun": [
        {"id": "step-2-16k", "name": "Step 2 16K", "description": "复杂中文推理"},
        {"id": "step-1-32k", "name": "Step 1 32K", "description": "长上下文通用模型"},
    ],
    "custom": [
        {"id": "gpt-5.6-sol", "name": "GPT-5.6 Sol", "description": "自定义网关 Responses 模型"},
    ],
}

NON_CHAT_MODEL_TOKENS = {
    "embedding",
    "rerank",
    "moderation",
    "dall-e",
    "imagen",
    "image",
    "veo",
    "video",
    "audio",
    "tts",
    "speech",
    "transcri",
    "whisper",
    "realtime",
    "live",
    "asr",
    "ocr",
}


def llm_public_config() -> dict[str, Any]:
    config = _stored_llm_config()
    provider = str(config.get("provider") or "openai")
    catalog_provider = str(config.get("catalog_provider") or provider)
    provider_name = MODEL_PROVIDER_NAMES.get(catalog_provider, catalog_provider)
    api_key = str(config.get("api_key", ""))
    readiness_error = chat_readiness_error(_active_model_from_config(config))
    return {
        "name": provider_name,
        "provider": provider,
        "catalog_provider": catalog_provider,
        "model": config.get("model", _default_model(provider)),
        "endpoint": _safe_endpoint(str(config.get("endpoint", ""))),
        "wire_api": str(config.get("wire_api") or ""),
        "reasoning_effort": str(config.get("reasoning_effort") or ""),
        "disable_response_storage": bool(config.get("disable_response_storage")),
        "enabled": bool(config.get("enabled")),
        "configured": bool(config.get("enabled")) and not bool(readiness_error),
        "has_api_key": bool(api_key),
        "api_key_masked": mask_secret(api_key) if api_key else "",
        "message": "模型配置已启用。" if bool(config.get("enabled")) and not readiness_error else readiness_error or "模型配置已保存，尚未启用。",
        "updated_at": config.get("updated_at", ""),
    }


def save_llm_config(update: dict[str, Any]) -> dict[str, Any]:
    state = store.read()
    current = _stored_llm_config(state)
    merged = _merge_llm_update(current, update)
    merged["updated_at"] = now_iso()
    state["llm"] = merged
    store.write(state)
    return llm_public_config()


def test_llm_config(update: dict[str, Any]) -> dict[str, Any]:
    model = _active_model_from_config(_merge_llm_update(_stored_llm_config(), update))
    result = diagnose_chat_completion(
        model,
        [{"role": "user", "content": "请只回复：SecFlow OK"}],
    )
    return {
        "status": result.get("status", "failed"),
        "message": result.get("message", ""),
        "latency_ms": result.get("latency_ms"),
        "provider": model.get("provider", ""),
        "model": model.get("model", ""),
        "configured": result.get("status") == "success",
    }


def list_llm_models(update: dict[str, Any]) -> dict[str, Any]:
    provider = str(update.get("provider") or "openai").strip().lower()
    if provider not in PROVIDER_DEFAULTS:
        raise ValueError(f"不支持的模型服务商：{provider}")
    catalog_provider = str(update.get("catalog_provider") or provider).strip().lower()
    if catalog_provider not in FALLBACK_MODELS:
        catalog_provider = "custom" if provider == "custom" else provider

    current = _stored_llm_config()
    endpoint = str(update.get("endpoint") or _default_endpoint(provider)).strip()
    api_key = str(update.get("api_key") or "").strip()
    current_endpoint = str(current.get("endpoint") or "").rstrip("/")
    current_catalog_provider = str(current.get("catalog_provider") or current.get("provider") or "")
    if (
        not api_key
        and provider == current.get("provider")
        and catalog_provider == current_catalog_provider
        and endpoint.rstrip("/") == current_endpoint
    ):
        api_key = str(current.get("api_key") or "").strip()

    if not api_key:
        return _fallback_model_catalog(catalog_provider, "填入 API Key 后，可从厂商模型接口同步真实模型列表。")
    if not endpoint.startswith(("http://", "https://")):
        return _fallback_model_catalog(catalog_provider, "API 地址需要包含 http:// 或 https://，当前显示内置推荐模型。")

    timeout_s = max(float(update.get("timeout_ms", 30000)) / 1000.0, 1.0)
    try:
        models = _fetch_provider_models(catalog_provider, endpoint.rstrip("/"), api_key, timeout_s)
    except Exception as exc:  # noqa: BLE001
        return _fallback_model_catalog(catalog_provider, f"厂商模型列表同步失败，已使用内置推荐模型：{exc}")

    if not models:
        return _fallback_model_catalog(catalog_provider, "厂商接口未返回可用模型，已使用内置推荐模型。")
    return {
        "provider": catalog_provider,
        "source": "provider",
        "models": models,
        "message": "已从厂商模型接口同步模型列表。",
    }


def active_model_from_env() -> dict[str, Any] | None:
    stored = _active_model_from_config(_stored_llm_config())
    if stored and stored.get("enabled"):
        return stored

    provider = os.getenv("SECFLOW_LLM_PROVIDER", "").strip().lower()
    if not provider:
        provider = "deepseek" if os.getenv("DEEPSEEK_API_KEY") else "openai"

    api_key = (
        os.getenv("SECFLOW_LLM_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or ""
    ).strip()
    endpoint = (
        os.getenv("SECFLOW_LLM_ENDPOINT")
        or os.getenv("DEEPSEEK_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or _default_endpoint(provider)
    ).strip()
    model = (
        os.getenv("SECFLOW_LLM_MODEL")
        or os.getenv("DEEPSEEK_MODEL")
        or os.getenv("OPENAI_MODEL")
        or _default_model(provider)
    ).strip()

    return {
        "name": os.getenv("SECFLOW_LLM_NAME") or f"{provider}:{model}",
        "provider": provider,
        "model": model,
        "endpoint": endpoint,
        "apiKey": api_key,
        "maxTokens": int(os.getenv("SECFLOW_LLM_MAX_TOKENS", "1800")),
        "temperature": float(os.getenv("SECFLOW_LLM_TEMPERATURE", "0.25")),
        "topP": float(os.getenv("SECFLOW_LLM_TOP_P", "0.9")),
        "timeoutMs": int(os.getenv("SECFLOW_LLM_TIMEOUT_MS", "60000")),
        "wireApi": os.getenv("SECFLOW_LLM_WIRE_API", "").strip(),
        "reasoningEffort": os.getenv("SECFLOW_LLM_REASONING_EFFORT", "").strip(),
        "disableResponseStorage": os.getenv("SECFLOW_LLM_DISABLE_RESPONSE_STORAGE", "").strip().lower()
        in {"1", "true", "yes", "on"},
    }


def llm_status() -> dict[str, Any]:
    model = active_model_from_env()
    error = chat_readiness_error(model)
    return {
        "configured": not bool(error),
        "name": model.get("name") if model else "",
        "provider": model.get("provider") if model else "",
        "model": model.get("model") if model else "",
        "endpoint": _safe_endpoint(model.get("endpoint", "")) if model else "",
        "message": error or "模型配置可用于对应厂商接口调用。",
    }


def chat_readiness_error(active_model: dict[str, Any] | None) -> str:
    if not active_model:
        return "未配置可用模型。"
    provider = str(active_model.get("provider", "")).lower()
    endpoint = _normalized_endpoint(active_model)
    if provider not in LOCAL_PROVIDERS and not str(active_model.get("apiKey", "")):
        return (
            f"{active_model.get('name', '当前模型')} 未配置 API Key。"
            "请通过 SECFLOW_LLM_API_KEY、DEEPSEEK_API_KEY 或 OPENAI_API_KEY 配置。"
        )
    if not endpoint.startswith(("http://", "https://")):
        return f"{active_model.get('name', '当前模型')} 的接口地址需要包含 http:// 或 https://。"
    return ""


def diagnose_chat_completion(
    active_model: dict[str, Any],
    messages: list[dict[str, str]],
    enable_thinking: bool = False,
    json_mode: bool = False,
) -> dict[str, Any]:
    readiness_error = chat_readiness_error(active_model)
    if readiness_error:
        return {"status": "failed", "message": readiness_error, "latency_ms": None}

    provider = str(active_model.get("provider", "")).lower()
    if provider == "claude":
        return _diagnose_anthropic_completion(active_model, messages)
    if provider == "openai" or _wire_api(active_model) == "responses":
        return _diagnose_openai_response(active_model, messages)

    endpoint = _normalized_endpoint(active_model)
    body: dict[str, Any] = {
        "model": active_model.get("model", "deepseek-chat"),
        "messages": messages,
        "max_tokens": int(active_model.get("maxTokens", 1800)),
        "temperature": float(active_model.get("temperature", 0.25)),
        "top_p": float(active_model.get("topP", 0.9)),
    }
    if enable_thinking and _supports_thinking_param(active_model):
        body["thinking"] = {"type": "enabled"}
    if json_mode:
        body["response_format"] = {"type": "json_object"}

    headers = {"Content-Type": "application/json"}
    api_key = str(active_model.get("apiKey", ""))
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    timeout_s = max(float(active_model.get("timeoutMs", 60000)) / 1000.0, 1.0)
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(f"{endpoint}/chat/completions", json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        detail = exc.response.text[:500] if exc.response is not None else str(exc)
        return {
            "status": "failed",
            "message": f"模型接口返回 HTTP {exc.response.status_code if exc.response else ''}：{detail}",
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {"status": "failed", "message": f"模型接口请求失败：{exc}", "latency_ms": latency_ms}

    latency_ms = int((time.perf_counter() - started) * 1000)
    try:
        choice = data["choices"][0]["message"]
    except Exception:  # noqa: BLE001
        return {"status": "failed", "message": "模型接口返回格式不符合 OpenAI Chat Completions。", "latency_ms": latency_ms}

    answer_text = str(choice.get("content", "") or "").strip()
    reasoning_text = str(choice.get("reasoning_content", "") or "").strip()
    if not answer_text and reasoning_text:
        answer_text = reasoning_text
    if not answer_text:
        return {"status": "failed", "message": "当前模型未返回可用结果。", "latency_ms": latency_ms}

    return {
        "status": "success",
        "message": "模型接口调用成功。",
        "latency_ms": latency_ms,
        "answer": answer_text,
        "reasoning": reasoning_text,
        "data": data,
    }


def _diagnose_openai_response(
    active_model: dict[str, Any],
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    endpoint = _normalized_endpoint(active_model)
    body: dict[str, Any] = {
        "model": active_model.get("model", _default_model("openai")),
        "input": [
            {"role": item.get("role", "user"), "content": item.get("content", "")}
            for item in messages
        ],
        "max_output_tokens": int(active_model.get("maxTokens", 1800)),
    }
    reasoning_effort = str(active_model.get("reasoningEffort") or "").strip()
    if reasoning_effort:
        body["reasoning"] = {"effort": reasoning_effort}
    if bool(active_model.get("disableResponseStorage")):
        body["store"] = False

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {active_model.get('apiKey', '')}",
    }
    timeout_s = max(float(active_model.get("timeoutMs", 60000)) / 1000.0, 1.0)
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(f"{endpoint}/responses", json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        detail = exc.response.text[:500] if exc.response is not None else str(exc)
        return {
            "status": "failed",
            "message": f"模型接口返回 HTTP {exc.response.status_code if exc.response else ''}：{detail}",
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {"status": "failed", "message": f"模型接口请求失败：{exc}", "latency_ms": latency_ms}

    latency_ms = int((time.perf_counter() - started) * 1000)
    answer_text = _extract_openai_response_text(data)
    if not answer_text:
        return {"status": "failed", "message": "当前模型未返回可用结果。", "latency_ms": latency_ms}

    return {
        "status": "success",
        "message": "模型接口调用成功。",
        "latency_ms": latency_ms,
        "answer": answer_text,
        "reasoning": "",
        "data": data,
    }


def _diagnose_anthropic_completion(
    active_model: dict[str, Any],
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    endpoint = _normalized_endpoint(active_model)
    system_parts = [item["content"] for item in messages if item.get("role") == "system"]
    chat_messages = [
        {"role": item.get("role", "user"), "content": item.get("content", "")}
        for item in messages
        if item.get("role") != "system"
    ]
    if not chat_messages:
        chat_messages = [{"role": "user", "content": "请回复 SecFlow OK"}]

    body: dict[str, Any] = {
        "model": active_model.get("model", "claude-3-5-sonnet-latest"),
        "messages": chat_messages,
        "max_tokens": int(active_model.get("maxTokens", 1800)),
    }
    if system_parts:
        body["system"] = "\n\n".join(system_parts)

    headers = {
        "Content-Type": "application/json",
        "x-api-key": str(active_model.get("apiKey", "")),
        "anthropic-version": "2023-06-01",
    }
    timeout_s = max(float(active_model.get("timeoutMs", 60000)) / 1000.0, 1.0)
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(f"{endpoint}/messages", json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        detail = exc.response.text[:500] if exc.response is not None else str(exc)
        return {
            "status": "failed",
            "message": f"模型接口返回 HTTP {exc.response.status_code if exc.response else ''}：{detail}",
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {"status": "failed", "message": f"模型接口请求失败：{exc}", "latency_ms": latency_ms}

    latency_ms = int((time.perf_counter() - started) * 1000)
    content = data.get("content", [])
    answer_text = "\n".join(
        str(part.get("text", "")).strip()
        for part in content
        if isinstance(part, dict) and part.get("type") == "text"
    ).strip()
    if not answer_text:
        return {"status": "failed", "message": "当前模型未返回可用结果。", "latency_ms": latency_ms}
    return {
        "status": "success",
        "message": "模型接口调用成功。",
        "latency_ms": latency_ms,
        "answer": answer_text,
        "reasoning": "",
        "data": data,
    }


def _default_endpoint(provider: str) -> str:
    if provider in PROVIDER_DEFAULTS:
        return str(PROVIDER_DEFAULTS[provider]["endpoint"])
    if provider == "deepseek":
        return "https://api.deepseek.com/v1"
    if provider == "openai":
        return "https://api.openai.com/v1"
    return "http://127.0.0.1:11434/v1"


def _default_model(provider: str) -> str:
    if provider in PROVIDER_DEFAULTS:
        return str(PROVIDER_DEFAULTS[provider]["model"])
    if provider == "deepseek":
        return "deepseek-v4-flash"
    if provider == "openai":
        return "gpt-5.6"
    return "qwen2.5-coder-security"


def _normalized_endpoint(active_model: dict[str, Any]) -> str:
    return str(active_model.get("endpoint", "") or _default_endpoint(str(active_model.get("provider", "")))).rstrip("/")


def _wire_api(active_model: dict[str, Any]) -> str:
    provider = str(active_model.get("provider", "")).lower()
    configured = str(active_model.get("wireApi") or "").strip().lower()
    if configured:
        return configured
    default = PROVIDER_DEFAULTS.get(provider, {})
    return str(default.get("wire_api") or ("responses" if provider == "openai" else "chat")).lower()


def _supports_thinking_param(active_model: dict[str, Any]) -> bool:
    provider = str(active_model.get("provider", "")).lower()
    model = str(active_model.get("model", "")).lower()
    if provider == "deepseek":
        return "reasoner" in model
    return provider in {"ollama", "vllm"} and any(token in model for token in ("reason", "thinking", "qwq"))


def _safe_endpoint(endpoint: str) -> str:
    if not endpoint:
        return ""
    return endpoint.replace("api_key=", "api_key=***")


def _fallback_model_catalog(provider: str, message: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "source": "fallback",
        "models": FALLBACK_MODELS.get(provider, []),
        "message": message,
    }


def _fetch_provider_models(provider: str, endpoint: str, api_key: str, timeout_s: float) -> list[dict[str, str]]:
    headers = {"Accept": "application/json"}
    if provider == "claude":
        headers.update(
            {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
        )
    else:
        headers["Authorization"] = f"Bearer {api_key}"

    with httpx.Client(timeout=timeout_s) as client:
        response = client.get(f"{endpoint}/models", headers=headers)
        response.raise_for_status()
        data = response.json()

    raw_models = data.get("data", data if isinstance(data, list) else [])
    if not isinstance(raw_models, list):
        return []
    models: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_models:
        if isinstance(item, str):
            model_id = item.strip()
            display_name = model_id
        elif isinstance(item, dict):
            model_id = str(item.get("id") or item.get("model") or item.get("name") or "").strip()
            display_name = str(item.get("display_name") or item.get("name") or model_id).strip()
        else:
            continue
        if not model_id or model_id in seen or not _is_supported_chat_model(provider, model_id):
            continue
        seen.add(model_id)
        models.append(
            {
                "id": model_id,
                "name": display_name or model_id,
                "description": "来自厂商官方 Models API",
            }
        )
    return models[:100]


def _is_supported_chat_model(provider: str, model_id: str) -> bool:
    normalized = model_id.strip().lower()
    if not normalized or any(token in normalized for token in NON_CHAT_MODEL_TOKENS):
        return False
    if provider == "openai":
        return normalized.startswith(("gpt-", "o1", "o3", "o4"))
    if provider == "claude":
        return normalized.startswith("claude-")
    if provider == "deepseek":
        return normalized.startswith("deepseek-")
    if provider == "google":
        return normalized.startswith("gemini-")
    return True


def _extract_openai_response_text(data: dict[str, Any]) -> str:
    direct = str(data.get("output_text") or "").strip()
    if direct:
        return direct

    parts: list[str] = []
    for item in data.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if not isinstance(content, dict):
                continue
            text = str(content.get("text") or "").strip()
            if text:
                parts.append(text)
    return "\n".join(parts).strip()


def _stored_llm_config(state: dict[str, Any] | None = None) -> dict[str, Any]:
    state = state or store.read()
    config = deepcopy(state.get("llm") or {})
    provider = str(config.get("provider") or "openai").lower()
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["openai"])
    config.setdefault("provider", provider)
    config.setdefault("model", defaults["model"])
    config.setdefault("endpoint", defaults["endpoint"])
    default_catalog_provider = "sub2api" if provider == "custom" and "carpool.composiastack.com" in str(config.get("endpoint") or "") else provider
    config.setdefault("catalog_provider", default_catalog_provider)
    config.setdefault("api_key", "")
    config.setdefault("enabled", False)
    config.setdefault("max_tokens", 1800)
    config.setdefault("temperature", 0.25)
    config.setdefault("top_p", 0.9)
    config.setdefault("timeout_ms", 60000)
    config.setdefault("wire_api", defaults.get("wire_api", "responses" if provider == "openai" else "chat"))
    config.setdefault("reasoning_effort", defaults.get("reasoning_effort", ""))
    config.setdefault("disable_response_storage", defaults.get("disable_response_storage", False))
    return config


def _merge_llm_update(current: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(current)
    provider = str(update.get("provider") or merged.get("provider") or "openai").lower()
    if provider not in PROVIDER_DEFAULTS:
        raise ValueError(f"不支持的模型服务商：{provider}")
    defaults = PROVIDER_DEFAULTS[provider]
    provider_changed = provider != current.get("provider")
    merged["provider"] = provider
    requested_catalog_provider = str(update.get("catalog_provider") or "").strip().lower()
    if requested_catalog_provider:
        merged["catalog_provider"] = requested_catalog_provider if requested_catalog_provider in FALLBACK_MODELS else "custom"
    elif provider_changed:
        merged["catalog_provider"] = provider
    catalog_provider_changed = str(merged.get("catalog_provider") or provider) != str(current.get("catalog_provider") or current.get("provider") or "")
    merged["model"] = str(update.get("model") or (defaults["model"] if provider_changed else merged.get("model"))).strip()
    merged["endpoint"] = str(update.get("endpoint") or (defaults["endpoint"] if provider_changed else merged.get("endpoint"))).strip()
    if provider_changed or catalog_provider_changed:
        merged["api_key"] = ""
    if provider_changed:
        merged["wire_api"] = str(defaults.get("wire_api") or ("responses" if provider == "openai" else "chat"))
        merged["reasoning_effort"] = str(defaults.get("reasoning_effort") or "")
        merged["disable_response_storage"] = bool(defaults.get("disable_response_storage", False))
    if "api_key" in update and update.get("api_key") is not None:
        api_key = str(update.get("api_key", "")).strip()
        if api_key:
            merged["api_key"] = api_key
    if "enabled" in update and update.get("enabled") is not None:
        merged["enabled"] = bool(update.get("enabled"))
    for source_key, target_key in [
        ("max_tokens", "max_tokens"),
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("timeout_ms", "timeout_ms"),
    ]:
        if source_key in update and update[source_key] is not None:
            merged[target_key] = update[source_key]
    if "reasoning_effort" in update and update.get("reasoning_effort") is not None:
        merged["reasoning_effort"] = str(update.get("reasoning_effort", "")).strip()
    if "disable_response_storage" in update and update.get("disable_response_storage") is not None:
        merged["disable_response_storage"] = bool(update.get("disable_response_storage"))
    if "wire_api" in update and update.get("wire_api") is not None:
        merged["wire_api"] = str(update.get("wire_api") or "").strip()
    return merged


def _active_model_from_config(config: dict[str, Any]) -> dict[str, Any]:
    provider = str(config.get("provider", "openai")).lower()
    catalog_provider = str(config.get("catalog_provider") or provider).lower()
    model = str(config.get("model") or _default_model(provider)).strip()
    endpoint = str(config.get("endpoint") or _default_endpoint(provider)).strip()
    return {
        "name": f"{MODEL_PROVIDER_NAMES.get(catalog_provider, catalog_provider)}:{model}",
        "provider": provider,
        "catalogProvider": catalog_provider,
        "model": model,
        "endpoint": endpoint,
        "apiKey": str(config.get("api_key", "")).strip(),
        "enabled": bool(config.get("enabled")),
        "maxTokens": int(config.get("max_tokens", 1800)),
        "temperature": float(config.get("temperature", 0.25)),
        "topP": float(config.get("top_p", 0.9)),
        "timeoutMs": int(config.get("timeout_ms", 60000)),
        "wireApi": str(config.get("wire_api") or ""),
        "reasoningEffort": str(config.get("reasoning_effort") or ""),
        "disableResponseStorage": bool(config.get("disable_response_storage")),
    }
