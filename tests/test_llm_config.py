from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.llm import (
    _fetch_provider_models,
    active_model_from_env,
    diagnose_chat_completion,
    list_llm_models,
    llm_public_config,
    save_llm_config,
)
from app.storage import StateStore, default_state


class LLMConfigTests(unittest.TestCase):
    def test_public_config_exposes_only_reasoning_levels_supported_by_the_selected_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                openai = save_llm_config(
                    {
                        "provider": "openai",
                        "model": "gpt-5.6-sol",
                        "endpoint": "https://api.openai.com/v1",
                        "api_key": "test-key",
                        "enabled": True,
                    }
                )
                self.assertEqual(
                    [option["value"] for option in openai["reasoning_options"]],
                    ["none", "low", "medium", "high", "xhigh", "max"],
                )

                deepseek_chat = save_llm_config(
                    {
                        "provider": "deepseek",
                        "model": "deepseek-chat",
                        "endpoint": "https://api.deepseek.com/v1",
                        "api_key": "test-key",
                        "enabled": True,
                    }
                )
                self.assertEqual(deepseek_chat["reasoning_options"], [{"value": "none", "fixed": True}])

                deepseek_reasoner = save_llm_config({"model": "deepseek-reasoner"})
                self.assertEqual(deepseek_reasoner["reasoning_options"], [{"value": "high", "fixed": True}])

    def test_responses_api_streams_real_output_text_deltas(self) -> None:
        captured: dict = {}
        deltas: list[str] = []

        class FakeStreamResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def raise_for_status(self) -> None:
                return None

            def iter_lines(self):
                return iter(
                    [
                        'event: response.output_text.delta',
                        'data: {"type":"response.output_text.delta","delta":"第一段"}',
                        'data: {"type":"response.output_text.delta","delta":"第二段"}',
                        'data: {"type":"response.completed","response":{"usage":{"total_tokens":12}}}',
                    ]
                )

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def stream(self, method: str, url: str, *, json: dict, headers: dict):
                captured.update(method=method, url=url, body=json, headers=headers)
                return FakeStreamResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            result = diagnose_chat_completion(
                {
                    "provider": "custom",
                    "model": "gpt-5.6-sol",
                    "endpoint": "https://carpool.example",
                    "apiKey": "test-key",
                    "maxTokens": 256,
                    "timeoutMs": 1000,
                    "wireApi": "responses",
                    "reasoningEffort": "xhigh",
                    "disableResponseStorage": True,
                },
                [{"role": "user", "content": "流式回答"}],
                on_delta=deltas.append,
            )

        self.assertEqual(result["status"], "success")
        self.assertTrue(result["streamed"])
        self.assertEqual(result["answer"], "第一段第二段")
        self.assertEqual(deltas, ["第一段", "第二段"])
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["url"], "https://carpool.example/responses")
        self.assertTrue(captured["body"]["stream"])
        self.assertEqual(captured["body"]["reasoning"], {"effort": "xhigh"})
        self.assertFalse(captured["body"]["store"])

    def test_chat_stream_does_not_emit_reasoning_content(self) -> None:
        deltas: list[str] = []

        class FakeStreamResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def raise_for_status(self) -> None:
                return None

            def iter_lines(self):
                return iter(
                    [
                        'data: {"choices":[{"delta":{"reasoning_content":"private reasoning"}}]}',
                        'data: {"choices":[{"delta":{"content":"公开回答"}}]}',
                        'data: {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2}}',
                        "data: [DONE]",
                    ]
                )

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def stream(self, *_args, **_kwargs):
                return FakeStreamResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            result = diagnose_chat_completion(
                {
                    "provider": "deepseek",
                    "model": "deepseek-chat",
                    "endpoint": "https://api.deepseek.com/v1",
                    "apiKey": "test-key",
                    "timeoutMs": 1000,
                },
                [{"role": "user", "content": "回答"}],
                on_delta=deltas.append,
            )

        self.assertEqual(result["answer"], "公开回答")
        self.assertEqual(deltas, ["公开回答"])
        self.assertEqual(result["data"]["usage"]["completion_tokens"], 2)
        self.assertNotIn("private reasoning", str(result))

    def test_anthropic_stream_emits_only_text_blocks(self) -> None:
        deltas: list[str] = []

        class FakeStreamResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def raise_for_status(self) -> None:
                return None

            def iter_lines(self):
                return iter(
                    [
                        'data: {"type":"message_start","message":{"id":"msg-1","usage":{"input_tokens":5}}}',
                        'data: {"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"private"}}',
                        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"公开文本"}}',
                        'data: {"type":"message_delta","usage":{"output_tokens":3}}',
                    ]
                )

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def stream(self, *_args, **_kwargs):
                return FakeStreamResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            result = diagnose_chat_completion(
                {
                    "provider": "claude",
                    "model": "claude-sonnet-5",
                    "endpoint": "https://api.anthropic.com/v1",
                    "apiKey": "test-key",
                    "timeoutMs": 1000,
                },
                [{"role": "user", "content": "回答"}],
                on_delta=deltas.append,
            )

        self.assertEqual(result["answer"], "公开文本")
        self.assertEqual(deltas, ["公开文本"])
        self.assertEqual(result["data"]["usage"], {"input_tokens": 5, "output_tokens": 3})
        self.assertNotIn("private", str(result))

    def test_llm_config_and_api_key_are_isolated_by_user_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                save_llm_config(
                    {
                        "provider": "openai",
                        "model": "gpt-alice",
                        "endpoint": "https://api.openai.com/v1",
                        "api_key": "sk-alice-secret",
                        "enabled": True,
                    },
                    user_id="alice@example.com",
                )
                save_llm_config(
                    {
                        "provider": "deepseek",
                        "model": "deepseek-bob",
                        "endpoint": "https://api.deepseek.com/v1",
                        "api_key": "sk-bob-secret",
                        "enabled": True,
                    },
                    user_id="bob@example.com",
                )
                alice = active_model_from_env("alice@example.com")
                bob = active_model_from_env("bob@example.com")
                alice_public = llm_public_config("alice@example.com")
                bob_public = llm_public_config("bob@example.com")

        self.assertEqual(alice["model"], "gpt-alice")
        self.assertEqual(alice["apiKey"], "sk-alice-secret")
        self.assertEqual(bob["model"], "deepseek-bob")
        self.assertEqual(bob["apiKey"], "sk-bob-secret")
        self.assertNotEqual(alice_public["api_key_masked"], bob_public["api_key_masked"])
        self.assertNotIn("sk-bob-secret", str(alice_public))
        self.assertNotIn("sk-alice-secret", str(bob_public))
    def test_deepseek_json_mode_uses_vendor_response_format(self) -> None:
        captured: dict = {}

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {"choices": [{"message": {"content": '{"ok": true}'}}]}

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def post(self, _url: str, *, json: dict, headers: dict):
                captured["body"] = json
                captured["headers"] = headers
                return FakeResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            result = diagnose_chat_completion(
                {
                    "provider": "deepseek",
                    "model": "deepseek-chat",
                    "endpoint": "https://api.deepseek.com/v1",
                    "apiKey": "test-key",
                    "maxTokens": 256,
                    "temperature": 0,
                    "topP": 1,
                    "timeoutMs": 1000,
                },
                [{"role": "user", "content": "返回 JSON"}],
                json_mode=True,
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(captured["body"]["response_format"], {"type": "json_object"})

    def test_custom_provider_uses_responses_api_with_reasoning_options(self) -> None:
        captured: dict = {}

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {"output_text": "SecFlow OK"}

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def post(self, url: str, *, json: dict, headers: dict):
                captured["url"] = url
                captured["body"] = json
                captured["headers"] = headers
                return FakeResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            result = diagnose_chat_completion(
                {
                    "provider": "custom",
                    "model": "gpt-5.6-sol",
                    "endpoint": "https://carpool.example",
                    "apiKey": "test-key",
                    "maxTokens": 256,
                    "timeoutMs": 1000,
                    "wireApi": "responses",
                    "reasoningEffort": "xhigh",
                    "disableResponseStorage": True,
                },
                [{"role": "user", "content": "返回 OK"}],
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(captured["url"], "https://carpool.example/responses")
        self.assertEqual(captured["body"]["model"], "gpt-5.6-sol")
        self.assertEqual(captured["body"]["reasoning"], {"effort": "xhigh"})
        self.assertFalse(captured["body"]["store"])
        self.assertEqual(captured["headers"]["Authorization"], "Bearer test-key")

    def test_fresh_install_has_empty_disabled_llm_configuration(self) -> None:
        config = default_state()["llm"]

        self.assertEqual(config["provider"], "custom")
        self.assertEqual(config["catalog_provider"], "sub2api")
        self.assertEqual(config["model"], "gpt-5.6-sol")
        self.assertEqual(config["endpoint"], "https://carpool.composiastack.com")
        self.assertEqual(config["wire_api"], "responses")
        self.assertEqual(config["reasoning_effort"], "xhigh")
        self.assertTrue(config["disable_response_storage"])
        self.assertEqual(config["api_key"], "")
        self.assertFalse(config["enabled"])

    def test_public_config_exposes_non_secret_custom_response_options(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                config = save_llm_config(
                    {
                        "provider": "custom",
                        "model": "gpt-5.6-sol",
                        "endpoint": "https://carpool.composiastack.com",
                        "wire_api": "responses",
                        "reasoning_effort": "xhigh",
                        "disable_response_storage": True,
                        "max_tokens": 4096,
                        "temperature": 0.4,
                        "top_p": 0.8,
                        "timeout_ms": 90000,
                        "enabled": True,
                    }
                )

        self.assertEqual(config["name"], "Sub2API")
        self.assertEqual(config["wire_api"], "responses")
        self.assertEqual(config["reasoning_effort"], "xhigh")
        self.assertEqual(config["max_tokens"], 4096)
        self.assertEqual(config["temperature"], 0.4)
        self.assertEqual(config["top_p"], 0.8)
        self.assertEqual(config["timeout_ms"], 90000)
        self.assertNotIn("api_key", config)
        self.assertTrue(config["disable_response_storage"])
        self.assertFalse(config["has_api_key"])
        self.assertNotIn("api_key", config)

    def test_saved_api_key_is_masked_in_public_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                config = save_llm_config(
                    {
                        "provider": "openai",
                        "model": "gpt-4o",
                        "endpoint": "https://api.openai.com/v1",
                        "api_key": "sk-test-secret-123456",
                        "enabled": True,
                    }
                )
                public = llm_public_config()

            self.assertTrue(config["has_api_key"])
            self.assertNotIn("sk-test-secret-123456", str(config))
            self.assertNotIn("sk-test-secret-123456", str(public))
            self.assertEqual(public["api_key_masked"], "sk-t********3456")

    def test_provider_switch_does_not_reuse_previous_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                save_llm_config(
                    {
                        "provider": "openai",
                        "model": "gpt-4o",
                        "endpoint": "https://api.openai.com/v1",
                        "api_key": "sk-openai-secret",
                        "enabled": True,
                    }
                )
                config = save_llm_config(
                    {
                        "provider": "claude",
                        "model": "claude-3-5-sonnet-latest",
                        "endpoint": "https://api.anthropic.com/v1",
                        "enabled": True,
                    }
                )

            self.assertEqual(config["provider"], "claude")
            self.assertFalse(config["has_api_key"])

    def test_model_list_without_key_returns_fallback_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                catalog = list_llm_models(
                    {
                        "provider": "deepseek",
                        "endpoint": "https://api.deepseek.com/v1",
                    }
                )

            self.assertEqual(catalog["provider"], "deepseek")
            self.assertEqual(catalog["source"], "fallback")
            self.assertTrue(catalog["models"])

    def test_custom_backend_uses_selected_vendor_fallback_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                catalog = list_llm_models(
                    {
                        "provider": "custom",
                        "catalog_provider": "qwen",
                        "endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                    }
                )

        self.assertEqual(catalog["provider"], "qwen")
        self.assertEqual(catalog["source"], "fallback")
        self.assertEqual(catalog["models"][0]["id"], "qwen3.8-max-preview")

    def test_custom_vendor_does_not_reuse_key_from_another_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with (
                patch("app.llm.store", local_store),
                patch("app.llm._fetch_provider_models") as fetch_models,
            ):
                save_llm_config(
                    {
                        "provider": "custom",
                        "model": "gpt-5.6-sol",
                        "endpoint": "https://carpool.composiastack.com",
                        "api_key": "sub2api-secret",
                    }
                )
                catalog = list_llm_models(
                    {
                        "provider": "custom",
                        "catalog_provider": "google",
                        "endpoint": "https://generativelanguage.googleapis.com/v1beta/openai",
                    }
                )

        fetch_models.assert_not_called()
        self.assertEqual(catalog["provider"], "google")
        self.assertEqual(catalog["source"], "fallback")

    def test_provider_model_sync_filters_non_chat_models(self) -> None:
        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {
                    "data": [
                        {"id": "gpt-5.6-sol", "name": "GPT-5.6 Sol"},
                        {"id": "text-embedding-4", "name": "Embedding"},
                        {"id": "gpt-image-2", "name": "Image"},
                        {"id": "whisper-2", "name": "Speech"},
                    ]
                }

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def get(self, _url: str, *, headers: dict):
                self.headers = headers
                return FakeResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            models = _fetch_provider_models("openai", "https://api.openai.com/v1", "sk-test", 1)

        self.assertEqual([model["id"] for model in models], ["gpt-5.6-sol"])


if __name__ == "__main__":
    unittest.main()
