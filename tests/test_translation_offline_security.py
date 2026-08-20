from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app.mcp.offline_translation import (
    OfflineTranslationIntegrityError,
    _verified_manifest,
    default_model_resource_dir,
)
from app.mcp.translation import (
    _mask_product_entities,
    _translation_cache,
    translate_json_payload,
)


def setup_function() -> None:
    _translation_cache.clear()


def test_offline_translation_preserves_windows_path_and_short_git_hash() -> None:
    source = (
        r"Exploit at C:\Program Files\SecFlow\app.exe was fixed in deadbee; "
        "see CVE-2026-1234."
    )

    result = translate_json_payload({"summary": source}, target_language="zh-Hans")
    translated = result.payload["summary"]

    assert result.translation_status == "translated"
    assert result.unresolved_fields == 0
    assert r"C:\Program Files\SecFlow\app.exe" in translated
    assert "deadbee" in translated
    assert "CVE-2026-1234" in translated
    assert result.offline is True
    assert result.network_used is False
    assert result.requires_api_key is False
    assert result.provider_calls == result.billable_tokens == result.token_usage == 0


def test_mixed_chinese_and_english_is_fully_localized() -> None:
    source = "该 issue allows remote attackers to execute arbitrary code."

    result = translate_json_payload({"summary": source}, target_language="zh-Hans")
    translated = result.payload["summary"]

    assert result.translation_status == "translated"
    assert result.unresolved_fields == 0
    assert "remote attackers" not in translated
    assert "execute arbitrary code" not in translated
    assert "任意代码" in translated


def test_product_entity_is_preserved_without_triggering_english_fallback() -> None:
    source = "Remote attackers can execute arbitrary code in Nginx before 1.2.3."

    result = translate_json_payload({"summary": source}, target_language="zh-Hans")
    translated = result.payload["summary"]

    assert result.translation_status == "translated"
    assert result.unresolved_fields == 0
    assert "Nginx" in translated
    assert "1.2.3" in translated
    assert "Remote attackers" not in translated


def test_product_mask_does_not_cross_sentence_boundaries_or_preserve_plain_prose() -> None:
    source = (
        "A flaw has been found in Comfast CF-N1-S 2.6.0.1. "
        "This affects the component URI Parameter Parsing. Local access is required."
    )

    _masked, entities = _mask_product_entities(source)
    preserved = {entity for _marker, entity in entities}

    assert "Comfast CF-N1-S" in preserved
    assert "URI Parameter Parsing" in preserved
    assert "Local" not in preserved
    assert all(". This" not in entity for entity in preserved)


def test_vuldb_style_translation_preserves_query_and_argument_evidence() -> None:
    source = (
        "A flaw has been found in SourceCodester Simple Online Food Ordering System 1.0. "
        "The impacted element is an unknown function of the file "
        "/admin/ajax.php?action=login. Executing a manipulation of the argument Username "
        "can lead to sql injection. The attack may be performed from remote."
    )

    result = translate_json_payload({"summary": source}, target_language="zh-Hans")
    translated = result.payload["summary"]

    assert result.translation_status == "translated"
    assert result.unresolved_fields == 0
    assert "SourceCodester Simple Online Food Ordering System" in translated
    assert "/admin/ajax.php?action=login" in translated
    assert "Username" in translated
    assert "SQL 注入" in translated
    assert "The impacted" not in translated
    assert "Executing a manipulation" not in translated
    assert "\\fn" not in translated


@pytest.mark.parametrize(
    ("source", "product", "forbidden"),
    [
        ("Buffer overflow in LibTIFF before 4.0.0.", "LibTIFF", "Buffer"),
        ("Integer overflow affects OpenSSL before 3.0.0.", "OpenSSL", "Integer"),
        ("Denial of service in Apache HTTP Server before 2.4.0.", "Apache HTTP Server", "Denial"),
        ("Information disclosure affects Jenkins before 2.1.0.", "Jenkins", "Information"),
        ("Prototype pollution in Lodash before 4.17.21.", "Lodash", "Prototype"),
        ("Out-of-bounds read in FFmpeg before 6.0.0.", "FFmpeg", "Out-of-bounds"),
    ],
)
def test_security_terms_translate_while_contextual_product_is_preserved(
    source: str,
    product: str,
    forbidden: str,
) -> None:
    result = translate_json_payload({"summary": source}, target_language="zh-Hans")
    translated = result.payload["summary"]

    assert result.translation_status == "translated"
    assert result.unresolved_fields == 0
    assert product in translated
    assert forbidden not in translated


@pytest.mark.parametrize("length", [5_000, 16_001])
def test_long_repeated_sentences_are_chunked_without_semantic_collapse(length: int) -> None:
    sentence = "Remote attacker can execute arbitrary code. "
    source = (sentence * ((length // len(sentence)) + 1))[:length]
    complete_sentences = source.count(sentence.strip())

    result = translate_json_payload({"summary": source}, target_language="zh-Hans")
    translated = result.payload["summary"]

    assert result.translation_status == "translated"
    assert result.candidate_fields == result.translated_fields == 1
    assert result.unresolved_fields == 0
    assert translated.count("任意代码") >= complete_sentences
    assert "Remote attacker" not in translated


def test_passthrough_audit_does_not_inherit_prior_model_usage() -> None:
    translated = translate_json_payload(
        {"summary": "Remote code execution exists."},
        target_language="zh-Hans",
    )
    assert translated.offline_model_used is True

    passthrough = translate_json_payload(
        {"summary": "Already English."},
        target_language="en",
    )

    assert passthrough.translation_status == "passthrough"
    assert passthrough.offline_model_used is False
    assert passthrough.resource_verified is False
    assert passthrough.model_sha256 == ""


def test_verified_cache_hit_retains_original_offline_resource_provenance() -> None:
    payload = {
        "summary": "Remote attackers can execute arbitrary code in Nginx before 1.2.3."
    }
    first = translate_json_payload(payload, target_language="zh-Hans")

    assert first.translation_status == "translated"
    assert first.resource_verified is True
    assert first.offline_model_used is True
    assert len(first.model_sha256) == 64
    expected_provenance = {
        "engine": first.engine,
        "engine_version": first.engine_version,
        "tokenizer": first.tokenizer,
        "tokenizer_version": first.tokenizer_version,
        "model_id": first.model_id,
        "model_sha256": first.model_sha256,
    }

    with patch("app.mcp.translation.offline_translation_engine.translate_batch") as engine:
        second = translate_json_payload(payload, target_language="zh-Hans")

    engine.assert_not_called()
    assert second.payload == first.payload
    assert second.translation_status == "translated"
    assert second.resource_verified is True
    assert second.offline_model_used is True
    assert {
        "engine": second.engine,
        "engine_version": second.engine_version,
        "tokenizer": second.tokenizer,
        "tokenizer_version": second.tokenizer_version,
        "model_id": second.model_id,
        "model_sha256": second.model_sha256,
    } == expected_provenance


def test_unverified_override_cache_never_claims_offline_model_provenance() -> None:
    payload = {"summary": "Firmware"}

    with patch("app.mcp.translation.offline_translation_engine.translate_batch") as engine:
        first = translate_json_payload(payload, target_language="zh-Hans")
    engine.assert_not_called()

    with (
        patch("app.mcp.translation.offline_translation_engine.translate_batch") as engine,
        patch(
            "app.mcp.translation._translate_prose_override",
            side_effect=AssertionError("cache miss unexpectedly recomputed the override"),
        ) as override,
    ):
        second = translate_json_payload(payload, target_language="zh-Hans")

    engine.assert_not_called()
    override.assert_not_called()
    for result in (first, second):
        assert result.payload["summary"] == "固件"
        assert result.translation_status == "translated"
        assert result.resource_verified is False
        assert result.offline_model_used is False
        assert result.model_sha256 == ""
        assert result.engine_version == ""
        assert result.tokenizer_version == ""


def test_runtime_manifest_requires_exact_offline_policy() -> None:
    manifest = json.loads(
        (default_model_resource_dir() / "manifest.json").read_text(encoding="utf-8")
    )
    manifest.pop("runtime_policy")
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(OfflineTranslationIntegrityError, match="runtime policy"):
            _verified_manifest(root)
