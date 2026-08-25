"""Verified, offline machine-translation runtime used by Translation MCP.

The runtime deliberately has no HTTP client and accepts no provider settings.
Its model files are part of the signed AegisAl application bundle and are
verified against ``manifest.json`` before CTranslate2 loads them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Sequence


MODEL_RESOURCE_ID = "opus-mt-en-zh-1.9"
SUPPORTED_TARGET_LANGUAGES = ("zh-Hans", "zh-Hant", "en")
_REQUIRED_FILES = frozenset(
    {
        "model/model.bin",
        "model/config.json",
        "model/shared_vocabulary.json",
        "sentencepiece.model",
    }
)
_REQUIRED_ROLES = frozenset(
    {
        "ctranslate2-model",
        "ctranslate2-config",
        "shared-vocabulary",
        "sentencepiece-model",
        "upstream-metadata",
        "upstream-attribution",
        "license",
        "documentation",
    }
)
_CJK = re.compile(r"[\u3400-\u9fff]")
_LATIN_PROSE = re.compile(r"[A-Za-z]{2,}")
_PINNED_CORE_SHA256 = {
    "model/model.bin": "1a039114d9456b6528fabb65b455b6f156319634a0f984b1f6018f7737d67598",
    "model/config.json": "3a8660f12559a223969532ff191e5e6f50d4ff24164517edbd6a5090dc5144c6",
    "model/shared_vocabulary.json": "c0b6e24705ec0489d5b810de365959c1013aecd644cfeca161b54ea1df6a7dc0",
    "sentencepiece.model": "872224b85a11edc9d769a94949fd387b67ea85b50708db9f91f32f5b497a9af3",
}
_EXPECTED_ENGINE = {"name": "CTranslate2", "version": "4.8.1"}
_EXPECTED_TOKENIZER = {"name": "SentencePiece", "version": "0.2.2"}
_EXPECTED_RUNTIME_POLICY = {
    "network_access": False,
    "requires_api_key": False,
    "uses_llm_tokens": False,
}
_EXPECTED_ARCHIVE_SHA256 = "433e7c4f034d87fbe2353161e05f18646d7999452f801a4e1f0378522b9850ab"
_MAX_SOURCE_TOKENS = 480


class OfflineTranslationError(RuntimeError):
    """Base class for local translation failures."""


class OfflineTranslationUnavailable(OfflineTranslationError):
    """The signed model or one of its native runtime dependencies is unavailable."""


class OfflineTranslationIntegrityError(OfflineTranslationUnavailable):
    """A bundled model resource failed its manifest or file-integrity check."""


class UnsupportedTranslationLanguage(OfflineTranslationError):
    """The requested target is outside the languages bundled with AegisAl."""


@dataclass(frozen=True, slots=True)
class OfflineTranslationInfo:
    engine: str = "CTranslate2"
    engine_version: str = ""
    tokenizer: str = "SentencePiece"
    tokenizer_version: str = ""
    model_id: str = MODEL_RESOURCE_ID
    model_sha256: str = ""
    resource_verified: bool = False

    def audit_fields(self) -> dict[str, Any]:
        return {
            "offline": True,
            "network_used": False,
            "requires_api_key": False,
            "provider_calls": 0,
            "billable_tokens": 0,
            "token_usage": 0,
            "model_used": False,
            "offline_model_used": self.resource_verified,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "tokenizer": self.tokenizer,
            "tokenizer_version": self.tokenizer_version,
            "model_id": self.model_id,
            "model_sha256": self.model_sha256,
            "resource_verified": self.resource_verified,
        }


def normalize_target_language(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "zh": "zh-Hans",
        "zh-cn": "zh-Hans",
        "zh-sg": "zh-Hans",
        "zh-hans": "zh-Hans",
        "zh-tw": "zh-Hant",
        "zh-hk": "zh-Hant",
        "zh-mo": "zh-Hant",
        "zh-hant": "zh-Hant",
        "en": "en",
        "en-us": "en",
        "en-gb": "en",
    }
    target = aliases.get(text)
    if target is None:
        requested = str(value or "").strip() or "<empty>"
        raise UnsupportedTranslationLanguage(
            f"Unsupported offline translation target: {requested}. "
            f"Supported targets: {', '.join(SUPPORTED_TARGET_LANGUAGES)}"
        )
    return target


def default_model_resource_dir() -> Path:
    override = str(os.getenv("SECFLOW_TRANSLATION_MODEL_DIR") or "").strip()
    if override:
        return Path(override).expanduser().resolve(strict=False)
    return (
        Path(__file__).resolve().parents[1]
        / "resources"
        / "translation-models"
        / MODEL_RESOURCE_ID
    )


class OfflineTranslationEngine:
    """Lazy CTranslate2/SentencePiece adapter for the bundled English-Chinese model."""

    def __init__(self, resource_dir: Path | None = None) -> None:
        self._resource_dir = (resource_dir or default_model_resource_dir()).resolve(strict=False)
        self._lock = RLock()
        self._translator: Any | None = None
        self._sentencepiece: Any | None = None
        self._opencc_s2t: Any | None = None
        self._opencc_t2s: Any | None = None
        self._info = OfflineTranslationInfo()

    @property
    def resource_dir(self) -> Path:
        return self._resource_dir

    @property
    def info(self) -> OfflineTranslationInfo:
        with self._lock:
            return self._info

    def warmup(self) -> OfflineTranslationInfo:
        """Load and verify the native engine before a stdio protocol starts."""

        self._ensure_loaded()
        return self.info

    def translate_batch(self, texts: Sequence[str], *, target_language: str) -> list[str]:
        target = normalize_target_language(target_language)
        clean = [str(text or "") for text in texts]
        if target == "en" or not clean:
            return clean

        self._ensure_loaded()
        translated = list(clean)
        text_segments: dict[int, list[str]] = {}
        source_parts: list[tuple[int, int, int]] = []
        token_batches: list[list[str]] = []
        part_counts: dict[tuple[int, int], int] = {}
        for index, text in enumerate(clean):
            if not text:
                continue
            # The bundled model is en->zh. Split mixed-language prose so
            # existing Chinese is converted with OpenCC while every English
            # span is still translated instead of treating the whole field as
            # already localized.
            segments = _mixed_language_segments(text)
            text_segments[index] = [segment for _translate, segment in segments]
            for segment_index, (requires_translation, segment) in enumerate(segments):
                if not requires_translation:
                    text_segments[index][segment_index] = self._convert_script(segment, target)
                    continue
                tokens = list(self._sentencepiece.encode(segment, out_type=str))
                chunks = [
                    tokens[offset : offset + _MAX_SOURCE_TOKENS]
                    for offset in range(0, len(tokens), _MAX_SOURCE_TOKENS)
                ] or [[]]
                part_counts[(index, segment_index)] = len(chunks)
                for part_index, chunk in enumerate(chunks):
                    source_parts.append((index, segment_index, part_index))
                    # config.json already declares add_source_bos=true with
                    # >>cmn_Hans<<. Adding it here would duplicate the target token.
                    token_batches.append(chunk)

        if token_batches:
            try:
                beam_size = max(1, min(int(os.getenv("SECFLOW_TRANSLATION_BEAM_SIZE", "2") or 2), 4))
            except ValueError:
                beam_size = 2
            try:
                results = self._translator.translate_batch(
                    token_batches,
                    beam_size=beam_size,
                    max_decoding_length=2048,
                    return_scores=False,
                )
            except Exception as exc:  # noqa: BLE001 - normalized at the MCP boundary.
                raise OfflineTranslationUnavailable(f"Offline translation execution failed: {exc}") from exc
            if len(results) != len(source_parts):
                raise OfflineTranslationUnavailable("Offline translation returned an incomplete batch")
            decoded_parts: dict[tuple[int, int], dict[int, str]] = {}
            for (index, segment_index, part_index), result in zip(source_parts, results, strict=True):
                hypotheses = getattr(result, "hypotheses", None) or []
                if not hypotheses:
                    raise OfflineTranslationUnavailable("Offline translation returned no hypothesis")
                decoded = str(self._sentencepiece.decode(hypotheses[0]) or "").strip()
                decoded = _normalize_translation_text(decoded)
                decoded = _normalize_security_terms(decoded)
                decoded_parts.setdefault((index, segment_index), {})[part_index] = decoded
            for (index, segment_index), parts in decoded_parts.items():
                expected_parts = part_counts[(index, segment_index)]
                if len(parts) != expected_parts:
                    raise OfflineTranslationUnavailable("Offline translation returned an incomplete text")
                source_segment = text_segments[index][segment_index]
                joined = " ".join(parts[part] for part in range(expected_parts)).strip()
                joined = _restore_edge_whitespace(source_segment, joined)
                text_segments[index][segment_index] = self._convert_script(joined, target)
        for index, segments in text_segments.items():
            translated[index] = "".join(segments)
        return translated

    def _convert_script(self, text: str, target: str) -> str:
        converter = self._opencc_s2t if target == "zh-Hant" else self._opencc_t2s
        if converter is None:
            raise OfflineTranslationUnavailable(
                f"OpenCC conversion runtime is unavailable for target {target}"
            )
        return str(converter.convert(text))

    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._translator is not None:
                return
            manifest, model_sha256 = _verified_manifest(self._resource_dir)
            try:
                import ctranslate2
                import sentencepiece
                from opencc import OpenCC
            except (ImportError, OSError) as exc:
                raise OfflineTranslationUnavailable(
                    "Bundled offline translation runtime is not installed"
                ) from exc

            engine = manifest.get("engine") if isinstance(manifest.get("engine"), dict) else {}
            tokenizer = manifest.get("tokenizer") if isinstance(manifest.get("tokenizer"), dict) else {}
            expected_engine = str(engine.get("version") or "").strip()
            expected_tokenizer = str(tokenizer.get("version") or "").strip()
            if expected_engine and str(ctranslate2.__version__) != expected_engine:
                raise OfflineTranslationIntegrityError(
                    f"CTranslate2 version mismatch: expected {expected_engine}, got {ctranslate2.__version__}"
                )
            if expected_tokenizer and str(sentencepiece.__version__) != expected_tokenizer:
                raise OfflineTranslationIntegrityError(
                    f"SentencePiece version mismatch: expected {expected_tokenizer}, got {sentencepiece.__version__}"
                )
            try:
                translator = ctranslate2.Translator(
                    str(self._resource_dir / "model"),
                    device="cpu",
                    compute_type="int8",
                    inter_threads=1,
                    intra_threads=max(1, min(int(os.cpu_count() or 1), 4)),
                )
                processor = sentencepiece.SentencePieceProcessor(
                    model_file=str(self._resource_dir / "sentencepiece.model")
                )
                opencc_s2t = OpenCC("s2t")
                opencc_t2s = OpenCC("t2s")
            except Exception as exc:  # noqa: BLE001 - native loader errors are not public contracts.
                raise OfflineTranslationUnavailable(
                    f"Bundled offline translation model could not be loaded: {exc}"
                ) from exc

            self._translator = translator
            self._sentencepiece = processor
            self._opencc_s2t = opencc_s2t
            self._opencc_t2s = opencc_t2s
            self._info = OfflineTranslationInfo(
                engine=str(engine.get("name") or "CTranslate2"),
                engine_version=str(ctranslate2.__version__),
                tokenizer=str(tokenizer.get("name") or "SentencePiece"),
                tokenizer_version=str(sentencepiece.__version__),
                model_id=MODEL_RESOURCE_ID,
                model_sha256=model_sha256,
                resource_verified=True,
            )


def _verified_manifest(resource_dir: Path) -> tuple[dict[str, Any], str]:
    manifest_path = resource_dir / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise OfflineTranslationUnavailable(
            f"Bundled offline translation manifest is missing: {manifest_path}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OfflineTranslationIntegrityError("Offline translation manifest is invalid") from exc
    if not isinstance(manifest, dict) or int(manifest.get("schema_version") or 0) != 1:
        raise OfflineTranslationIntegrityError("Unsupported offline translation manifest schema")
    if manifest.get("model_id") != MODEL_RESOURCE_ID:
        raise OfflineTranslationIntegrityError("Offline translation manifest identity is invalid")
    languages = manifest.get("languages") if isinstance(manifest.get("languages"), dict) else {}
    if str(languages.get("source") or "") != "en" or str(languages.get("target") or "") != "zh-Hans":
        raise OfflineTranslationIntegrityError("Offline translation manifest language pair is invalid")
    engine = manifest.get("engine") if isinstance(manifest.get("engine"), dict) else {}
    tokenizer = manifest.get("tokenizer") if isinstance(manifest.get("tokenizer"), dict) else {}
    if engine != _EXPECTED_ENGINE:
        raise OfflineTranslationIntegrityError("Offline translation engine declaration is invalid")
    if tokenizer != _EXPECTED_TOKENIZER:
        raise OfflineTranslationIntegrityError("Offline translation tokenizer declaration is invalid")
    runtime_policy = (
        manifest.get("runtime_policy")
        if isinstance(manifest.get("runtime_policy"), dict)
        else {}
    )
    if runtime_policy != _EXPECTED_RUNTIME_POLICY:
        raise OfflineTranslationIntegrityError("Offline translation runtime policy is invalid")
    upstream = manifest.get("upstream") if isinstance(manifest.get("upstream"), dict) else {}
    if (
        upstream.get("archive_sha256") != _EXPECTED_ARCHIVE_SHA256
        or upstream.get("license") != "CC-BY-4.0"
        or upstream.get("package") != "translate-en_zh-1_9.argosmodel"
        or upstream.get("package_version") != "1.9"
    ):
        raise OfflineTranslationIntegrityError("Offline translation upstream identity is invalid")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise OfflineTranslationIntegrityError("Offline translation manifest has no file inventory")
    seen: set[str] = set()
    roles: set[str] = set()
    digest_material: list[str] = []
    root = resource_dir.resolve(strict=True)
    for entry in entries:
        if not isinstance(entry, dict):
            raise OfflineTranslationIntegrityError("Offline translation file inventory is invalid")
        relative = str(entry.get("path") or "").replace("\\", "/").strip()
        relative_path = Path(relative)
        if not relative or relative_path.is_absolute() or ".." in relative_path.parts or relative in seen:
            raise OfflineTranslationIntegrityError("Offline translation manifest contains an unsafe file path")
        seen.add(relative)
        role = str(entry.get("role") or "").strip()
        if not role:
            raise OfflineTranslationIntegrityError("Offline translation file role is invalid")
        roles.add(role)
        path = (root / relative_path).resolve(strict=False)
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise OfflineTranslationIntegrityError("Offline translation file escapes the resource directory") from exc
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise OfflineTranslationIntegrityError(f"Offline translation file is missing: {relative}") from exc
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise OfflineTranslationIntegrityError(f"Offline translation resource is not a regular file: {relative}")
        expected_size = int(entry.get("size") or entry.get("size_bytes") or -1)
        if expected_size < 0 or metadata.st_size != expected_size:
            raise OfflineTranslationIntegrityError(f"Offline translation file size mismatch: {relative}")
        expected_sha256 = str(entry.get("sha256") or "").strip().lower()
        actual_sha256 = _sha256_file(path)
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or not hmac.compare_digest(
            expected_sha256, actual_sha256
        ):
            raise OfflineTranslationIntegrityError(f"Offline translation file hash mismatch: {relative}")
        pinned_sha256 = _PINNED_CORE_SHA256.get(relative)
        if pinned_sha256 and not hmac.compare_digest(pinned_sha256, actual_sha256):
            raise OfflineTranslationIntegrityError(
                f"Offline translation file does not match the pinned release: {relative}"
            )
        digest_material.append(f"{relative}\0{actual_sha256}\0{metadata.st_size}")
    missing = _REQUIRED_FILES - seen
    if missing:
        raise OfflineTranslationIntegrityError(
            f"Offline translation manifest omits required files: {', '.join(sorted(missing))}"
        )
    missing_roles = _REQUIRED_ROLES - roles
    if missing_roles:
        raise OfflineTranslationIntegrityError(
            f"Offline translation manifest omits required roles: {', '.join(sorted(missing_roles))}"
        )
    disk_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    if disk_files != seen:
        raise OfflineTranslationIntegrityError("Offline translation file inventory is not exact")
    model_sha256 = hashlib.sha256("\n".join(sorted(digest_material)).encode("utf-8")).hexdigest()
    return manifest, model_sha256


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalize_translation_text(text: str) -> str:
    # Some OPUS hypotheses expose a literal SentencePiece word-boundary marker.
    clean = re.sub(r"\s*\u2581\s*", " ", text)
    clean = re.sub(r"[ \t]{2,}", " ", clean)
    return clean.strip()


def _mixed_language_segments(text: str) -> list[tuple[bool, str]]:
    if not _CJK.search(text):
        return _split_latin_sentences(text)
    segments: list[tuple[bool, str]] = []
    cursor = 0
    for match in re.finditer(r"[\u3400-\u9fff]+", text):
        if match.start() > cursor:
            value = text[cursor : match.start()]
            segments.extend(_split_latin_sentences(value))
        segments.append((False, match.group(0)))
        cursor = match.end()
    if cursor < len(text):
        value = text[cursor:]
        segments.extend(_split_latin_sentences(value))
    return segments or [(False, text)]


def _split_latin_sentences(text: str) -> list[tuple[bool, str]]:
    if not _LATIN_PROSE.search(text):
        return [(False, text)]
    output: list[tuple[bool, str]] = []
    cursor = 0
    for boundary in re.finditer(r"(?:[.!?]+[\"')\]]*\s+|\n+)", text):
        end = boundary.end()
        value = text[cursor:end]
        if value:
            output.append((bool(_LATIN_PROSE.search(value)), value))
        cursor = end
    if cursor < len(text):
        value = text[cursor:]
        output.append((bool(_LATIN_PROSE.search(value)), value))
    return output or [(True, text)]


def _restore_edge_whitespace(source: str, translated: str) -> str:
    leading = re.match(r"^\s*", source).group(0)
    trailing = re.search(r"\s*$", source).group(0)
    return f"{leading}{translated.strip()}{trailing}"


def _normalize_security_terms(text: str) -> str:
    replacements = (
        (r"(?i)remote\s+code\s+execution", "远程代码执行"),
        (r"(?i)stored\s+xss", "存储型 XSS"),
        (r"(?i)reflected\s+xss", "反射型 XSS"),
        (r"(?i)cross[- ]site\s+scripting", "跨站脚本"),
        (r"(?i)cross[- ]site\s+request\s+forgery", "跨站请求伪造"),
        (r"(?i)server[- ]side\s+request\s+forgery", "服务端请求伪造"),
        (r"(?i)sql\s+injection", "SQL 注入"),
        (r"(?i)command\s+injection", "命令注入"),
        (r"(?i)(?:directory|path)\s+traversal", "路径遍历"),
    )
    clean = text
    for pattern, replacement in replacements:
        clean = re.sub(pattern, replacement, clean)
    return clean


offline_translation_engine = OfflineTranslationEngine()


__all__ = [
    "MODEL_RESOURCE_ID",
    "SUPPORTED_TARGET_LANGUAGES",
    "OfflineTranslationEngine",
    "OfflineTranslationError",
    "OfflineTranslationInfo",
    "OfflineTranslationIntegrityError",
    "OfflineTranslationUnavailable",
    "UnsupportedTranslationLanguage",
    "default_model_resource_dir",
    "normalize_target_language",
    "offline_translation_engine",
]
