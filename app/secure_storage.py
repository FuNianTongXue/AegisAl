from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import zlib
from ctypes import wintypes
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ENVELOPE_MARKER = "__secflow_encrypted__"
ENVELOPE_VERSION = 1
KEYCHAIN_SERVICE = "com.secflow.ai.mac.intelligence"
KEYCHAIN_ACCOUNT = "local-storage-master-v1"
KEYCHAIN_ITEM_NOT_FOUND_EXIT_CODE = 44
WINDOWS_KEY_FILE_NAME = ".secflow-local-storage-key.dpapi"
WINDOWS_DPAPI_DESCRIPTION = "AegisAl local storage master key"
WINDOWS_DPAPI_ENTROPY = hashlib.sha256(b"SecFlow:Windows:LocalStorage:v1").digest()
_MASTER_KEY_CACHE: bytes | None = None
_MASTER_KEY_CACHE_SOURCE = ""


def encrypt_json_to_text(value: Any, purpose: str, *, compact: bool = False) -> str:
    separators = (",", ":") if compact else None
    plaintext = json.dumps(value, ensure_ascii=False, separators=separators).encode("utf-8")
    envelope = encrypt_bytes(plaintext, purpose)
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))


def decrypt_json_from_text(text: str, purpose: str) -> Any:
    parsed = json.loads(text)
    if _is_envelope(parsed):
        return json.loads(decrypt_bytes(parsed, purpose).decode("utf-8"))
    return parsed


def encrypt_bytes(plaintext: bytes, purpose: str) -> dict[str, Any]:
    master = _master_key()
    salt = os.urandom(32)
    aad = _aad(purpose)
    inner_key = _derive_key(master, salt, f"{purpose}:inner".encode("utf-8"))
    outer_key = _derive_key(master, salt, f"{purpose}:outer".encode("utf-8"))
    inner_nonce = os.urandom(12)
    outer_nonce = os.urandom(12)

    compressed = zlib.compress(plaintext, level=9)
    inner_ciphertext = AESGCM(inner_key).encrypt(inner_nonce, compressed, aad)
    outer_ciphertext = AESGCM(outer_key).encrypt(outer_nonce, inner_ciphertext, aad)
    return {
        ENVELOPE_MARKER: True,
        "version": ENVELOPE_VERSION,
        "alg": "HKDF-SHA256/AES-256-GCM/double-layer/zlib",
        "purpose": purpose,
        "salt": _b64(salt),
        "innerNonce": _b64(inner_nonce),
        "outerNonce": _b64(outer_nonce),
        "payload": _b64(outer_ciphertext),
    }


def decrypt_bytes(envelope: dict[str, Any], purpose: str) -> bytes:
    if not _is_envelope(envelope):
        raise ValueError("not an AegisAl encrypted envelope")
    envelope_purpose = str(envelope.get("purpose") or "")
    if envelope_purpose and envelope_purpose != purpose:
        raise ValueError("encrypted payload purpose mismatch")
    salt = _unb64(str(envelope["salt"]))
    inner_nonce = _unb64(str(envelope["innerNonce"]))
    outer_nonce = _unb64(str(envelope["outerNonce"]))
    payload = _unb64(str(envelope["payload"]))
    aad = _aad(envelope_purpose or purpose)
    master = _master_key()
    cache_source = _master_key_cache_source(os.getenv("SECFLOW_STORAGE_MASTER_KEY", "").strip())

    def decrypt_with(key: bytes) -> bytes:
        inner_key = _derive_key(key, salt, f"{purpose}:inner".encode("utf-8"))
        outer_key = _derive_key(key, salt, f"{purpose}:outer".encode("utf-8"))
        inner_ciphertext = AESGCM(outer_key).decrypt(outer_nonce, payload, aad)
        compressed = AESGCM(inner_key).decrypt(inner_nonce, inner_ciphertext, aad)
        return zlib.decompress(compressed)

    try:
        return decrypt_with(master)
    except InvalidTag as exc:
        initial_invalid_tag = exc

    for recovery_key in _decryption_recovery_keys(master):
        try:
            plaintext = decrypt_with(recovery_key)
        except InvalidTag:
            continue
        _cache_master_key(recovery_key, cache_source)
        return plaintext
    raise initial_invalid_tag


def is_encrypted_text(text: str) -> bool:
    try:
        return _is_envelope(json.loads(text))
    except Exception:  # noqa: BLE001
        return False


def secure_metadata_key(key: str) -> str:
    if key == "schema_version":
        return key
    digest = hashlib.sha256(f"secflow-metadata:{key}".encode("utf-8")).hexdigest()
    return f"m:{digest[:32]}"


def sign_local_payload(value: Any, purpose: str) -> str:
    """Sign a Host-owned local attestation with the platform storage key."""

    payload = _canonical_attestation_payload(value)
    salt = hashlib.sha256(f"SecFlowLocalAttestation:{purpose}:v1".encode("utf-8")).digest()
    key = _derive_key(_master_key(), salt, f"{purpose}:attestation".encode("utf-8"))
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_local_payload_signature(value: Any, purpose: str, signature: Any) -> bool:
    if type(signature) is not str or len(signature) != 64:
        return False
    try:
        expected = sign_local_payload(value, purpose)
    except (OSError, TypeError, ValueError):
        return False
    return hmac.compare_digest(signature.lower(), expected)


def _canonical_attestation_payload(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def storage_crypto_status() -> dict[str, Any]:
    provider = _key_provider_name()
    return {
        "enabled": True,
        "algorithm": "HKDF-SHA256/AES-256-GCM/double-layer",
        "keyProvider": provider,
        "keychainService": _keychain_service() if provider == "macOS Keychain" else "",
    }


def _is_envelope(value: Any) -> bool:
    return isinstance(value, dict) and value.get(ENVELOPE_MARKER) is True


def _aad(purpose: str) -> bytes:
    return f"SecFlowLocalStorage:{purpose}:v{ENVELOPE_VERSION}".encode("utf-8")


def _derive_key(master: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"secflow-ai-mac:" + info,
    ).derive(master)


def _master_key() -> bytes:
    global _MASTER_KEY_CACHE, _MASTER_KEY_CACHE_SOURCE
    env_key = os.getenv("SECFLOW_STORAGE_MASTER_KEY", "").strip()
    cache_source = _master_key_cache_source(env_key)
    if _MASTER_KEY_CACHE is not None and _MASTER_KEY_CACHE_SOURCE == cache_source:
        return _MASTER_KEY_CACHE

    if env_key:
        _MASTER_KEY_CACHE = _decode_or_derive_key(env_key)
        _MASTER_KEY_CACHE_SOURCE = cache_source
        return _MASTER_KEY_CACHE

    keychain_key = _load_keychain_key()
    if keychain_key:
        _MASTER_KEY_CACHE = keychain_key
        _MASTER_KEY_CACHE_SOURCE = cache_source
        return _MASTER_KEY_CACHE

    if sys.platform == "win32" and os.getenv("SECFLOW_DISABLE_DPAPI") != "1":
        _MASTER_KEY_CACHE = _load_or_create_dpapi_key()
        _MASTER_KEY_CACHE_SOURCE = cache_source
        return _MASTER_KEY_CACHE

    _MASTER_KEY_CACHE = _load_or_create_file_key()
    _MASTER_KEY_CACHE_SOURCE = cache_source
    return _MASTER_KEY_CACHE


def _decryption_recovery_keys(failed_key: bytes) -> list[bytes]:
    """Return existing alternate keys after the cached key fails authentication.

    A transient macOS Keychain failure previously made the runtime create and
    cache a fallback file key. Trying only that key caused an InvalidTag even
    after Keychain access recovered, and StateStore then replaced the user's
    settings. Decryption may safely try existing local key providers because a
    candidate is accepted only after AES-GCM authentication succeeds.
    """

    env_key = os.getenv("SECFLOW_STORAGE_MASTER_KEY", "").strip()
    if env_key:
        return []

    candidates: list[bytes] = []
    seen = {failed_key}

    def add(key: bytes | None) -> None:
        if key is not None and key not in seen:
            seen.add(key)
            candidates.append(key)

    add(_load_keychain_key(create_if_missing=False))
    if sys.platform == "win32" and os.getenv("SECFLOW_DISABLE_DPAPI") != "1":
        add(_load_existing_dpapi_key())
    add(_load_existing_file_key())
    return candidates


def _master_key_cache_source(env_key: str) -> str:
    if env_key:
        return f"env:{hashlib.sha256(env_key.encode('utf-8')).hexdigest()}"
    runtime_identity = "\0".join(
        (
            sys.platform,
            _keychain_service(),
            os.getenv("SECFLOW_KEYCHAIN_PATH", "").strip(),
            os.getenv("SECFLOW_TRIAL_ENABLED", "").strip(),
            os.getenv("SECFLOW_DISABLE_KEYCHAIN", "").strip(),
            os.getenv("SECFLOW_DISABLE_DPAPI", "").strip(),
            str(_file_key_path().expanduser().resolve(strict=False)),
        )
    )
    return f"runtime:{hashlib.sha256(runtime_identity.encode('utf-8')).hexdigest()}"


def _cache_master_key(key: bytes, source: str) -> None:
    global _MASTER_KEY_CACHE, _MASTER_KEY_CACHE_SOURCE
    _MASTER_KEY_CACHE = key
    _MASTER_KEY_CACHE_SOURCE = source


def _key_provider_name() -> str:
    if os.getenv("SECFLOW_STORAGE_MASTER_KEY", "").strip():
        return "environment"
    if sys.platform == "darwin" and Path(os.getenv("SECFLOW_SECURITY_CLI", "/usr/bin/security")).exists():
        return "macOS Keychain"
    if sys.platform == "win32" and os.getenv("SECFLOW_DISABLE_DPAPI") != "1":
        return "Windows DPAPI"
    return "local fallback key file"


def _load_keychain_key(*, create_if_missing: bool = True) -> bytes | None:
    context = _keychain_cli_context()
    if context is None:
        return None
    security, keychain_arguments = context

    existing, item_missing = _read_keychain_key(security, keychain_arguments)
    if existing is not None:
        return existing
    if not create_if_missing or not item_missing:
        return None

    file_key_path = _file_key_path()
    existing_file_key = (
        _wait_for_existing_file_key()
        if file_key_path.is_file()
        else _load_existing_file_key()
    )
    key_material = existing_file_key or os.urandom(32)
    encoded = base64.b64encode(key_material).decode("ascii")
    try:
        created = subprocess.run(
            [
                str(security),
                "add-generic-password",
                "-s",
                _keychain_service(),
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
                encoded,
                *keychain_arguments,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    # Never update an existing item here. Concurrent backend processes may all
    # observe an empty Keychain on first launch; the add without -U lets only
    # one process win. A successful add is authoritative for this process;
    # losers re-read the winner below.
    if created.returncode == 0:
        return _decode_persisted_key(encoded)
    persisted, _ = _read_keychain_key(security, keychain_arguments)
    if persisted is not None:
        return persisted
    return None


def _read_keychain_key(
    security: Path,
    keychain_arguments: list[str],
) -> tuple[bytes | None, bool]:
    try:
        result = subprocess.run(
            [
                str(security),
                "find-generic-password",
                "-s",
                _keychain_service(),
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
                *keychain_arguments,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, False
    if result.returncode == 0 and result.stdout.strip():
        try:
            # Existing releases accepted either a raw passphrase or an
            # encoded 32-byte key. Keep both forms readable during migration.
            return _decode_or_derive_key(result.stdout.strip()), False
        except ValueError:
            return None, False
    return None, _keychain_item_missing(result)


def _keychain_item_missing(result: subprocess.CompletedProcess[str]) -> bool:
    error = str(result.stderr or "").lower()
    return (
        result.returncode in {KEYCHAIN_ITEM_NOT_FOUND_EXIT_CODE, -25300}
        or "could not be found" in error
        or "item not found" in error
    )


def _keychain_cli_context() -> tuple[Path, list[str]] | None:
    if sys.platform != "darwin" or os.getenv("SECFLOW_DISABLE_KEYCHAIN") == "1":
        return None
    security = Path(os.getenv("SECFLOW_SECURITY_CLI", "/usr/bin/security"))
    if not security.exists():
        return None
    configured_keychain = Path(os.getenv("SECFLOW_KEYCHAIN_PATH", "").strip()).expanduser()
    keychain_arguments = [str(configured_keychain)] if configured_keychain.is_file() else []
    return security, keychain_arguments


def _keychain_service() -> str:
    return os.getenv("SECFLOW_KEYCHAIN_SERVICE", KEYCHAIN_SERVICE).strip() or KEYCHAIN_SERVICE


def _load_or_create_file_key() -> bytes:
    key_path = _file_key_path()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _load_existing_file_key()
    if existing is not None:
        return existing

    encoded = base64.b64encode(os.urandom(32)).decode("ascii")
    try:
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        winner = _wait_for_existing_file_key()
        if winner is None:
            raise OSError("local storage key file exists but is unreadable")
        return winner
    with os.fdopen(descriptor, "w", encoding="utf-8") as key_file:
        key_file.write(encoded)
        key_file.flush()
        os.fsync(key_file.fileno())
    return _decode_persisted_key(encoded)


def _wait_for_existing_file_key() -> bytes | None:
    # Another backend process may have won O_EXCL and still be flushing its
    # value. Wait briefly for that atomic creator; never replace its file.
    for _ in range(40):
        winner = _load_existing_file_key()
        if winner is not None:
            return winner
        time.sleep(0.01)
    return None


def _load_existing_file_key() -> bytes | None:
    key_path = _file_key_path()
    if not key_path.is_file():
        return None
    try:
        raw = key_path.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        return _decode_or_derive_key(raw)
    except (OSError, ValueError):
        return None


def _file_key_path() -> Path:
    configured_path = os.getenv("SECFLOW_STORAGE_KEY_FILE", "").strip()
    return (
        Path(configured_path)
        if configured_path
        else Path(os.getenv("SECFLOW_DATA_DIR", "data")) / ".secflow-local-storage.key"
    )


def _load_or_create_dpapi_key() -> bytes:
    key_path = _dpapi_key_path()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        protected = base64.b64decode(key_path.read_text(encoding="ascii").strip(), validate=True)
        key = _dpapi_unprotect(protected)
        if len(key) != 32:
            raise ValueError("invalid Windows DPAPI storage key")
        return key

    key = os.urandom(32)
    protected = _dpapi_protect(key)
    encoded = base64.b64encode(protected).decode("ascii")
    temporary_path = key_path.with_suffix(f"{key_path.suffix}.tmp")
    temporary_path.write_text(encoded, encoding="ascii")
    temporary_path.replace(key_path)
    return key


def _load_existing_dpapi_key() -> bytes | None:
    key_path = _dpapi_key_path()
    if not key_path.is_file():
        return None
    try:
        protected = base64.b64decode(key_path.read_text(encoding="ascii").strip(), validate=True)
        key = _dpapi_unprotect(protected)
    except (OSError, ValueError):
        return None
    return key if len(key) == 32 else None


def _dpapi_key_path() -> Path:
    configured_path = os.getenv("SECFLOW_STORAGE_KEY_FILE", "").strip()
    return (
        Path(configured_path)
        if configured_path
        else Path(os.getenv("SECFLOW_DATA_DIR", "data")) / WINDOWS_KEY_FILE_NAME
    )


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(value: bytes) -> tuple[_DataBlob, Any]:
    buffer = ctypes.create_string_buffer(value, len(value))
    pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    return _DataBlob(len(value), pointer), buffer


def _dpapi_protect(value: bytes) -> bytes:
    return _dpapi_call("CryptProtectData", value, WINDOWS_DPAPI_DESCRIPTION)


def _dpapi_unprotect(value: bytes) -> bytes:
    return _dpapi_call("CryptUnprotectData", value, None)


def _dpapi_call(function_name: str, value: bytes, description: str | None) -> bytes:
    if sys.platform != "win32":
        raise OSError("Windows DPAPI is only available on Windows")
    input_blob, input_buffer = _blob(value)
    entropy_blob, entropy_buffer = _blob(WINDOWS_DPAPI_ENTROPY)
    output_blob = _DataBlob()
    description_pointer = ctypes.c_wchar_p(description) if description else None
    crypt32 = ctypes.windll.crypt32
    function = getattr(crypt32, function_name)
    succeeded = function(
        ctypes.byref(input_blob),
        description_pointer,
        ctypes.byref(entropy_blob),
        None,
        None,
        0x01,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(output_blob),
    )
    _ = input_buffer, entropy_buffer
    if not succeeded:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output_blob.pbData)


def _decode_or_derive_key(value: str) -> bytes:
    raw = value.strip()
    for decoder in (_decode_base64, _decode_hex):
        decoded = decoder(raw)
        if decoded and len(decoded) == 32:
            return decoded
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _decode_persisted_key(value: str) -> bytes:
    raw = value.strip()
    if not raw:
        raise ValueError("invalid persisted local storage key")
    for decoder in (_decode_base64, _decode_hex):
        decoded = decoder(raw)
        if decoded and len(decoded) == 32:
            return decoded
    # Values written by the first storage implementation were arbitrary text
    # passphrases. Keep those installations readable while rejecting an empty
    # or malformed generated value instead of silently deriving from it.
    if len(raw) >= 40 and all(
        character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        for character in raw
    ):
        raise ValueError("invalid persisted local storage key")
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _decode_base64(value: str) -> bytes | None:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:  # noqa: BLE001
        return None


def _decode_hex(value: str) -> bytes | None:
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)
