from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import subprocess
import sys
import zlib
from ctypes import wintypes
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ENVELOPE_MARKER = "__secflow_encrypted__"
ENVELOPE_VERSION = 1
KEYCHAIN_SERVICE = "com.secflow.ai.mac.intelligence"
KEYCHAIN_ACCOUNT = "local-storage-master-v1"
WINDOWS_KEY_FILE_NAME = ".secflow-local-storage-key.dpapi"
WINDOWS_DPAPI_DESCRIPTION = "SecFlow local storage master key"
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
        raise ValueError("not a SecFlow encrypted envelope")
    envelope_purpose = str(envelope.get("purpose") or "")
    if envelope_purpose and envelope_purpose != purpose:
        raise ValueError("encrypted payload purpose mismatch")
    master = _master_key()
    salt = _unb64(str(envelope["salt"]))
    inner_nonce = _unb64(str(envelope["innerNonce"]))
    outer_nonce = _unb64(str(envelope["outerNonce"]))
    payload = _unb64(str(envelope["payload"]))
    aad = _aad(envelope_purpose or purpose)
    inner_key = _derive_key(master, salt, f"{purpose}:inner".encode("utf-8"))
    outer_key = _derive_key(master, salt, f"{purpose}:outer".encode("utf-8"))
    inner_ciphertext = AESGCM(outer_key).decrypt(outer_nonce, payload, aad)
    compressed = AESGCM(inner_key).decrypt(inner_nonce, inner_ciphertext, aad)
    return zlib.decompress(compressed)


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
    cache_source = f"env:{hashlib.sha256(env_key.encode('utf-8')).hexdigest()}" if env_key else "runtime"
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


def _key_provider_name() -> str:
    if os.getenv("SECFLOW_STORAGE_MASTER_KEY", "").strip():
        return "environment"
    if sys.platform == "darwin" and Path(os.getenv("SECFLOW_SECURITY_CLI", "/usr/bin/security")).exists():
        return "macOS Keychain"
    if sys.platform == "win32" and os.getenv("SECFLOW_DISABLE_DPAPI") != "1":
        return "Windows DPAPI"
    return "local fallback key file"


def _load_keychain_key() -> bytes | None:
    if sys.platform != "darwin" or os.getenv("SECFLOW_DISABLE_KEYCHAIN") == "1":
        return None
    security = Path(os.getenv("SECFLOW_SECURITY_CLI", "/usr/bin/security"))
    if not security.exists():
        return None

    try:
        existing = subprocess.run(
            [
                str(security),
                "find-generic-password",
                "-s",
                _keychain_service(),
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if existing.returncode == 0 and existing.stdout.strip():
        return _decode_or_derive_key(existing.stdout.strip())

    encoded = base64.b64encode(os.urandom(32)).decode("ascii")
    try:
        created = subprocess.run(
            [
                str(security),
                "add-generic-password",
                "-U",
                "-s",
                _keychain_service(),
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
                encoded,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if created.returncode == 0:
        return _decode_or_derive_key(encoded)
    return None


def _keychain_service() -> str:
    return os.getenv("SECFLOW_KEYCHAIN_SERVICE", KEYCHAIN_SERVICE).strip() or KEYCHAIN_SERVICE


def _load_or_create_file_key() -> bytes:
    configured_path = os.getenv("SECFLOW_STORAGE_KEY_FILE", "").strip()
    if configured_path:
        key_path = Path(configured_path)
    else:
        key_path = Path(os.getenv("SECFLOW_DATA_DIR", "data")) / ".secflow-local-storage.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return _decode_or_derive_key(key_path.read_text(encoding="utf-8").strip())
    encoded = base64.b64encode(os.urandom(32)).decode("ascii")
    key_path.write_text(encoded, encoding="utf-8")
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    return _decode_or_derive_key(encoded)


def _load_or_create_dpapi_key() -> bytes:
    configured_path = os.getenv("SECFLOW_STORAGE_KEY_FILE", "").strip()
    key_path = (
        Path(configured_path)
        if configured_path
        else Path(os.getenv("SECFLOW_DATA_DIR", "data")) / WINDOWS_KEY_FILE_NAME
    )
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
