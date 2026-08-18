from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path
from typing import Any

from fastapi.responses import FileResponse

from app.storage import DATA_DIR, now_iso, store


MAX_AVATAR_BYTES = 2 * 1024 * 1024
SUPPORTED_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
SUPPORTED_LANGUAGES = {"zh-Hans", "zh-Hant", "en", "ko", "ja", "es", "fr", "de", "it", "ru"}
LEGAL_DOCUMENT_IDS = {"terms", "privacy"}
LEGAL_CURRENT_DATE = "2026年7月20日"
APP_NAME = "安全智脑"
APP_SUBTITLE = "Security AI Assistant"
APP_VERSION = os.getenv("SECFLOW_APP_VERSION", "1.3.3").strip() or "1.3.3"
APP_RELEASE_CHANNEL = os.getenv("SECFLOW_APP_RELEASE_CHANNEL", "内测版").strip() or "内测版"
APP_VERSION_LABEL = f"v{APP_VERSION} {APP_RELEASE_CHANNEL}"
APP_COPYRIGHT = "© 2026 安全智脑 Security AI. All Rights Reserved."
LANGUAGE_ALIASES = {
    "zh-hans": "zh-Hans",
    "zh_cn": "zh-Hans",
    "zh-cn": "zh-Hans",
    "zh": "zh-Hans",
    "zhhans": "zh-Hans",
    "zh-hant": "zh-Hant",
    "zh_tw": "zh-Hant",
    "zh-tw": "zh-Hant",
    "zh_hk": "zh-Hant",
    "zh-hk": "zh-Hant",
    "zhtw": "zh-Hant",
    "zhhant": "zh-Hant",
    "en": "en",
    "en_us": "en",
    "en-us": "en",
    "english": "en",
    "ko": "ko",
    "ko_kr": "ko",
    "ko-kr": "ko",
    "korean": "ko",
    "ja": "ja",
    "ja_jp": "ja",
    "ja-jp": "ja",
    "japanese": "ja",
    "es": "es",
    "es_es": "es",
    "es-es": "es",
    "spanish": "es",
    "fr": "fr",
    "fr_fr": "fr",
    "fr-fr": "fr",
    "french": "fr",
    "de": "de",
    "de_de": "de",
    "de-de": "de",
    "german": "de",
    "it": "it",
    "it_it": "it",
    "it-it": "it",
    "italian": "it",
    "ru": "ru",
    "ru_ru": "ru",
    "ru-ru": "ru",
    "russian": "ru",
}
AVATAR_MEDIA_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}


def default_profile_settings() -> dict[str, Any]:
    return {
        "display_name": "",
        "email": "",
        "phone": "",
        "department": "",
        "role": "",
        "employee_id": "",
        "bio": "",
        "avatar_file_name": "",
        "avatar_content_type": "",
        "avatar_updated_at": "",
        "updated_at": "",
    }


def default_preference_settings() -> dict[str, Any]:
    return {
        "language": "zh-Hans",
        "dark_mode": False,
        "font_size": "default",
        "launch_at_login": False,
        "auto_check_updates": True,
        "updated_at": "",
    }


def default_legal_documents() -> dict[str, dict[str, Any]]:
    return {
        "terms": {
            "id": "terms",
            "title": "服务协议",
            "heading": "安全智脑服务协议",
            "updated_at": LEGAL_CURRENT_DATE,
            "effective_at": LEGAL_CURRENT_DATE,
            "intro": "欢迎使用安全智脑（以下简称“本软件”）。本协议是您与安全智脑团队之间关于使用本软件服务所订立的协议。请您仔细阅读本协议的全部内容，您一旦安装、复制或以其他方式使用本软件，即表示您已阅读并同意接受本协议各项条款的约束。",
            "sections": [
                {
                    "heading": "一、协议的接受与修改",
                    "paragraphs": [
                        "我们有权根据需要随时修改本协议条款，修改后的协议一经公布即有效代替原来的协议条款。您可随时查阅最新版协议。如您不同意相关修改，请立即停止使用本软件。",
                    ],
                },
                {
                    "heading": "二、服务内容",
                    "paragraphs": [
                        "安全智脑是一款基于人工智能技术的网络安全辅助工具，主要功能包括但不限于：",
                        "1. 智能问答：提供网络安全领域的知识问答服务；",
                        "2. 情报采集：聚合多源安全情报信息；",
                        "3. 知识图谱：安全领域实体关系可视化展示；",
                        "4. 漏洞库：漏洞信息查询与分析。",
                    ],
                },
                {
                    "heading": "三、用户账号",
                    "paragraphs": [
                        "您需要注册并登录账号才能使用本软件的完整功能。您应妥善保管账号和密码，对您账号下的所有行为承担责任。如发现账号被盗用，请立即通知我们。",
                    ],
                },
                {
                    "heading": "四、用户行为规范",
                    "paragraphs": [
                        "您在使用本软件时，应遵守相关法律法规，不得利用本软件从事任何违法违规活动，包括但不限于：",
                        "1. 发布、传播违法或不良信息；",
                        "2. 利用本软件从事未经授权的网络攻击、渗透测试等活动；",
                        "3. 侵犯他人合法权益；",
                        "4. 干扰本软件正常运行。",
                    ],
                },
                {
                    "heading": "五、知识产权",
                    "paragraphs": [
                        "本软件的一切知识产权，包括但不限于著作权、专利权、商标权等，均归安全智脑团队所有。未经授权，您不得对本软件进行复制、修改、分发、反编译等。",
                    ],
                },
                {
                    "heading": "六、免责声明",
                    "paragraphs": [
                        "本软件提供的信息仅供参考，不构成任何安全建议或操作指导。您因使用本软件信息而产生的任何直接或间接损失，我们不承担责任。本软件按“现状”提供，我们不保证服务会中断，也不保证服务的绝对准确性。",
                    ],
                },
                {
                    "heading": "七、协议终止",
                    "paragraphs": [
                        "如您违反本协议，我们有权立即终止您的账号使用权限。您也可以随时注销账号终止本协议。协议终止后，相关条款（如知识产权、免责声明等）仍然有效。",
                    ],
                },
                {
                    "heading": "八、联系我们",
                    "paragraphs": [
                        "如您对本协议有任何疑问或建议，请通过以下方式联系我们：",
                        "邮箱：support@security-ai.com",
                    ],
                },
            ],
        },
        "privacy": {
            "id": "privacy",
            "title": "隐私政策",
            "heading": "安全智脑隐私政策",
            "updated_at": LEGAL_CURRENT_DATE,
            "effective_at": LEGAL_CURRENT_DATE,
            "intro": "安全智脑非常重视用户的隐私保护。本隐私政策将帮助您了解我们如何收集、使用、存储和保护您的个人信息。请您在使用本软件前仔细阅读本政策。",
            "sections": [
                {
                    "heading": "一、我们收集的信息",
                    "paragraphs": [
                        "为了向您提供更好的服务，我们可能会收集以下类型的信息：",
                        "账户信息：昵称、邮箱账号、手机号等；",
                        "使用信息：您在本软件中的设置、查询记录和交互信息；",
                        "设备信息：设备型号、操作系统版本、应用版本等；",
                        "日志信息：错误日志、运行状态和服务调用记录。",
                    ],
                },
                {
                    "heading": "二、信息的使用",
                    "paragraphs": [
                        "我们收集的信息将用于以下目的：",
                        "1. 提供、维护和改进本软件的服务；",
                        "2. 向您发送服务通知和更新信息；",
                        "3. 保障账户安全，防范欺诈等违法行为；",
                        "4. 在获得您同意的前提下，进行产品优化和数据分析。",
                    ],
                },
                {
                    "heading": "三、信息的共享与披露",
                    "paragraphs": [
                        "我们不会向第三方出售您的个人信息。仅在以下情况下，我们可能会共享您的信息：",
                        "1. 获得您的明确同意；",
                        "2. 法律法规要求或司法机关、行政机关依法定程序要求；",
                        "3. 为保护我们或用户的合法权益所必需。",
                    ],
                },
                {
                    "heading": "四、信息的存储与保护",
                    "paragraphs": [
                        "我们采用业界标准的安全技术和管理措施来保护您的个人信息，包括加密传输、访问控制、数据脱敏等。但请您理解，由于技术限制和可能的恶意攻击，我们无法保证信息的绝对安全。",
                        "您的个人信息将存储在中华人民共和国境内。如需跨境传输，我们将依法履行相关义务。",
                    ],
                },
                {
                    "heading": "五、您的权利",
                    "paragraphs": [
                        "您对您的个人信息享有以下权利：",
                        "1. 访问、更正您的个人信息；",
                        "2. 删除您的个人信息；",
                        "3. 撤回您的授权同意；",
                        "4. 注销您的账号。",
                    ],
                },
                {
                    "heading": "六、未成年人保护",
                    "paragraphs": [
                        "本软件主要面向成年用户。如您是未成年人，请在监护人的指导下使用本软件。我们不会主动收集未成年人的个人信息。",
                    ],
                },
                {
                    "heading": "七、政策更新",
                    "paragraphs": [
                        "我们可能会适时更新本隐私政策。更新后的政策将在本软件内公布，重大变更将通过显著方式通知您。继续使用本软件即表示您同意更新后的政策。",
                    ],
                },
                {
                    "heading": "八、联系我们",
                    "paragraphs": [
                        "如您对本隐私政策有任何疑问、意见或建议，或需要行使您的权利，请通过以下方式联系我们：",
                        "邮箱：privacy@security-ai.com",
                    ],
                },
            ],
        },
    }


def public_settings_snapshot(user_id: str = "default") -> dict[str, Any]:
    return {
        "profile": get_profile_settings(user_id),
        "preferences": get_preference_settings(),
        "about": about_settings(),
        "legal": get_legal_documents(),
    }


def get_profile_settings(user_id: str = "default") -> dict[str, Any]:
    state = store.read()
    resolved_user_id = _normalize_user_id(user_id)
    profile = _stored_profile(_settings_bucket(state), resolved_user_id)
    if not isinstance(profile, dict):
        profile = {}
    result = default_profile_settings()
    result.update({key: value for key, value in profile.items() if key in result})
    result["avatar_available"] = (
        avatar_path(result, resolved_user_id).is_file() if result.get("avatar_file_name") else False
    )
    return result


def update_profile_settings(update: dict[str, Any], user_id: str = "default") -> dict[str, Any]:
    state = store.read()
    settings = _settings_bucket(state)
    resolved_user_id = _normalize_user_id(user_id)
    current = default_profile_settings()
    existing = _stored_profile(settings, resolved_user_id)
    if isinstance(existing, dict):
        current.update(existing)
    for key in ("display_name", "email", "phone", "department", "role", "employee_id", "bio"):
        if key in update and update[key] is not None:
            current[key] = str(update[key]).strip()
    if len(str(current.get("bio") or "")) > 200:
        current["bio"] = str(current.get("bio") or "")[:200]
    current["updated_at"] = now_iso()
    _store_profile(settings, resolved_user_id, current)
    store.write(state)
    return get_profile_settings(resolved_user_id)


def save_profile_avatar(
    file_name: str,
    content_base64: str,
    content_type: str = "",
    user_id: str = "default",
) -> dict[str, Any]:
    clean_name = Path(file_name).name.strip()
    extension = Path(clean_name).suffix.lower()
    if extension not in SUPPORTED_AVATAR_EXTENSIONS:
        raise ValueError("仅支持 JPG、PNG 或 WebP 图片")
    try:
        data = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("头像内容不是有效的 Base64 数据") from exc
    if not data:
        raise ValueError("头像文件为空")
    if len(data) > MAX_AVATAR_BYTES:
        raise ValueError("头像文件不能超过 2MB")
    _validate_avatar_magic(data, extension)

    state = store.read()
    settings = _settings_bucket(state)
    resolved_user_id = _normalize_user_id(user_id)
    profile = default_profile_settings()
    existing = _stored_profile(settings, resolved_user_id)
    if isinstance(existing, dict):
        profile.update(existing)
    _remove_avatar_files(resolved_user_id)
    avatar_dir(resolved_user_id).mkdir(parents=True, exist_ok=True)
    target_name = f"avatar{extension}"
    target = avatar_dir(resolved_user_id) / target_name
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    profile["avatar_file_name"] = target_name
    profile["avatar_content_type"] = content_type.strip() or AVATAR_MEDIA_TYPES[extension]
    profile["avatar_updated_at"] = now_iso()
    profile["updated_at"] = now_iso()
    _store_profile(settings, resolved_user_id, profile)
    store.write(state)
    return get_profile_settings(resolved_user_id)


def delete_profile_avatar(user_id: str = "default") -> dict[str, Any]:
    state = store.read()
    settings = _settings_bucket(state)
    resolved_user_id = _normalize_user_id(user_id)
    profile = default_profile_settings()
    existing = _stored_profile(settings, resolved_user_id)
    if isinstance(existing, dict):
        profile.update(existing)
    _remove_avatar_files(resolved_user_id)
    profile["avatar_file_name"] = ""
    profile["avatar_content_type"] = ""
    profile["avatar_updated_at"] = ""
    profile["updated_at"] = now_iso()
    _store_profile(settings, resolved_user_id, profile)
    store.write(state)
    return get_profile_settings(resolved_user_id)


def avatar_response(user_id: str = "default") -> FileResponse:
    resolved_user_id = _normalize_user_id(user_id)
    profile = get_profile_settings(resolved_user_id)
    path = avatar_path(profile, resolved_user_id)
    if not path.is_file():
        raise KeyError("avatar")
    return FileResponse(
        path,
        media_type=str(profile.get("avatar_content_type") or AVATAR_MEDIA_TYPES.get(path.suffix.lower(), "application/octet-stream")),
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def get_preference_settings() -> dict[str, Any]:
    state = store.read()
    preferences = _settings_bucket(state).get("preferences")
    if not isinstance(preferences, dict):
        preferences = {}
    result = default_preference_settings()
    result.update({key: value for key, value in preferences.items() if key in result})
    result["language"] = normalize_language(str(result.get("language") or "zh-Hans"))
    return result


def update_preference_settings(update: dict[str, Any]) -> dict[str, Any]:
    state = store.read()
    settings = _settings_bucket(state)
    current = default_preference_settings()
    existing = settings.get("preferences")
    if isinstance(existing, dict):
        current.update(existing)
    if "language" in update and update["language"] is not None:
        current["language"] = normalize_language(str(update["language"]))
    if "font_size" in update and update["font_size"] is not None:
        current["font_size"] = str(update["font_size"]).strip() or "default"
    for key in ("dark_mode", "launch_at_login", "auto_check_updates"):
        if key in update and update[key] is not None:
            current[key] = bool(update[key])
    current["updated_at"] = now_iso()
    settings["preferences"] = current
    store.write(state)
    return get_preference_settings()


def normalize_language(value: str) -> str:
    clean = str(value or "").strip()
    if clean in SUPPORTED_LANGUAGES:
        return clean
    return LANGUAGE_ALIASES.get(clean.lower().replace(" ", "-"), "zh-Hans")


def get_legal_documents() -> dict[str, dict[str, Any]]:
    state = store.read()
    stored = _settings_bucket(state).get("legal")
    if not isinstance(stored, dict):
        stored = {}
    defaults = default_legal_documents()
    return {
        document_id: _merge_legal_document(default_document, stored.get(document_id))
        for document_id, default_document in defaults.items()
    }


def get_legal_document(document_id: str) -> dict[str, Any]:
    clean_id = _normalize_legal_document_id(document_id)
    return get_legal_documents()[clean_id]


def update_legal_document(document_id: str, update: dict[str, Any]) -> dict[str, Any]:
    clean_id = _normalize_legal_document_id(document_id)
    state = store.read()
    settings = _settings_bucket(state)
    legal = settings.get("legal")
    if not isinstance(legal, dict):
        legal = {}
        settings["legal"] = legal
    current = get_legal_document(clean_id)
    for key in ("title", "heading", "updated_at", "effective_at", "intro"):
        if key in update and update[key] is not None:
            current[key] = str(update[key]).strip()
    if "sections" in update and update["sections"] is not None:
        current["sections"] = [
            {
                "heading": str(section.get("heading") or "").strip(),
                "paragraphs": [str(item).strip() for item in section.get("paragraphs") or [] if str(item).strip()],
            }
            for section in update["sections"]
            if isinstance(section, dict)
        ]
    current["id"] = clean_id
    current["revision_updated_at"] = now_iso()
    legal[clean_id] = current
    store.write(state)
    return get_legal_document(clean_id)


def about_settings() -> dict[str, Any]:
    return {
        "name": APP_NAME,
        "subtitle": APP_SUBTITLE,
        "version": APP_VERSION,
        "release_channel": APP_RELEASE_CHANNEL,
        "version_label": APP_VERSION_LABEL,
        "latest": True,
        "last_checked_at": "2024-01-15 14:32",
        "copyright": APP_COPYRIGHT,
        "logo": {
            "style": "rounded-square-shield-star",
            "primary_color": "#2CAFD2",
            "secondary_color": "#0F193A",
        },
        "features": [
            "智能问答：基于大语言模型的网络安全知识问答，支持漏洞分析、渗透测试建议等",
            "情报采集：多源安全情报聚合与分析，实时追踪最新安全动态",
            "知识图谱：安全领域实体关系可视化，快速定位关联信息",
            "漏洞库：全面的漏洞数据库，支持 CVE 编号查询与修复建议",
        ],
    }


def avatar_dir(user_id: str = "default") -> Path:
    resolved_user_id = _normalize_user_id(user_id)
    base = DATA_DIR / "settings" / "profile"
    if resolved_user_id == "default":
        return base
    digest = hashlib.sha256(resolved_user_id.encode("utf-8")).hexdigest()[:32]
    return base / digest


def avatar_path(profile: dict[str, Any], user_id: str = "default") -> Path:
    file_name = Path(str(profile.get("avatar_file_name") or "")).name
    directory = avatar_dir(user_id)
    return directory / file_name if file_name else directory / "avatar"


def _settings_bucket(state: dict[str, Any]) -> dict[str, Any]:
    settings = state.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        state["settings"] = settings
    return settings


def _normalize_legal_document_id(document_id: str) -> str:
    clean_id = str(document_id or "").strip().lower()
    if clean_id not in LEGAL_DOCUMENT_IDS:
        raise KeyError(clean_id)
    return clean_id


def _merge_legal_document(default_document: dict[str, Any], stored_document: Any) -> dict[str, Any]:
    result = {
        "id": default_document["id"],
        "title": default_document["title"],
        "heading": default_document["heading"],
        "updated_at": default_document["updated_at"],
        "effective_at": default_document["effective_at"],
        "intro": default_document["intro"],
        "sections": list(default_document["sections"]),
        "revision_updated_at": "",
    }
    if not isinstance(stored_document, dict):
        return result
    for key in ("title", "heading", "updated_at", "effective_at", "intro", "revision_updated_at"):
        if isinstance(stored_document.get(key), str) and stored_document[key].strip():
            result[key] = stored_document[key].strip()
    sections = stored_document.get("sections")
    if isinstance(sections, list) and sections:
        cleaned_sections: list[dict[str, Any]] = []
        for section in sections:
            if not isinstance(section, dict):
                continue
            heading = str(section.get("heading") or "").strip()
            paragraphs = [str(item).strip() for item in section.get("paragraphs") or [] if str(item).strip()]
            if heading and paragraphs:
                cleaned_sections.append({"heading": heading, "paragraphs": paragraphs})
        if cleaned_sections:
            result["sections"] = cleaned_sections
    return result


def _remove_avatar_files(user_id: str = "default") -> None:
    for extension in SUPPORTED_AVATAR_EXTENSIONS:
        try:
            (avatar_dir(user_id) / f"avatar{extension}").unlink()
        except FileNotFoundError:
            pass


def _normalize_user_id(user_id: str) -> str:
    return str(user_id or "default").strip() or "default"


def _stored_profile(settings: dict[str, Any], user_id: str) -> dict[str, Any]:
    profiles = settings.get("profiles")
    if isinstance(profiles, dict) and isinstance(profiles.get(user_id), dict):
        return profiles[user_id]
    legacy = settings.get("profile")
    if not isinstance(legacy, dict):
        return {}
    legacy_email = str(legacy.get("email") or "").strip().casefold()
    if user_id == "default" or (legacy_email and legacy_email == user_id.casefold()):
        return legacy
    return {}


def _store_profile(settings: dict[str, Any], user_id: str, profile: dict[str, Any]) -> None:
    if user_id == "default":
        settings["profile"] = profile
        return
    profiles = settings.setdefault("profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}
        settings["profiles"] = profiles
    profiles[user_id] = profile


def _validate_avatar_magic(data: bytes, extension: str) -> None:
    if extension in {".jpg", ".jpeg"} and not data.startswith(b"\xff\xd8\xff"):
        raise ValueError("无法读取图片内容")
    if extension == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("无法读取图片内容")
    if extension == ".webp" and not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
        raise ValueError("无法读取图片内容")
