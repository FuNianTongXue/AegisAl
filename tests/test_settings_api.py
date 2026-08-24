from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.storage import StateStore


ONE_BY_ONE_PNG = base64.b64encode(
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\xf8\x0f\x00\x01\x01\x01\x00\x18\xdd\x8d\xb0"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
).decode("ascii")


class SettingsApiTests(unittest.TestCase):
    def test_profile_and_avatar_are_isolated_by_user_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            local_store = StateStore(root / "state.json")
            with (
                patch("app.settings.store", local_store),
                patch("app.settings.DATA_DIR", root),
            ):
                client = TestClient(app)
                saved_a = client.patch(
                    "/api/settings/profile",
                    params={"user_id": "alice@example.com"},
                    json={"display_name": "Alice", "email": "alice@example.com"},
                )
                avatar_a = client.post(
                    "/api/settings/profile/avatar",
                    params={"user_id": "alice@example.com"},
                    json={
                        "file_name": "avatar.png",
                        "content_base64": ONE_BY_ONE_PNG,
                        "content_type": "image/png",
                    },
                )
                profile_b = client.get(
                    "/api/settings/profile",
                    params={"user_id": "bob@example.com"},
                )
                avatar_b = client.get(
                    "/api/settings/profile/avatar",
                    params={"user_id": "bob@example.com"},
                )
                saved_b = client.patch(
                    "/api/settings/profile",
                    params={"user_id": "bob@example.com"},
                    json={"display_name": "Bob", "email": "bob@example.com"},
                )
                profile_a = client.get(
                    "/api/settings/profile",
                    params={"user_id": "alice@example.com"},
                )

        self.assertEqual(saved_a.status_code, 200)
        self.assertTrue(avatar_a.json()["data"]["avatar_available"])
        self.assertNotEqual(profile_b.json()["data"]["display_name"], "Alice")
        self.assertFalse(profile_b.json()["data"]["avatar_available"])
        self.assertEqual(avatar_b.status_code, 404)
        self.assertEqual(saved_b.json()["data"]["display_name"], "Bob")
        self.assertEqual(profile_a.json()["data"]["display_name"], "Alice")
        self.assertTrue(profile_a.json()["data"]["avatar_available"])

    def test_profile_preferences_and_avatar_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            local_store = StateStore(root / "state.json")
            with (
                patch("app.settings.store", local_store),
                patch("app.settings.DATA_DIR", root),
            ):
                client = TestClient(app)
                profile = client.get("/api/settings/profile")
                self.assertEqual(profile.status_code, 200)
                self.assertEqual(profile.json()["data"]["display_name"], "")

                updated = client.patch(
                    "/api/settings/profile",
                    json={
                        "display_name": "小安",
                        "email": "xiaoan@example.com",
                        "phone": "138 **** 6688",
                        "department": "安全运营",
                        "role": "安全专家",
                        "employee_id": "SEC-1",
                        "bio": "本机资料",
                    },
                )
                self.assertEqual(updated.status_code, 200)
                self.assertEqual(updated.json()["data"]["display_name"], "小安")

                preferences = client.patch(
                    "/api/settings/preferences",
                    json={
                        "language": "en",
                        "dark_mode": True,
                        "font_size": "large",
                        "launch_at_login": True,
                        "auto_check_updates": False,
                    },
                )
                self.assertEqual(preferences.status_code, 200)
                self.assertTrue(preferences.json()["data"]["dark_mode"])
                self.assertEqual(preferences.json()["data"]["font_size"], "large")
                self.assertEqual(preferences.json()["data"]["language"], "en")

                multilingual_preferences = client.patch(
                    "/api/settings/preferences",
                    json={
                        "language": "ru",
                        "dark_mode": False,
                        "font_size": "default",
                        "launch_at_login": False,
                        "auto_check_updates": True,
                    },
                )
                self.assertEqual(multilingual_preferences.status_code, 200)
                self.assertEqual(multilingual_preferences.json()["data"]["language"], "ru")

                traditional_preferences = client.patch(
                    "/api/settings/preferences",
                    json={
                        "language": "zh-Hant",
                        "dark_mode": False,
                        "font_size": "default",
                        "launch_at_login": False,
                        "auto_check_updates": True,
                    },
                )
                self.assertEqual(traditional_preferences.status_code, 200)
                self.assertEqual(traditional_preferences.json()["data"]["language"], "zh-Hant")

                invalid_preferences = client.patch(
                    "/api/settings/preferences",
                    json={
                        "language": "pt",
                        "dark_mode": False,
                        "font_size": "default",
                        "launch_at_login": False,
                        "auto_check_updates": True,
                    },
                )
                self.assertEqual(invalid_preferences.status_code, 422)

                legal = client.get("/api/settings/legal")
                self.assertEqual(legal.status_code, 200)
                self.assertEqual(legal.json()["data"]["terms"]["updated_at"], "2026年7月20日")
                self.assertEqual(legal.json()["data"]["privacy"]["effective_at"], "2026年7月20日")
                settings_snapshot = client.get("/api/settings")
                self.assertEqual(settings_snapshot.status_code, 200)
                self.assertEqual(settings_snapshot.json()["data"]["about"]["version"], app.version)
                self.assertEqual(settings_snapshot.json()["data"]["about"]["release_channel"], "内测版")
                self.assertEqual(settings_snapshot.json()["data"]["about"]["version_label"], f"v{app.version} 内测版")
                self.assertEqual(settings_snapshot.json()["data"]["about"]["logo"]["style"], "rounded-square-shield-star")

                terms = client.get("/api/settings/legal/terms")
                self.assertEqual(terms.status_code, 200)
                self.assertEqual(terms.json()["data"]["heading"], "神盾服务协议")

                updated_terms = client.patch(
                    "/api/settings/legal/terms",
                    json={
                        "updated_at": "2026年7月20日",
                        "effective_at": "2026年7月20日",
                        "intro": "测试更新服务协议。",
                        "sections": [
                            {
                                "heading": "一、测试章节",
                                "paragraphs": ["后续可通过后端接口更新协议内容。"],
                            }
                        ],
                    },
                )
                self.assertEqual(updated_terms.status_code, 200)
                self.assertEqual(updated_terms.json()["data"]["intro"], "测试更新服务协议。")
                self.assertEqual(updated_terms.json()["data"]["sections"][0]["heading"], "一、测试章节")
                self.assertEqual(client.get("/api/settings/legal/unknown").status_code, 404)

                avatar = client.post(
                    "/api/settings/profile/avatar",
                    json={
                        "file_name": "avatar.png",
                        "content_base64": ONE_BY_ONE_PNG,
                        "content_type": "image/png",
                    },
                )
                self.assertEqual(avatar.status_code, 200)
                self.assertTrue(avatar.json()["data"]["avatar_available"])
                self.assertEqual(client.get("/api/settings/profile/avatar").status_code, 200)

                removed = client.delete("/api/settings/profile/avatar")
                self.assertEqual(removed.status_code, 200)
                self.assertFalse(removed.json()["data"]["avatar_available"])
                self.assertEqual(client.get("/api/settings/profile/avatar").status_code, 404)

    def test_avatar_upload_rejects_unsupported_file_type(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            local_store = StateStore(root / "state.json")
            with (
                patch("app.settings.store", local_store),
                patch("app.settings.DATA_DIR", root),
            ):
                client = TestClient(app)
                response = client.post(
                    "/api/settings/profile/avatar",
                    json={
                        "file_name": "avatar.gif",
                        "content_base64": ONE_BY_ONE_PNG,
                        "content_type": "image/gif",
                    },
                )
                self.assertEqual(response.status_code, 422)
                self.assertIn("仅支持", response.text)


if __name__ == "__main__":
    unittest.main()
