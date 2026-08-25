from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from app.packaged_edition import PackagedEditionError, apply_packaged_edition_defaults


SOURCE_FIELDS = {
    "source_revision": "0794f79b58900bf34a5a08ea0802edf27108c2fe",
    "source_dirty_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


class PackagedEditionTests(unittest.TestCase):
    def test_trial_manifest_overrides_inherited_runtime_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "aegisal-edition.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "edition": "trial",
                        "app_version": "1.3.4",
                        "release_channel": "14天试用版",
                        "backend_port": 18784,
                        "trial_duration_hours": 336,
                        "keychain_service": "ai.secflow.security-agent.trial14days",
                        **SOURCE_FIELDS,
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "SECFLOW_TRIAL_ENABLED": "0",
                    "SECFLOW_TRIAL_DURATION_HOURS": "1",
                    "SECFLOW_KEYCHAIN_SERVICE": "untrusted",
                    "SECFLOW_SECURITY_CLI": "/tmp/untrusted-security",
                    "SECFLOW_STORAGE_MASTER_KEY": "known-key",
                    "SECFLOW_STORAGE_KEY_FILE": "/tmp/untrusted-key",
                    "SECFLOW_KEYCHAIN_PATH": "/tmp/untrusted.keychain-db",
                    "SECFLOW_DISABLE_KEYCHAIN": "1",
                    "SECFLOW_DISABLE_DPAPI": "1",
                    "SECFLOW_TRIAL_REGISTRY_KEY": "Software\\Untrusted",
                    "SECFLOW_TRIAL_REGISTRY_VALUE": "UntrustedTrial",
                },
                clear=False,
            ):
                with patch.object(sys, "platform", "darwin"):
                    edition = apply_packaged_edition_defaults(path, required=True)

                self.assertIsNotNone(edition)
                self.assertTrue(edition.trial_enabled)
                self.assertEqual(os.environ["SECFLOW_TRIAL_ENABLED"], "1")
                self.assertEqual(os.environ["SECFLOW_TRIAL_DURATION_HOURS"], "336")
                self.assertEqual(
                    os.environ["SECFLOW_KEYCHAIN_SERVICE"],
                    "ai.secflow.security-agent.trial14days",
                )
                self.assertEqual(os.environ["SECFLOW_SECURITY_CLI"], "/usr/bin/security")
                for variable in (
                    "SECFLOW_STORAGE_MASTER_KEY",
                    "SECFLOW_STORAGE_KEY_FILE",
                    "SECFLOW_KEYCHAIN_PATH",
                    "SECFLOW_DISABLE_KEYCHAIN",
                    "SECFLOW_DISABLE_DPAPI",
                    "SECFLOW_TRIAL_REGISTRY_KEY",
                    "SECFLOW_TRIAL_REGISTRY_VALUE",
                ):
                    self.assertNotIn(variable, os.environ)

    def test_required_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(PackagedEditionError):
                apply_packaged_edition_defaults(
                    Path(temp_dir) / "missing-edition.json",
                    required=True,
                )

    def test_frozen_executable_rejects_a_modified_external_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "aegisal-edition.json"
            payload = {
                "schema_version": 1,
                "edition": "trial",
                "app_version": "1.3.4",
                "release_channel": "14天试用版",
                "backend_port": 18784,
                "trial_duration_hours": 336,
                "keychain_service": "ai.secflow.security-agent.trial14days",
                **SOURCE_FIELDS,
            }
            path.write_text(json.dumps({**payload, "edition": "formal"}), encoding="utf-8")
            embedded = types.ModuleType("_aegisal_frozen_edition")
            embedded.PAYLOAD = payload
            with (
                patch.object(sys, "frozen", True, create=True),
                patch.dict(sys.modules, {"_aegisal_frozen_edition": embedded}),
            ):
                with self.assertRaises(PackagedEditionError):
                    apply_packaged_edition_defaults(path, required=True)

    def test_frozen_executable_requires_embedded_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "aegisal-edition.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "edition": "trial",
                        "app_version": "1.3.4",
                        "release_channel": "14天试用版",
                        "backend_port": 18784,
                        "trial_duration_hours": 336,
                        "keychain_service": "ai.secflow.security-agent.trial14days",
                        **SOURCE_FIELDS,
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch.object(sys, "frozen", True, create=True),
                patch.dict(sys.modules, {}, clear=False),
            ):
                sys.modules.pop("_aegisal_frozen_edition", None)
                with self.assertRaises(PackagedEditionError):
                    apply_packaged_edition_defaults(path, required=True)

    def test_formal_manifest_clears_inherited_trial_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "aegisal-edition.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "edition": "formal",
                        "app_version": "1.3.4",
                        "release_channel": "正式版",
                        "backend_port": 18781,
                        "trial_duration_hours": None,
                        "keychain_service": "ai.secflow.security-agent",
                        **SOURCE_FIELDS,
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"SECFLOW_TRIAL_ENABLED": "1", "SECFLOW_TRIAL_DURATION_HOURS": "336"},
                clear=False,
            ):
                edition = apply_packaged_edition_defaults(path, required=True)

                self.assertIsNotNone(edition)
                self.assertFalse(edition.trial_enabled)
                self.assertEqual(os.environ["SECFLOW_TRIAL_ENABLED"], "0")
                self.assertNotIn("SECFLOW_TRIAL_DURATION_HOURS", os.environ)

    def test_frozen_executable_rejects_modified_source_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "aegisal-edition.json"
            payload = {
                "schema_version": 1,
                "edition": "trial",
                "app_version": "1.3.4",
                "release_channel": "14天试用版",
                "backend_port": 18784,
                "trial_duration_hours": 336,
                "keychain_service": "ai.secflow.security-agent.trial14days",
                **SOURCE_FIELDS,
            }
            path.write_text(
                json.dumps({**payload, "source_revision": "tampered"}),
                encoding="utf-8",
            )
            embedded = types.ModuleType("_aegisal_frozen_edition")
            embedded.PAYLOAD = payload
            with (
                patch.object(sys, "frozen", True, create=True),
                patch.dict(sys.modules, {"_aegisal_frozen_edition": embedded}),
            ):
                with self.assertRaises(PackagedEditionError):
                    apply_packaged_edition_defaults(path, required=True)


if __name__ == "__main__":
    unittest.main()
