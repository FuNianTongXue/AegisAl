from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
import urllib.request
import zipfile
from pathlib import Path


ARCHIVE_URL = "https://argos-net.com/v1/translate-en_zh-1_9.argosmodel"
ARCHIVE_SHA256 = "433e7c4f034d87fbe2353161e05f18646d7999452f801a4e1f0378522b9850ab"
MODEL_MEMBER = "translate-en_zh-1_9/model/model.bin"
MODEL_SHA256 = "1a039114d9456b6528fabb65b455b6f156319634a0f984b1f6018f7737d67598"
MODEL_SIZE = 82_713_318


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_model(path: Path) -> bool:
    return path.is_file() and path.stat().st_size == MODEL_SIZE and _sha256(path) == MODEL_SHA256


def fetch_model(target: Path) -> Path:
    target = target.expanduser().resolve(strict=False)
    if _valid_model(target):
        print(f"offline translation model already verified: {target}")
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secflow-translation-model-") as temp_dir:
        archive = Path(temp_dir) / "translate-en_zh-1_9.argosmodel"
        request = urllib.request.Request(
            ARCHIVE_URL,
            headers={"User-Agent": "SecFlow-translation-model-fetch/1.0"},
        )
        with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        if _sha256(archive) != ARCHIVE_SHA256:
            raise RuntimeError("offline translation archive SHA-256 mismatch")

        with zipfile.ZipFile(archive) as package:
            info = package.getinfo(MODEL_MEMBER)
            if info.file_size != MODEL_SIZE:
                raise RuntimeError("offline translation model size mismatch")
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=".model.bin.",
                dir=target.parent,
            )
            os.close(file_descriptor)
            temporary = Path(temporary_name)
            try:
                with package.open(info) as source, temporary.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                if not _valid_model(temporary):
                    raise RuntimeError("offline translation model SHA-256 mismatch")
                temporary.chmod(0o644)
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)

    print(f"offline translation model fetched and verified: {target}")
    return target


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    default_target = (
        root
        / "app"
        / "resources"
        / "translation-models"
        / "opus-mt-en-zh-1.9"
        / "model"
        / "model.bin"
    )
    parser = argparse.ArgumentParser(
        description="Fetch the pinned SecFlow offline translation model.",
    )
    parser.add_argument("--target", type=Path, default=default_target)
    args = parser.parse_args()
    fetch_model(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
