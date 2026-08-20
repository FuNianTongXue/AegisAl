from __future__ import annotations

import hashlib
import base64
import html
import io
import json
import os
import re
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text
from app.storage import DATA_DIR, now_iso


REPORT_INDEX_PURPOSE = "secflow-report-index"
REPORT_ARTIFACT_INDEX_PURPOSE = "secflow-report-artifact-index"
_ENGINE_NAME_PATTERN = re.compile(r"CodeQL|Semgrep", flags=re.IGNORECASE)
_REPORT_STYLE_MARKER = "<!-- secflow-report-style:v2 -->"
_REPORT_FORMATS = {"md", "html", "pdf", "docx", "xlsx"}
_SCAN_RESULT_JSON_SCHEMA = "secflow.scan-results/v1"
_REPORT_DOCUMENT_JSON_SCHEMA = "secflow.report-document/v1"
REPORT_DOCUMENT_SCHEMA_VERSION = 5
_REPORT_DOCUMENT_SCHEMA_VERSION = REPORT_DOCUMENT_SCHEMA_VERSION
_REPORT_FILE_PREVIEW_LIMIT = 8
_REPORT_DEPENDENCY_PREVIEW_LIMIT = 10
_REPORT_RECORD_LIMIT = 30
_REPORT_FINDING_LIMIT = 30
_REPORT_MEDIA_TYPES = {
    "md": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
_REPORT_WEB_FONT_FAMILY = (
    '"SF Pro Text", "PingFang SC", "Apple Color Emoji", '
    '-apple-system, BlinkMacSystemFont, "Microsoft YaHei", "Segoe UI", sans-serif'
)
_CHINA_STANDARD_TIME = timezone(timedelta(hours=8), name="UTC+08:00")
_DEPRECATED_REPORT_SECTIONS = {
    "扫描文件与规则",
    "掃描檔案與規則",
    "Scan files and rules",
    "Scanned files and rules",
}


class ReportDownloadArtifactStore:
    def __init__(self, root: Path | None = None, *, retain: int = 100) -> None:
        self.root = root or (DATA_DIR / "report_artifacts")
        self.index_path = self.root / "index.json"
        self.retain = max(10, min(int(retain), 500))
        self._lock = RLock()

    def save(self, content: bytes, *, file_name: str, media_type: str, user_id: str) -> dict[str, Any]:
        digest = hashlib.sha256(content).hexdigest()
        owner = str(user_id or "").strip()
        if not owner:
            raise ValueError("Artifact owner user_id is required")
        artifact_id = f"report-artifact-{uuid4().hex}"
        safe_name = Path(str(file_name or "SecFlow-report.bin")).name
        suffix = Path(safe_name).suffix.lower() or ".bin"
        path = self.root / f"{artifact_id}{suffix}"
        generated_at = now_iso()
        item = {
            "id": artifact_id,
            "kind": "report",
            "file_name": safe_name,
            "media_type": media_type,
            "download_path": f"/api/assistant/artifacts/{artifact_id}?{urlencode({'user_id': owner})}",
            "sha256": digest,
            "size": len(content),
            "generated_at": generated_at,
            "user_id": owner,
            "storage_name": path.name,
        }
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
            index = self._read_index()
            index.append(item)
            self._write_index(index)
        return {key: value for key, value in item.items() if key not in {"user_id", "storage_name"}}

    def resolve(self, artifact_id: str, *, user_id: str = "default") -> tuple[Path, str, str]:
        clean_id = str(artifact_id or "").strip()
        if not re.fullmatch(r"report-artifact-[a-f0-9]{32}", clean_id):
            raise KeyError(artifact_id)
        owner = str(user_id or "").strip()
        with self._lock:
            item = next(
                (
                    entry
                    for entry in self._read_index()
                    if entry.get("id") == clean_id and entry.get("user_id") == owner
                ),
                None,
            )
            if not item:
                raise KeyError(artifact_id)
            path = self.root / Path(str(item.get("storage_name") or "")).name
            if (
                not path.is_file()
                or path.is_symlink()
                or path.parent.resolve() != self.root.resolve()
                or path.stat().st_nlink != 1
            ):
                raise KeyError(artifact_id)
        return path, Path(str(item.get("file_name") or path.name)).name, str(item.get("media_type") or "application/octet-stream")

    def _read_index(self) -> list[dict[str, Any]]:
        if not self.index_path.is_file():
            return []
        try:
            decoded = decrypt_json_from_text(self.index_path.read_text(encoding="utf-8"), REPORT_ARTIFACT_INDEX_PURPOSE)
            return [item for item in decoded if isinstance(item, dict)] if isinstance(decoded, list) else []
        except Exception:  # noqa: BLE001
            return []

    def _write_index(self, index: list[dict[str, Any]]) -> None:
        temporary = self.index_path.with_suffix(".tmp")
        temporary.write_text(encrypt_json_to_text(index, REPORT_ARTIFACT_INDEX_PURPOSE), encoding="utf-8")
        os.replace(temporary, self.index_path)


def _normalize_report_language(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    if text in {"zh-hant", "zh-tw", "zh-hk", "zhtw", "zhhant", "traditional-chinese"}:
        return "zh-Hant"
    if text in {"en", "en-us", "english"}:
        return "en"
    if text in {"ko", "ko-kr", "kr", "korean"}:
        return "ko"
    if text in {"ja", "ja-jp", "jp", "japanese"}:
        return "ja"
    if text in {"es", "es-es", "spanish", "español"}:
        return "es"
    if text in {"fr", "fr-fr", "french", "français"}:
        return "fr"
    if text in {"de", "de-de", "german", "deutsch"}:
        return "de"
    if text in {"it", "it-it", "italian", "italiano"}:
        return "it"
    if text in {"ru", "ru-ru", "russian", "русский"}:
        return "ru"
    return "zh-Hans"


def _report_china_time(value: Any) -> str:
    text = str(value or "").strip()
    if not text or text == "-":
        return "-"
    already_local = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2})[ T](\d{2}):(\d{2})(?::\d{2}(?:\.\d+)?)?(?:\s*UTC\+08:00|\+08:00)?",
        text,
    )
    if already_local and ("T" not in text or text.endswith(("UTC+08:00", "+08:00"))):
        return f"{already_local.group(1)} {already_local.group(2)}:{already_local.group(3)}"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(_CHINA_STANDARD_TIME).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return text


_REPORT_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "title": "Dependency and code vulnerability analysis report",
        "generated_at": "Generated at",
        "question": "User question",
        "attachment_analysis": "Attachment security analysis",
        "attachments": "Attachments",
        "dependencies": "Identified dependencies",
        "dependency_vulnerabilities": "Dependency vulnerabilities",
        "code_findings": "Code findings",
        "execution": "Execution flow",
        "step1": "Read pom.xml, Gradle build files, and code attachments, then extract dependencies and code files.",
        "step2": "Query and verify dependency vulnerabilities by component and version.",
        "step3": "Locate code findings, exact line numbers, and input propagation paths in uploaded source code.",
        "step4": "Summarize dependency fixed versions plus code risk snippets and fixed code.",
        "step5": "Summarize risks, remediation guidance, and reference links.",
        "step6": "Generate the complete Markdown report and write it to Reports.",
        "files_section": "Attachments and dependencies",
        "no_files": "No valid attachments were identified.",
        "detected_dependencies": "Detected dependencies",
        "unknown": "unknown",
        "unknown_file": "unknown file",
        "not_specified": "Not specified",
        "confidence": "confidence",
        "no_dependencies": "No dependencies usable for vulnerability matching were parsed from attachments.",
        "dependency_section": "Dependency vulnerabilities (components and versions)",
        "no_dependency_hits": "No vulnerabilities were confirmed from explicit component versions.",
        "unresolved": "%d dependencies have unspecified versions and were not counted as hits; this does not prove the project is safe.",
        "code_section": "Code findings (files, lines, and fixed code)",
        "no_code_hits": "Uploaded source code was analyzed, but no high-confidence code finding was confirmed.",
        "no_code_scope": "No analyzable source code was uploaded; add the corresponding business code and analyze again.",
        "runtime": "Runtime summary",
        "conclusion": "Conclusion summary",
        "no_summary": "No summary.",
        "vuln_name": "Vulnerability name",
        "severity": "Severity",
        "description": "Description",
        "component_range": "Component version range",
        "fixed_version": "Fixed version",
        "references": "References",
        "risk_type": "Risk type",
        "related_vulnerability": "Related dependency vulnerability",
        "related_component": "Related component",
        "risk_location": "Risk location",
        "code_range": "Code range",
        "remediation": "Remediation",
        "priority": "Priority",
        "security_context": "Security context",
        "triage_note": "Analysis note",
        "input_location": "Input location",
        "merged_sinks": "Merged money update points",
        "related_findings": "Related sub-findings",
        "vulnerable_snippet": "Vulnerable code snippet (lines %s, risk line %s):",
        "fixed_code": "Fixed code:",
        "path": "Full Source→Sink path:",
        "no_path": "No path returned.",
        "line": "line %s",
        "static_finding": "Static analysis finding",
        "static_risk": "Static code risk",
        "default_remediation": "Validate external input and constrain dangerous calls.",
        "no_snippet": "No code snippet returned",
        "no_fixed": "No verifiable fixed code generated",
    },
    "ja": {
        "title": "依存関係脆弱性とコード脆弱性の分析レポート",
        "generated_at": "生成時間",
        "question": "ユーザー質問",
        "attachment_analysis": "添付ファイルのセキュリティ分析",
        "attachments": "添付数",
        "dependencies": "識別した依存関係",
        "dependency_vulnerabilities": "依存関係脆弱性",
        "code_findings": "コード脆弱性",
        "execution": "実行チェーン",
        "step1": "pom.xml、Gradle ビルドファイル、コード添付を読み取り、依存関係とコードファイルを抽出します。",
        "step2": "コンポーネントとバージョンに基づいて依存関係脆弱性を照会・検証します。",
        "step3": "アップロードされたソースコード内でコード脆弱性、正確な行番号、入力伝播パスを特定します。",
        "step4": "依存関係の修正バージョン、コードのリスク片、修正コードをそれぞれ整理します。",
        "step5": "リスク、修正提案、参考リンクをまとめます。",
        "step6": "完全な Markdown レポートを生成し、レポートセンターに書き込みます。",
        "files_section": "添付ファイルと依存関係",
        "no_files": "有効な添付ファイルは識別されませんでした。",
        "detected_dependencies": "識別された依存関係",
        "unknown": "unknown",
        "unknown_file": "不明なファイル",
        "not_specified": "未指定",
        "confidence": "信頼度",
        "no_dependencies": "添付ファイルから脆弱性照合に使える依存関係を解析できませんでした。",
        "dependency_section": "依存関係脆弱性（コンポーネントとバージョン）",
        "no_dependency_hits": "明確なコンポーネントバージョンから確認できた脆弱性はありません。",
        "unresolved": "%d 個の依存関係はバージョン未指定のため命中に含めていません。これは安全性の証明ではありません。",
        "code_section": "コード脆弱性（ファイル、行番号、修正コード）",
        "no_code_hits": "アップロードされたソースコードを分析しましたが、高信頼度のコード脆弱性位置は確認されませんでした。",
        "no_code_scope": "分析可能なソースコードはアップロードされていません。対応する業務コードを追加して再分析してください。",
        "runtime": "実行概要",
        "conclusion": "結論概要",
        "no_summary": "概要なし。",
        "vuln_name": "脆弱性名",
        "severity": "深刻度",
        "description": "説明",
        "component_range": "コンポーネントバージョン範囲",
        "fixed_version": "修正バージョン",
        "references": "参考リンク",
        "risk_type": "リスクタイプ",
        "related_vulnerability": "関連する依存関係脆弱性",
        "related_component": "関連コンポーネント",
        "risk_location": "リスク位置",
        "code_range": "コード範囲",
        "remediation": "修正提案",
        "priority": "優先度",
        "security_context": "セキュリティコンテキスト",
        "triage_note": "分析メモ",
        "input_location": "入力位置",
        "merged_sinks": "統合された資金更新点",
        "related_findings": "関連サブリスク",
        "vulnerable_snippet": "脆弱なコード片（%s 行、リスク行 %s）：",
        "fixed_code": "修正後コード：",
        "path": "完全な Source→Sink パス：",
        "no_path": "パスは返されませんでした。",
        "line": "第 %s 行",
        "static_finding": "静的分析の検出",
        "static_risk": "静的コードリスク",
        "default_remediation": "外部入力を検証し、危険な呼び出しを制限してください。",
        "no_snippet": "コード片は返されませんでした",
        "no_fixed": "検証可能な修正コードは生成されませんでした",
    },
    "ko": {
        "title": "의존성 취약점 및 코드 취약점 분석 보고서",
        "generated_at": "생성 시간",
        "question": "사용자 질문",
        "attachment_analysis": "첨부 파일 보안 분석",
        "attachments": "첨부 수",
        "dependencies": "식별한 의존성",
        "dependency_vulnerabilities": "의존성 취약점",
        "code_findings": "코드 취약점",
        "execution": "실행 흐름",
        "step1": "pom.xml, Gradle 빌드 파일, 코드 첨부를 읽어 의존성과 코드 파일을 추출합니다.",
        "step2": "컴포넌트와 버전을 기준으로 의존성 취약점을 조회하고 검증합니다.",
        "step3": "업로드된 소스코드에서 코드 취약점, 정확한 줄 번호, 입력 전파 경로를 찾습니다.",
        "step4": "의존성 수정 버전과 코드 위험 조각 및 수정 코드를 각각 요약합니다.",
        "step5": "위험, 수정 제안, 참고 링크를 요약합니다.",
        "step6": "완전한 Markdown 보고서를 생성해 보고서 센터에 기록합니다.",
        "files_section": "첨부 파일 및 의존성",
        "no_files": "유효한 첨부 파일을 식별하지 못했습니다.",
        "detected_dependencies": "식별된 의존성",
        "unknown": "unknown",
        "unknown_file": "알 수 없는 파일",
        "not_specified": "명확하지 않음",
        "confidence": "신뢰도",
        "no_dependencies": "첨부 파일에서 취약점 매칭에 사용할 수 있는 의존성을 파싱하지 못했습니다.",
        "dependency_section": "의존성 취약점(컴포넌트 및 버전)",
        "no_dependency_hits": "명확한 컴포넌트 버전으로 확인된 취약점은 없습니다.",
        "unresolved": "%d개 의존성은 버전이 명확하지 않아 명중에 포함하지 않았습니다. 이는 안전함을 증명하지 않습니다.",
        "code_section": "코드 취약점(파일, 줄 번호 및 수정 코드)",
        "no_code_hits": "업로드한 소스코드를 분석했지만 신뢰도 높은 코드 취약점 위치는 확인되지 않았습니다.",
        "no_code_scope": "분석 가능한 소스코드가 업로드되지 않았습니다. 해당 업무 코드를 추가해 다시 분석하세요.",
        "runtime": "실행 요약",
        "conclusion": "결론 요약",
        "no_summary": "요약 없음.",
        "vuln_name": "취약점 이름",
        "severity": "심각도",
        "description": "설명",
        "component_range": "컴포넌트 버전 범위",
        "fixed_version": "수정 버전",
        "references": "참고 링크",
        "risk_type": "위험 유형",
        "related_vulnerability": "관련 의존성 취약점",
        "related_component": "관련 컴포넌트",
        "risk_location": "위험 위치",
        "code_range": "코드 범위",
        "remediation": "수정 제안",
        "priority": "우선순위",
        "security_context": "보안 컨텍스트",
        "triage_note": "분석 메모",
        "input_location": "입력 위치",
        "merged_sinks": "병합된 자금 업데이트 지점",
        "related_findings": "관련 하위 위험",
        "vulnerable_snippet": "취약한 코드 조각(%s줄, 위험 줄 %s):",
        "fixed_code": "수정 코드:",
        "path": "전체 Source→Sink 경로:",
        "no_path": "경로가 반환되지 않았습니다.",
        "line": "%s행",
        "static_finding": "정적 분석 발견",
        "static_risk": "정적 코드 위험",
        "default_remediation": "외부 입력을 검증하고 위험한 호출을 제한하세요.",
        "no_snippet": "코드 조각이 반환되지 않았습니다",
        "no_fixed": "검증 가능한 수정 코드가 생성되지 않았습니다",
    },
}


def _rt(language: str, key: str) -> str:
    language = _normalize_report_language(language)
    if language in {"zh-Hans", "zh-Hant"}:
        return key
    return _REPORT_TEXT.get(language, _REPORT_TEXT["en"]).get(key, _REPORT_TEXT["en"].get(key, key))


_DEPENDENCY_FILE_KINDS = {
    "pom",
    "gradle",
    "gradle_version_catalog",
    "gradle_properties",
    "package_json",
    "package-lock",
    "yarn_lock",
    "pnpm_lock",
    "requirements",
    "pipfile",
    "poetry",
    "go_mod",
    "cargo",
    "composer",
}
_CODE_FILE_KINDS = {"code", "source", "java", "kotlin", "python", "javascript", "typescript", "go", "rust", "php", "ruby", "swift"}


def _append_section_heading(lines: list[str], index: int, title: str) -> int:
    lines.extend(["", f"## {index}. {title}", ""])
    return index + 1


def _report_section_title(language: str, key: str) -> str:
    normalized = _normalize_report_language(language)
    titles = {
        "zh-Hans": {"summary": "执行摘要", "method": "方法与限制"},
        "zh-Hant": {"summary": "執行摘要", "method": "方法與限制"},
        "en": {"summary": "Executive summary", "method": "Method and limitations"},
        "ja": {"summary": "エグゼクティブサマリー", "method": "分析方法と制限"},
        "ko": {"summary": "요약", "method": "분석 방법 및 제한 사항"},
    }
    return titles.get(normalized, titles["en"])[key]


def _report_limitation(language: str) -> str:
    normalized = _normalize_report_language(language)
    values = {
        "zh-Hans": "限制：报告基于上传内容、可用漏洞情报和静态分析，未做动态利用验证；未命中不代表无风险。",
        "zh-Hant": "限制：報告依據上傳內容、可用漏洞情報和靜態分析，未做動態利用驗證；未命中不代表無風險。",
        "en": "Limitation: this report uses only the uploaded content, available vulnerability intelligence, and static path analysis. No dynamic exploit validation was performed, and a non-hit does not prove safety.",
        "ja": "制限：本レポートはアップロード内容、利用可能な脆弱性情報、静的パス解析のみに基づきます。動的な悪用検証は実施しておらず、未検出は安全性を証明しません。",
        "ko": "제한 사항: 이 보고서는 업로드한 내용, 사용 가능한 취약점 정보와 정적 경로 분석만을 기반으로 합니다. 동적 악용 검증은 수행하지 않았으며 미탐지는 안전함을 증명하지 않습니다.",
    }
    return values.get(normalized, values["en"])


def _has_dependency_scope(files: list[dict[str, Any]], dependencies: list[dict[str, Any]], records: list[dict[str, Any]]) -> bool:
    return bool(
        dependencies
        or records
        or any(str(item.get("kind") or "").strip().lower() in _DEPENDENCY_FILE_KINDS for item in files if isinstance(item, dict))
    )


def _has_code_scope(files: list[dict[str, Any]], static_analysis: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
    try:
        finding_count = int(static_analysis.get("finding_count") or 0)
    except (TypeError, ValueError):
        finding_count = 0
    return bool(
        findings
        or finding_count
        or static_analysis.get("files")
        or any(str(item.get("kind") or "").strip().lower() in _CODE_FILE_KINDS for item in files if isinstance(item, dict))
    )


def build_report_metrics(
    *,
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    language: str = "zh-Hans",
    generated_at: str | None = None,
) -> dict[str, Any]:
    files = [item for item in dependency_scan.get("files") or [] if isinstance(item, dict)]
    dependencies = [item for item in dependency_scan.get("dependencies") or [] if isinstance(item, dict)]
    findings = [item for item in static_analysis.get("findings") or [] if isinstance(item, dict)]
    license_scan = dependency_scan.get("license_scan") if isinstance(dependency_scan.get("license_scan"), dict) else {}
    try:
        finding_count = int(static_analysis.get("finding_count") or len(findings))
    except (TypeError, ValueError):
        finding_count = len(findings)
    severity = _structured_severity_distribution(records, findings)
    return {
        "generated_at": _report_china_time(generated_at or now_iso()),
        "language": _normalize_report_language(language),
        "attachments": len(files),
        "dependencies": len(dependencies),
        "licenses": len([item for item in license_scan.get("licenses") or [] if isinstance(item, dict)]),
        "unresolved_dependencies": sum(1 for dependency in dependencies if not dependency.get("version")),
        "dependency_vulnerabilities": len(records),
        "code_findings": max(finding_count, len(findings)),
        "severity": severity,
        "high_risk": severity["CRITICAL"] + severity["HIGH"],
        "medium_risk": severity["MEDIUM"],
        "total_risks": len(records) + max(finding_count, len(findings)),
        "has_dependency_scope": _has_dependency_scope(files, dependencies, records),
        "has_code_scope": _has_code_scope(files, static_analysis, findings),
    }


def _structured_severity_distribution(
    records: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, int]:
    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in [*records, *findings]:
        if not isinstance(item, dict):
            continue
        key = _normalize_report_severity(item.get("severity"))
        if not key:
            key = {"P0": "CRITICAL", "P1": "HIGH", "P2": "MEDIUM", "P3": "LOW"}.get(
                str(item.get("priority") or "").strip().upper(), ""
            )
        if key:
            severity[key] += 1
    return severity


def _normalize_report_severity(value: Any) -> str:
    normalized = str(value or "").strip().upper()
    aliases = {
        "CRITICAL": "CRITICAL",
        "SEVERE": "CRITICAL",
        "严重": "CRITICAL",
        "危急": "CRITICAL",
        "HIGH": "HIGH",
        "高危": "HIGH",
        "高": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "中危": "MEDIUM",
        "中": "MEDIUM",
        "LOW": "LOW",
        "低危": "LOW",
        "低": "LOW",
    }
    return aliases.get(normalized, "")


def _report_severity_zh(value: Any) -> str:
    return _report_severity_label(value, "zh-Hans")


def _report_severity_label(value: Any, language: str) -> str:
    """Localize a severity for customer-visible report content.

    Canonical severity values stay unchanged in scan JSON, SARIF, and chart
    inputs; only the rendered label is localized. This keeps downstream risk
    calculations deterministic and avoids another translation-model call.
    """

    normalized_language = _normalize_report_language(language)
    severity = _normalize_report_severity(value)
    if severity:
        return _report_severity_labels(normalized_language)[severity]
    return {
        "zh-Hans": "未知",
        "zh-Hant": "未知",
        "ja": "不明",
        "ko": "알 수 없음",
        "es": "Desconocida",
        "fr": "Inconnue",
        "de": "Unbekannt",
        "it": "Sconosciuta",
        "ru": "Неизвестно",
        "en": "Unknown",
    }.get(normalized_language, "Unknown")


def _report_finding_remediation(
    finding: dict[str, Any],
    language: str = "zh-Hans",
) -> str:
    for key in ("remediation", "recommendation", "fix", "fix_recommendation"):
        value = _report_plain_text(finding.get(key) or "")
        if value and value != "-":
            return value
    normalized_language = _normalize_report_language(language)
    if normalized_language == "en":
        if finding.get("fixed_snippet"):
            return (
                "Replace the risky call with the fixed code below, then add security regression tests "
                "for input boundaries, error paths, and affected business flows."
            )
        return (
            "Constrain the dangerous call or unsafe configuration described by the finding and prefer "
            "a project-validated safe API or setting. Add unit, integration, and security regression "
            "tests for the affected location, then verify that the complete Source-to-Sink path is blocked."
        )
    if normalized_language == "zh-Hant":
        if finding.get("fixed_snippet"):
            return "依照下方修復程式碼替換風險呼叫，並補充涵蓋輸入邊界、異常路徑與業務流程的安全迴歸測試。"
        return (
            "根據風險說明收斂對應危險呼叫或不安全設定，優先採用專案已驗證的安全 API 或設定；"
            "補充涵蓋該風險位置的單元測試、整合測試與安全迴歸，並複核 Source→Sink 路徑已被阻斷。"
        )
    if finding.get("fixed_snippet"):
        return "按下方修复代码替换风险调用，并补充覆盖输入边界、异常路径和业务流程的安全回归测试。"
    return (
        "根据风险说明收敛对应危险调用或不安全配置，优先采用项目已验证的安全 API 或配置；"
        "补充覆盖该风险位置的单元测试、集成测试和安全回归，并复核 Source→Sink 路径已被阻断。"
    )


def _has_uploaded_code(files: list[dict[str, Any]], static_analysis: dict[str, Any] | None = None) -> bool:
    if any(str(item.get("kind") or "").strip().lower() in _CODE_FILE_KINDS for item in files if isinstance(item, dict)):
        return True
    if static_analysis:
        return bool(static_analysis.get("files"))
    return False


def _no_code_findings_message(files: list[dict[str, Any]], static_analysis: dict[str, Any], language: str) -> str:
    if _has_uploaded_code(files, static_analysis):
        if _normalize_report_language(language) in {"zh-Hans", "zh-Hant"}:
            return "已对上传源码执行静态路径分析，未确认高置信代码漏洞位置。"
        return _rt(language, "no_code_hits")
    if _normalize_report_language(language) in {"zh-Hans", "zh-Hant"}:
        return "未上传可分析源码，未确认具体漏洞位置；建议补充对应业务代码后重新分析。"
    return _rt(language, "no_code_scope")


def _actual_execution_steps(
    *,
    files: list[dict[str, Any]],
    dependencies: list[dict[str, Any]],
    records: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    unresolved_dependencies: list[dict[str, Any]],
    fields: dict[str, Any] | None,
    language: str,
) -> list[str]:
    if _normalize_report_language(language) in {"zh-Hans", "zh-Hant"}:
        steps: list[str] = []
        if files:
            steps.append(f"读取用户上传的 {len(files)} 个文件，并按文件类型提取可分析内容。")
        else:
            steps.append("未识别到有效上传文件，仅基于当前返回的扫描事实生成报告。")
        if dependencies:
            steps.append(f"解析依赖清单，识别 {len(dependencies)} 个依赖坐标。")
            if records:
                steps.append(f"按明确组件版本核验依赖漏洞，确认 {len(records)} 条命中。")
            else:
                steps.append("按明确组件版本完成依赖漏洞核验，未确认依赖漏洞命中。")
        elif unresolved_dependencies:
            steps.append(f"发现 {len(unresolved_dependencies)} 个依赖版本未明确，未计入漏洞命中。")
        if findings:
            steps.append(f"对上传源码执行 AST/CFG/DFG 路径分析，确认 {len(findings)} 条代码风险。")
        elif any(str(item.get("kind") or "").strip().lower() in _CODE_FILE_KINDS for item in files if isinstance(item, dict)):
            steps.append("对上传源码执行静态路径分析，未确认具体代码漏洞位置。")
        if records or findings:
            steps.append("汇总已确认风险、修复版本、修复建议、风险代码片段与修复代码。")
        else:
            steps.append("汇总本次扫描未命中的范围、限制条件和后续补充分析建议。")
        if fields:
            steps.append("整理运行摘要和报告编号等本次扫描元信息。")
        steps.append("按实际扫描结果生成 Markdown 报告。")
        return steps

    steps = []
    if files:
        steps.append(f"Read {len(files)} uploaded file(s) and extracted analyzable content by file type.")
    else:
        steps.append("No valid uploaded files were identified; the report is based only on available scan facts.")
    if dependencies:
        steps.append(f"Parsed dependency manifests and identified {len(dependencies)} dependency coordinate(s).")
        if records:
            steps.append(f"Verified dependency vulnerabilities by explicit component version and confirmed {len(records)} hit(s).")
        else:
            steps.append("Verified dependency vulnerabilities by explicit component version; no dependency hit was confirmed.")
    elif unresolved_dependencies:
        steps.append(f"Found {len(unresolved_dependencies)} dependency item(s) without explicit versions; they were not counted as hits.")
    if findings:
        steps.append(f"Ran AST/CFG/DFG path analysis on uploaded source code and confirmed {len(findings)} code finding(s).")
    elif any(str(item.get("kind") or "").strip().lower() in _CODE_FILE_KINDS for item in files if isinstance(item, dict)):
        steps.append("Ran static path analysis on uploaded source code; no exact code finding was confirmed.")
    if records or findings:
        steps.append("Summarized confirmed risks, fixed versions, remediation guidance, vulnerable snippets, and fixed code.")
    else:
        steps.append("Summarized the non-hit scope, scan limitations, and suggested follow-up inputs.")
    if fields:
        steps.append("Included runtime summary and report metadata from this scan.")
    steps.append("Generated the Markdown report from actual scan results.")
    return steps


class ReportStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or (DATA_DIR / "reports")
        self.index_path = self.root / "index.json"
        self._lock = RLock()

    def list_reports(self) -> list[dict[str, Any]]:
        with self._lock:
            index = self._read_index()
        ordered = sorted(index, key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return [_public_report_summary(item) for item in ordered]

    def get_report(self, report_id: str) -> dict[str, Any]:
        clean_id = _safe_report_id(report_id)
        with self._lock:
            metadata = next((item for item in self._read_index() if item.get("id") == clean_id), None)
            if not metadata:
                raise KeyError(report_id)
            path = self.root / self._metadata_file_name(metadata, "md")
            if not path.exists():
                raise KeyError(report_id)
            content = self._sanitize_report_file(path)
        return {**_public_report_summary(metadata), "content": content}

    def get_report_json(self, report_id: str) -> dict[str, Any]:
        clean_id = _safe_report_id(report_id)
        with self._lock:
            metadata = next((item for item in self._read_index() if item.get("id") == clean_id), None)
            if not metadata:
                raise KeyError(report_id)
            metadata = self._ensure_report_artifacts(metadata)
            source_path = self.root / Path(str(metadata.get("source_json_file") or "")).name
            if not source_path.is_file() or source_path.parent.resolve() != self.root.resolve():
                raise KeyError(report_id)
            document = _load_report_json_document(source_path)
        return document

    def resolve_download(self, report_id: str, report_format: str | None = None) -> tuple[Path, str] | tuple[Path, str, str]:
        if report_format is None:
            path, file_name, _ = self._resolve_download(report_id, "md")
            return path, file_name
        return self._resolve_download(report_id, report_format)

    def prepare_download_artifact(
        self,
        report_ids: list[str],
        formats: list[str],
        *,
        user_id: str = "default",
    ) -> dict[str, Any]:
        clean_ids = list(dict.fromkeys(_safe_report_id(value) for value in report_ids if str(value).strip()))
        clean_formats = list(dict.fromkeys(_normalize_report_format(value) for value in formats if str(value).strip()))
        if not clean_ids:
            raise ValueError("At least one report is required")
        if not clean_formats:
            raise ValueError("At least one report format is required")
        catalog = {str(item.get("id") or ""): item for item in self.list_reports()}
        for report_id in clean_ids:
            report = catalog.get(report_id)
            if not report:
                raise KeyError(report_id)
            metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
            if str(metadata.get("user_id") or "default") != str(user_id or "default"):
                raise KeyError(report_id)

        resolved: list[tuple[str, str, Path, str, str]] = []
        for report_id in clean_ids:
            for report_format in clean_formats:
                path, file_name, media_type = self._resolve_download(report_id, report_format)
                resolved.append((report_id, report_format, path, file_name, media_type))
        if len(resolved) == 1:
            _, _, path, file_name, media_type = resolved[0]
            return report_artifact_store.save(
                path.read_bytes(),
                file_name=file_name,
                media_type=media_type,
                user_id=user_id,
            )

        archive = io.BytesIO()
        with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
            for report_id, _, path, file_name, _ in resolved:
                arcname = f"{report_id}/{Path(file_name).name}" if len(clean_ids) > 1 else Path(file_name).name
                bundle.writestr(arcname, path.read_bytes())
            for report_id in clean_ids:
                report = catalog[report_id]
                for key in ("source_json_file", "sarif_file"):
                    auxiliary_name = Path(str(report.get(key) or "")).name
                    auxiliary_path = self.root / auxiliary_name
                    if not auxiliary_name or not auxiliary_path.is_file() or auxiliary_path.parent.resolve() != self.root.resolve():
                        continue
                    arcname = f"{report_id}/{auxiliary_name}" if len(clean_ids) > 1 else auxiliary_name
                    bundle.writestr(arcname, auxiliary_path.read_bytes())
        label = "all-reports" if len(clean_ids) > 1 else clean_ids[0]
        return report_artifact_store.save(
            archive.getvalue(),
            file_name=f"SecFlow-{label}-bundle.zip",
            media_type="application/zip",
            user_id=user_id,
        )

    def _resolve_download(self, report_id: str, report_format: str) -> tuple[Path, str, str]:
        clean_format = _normalize_report_format(report_format)
        clean_id = _safe_report_id(report_id)
        with self._lock:
            index = self._read_index()
            metadata = next((item for item in index if item.get("id") == clean_id), None)
            if not metadata:
                raise KeyError(report_id)
            metadata = self._ensure_report_artifacts(metadata)
            self._write_index(index)
            if clean_format not in set(metadata.get("available_formats") or []):
                raise ValueError(f"Report format is unavailable: {clean_format}")
            file_name = self._metadata_file_name(metadata, clean_format)
            path = self.root / file_name
            if not path.is_file() or path.parent.resolve() != self.root.resolve():
                raise KeyError(report_id)
            if clean_format == "md":
                self._sanitize_report_file(path)
        return path, file_name, _REPORT_MEDIA_TYPES[clean_format]

    def sanitize_existing_reports(self) -> None:
        with self._lock:
            if not self.root.exists():
                return
            for path in self.root.glob("*.md"):
                if path.is_file():
                    self._sanitize_report_file(path)

    def delete_reports(self, report_ids: list[str]) -> dict[str, Any]:
        requested_ids = list(
            dict.fromkeys(
                value
                for raw_value in report_ids
                if (value := str(raw_value).strip()) and _safe_report_id(value) == value
            )
        )
        with self._lock:
            index = self._read_index()
            requested_set = set(requested_ids)
            removed = [item for item in index if str(item.get("id") or "") in requested_set]
            removed_ids = [str(item.get("id") or "") for item in removed]
            if removed:
                removed_set = set(removed_ids)
                self._write_index([item for item in index if str(item.get("id") or "") not in removed_set])
                for item in removed:
                    for file_name in self._all_metadata_file_names(item):
                        path = self.root / file_name
                        if path.parent.resolve() == self.root.resolve():
                            path.unlink(missing_ok=True)
        removed_set = set(removed_ids)
        return {
            "requested": len(requested_ids),
            "deleted": len(removed_ids),
            "deleted_ids": removed_ids,
            "missing_ids": [report_id for report_id in requested_ids if report_id not in removed_set],
        }

    def save_markdown(
        self,
        title: str,
        content: str,
        *,
        mode: str,
        vulnerability_count: int,
        finding_count: int,
        metadata: dict[str, Any] | None = None,
        input_fingerprint: str = "",
        report_source: dict[str, Any] | None = None,
        rendered_artifacts: dict[str, bytes | str] | None = None,
        report_document: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        content = _sanitize_report_content(content)
        created_at = now_iso()
        digest = hashlib.sha256(f"{created_at}\n{title}\n{content}".encode("utf-8")).hexdigest()[:12]
        report_id = f"report-{created_at.replace(':', '').replace('+', 'z')}-{digest}"
        report_id = _safe_report_id(report_id)
        base_name = _report_file_base_name(title, metadata or {}, created_at)
        file_names = _report_file_names(base_name)
        source_json_file = f"{_safe_report_file_stem(base_name)}.json"
        sarif_file = f"{_safe_report_file_stem(base_name)}.sarif.json"
        summary = {
            "id": report_id,
            "title": title.strip() or "依赖漏洞与代码漏洞分析报告",
            "file_name": file_names["md"],
            "file_names": file_names,
            "source_json_file": source_json_file,
            "sarif_file": sarif_file,
            "available_formats": sorted(_REPORT_FORMATS),
            "created_at": created_at,
            "mode": mode,
            "vulnerability_count": int(vulnerability_count),
            "finding_count": int(finding_count),
            "metadata": metadata or {},
        }
        if input_fingerprint:
            summary["_input_fingerprint"] = input_fingerprint
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            index = self._read_index()
            if input_fingerprint:
                existing = next(
                    (
                        item
                        for item in index
                        if item.get("_input_fingerprint") == input_fingerprint
                        and (self.root / Path(str(item.get("file_name") or "")).name).is_file()
                    ),
                    None,
                )
                if existing:
                    self._remove_stale_artifacts(existing)
                    existing.update(
                        {
                            "title": summary["title"],
                            "file_name": file_names["md"],
                            "file_names": file_names,
                            "source_json_file": source_json_file,
                            "sarif_file": sarif_file,
                            "available_formats": sorted(_REPORT_FORMATS),
                            "mode": mode,
                            "vulnerability_count": int(vulnerability_count),
                            "finding_count": int(finding_count),
                            "metadata": metadata or {},
                            "updated_at": created_at,
                        }
                    )
                    self._write_report_artifacts(
                        existing,
                        content,
                        report_source=report_source,
                        rendered_artifacts=rendered_artifacts,
                        report_document=report_document,
                    )
                    self._write_index(index)
                    return _public_report_summary(existing)
            self._write_report_artifacts(
                summary,
                content,
                report_source=report_source,
                rendered_artifacts=rendered_artifacts,
                report_document=report_document,
            )
            index = [item for item in index if item.get("id") != report_id]
            index.insert(0, summary)
            self._write_index(index[:100])
        return _public_report_summary(summary)

    def save_json_report(
        self,
        title: str,
        content: str,
        *,
        report_source: dict[str, Any],
        mode: str,
        vulnerability_count: int,
        finding_count: int,
        metadata: dict[str, Any] | None = None,
        input_fingerprint: str = "",
        rendered_artifacts: dict[str, bytes | str] | None = None,
        report_document: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        validated_source = validate_scan_result_json(report_source)
        return self.save_markdown(
            title,
            content,
            mode=mode,
            vulnerability_count=vulnerability_count,
            finding_count=finding_count,
            metadata=metadata,
            input_fingerprint=input_fingerprint,
            report_source=validated_source,
            rendered_artifacts=rendered_artifacts,
            report_document=report_document,
        )

    def _write_report_artifacts(
        self,
        metadata: dict[str, Any],
        markdown: str,
        *,
        report_source: dict[str, Any] | None = None,
        rendered_artifacts: dict[str, bytes | str] | None = None,
        report_document: dict[str, Any] | None = None,
    ) -> None:
        metadata["file_names"] = _coerce_report_file_names(metadata)
        metadata["file_name"] = metadata["file_names"]["md"]
        metadata["source_json_file"] = Path(
            str(metadata.get("source_json_file") or f"{Path(metadata['file_name']).stem}.json")
        ).name
        metadata["sarif_file"] = Path(
            str(metadata.get("sarif_file") or f"{Path(metadata['file_name']).stem}.sarif.json")
        ).name
        metadata["render_pipeline"] = [
            "scan_results_to_json",
            "report_sarif_mcp_json",
            "report_chart_mcp_json",
            "report_mermaid_mcp_json",
            "report_markdown_mcp_json",
            "report_word_mcp_docx",
            "report_excel_mcp_xlsx",
            "report_pdf_mcp_pdf",
            "html_renderer_json",
        ]
        available_formats = {"md"}
        artifact_errors: dict[str, str] = {}
        render_metadata = _report_render_metadata(metadata)
        provided_report_document = isinstance(report_document, dict) and bool(report_document)
        report_document = (
            validate_report_document_json(report_document)
            if provided_report_document
            else _build_report_json_document(markdown, render_metadata, report_source=report_source)
        )
        report_json_bytes = _canonical_report_json_bytes(report_document, pretty=True)
        metadata["report_json_sha256"] = hashlib.sha256(report_json_bytes).hexdigest()
        source_json_path = self.root / metadata["source_json_file"]
        source_json_path.write_bytes(report_json_bytes)
        source_json_path.chmod(0o600)
        sarif_envelope = report_document.get("sarif") if isinstance(report_document.get("sarif"), dict) else {}
        sarif_document = sarif_envelope.get("sarif") if isinstance(sarif_envelope.get("sarif"), dict) else {}
        sarif_path = self.root / metadata["sarif_file"]
        if sarif_document:
            sarif_path.write_bytes(_canonical_report_json_bytes(sarif_document, pretty=True))
            sarif_path.chmod(0o600)
        else:
            sarif_path.unlink(missing_ok=True)
        markdown = str((report_document.get("report") or {}).get("markdown") or markdown)
        if rendered_artifacts and isinstance(rendered_artifacts.get("md"), str) and not provided_report_document:
            markdown = _sanitize_report_content(str(rendered_artifacts["md"]))
            report_document = _build_report_json_document(markdown, render_metadata, report_source=report_source)
            report_json_bytes = _canonical_report_json_bytes(report_document, pretty=True)
            metadata["report_json_sha256"] = hashlib.sha256(report_json_bytes).hexdigest()
            source_json_path.write_bytes(report_json_bytes)
            source_json_path.chmod(0o600)
        (self.root / metadata["file_names"]["md"]).write_text(markdown, encoding="utf-8")
        try:
            (self.root / metadata["file_names"]["html"]).write_text(
                _build_html_report(
                    markdown,
                    render_metadata,
                    document=report_document.get("report"),
                    visuals=report_document.get("visuals"),
                ),
                encoding="utf-8",
            )
            available_formats.add("html")
        except Exception as exc:  # noqa: BLE001
            artifact_errors["html"] = str(exc)
            (self.root / metadata["file_names"]["html"]).unlink(missing_ok=True)
        binary_artifacts = dict(rendered_artifacts or {})
        if not binary_artifacts:
            binary_artifacts, fallback_errors = _render_binary_report_artifacts_with_mcps(
                report_document,
                metadata=metadata,
            )
            artifact_errors.update(fallback_errors)
        for report_format, signature in (("docx", b"PK"), ("xlsx", b"PK"), ("pdf", b"%PDF")):
            path = self.root / metadata["file_names"][report_format]
            payload = binary_artifacts.get(report_format)
            try:
                if not isinstance(payload, bytes) or not payload.startswith(signature):
                    raise ValueError(f"{report_format.upper()} MCP artifact is missing or invalid")
                path.write_bytes(payload)
                path.chmod(0o600)
                available_formats.add(report_format)
            except Exception as exc:  # noqa: BLE001
                artifact_errors.setdefault(report_format, str(exc))
                path.unlink(missing_ok=True)
        metadata["available_formats"] = sorted(available_formats)
        if artifact_errors:
            metadata["_artifact_errors"] = artifact_errors
        else:
            metadata.pop("_artifact_errors", None)

    def _ensure_report_artifacts(self, metadata: dict[str, Any]) -> dict[str, Any]:
        md_name = self._metadata_file_name(metadata, "md")
        md_path = self.root / md_name
        if not md_path.is_file():
            raise KeyError(str(metadata.get("id") or ""))
        markdown = self._sanitize_report_file(md_path)
        metadata["file_names"] = _coerce_report_file_names(metadata)
        metadata["file_name"] = metadata["file_names"]["md"]
        metadata["source_json_file"] = Path(
            str(metadata.get("source_json_file") or f"{Path(metadata['file_name']).stem}.json")
        ).name
        metadata["sarif_file"] = Path(
            str(metadata.get("sarif_file") or f"{Path(metadata['file_name']).stem}.sarif.json")
        ).name
        metadata["render_pipeline"] = [
            "scan_results_to_json",
            "report_sarif_mcp_json",
            "report_chart_mcp_json",
            "report_mermaid_mcp_json",
            "report_markdown_mcp_json",
            "report_word_mcp_docx",
            "report_excel_mcp_xlsx",
            "report_pdf_mcp_pdf",
            "html_renderer_json",
        ]
        available_formats = {"md"}
        artifact_errors: dict[str, str] = {}
        html_path = self.root / metadata["file_names"]["html"]
        pdf_path = self.root / metadata["file_names"]["pdf"]
        docx_path = self.root / metadata["file_names"]["docx"]
        xlsx_path = self.root / metadata["file_names"]["xlsx"]
        render_metadata = _report_render_metadata(metadata)
        source_json_path = self.root / metadata["source_json_file"]
        if source_json_path.is_file():
            report_document = _load_report_json_document(source_json_path)
        else:
            report_document = _build_report_json_document(markdown, render_metadata)
            source_json_path.write_bytes(_canonical_report_json_bytes(report_document, pretty=True))
            source_json_path.chmod(0o600)
        metadata["report_json_sha256"] = hashlib.sha256(source_json_path.read_bytes()).hexdigest()
        sarif_path = self.root / metadata["sarif_file"]
        sarif_envelope = report_document.get("sarif") if isinstance(report_document.get("sarif"), dict) else {}
        sarif_document = sarif_envelope.get("sarif") if isinstance(sarif_envelope.get("sarif"), dict) else {}
        if sarif_document and not sarif_path.is_file():
            sarif_path.write_bytes(_canonical_report_json_bytes(sarif_document, pretty=True))
            sarif_path.chmod(0o600)
        try:
            if not html_path.is_file():
                html_path.write_text(
                    _build_html_report(
                        markdown,
                        render_metadata,
                        document=report_document.get("report"),
                        visuals=report_document.get("visuals"),
                    ),
                    encoding="utf-8",
                )
            available_formats.add("html")
        except Exception as exc:  # noqa: BLE001
            artifact_errors["html"] = str(exc)
            html_path.unlink(missing_ok=True)
        missing_binary = not pdf_path.is_file() or not docx_path.is_file() or not xlsx_path.is_file()
        generated: dict[str, bytes] = {}
        if missing_binary:
            generated, generated_errors = _render_binary_report_artifacts_with_mcps(
                report_document,
                metadata=metadata,
            )
            artifact_errors.update(generated_errors)
        for report_format, path, signature in (
            ("docx", docx_path, b"PK"),
            ("xlsx", xlsx_path, b"PK"),
            ("pdf", pdf_path, b"%PDF"),
        ):
            try:
                if not path.is_file() or path.stat().st_size == 0:
                    payload = generated.get(report_format)
                    if not isinstance(payload, bytes) or not payload.startswith(signature):
                        raise ValueError(f"{report_format.upper()} MCP artifact is unavailable")
                    path.write_bytes(payload)
                    path.chmod(0o600)
                if not path.read_bytes()[:4].startswith(signature):
                    raise ValueError(f"{report_format.upper()} report signature is invalid")
                available_formats.add(report_format)
            except Exception as exc:  # noqa: BLE001
                artifact_errors[report_format] = str(exc)
                path.unlink(missing_ok=True)
        metadata["available_formats"] = sorted(available_formats)
        if artifact_errors:
            metadata["_artifact_errors"] = artifact_errors
        else:
            metadata.pop("_artifact_errors", None)
        return metadata

    def _remove_stale_artifacts(self, metadata: dict[str, Any]) -> None:
        for file_name in self._all_metadata_file_names(metadata):
            path = self.root / file_name
            if path.parent.resolve() == self.root.resolve():
                path.unlink(missing_ok=True)

    @staticmethod
    def _metadata_file_name(metadata: dict[str, Any], report_format: str) -> str:
        names = metadata.get("file_names") if isinstance(metadata.get("file_names"), dict) else {}
        file_name = names.get(report_format) if isinstance(names, dict) else ""
        if not file_name and report_format == "md":
            file_name = metadata.get("file_name")
        if not file_name:
            stem = Path(str(metadata.get("file_name") or metadata.get("id") or "secflow-report")).stem
            file_name = f"{stem}.{report_format}"
        return Path(str(file_name)).name

    @staticmethod
    def _all_metadata_file_names(metadata: dict[str, Any]) -> list[str]:
        names: list[str] = []
        file_names = metadata.get("file_names")
        if isinstance(file_names, dict):
            names.extend(Path(str(value)).name for value in file_names.values() if value)
        if metadata.get("file_name"):
            names.append(Path(str(metadata.get("file_name"))).name)
        if metadata.get("source_json_file"):
            names.append(Path(str(metadata.get("source_json_file"))).name)
        if metadata.get("sarif_file"):
            names.append(Path(str(metadata.get("sarif_file"))).name)
        return list(dict.fromkeys(name for name in names if name))

    def _read_index(self) -> list[dict[str, Any]]:
        if not self.index_path.exists():
            return []
        try:
            raw = self.index_path.read_text(encoding="utf-8")
            decoded = decrypt_json_from_text(raw, REPORT_INDEX_PURPOSE)
            if isinstance(decoded, list):
                return [item for item in decoded if isinstance(item, dict)]
        except Exception:  # noqa: BLE001
            try:
                legacy = json.loads(self.index_path.read_text(encoding="utf-8"))
                if isinstance(legacy, list):
                    self._write_index(legacy)
                    return [item for item in legacy if isinstance(item, dict)]
            except Exception:  # noqa: BLE001
                return []
        return []

    def _write_index(self, index: list[dict[str, Any]]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.index_path.with_suffix(".tmp")
        tmp.write_text(encrypt_json_to_text(index, REPORT_INDEX_PURPOSE), encoding="utf-8")
        os.replace(tmp, self.index_path)

    @staticmethod
    def _sanitize_report_file(path: Path) -> str:
        content = path.read_text(encoding="utf-8")
        sanitized = _sanitize_report_content(content)
        if sanitized != content:
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_text(sanitized, encoding="utf-8")
            os.replace(temporary, path)
        return sanitized


def _append_compact_scan_scope(
    lines: list[str],
    *,
    files: list[dict[str, Any]],
    dependencies: list[dict[str, Any]],
    has_dependency_scope: bool,
    language: str,
) -> None:
    language = _normalize_report_language(language)
    labels = {
        "zh-Hans": {
            "composition": "文件构成",
            "type": "类型",
            "count": "数量",
            "examples": "文件样例",
            "files_omitted": "其余 %d 个文件不在正文逐项展开；完整清单保留在报告元数据中。",
            "no_files": "未识别到有效附件。",
            "dependencies": "识别到的依赖",
            "dependencies_omitted": "其余 %d 个依赖不在正文逐项展开；统计数字仍按完整扫描结果计算。",
            "no_dependencies": "未从附件中解析出可用于漏洞匹配的依赖。",
            "unknown": "未知文件",
            "unspecified": "版本未明确",
            "confidence": "置信度",
        },
        "zh-Hant": {
            "composition": "檔案構成",
            "type": "類型",
            "count": "數量",
            "examples": "檔案範例",
            "files_omitted": "其餘 %d 個檔案不在正文逐項展開；完整清單保留在報告中繼資料中。",
            "no_files": "未識別到有效附件。",
            "dependencies": "識別到的相依套件",
            "dependencies_omitted": "其餘 %d 個相依套件不在正文逐項展開；統計數字仍按完整掃描結果計算。",
            "no_dependencies": "未從附件解析出可用於漏洞比對的相依套件。",
            "unknown": "未知檔案",
            "unspecified": "版本未明確",
            "confidence": "信賴度",
        },
        "en": {
            "composition": "File composition",
            "type": "Type",
            "count": "Count",
            "examples": "File examples",
            "files_omitted": "%d additional files are omitted from the body; the complete list remains in report metadata.",
            "no_files": "No valid attachments were identified.",
            "dependencies": "Identified dependencies",
            "dependencies_omitted": "%d additional dependencies are omitted from the body; metrics still use the complete scan result.",
            "no_dependencies": "No dependencies usable for vulnerability matching were parsed from attachments.",
            "unknown": "unknown file",
            "unspecified": "version unspecified",
            "confidence": "confidence",
        },
        "ja": {
            "composition": "ファイル構成",
            "type": "種類",
            "count": "件数",
            "examples": "ファイル例",
            "files_omitted": "残り %d 個のファイルは本文では省略し、完全な一覧はレポートメタデータに保持しています。",
            "no_files": "有効な添付ファイルは識別されませんでした。",
            "dependencies": "識別された依存関係",
            "dependencies_omitted": "残り %d 個の依存関係は本文では省略しています。集計値は完全なスキャン結果に基づきます。",
            "no_dependencies": "脆弱性照合に使用できる依存関係を解析できませんでした。",
            "unknown": "不明なファイル",
            "unspecified": "バージョン未指定",
            "confidence": "信頼度",
        },
        "ko": {
            "composition": "파일 구성",
            "type": "유형",
            "count": "개수",
            "examples": "파일 예시",
            "files_omitted": "나머지 %d개 파일은 본문에서 생략했으며 전체 목록은 보고서 메타데이터에 보관됩니다.",
            "no_files": "유효한 첨부 파일을 식별하지 못했습니다.",
            "dependencies": "식별된 의존성",
            "dependencies_omitted": "나머지 %d개 의존성은 본문에서 생략했습니다. 통계는 전체 스캔 결과를 기준으로 합니다.",
            "no_dependencies": "취약점 매칭에 사용할 수 있는 의존성을 파싱하지 못했습니다.",
            "unknown": "알 수 없는 파일",
            "unspecified": "버전 미지정",
            "confidence": "신뢰도",
        },
    }.get(language, {})
    if not labels:
        labels = {
            "composition": "File composition",
            "type": "Type",
            "count": "Count",
            "examples": "File examples",
            "files_omitted": "%d additional files are omitted from the body; the complete list remains in report metadata.",
            "no_files": "No valid attachments were identified.",
            "dependencies": "Identified dependencies",
            "dependencies_omitted": "%d additional dependencies are omitted from the body; metrics still use the complete scan result.",
            "no_dependencies": "No dependencies usable for vulnerability matching were parsed from attachments.",
            "unknown": "unknown file",
            "unspecified": "version unspecified",
            "confidence": "confidence",
        }

    valid_files = [item for item in files if isinstance(item, dict)]
    if valid_files:
        kind_counts = Counter(str(item.get("kind") or "unknown").strip() or "unknown" for item in valid_files)
        lines.extend(
            [
                f"### {labels['composition']}",
                "",
                f"| {labels['type']} | {labels['count']} |",
                "| --- | ---: |",
            ]
        )
        for kind, count in sorted(kind_counts.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"| {_escape_markdown_table_cell(kind)} | {count} |")
        preview_count = min(len(valid_files), _REPORT_FILE_PREVIEW_LIMIT)
        lines.extend(["", f"### {labels['examples']} ({preview_count}/{len(valid_files)})", ""])
        for item in valid_files[:_REPORT_FILE_PREVIEW_LIMIT]:
            file_name = _single_line_report_value(item.get("file_name") or labels["unknown"])
            kind = _single_line_report_value(item.get("kind") or "unknown")
            lines.append(f"- `{file_name}` ({kind})")
        omitted = len(valid_files) - preview_count
        if omitted > 0:
            lines.extend(["", f"> {labels['files_omitted'] % omitted}"])
    else:
        lines.append(f"- {labels['no_files']}")

    lines.append("")
    if has_dependency_scope and dependencies:
        preview_count = min(len(dependencies), _REPORT_DEPENDENCY_PREVIEW_LIMIT)
        lines.extend([f"### {labels['dependencies']} ({preview_count}/{len(dependencies)})", ""])
        for dependency in dependencies[:_REPORT_DEPENDENCY_PREVIEW_LIMIT]:
            ecosystem = _single_line_report_value(dependency.get("ecosystem") or "unknown")
            name = _single_line_report_value(dependency.get("name") or "")
            version = _single_line_report_value(dependency.get("version") or labels["unspecified"])
            source_file = _single_line_report_value(dependency.get("source_file") or labels["unknown"])
            confidence = _single_line_report_value(dependency.get("confidence") or "medium")
            lines.append(
                f"- {ecosystem} / `{name}` @ `{version}` ({source_file}, {labels['confidence']} {confidence})"
            )
        omitted = len(dependencies) - preview_count
        if omitted > 0:
            lines.extend(["", f"> {labels['dependencies_omitted'] % omitted}"])
    elif has_dependency_scope:
        lines.append(labels["no_dependencies"])


def _single_line_report_value(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").replace("`", "'")).strip()


def _append_truncation_notice(lines: list[str], *, omitted: int, language: str, item: str) -> None:
    if omitted <= 0:
        return
    normalized = _normalize_report_language(language)
    if normalized in {"zh-Hans", "zh-Hant"}:
        noun = "漏洞记录" if item == "dependency" else "代码发现"
        lines.extend(["", f"> 其余 {omitted} 条{noun}未在正文展开；报告统计仍按完整扫描结果计算。", ""])
    elif normalized == "ja":
        lines.extend(["", f"> 残り {omitted} 件は本文では省略しています。集計値は完全なスキャン結果に基づきます。", ""])
    elif normalized == "ko":
        lines.extend(["", f"> 나머지 {omitted}건은 본문에서 생략했습니다. 통계는 전체 스캔 결과를 기준으로 합니다.", ""])
    else:
        lines.extend(["", f"> {omitted} additional items are omitted from the body; metrics still use the complete scan result.", ""])


def _report_mcp_audit_lines(mcp_audit: dict[str, Any] | None, language: str) -> list[str]:
    audit = mcp_audit if isinstance(mcp_audit, dict) else {}
    if not audit:
        return []
    normalized = _normalize_report_language(language)
    server = _single_line_report_value(audit.get("server") or "SecFlow Report Chart MCP")
    tool = _report_inline_code(audit.get("tool") or "build_scan_report_charts")
    status = str(audit.get("status") or "unknown").strip().lower()
    fact_count = int(audit.get("fact_count") or 0)
    invoked_at = _single_line_report_value(_report_china_time(audit.get("invoked_at") or "-"))
    digest = _report_inline_code(audit.get("output_sha256") or "-")
    if normalized in {"zh-Hans", "zh-Hant"}:
        status_label = "已完成" if status == "completed" else "失败"
        return [
            f"- 报告 MCP：{server} / `{tool}`",
            f"- MCP 调用状态：{status_label}（事实 {fact_count} 条，调用时间 {invoked_at}）",
            f"- MCP 输出 SHA-256：`{digest}`",
        ]
    if normalized == "ja":
        return [
            f"- Report MCP: {server} / `{tool}`",
            f"- MCP status: {'完了' if status == 'completed' else '失敗'} ({fact_count} facts, {invoked_at})",
            f"- MCP output SHA-256: `{digest}`",
        ]
    if normalized == "ko":
        return [
            f"- Report MCP: {server} / `{tool}`",
            f"- MCP status: {'완료' if status == 'completed' else '실패'} ({fact_count} facts, {invoked_at})",
            f"- MCP output SHA-256: `{digest}`",
        ]
    return [
        f"- Report MCP: {server} / `{tool}`",
        f"- MCP status: {'completed' if status == 'completed' else 'failed'} ({fact_count} facts, {invoked_at})",
        f"- MCP output SHA-256: `{digest}`",
    ]


def _append_report_mcp_audit(lines: list[str], mcp_audit: dict[str, Any] | None, language: str) -> None:
    lines.extend(_report_mcp_audit_lines(mcp_audit, language))


def build_dependency_markdown_report(
    *,
    question: str,
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    summary: str,
    fields: dict[str, Any] | None = None,
    language: str = "zh-Hans",
    mcp_audit: dict[str, Any] | None = None,
    report_code_blocks: list[dict[str, Any]] | None = None,
) -> str:
    language = _normalize_report_language(language)
    if language not in {"zh-Hans", "zh-Hant"}:
        return _build_localized_dependency_markdown_report(
            question=question,
            dependency_scan=dependency_scan,
            records=records,
            static_analysis=static_analysis,
            summary=summary,
            fields=fields,
            language=language,
            mcp_audit=mcp_audit,
            report_code_blocks=report_code_blocks,
        )
    files = dependency_scan.get("files") or []
    dependencies = dependency_scan.get("dependencies") or []
    unresolved_dependencies = [dependency for dependency in dependencies if not dependency.get("version")]
    findings = static_analysis.get("findings") or []
    finding_count = int(static_analysis.get("finding_count") or len(findings))
    has_dependency_scope = _has_dependency_scope(files, dependencies, records)
    has_code_scope = _has_code_scope(files, static_analysis, findings)
    lines: list[str] = [
        "# 依赖漏洞与代码漏洞分析报告",
        "",
        f"- 生成时间：{_report_china_time(now_iso())}",
        f"- 用户问题：{question.strip() or '附件安全分析'}",
        f"- 附件数量：{len(files)}",
    ]
    if has_dependency_scope:
        lines.append(f"- 识别依赖：{len(dependencies)} 个")
        lines.append(f"- 依赖漏洞：{len(records)} 条")
    if has_code_scope:
        lines.append(f"- 代码漏洞：{finding_count} 条")
    _append_report_mcp_audit(lines, mcp_audit, language)
    lines.append("")

    section_index = 1
    section_index = _append_section_heading(lines, section_index, _report_section_title(language, "summary"))
    lines.extend([summary.strip() or "暂无摘要。", ""])

    section_index = _append_section_heading(lines, section_index, "扫描范围")
    _append_compact_scan_scope(
        lines,
        files=files,
        dependencies=dependencies,
        has_dependency_scope=has_dependency_scope,
        language=language,
    )

    if has_dependency_scope:
        section_index = _append_section_heading(lines, section_index, "依赖漏洞（组件与版本）")
        if records:
            for index, record in enumerate(records[:_REPORT_RECORD_LIMIT], start=1):
                lines.extend(_record_markdown(index, record))
            _append_truncation_notice(
                lines,
                omitted=len(records) - _REPORT_RECORD_LIMIT,
                language=language,
                item="dependency",
            )
        else:
            lines.append("当前未基于明确组件版本确认漏洞。")
            if unresolved_dependencies:
                lines.append(
                    f"另有 {len(unresolved_dependencies)} 个依赖版本未明确，未计入漏洞命中；不能据此判定为安全。"
                )

    if has_code_scope:
        section_index = _append_section_heading(lines, section_index, "代码漏洞（文件、行号与修复代码）")
        if findings:
            for index, finding in enumerate(findings[:_REPORT_FINDING_LIMIT], start=1):
                lines.extend(
                    _finding_markdown(
                        index,
                        finding,
                        code_block=_report_code_block_for_finding(report_code_blocks, finding, index - 1),
                    )
                )
            _append_truncation_notice(
                lines,
                omitted=max(finding_count, len(findings)) - _REPORT_FINDING_LIMIT,
                language=language,
                item="code",
            )
        else:
            lines.append(_no_code_findings_message(files, static_analysis, "zh-Hans"))

    if fields:
        section_index = _append_section_heading(lines, section_index, "运行摘要")
        for key, value in fields.items():
            lines.append(f"- {key}：{value}")

    _append_section_heading(lines, section_index, _report_section_title(language, "method"))
    method_steps = _actual_execution_steps(
        files=files,
        dependencies=dependencies,
        records=records,
        findings=findings,
        unresolved_dependencies=unresolved_dependencies,
        fields=fields,
        language=language,
    )
    lines.extend([*(f"{index}. {step}" for index, step in enumerate(method_steps, start=1)), "", f"> {_report_limitation(language)}", ""])
    return "\n".join(lines)


def build_agent_task_markdown_report(
    task: dict[str, Any],
    *,
    mcp_audit: dict[str, Any] | None = None,
    report_code_blocks: list[dict[str, Any]] | None = None,
) -> str:
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    dependencies = [item for item in (result.get("dependencies") or []) if isinstance(item, dict)]
    license_scan = result.get("license_scan") if isinstance(result.get("license_scan"), dict) else {}
    licenses = [item for item in (result.get("licenses") or license_scan.get("licenses") or []) if isinstance(item, dict)]
    language_results = result.get("language_results") if isinstance(result.get("language_results"), dict) else {}
    findings: list[tuple[str, dict[str, Any]]] = []
    review_findings: list[tuple[str, dict[str, Any]]] = []
    severity = Counter()
    for language in result.get("languages") or task.get("languages") or []:
        language_result = language_results.get(language) if isinstance(language_results.get(language), dict) else {}
        for finding in language_result.get("findings") or []:
            if isinstance(finding, dict):
                findings.append((str(language), finding))
                severity[str(finding.get("severity") or "UNKNOWN").upper()] += 1
        for finding in language_result.get("review_findings") or []:
            if isinstance(finding, dict):
                review_findings.append((str(language), finding))

    project = _report_plain_text(task.get("workspace_name") or "项目")
    objective = _report_plain_text(task.get("objective") or "项目代码安全扫描")
    workspace = _report_plain_text(task.get("workspace_path") or "-")
    scope_type = "单个文件" if task.get("workspace_type") == "file" else "目录"
    summary = _report_plain_text(result.get("summary") or "扫描已完成。")
    language_labels = "、".join(_agent_report_language_label(item) for item in result.get("languages") or []) or "未识别"
    lines = [
        f"# {project} 代码安全漏洞扫描报告",
        "",
        f"- 生成时间：{_report_china_time(now_iso())}",
        f"- 扫描目标：{objective}",
        f"- 工作区：{workspace}",
        f"- 扫描范围：{scope_type}",
        f"- 项目语言：{language_labels}",
        f"- 源文件：{int(result.get('total_files') or 0)} 个",
        f"- 依赖组件：{int(result.get('dependency_count') or len(dependencies))} 个",
        f"- 项目许可：{len(licenses)} 种",
        f"- 代码风险：{int(result.get('total_findings') or len(findings))} 条",
        f"- 复核候选：{int(result.get('total_review_findings') or len(review_findings))} 条",
        *_report_mcp_audit_lines(mcp_audit, "zh-Hans"),
        "",
        "## 1. 执行摘要",
        "",
        summary,
        "",
        "## 2. 扫描范围",
        "",
        f"- 项目名称：{project}",
        f"- 工作区路径：`{_report_inline_code(task.get('workspace_path') or '-')}`",
        f"- 范围类型：{scope_type}",
        f"- 扫描目标：{objective}",
        f"- 语言分派：{language_labels}",
        "",
        "## 3. 风险等级统计",
        "",
        "| 严重等级 | 数量 |",
        "| --- | ---: |",
    ]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        lines.append(f"| {_report_severity_zh(level)} | {severity[level]} |")

    lines.extend(["", "## 4. 语言与语法分析结果", ""])
    if language_results:
        lines.extend(
            [
                "| 语言 | 文件 | 风险 | 解析成功 | 解析错误 | AST 节点 | CFG 节点/边 | DFG 边 | 规则文件 |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for language in result.get("languages") or language_results.keys():
            item = language_results.get(language) if isinstance(language_results.get(language), dict) else {}
            syntax = item.get("syntax_summary") if isinstance(item.get("syntax_summary"), dict) else {}
            rules = "<br>".join(_escape_markdown_table_cell(value) for value in item.get("rule_files") or []) or "-"
            lines.append(
                "| {language} | {files} | {findings} | {parsed} | {errors} | {ast} | {cfg_nodes}/{cfg_edges} | {dfg} | {rules} |".format(
                    language=_escape_markdown_table_cell(_agent_report_language_label(language)),
                    files=int(item.get("file_count") or 0),
                    findings=int(item.get("finding_count") or 0),
                    parsed=int(syntax.get("parsed_files") or 0),
                    errors=int(syntax.get("parse_error_files") or 0),
                    ast=int(syntax.get("ast_node_count") or 0),
                    cfg_nodes=int(syntax.get("cfg_node_count") or 0),
                    cfg_edges=int(syntax.get("cfg_edge_count") or 0),
                    dfg=int(syntax.get("dfg_edge_count") or 0),
                    rules=rules,
                )
            )
    else:
        lines.append("未识别到可执行专属规则扫描的语言。")

    lines.extend(["", "## 5. 依赖组件完整清单", ""])
    if dependencies:
        lines.extend(
            [
                "| # | 生态 | 组件 | 版本 | 来源文件 | 声明类型 | 声明 | 置信度 |",
                "| ---: | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for index, dependency in enumerate(dependencies, start=1):
            lines.append(
                "| {index} | {ecosystem} | {name} | {version} | {source} | {source_type} | {declaration} | {confidence} |".format(
                    index=index,
                    ecosystem=_escape_markdown_table_cell(dependency.get("ecosystem") or "-"),
                    name=_escape_markdown_table_cell(dependency.get("name") or "-"),
                    version=_escape_markdown_table_cell(dependency.get("version") or "未指定"),
                    source=_escape_markdown_table_cell(dependency.get("source_file") or "-"),
                    source_type=_escape_markdown_table_cell(dependency.get("source_type") or "-"),
                    declaration=_escape_markdown_table_cell(dependency.get("declaration") or "-"),
                    confidence=_escape_markdown_table_cell(dependency.get("confidence") or "-"),
                )
            )
    else:
        lines.append("本次扫描未识别到依赖组件。")

    lines.extend(["", "### 5.1 项目许可识别", ""])
    if licenses:
        lines.extend(
            [
                f"- 识别覆盖：`{_report_inline_code(license_scan.get('coverage_status') or 'unknown')}`",
                f"- OSI License API：`{_report_inline_code((license_scan.get('registry') or {}).get('status') or 'unknown')}`",
                "",
                "| SPDX 标识 | 许可名称 | 置信度 | 识别方式 | 证据文件 | OSI 收录 | OSI 批准标记 | 官方链接 |",
                "| --- | --- | ---: | --- | --- | --- | --- | --- |",
            ]
        )
        for item in licenses:
            osi = item.get("osi") if isinstance(item.get("osi"), dict) else {}
            approval = {
                "approved": "接口标记已批准",
                "not_indicated": "接口未提供批准标记",
                "not_found": "接口未收录",
            }.get(str(osi.get("approval_status") or "not_found"), str(osi.get("approval_status") or "-"))
            lines.append(
                "| {spdx} | {name} | {confidence:.2f} | {methods} | {sources} | {listed} | {approval} | {url} |".format(
                    spdx=_escape_markdown_table_cell(item.get("spdx_id") or "-"),
                    name=_escape_markdown_table_cell(item.get("name") or "-"),
                    confidence=float(item.get("confidence") or 0),
                    methods="<br>".join(_escape_markdown_table_cell(value) for value in item.get("detection_methods") or []) or "-",
                    sources="<br>".join(_escape_markdown_table_cell(value) for value in item.get("source_files") or []) or "-",
                    listed="是" if osi.get("listed") else "否",
                    approval=_escape_markdown_table_cell(approval),
                    url=_escape_markdown_table_cell(osi.get("official_url") or "-"),
                )
            )
        lines.extend(
            [
                "",
                "> 许可识别用于供应链盘点和审计提示，不构成法律意见；依赖组件自身许可仍需结合包仓库元数据和发布物复核。",
            ]
        )
    else:
        coverage = str(license_scan.get("coverage_status") or "not_run")
        lines.append(f"未识别到明确项目许可（覆盖状态：`{_report_inline_code(coverage)}`）；这不等同于项目没有许可约束。")

    lines.extend(["", "## 6. 代码风险详情", ""])
    if findings or review_findings:
        for index, (language, finding) in enumerate(findings, start=1):
            lines.extend(
                _agent_finding_markdown(
                    task,
                    index_label=f"6.{index}",
                    language=language,
                    finding=finding,
                    disposition="confirmed",
                    code_block=_report_code_block_for_finding(report_code_blocks, finding, index - 1),
                )
            )
        for index, (language, finding) in enumerate(review_findings, start=1):
            lines.extend(
                _agent_finding_markdown(
                    task,
                    index_label=f"6.R{index}",
                    language=language,
                    finding=finding,
                    disposition="review",
                    code_block=_report_code_block_for_finding(
                        report_code_blocks,
                        finding,
                        len(findings) + index - 1,
                    ),
                )
            )
    else:
        lines.append("本次规则扫描与 AST/CFG/DFG 分析未返回代码风险。")

    adaptation = result.get("adaptation") if isinstance(result.get("adaptation"), dict) else {}
    skill = adaptation.get("skill") if isinstance(adaptation.get("skill"), dict) else {}
    baseline_metrics = adaptation.get("baseline_metrics") if isinstance(adaptation.get("baseline_metrics"), dict) else {}
    current_metrics = adaptation.get("current_metrics") if isinstance(adaptation.get("current_metrics"), dict) else {}
    lines.extend(
        [
            "## 7. 项目自适应与回归审计",
            "",
            f"- 自适应状态：`{_report_inline_code(adaptation.get('status') or 'not_recorded')}`",
            f"- 模型分析轮数：{int(adaptation.get('attempts') or 0)}",
            f"- Overlay 重扫轮数：{int(adaptation.get('iterations') or 0)}",
            f"- Skill：`{_report_inline_code(skill.get('name') or '-')}`",
            f"- Skill SHA-256：`{_report_inline_code(skill.get('sha256') or '-')}`",
            f"- Prompt 版本：`{_report_inline_code(skill.get('prompt_version') or '-')}`",
            f"- 终止原因：`{_report_inline_code(adaptation.get('termination_reason') or '-')}`",
            "",
        ]
    )
    if baseline_metrics or current_metrics:
        lines.extend(["| 指标 | 冻结基线 | 当前结果 |", "| --- | ---: | ---: |"])
        for key, label in (
            ("findings", "主告警"),
            ("review_findings", "复核候选"),
            ("parse_error_files", "解析错误文件"),
            ("cfg_edges", "CFG 边"),
            ("dfg_edges", "DFG 边"),
        ):
            lines.append(
                f"| {label} | {int(baseline_metrics.get(key) or 0)} | {int(current_metrics.get(key) or 0)} |"
            )
        lines.append("")
    overlays = [item for item in adaptation.get("overlays") or [] if isinstance(item, dict)]
    if overlays:
        lines.extend(["| 轮次 | Overlay SHA-256 | 置信度 | 范围 |", "| ---: | --- | ---: | --- |"])
        for index, overlay in enumerate(overlays, start=1):
            lines.append(
                "| {index} | `{fingerprint}` | {confidence:.2f} | `{scope}` |".format(
                    index=index,
                    fingerprint=_report_inline_code(overlay.get("fingerprint") or "-"),
                    confidence=float(overlay.get("confidence") or 0.0),
                    scope=_report_inline_code(overlay.get("scope") or "-"),
                )
            )
        lines.append("")
    else:
        lines.extend(["未应用项目 Overlay；冻结规则扫描结果保持原样。", ""])

    lines.extend(["## 8. 执行记录", ""])
    events = [item for item in (task.get("events") or []) if isinstance(item, dict)]
    if events:
        lines.extend(["| 序号 | 时间 | 节点 | 状态 | 说明 |", "| ---: | --- | --- | --- | --- |"])
        for event in events:
            lines.append(
                "| {sequence} | {time} | {node} | {status} | {message} |".format(
                    sequence=int(event.get("sequence") or 0),
                    time=_escape_markdown_table_cell(_report_china_time(event.get("time") or "-")),
                    node=_escape_markdown_table_cell(event.get("node") or "-"),
                    status=_escape_markdown_table_cell(event.get("status") or "-"),
                    message=_escape_markdown_table_cell(event.get("message") or "-"),
                )
            )
    else:
        lines.append("暂无执行记录。")

    lines.extend(
        [
            "",
            "## 9. 方法与限制",
            "",
            "本报告基于本次工作区内实际纳入的源文件、项目清单、冻结语言规则以及 AST/CFG/DFG/污点分析结果生成。项目 Overlay 只作用于当前任务，不修改全局规则，也不作为 500 项目冻结评测或资格指标的输入。没有独立真值或运行轨迹时，模型候选不能证明真实漏报或误报；未纳入扫描的文件、动态运行路径、部署配置和未明确版本的依赖仍需结合人工复核、动态测试与供应链数据进一步确认。",
            "",
        ]
    )
    return "\n".join(lines)


def _agent_finding_markdown(
    task: dict[str, Any],
    *,
    index_label: str,
    language: str,
    finding: dict[str, Any],
    disposition: str,
    code_block: dict[str, Any] | None = None,
) -> list[str]:
    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
    file_name = str(finding.get("file_name") or finding.get("file") or sink.get("file") or "未知文件")
    risk_line = _positive_report_line(finding.get("line") or finding.get("risk_line") or sink.get("line"))
    location = f"{_report_inline_code(file_name)}:{risk_line}" if risk_line else _report_inline_code(file_name)
    title = _report_plain_text(finding.get("title") or "代码风险")
    disposition_label = "已确认主告警" if disposition == "confirmed" else "复核候选（不计入已确认漏洞）"
    title_prefix = "" if disposition == "confirmed" else "[复核候选] "
    lines = [
        f"### {index_label} {title_prefix}{title}",
        "",
        f"- 判定状态：{disposition_label}",
        f"- 严重等级：{_report_severity_zh(finding.get('severity'))}",
        f"- 项目语言：{_agent_report_language_label(language)}",
        f"- 规则编号：`{_report_inline_code(finding.get('rule_id') or '-')}`",
        f"- 风险位置：`{location}`",
        f"- 风险说明：{_report_plain_text(finding.get('description') or '未提供说明。')}",
        f"- 修复方案：{_report_finding_remediation(finding)}",
    ]
    if finding.get("confidence"):
        lines.append(f"- 置信度：`{_report_inline_code(finding.get('confidence'))}`")
    if finding.get("project_overlay_action"):
        lines.append(f"- Overlay 动作：`{_report_inline_code(finding.get('project_overlay_action'))}`")
    if source:
        lines.append(f"- 污点源：`{_agent_evidence_location(source, file_name)}`")
    if sink:
        lines.append(f"- 污点汇：`{_agent_evidence_location(sink, file_name)}`")

    snippet, line_start, line_end, snippet_source = _agent_finding_snippet(task, finding, file_name, risk_line)
    structured_snippet = _report_code_block_markdown(code_block)
    if structured_snippet:
        snippet = structured_snippet
        line_start = _positive_report_line(code_block.get("line_start")) or line_start
        line_end = _positive_report_line(code_block.get("line_end")) or line_end
        snippet_source = _report_plain_text(code_block.get("source") or snippet_source)
    code_language = _code_fence_language(file_name)
    if snippet:
        if line_start and line_end:
            line_range = str(line_start) if line_start == line_end else f"{line_start}-{line_end}"
            snippet_label = f"证据代码片段（第 {line_range} 行，风险点为第 {risk_line or line_start} 行；来源：{snippet_source}）："
        else:
            snippet_label = f"证据代码片段（来源：{snippet_source}）："
        lines.extend(["", snippet_label, f"```{code_language}", snippet, "```"])
    else:
        lines.extend(["", "> 未能从扫描证据或受限工作区读取对应代码片段；该发现需要人工复核源码位置。"])

    fixed_snippet = _safe_report_code(finding.get("fixed_snippet"))
    if fixed_snippet:
        lines.extend(["", "可核验修复代码：", f"```{code_language}", fixed_snippet, "```"])

    taint_path = finding.get("taint_path") or finding.get("dataflow") or finding.get("path")
    if taint_path:
        lines.extend(["", "Source → Sink 污点路径："])
        if isinstance(taint_path, list):
            for step in taint_path[:20]:
                if isinstance(step, dict):
                    kind = _report_plain_text(step.get("kind") or step.get("type") or "step")
                    step_location = _agent_evidence_location(step, file_name)
                    label = _report_plain_text(step.get("label") or step.get("description") or "")
                    lines.append(f"- {kind}：`{step_location}`" + (f"｜{label}" if label != "-" else ""))
                else:
                    lines.append(f"- {_report_plain_text(step)}")
        elif isinstance(taint_path, dict):
            lines.append(f"- `{_report_inline_code(json.dumps(taint_path, ensure_ascii=False, sort_keys=True))}`")
        else:
            lines.append(f"- {_report_plain_text(taint_path)}")
    lines.append("")
    return lines


def _agent_finding_snippet(
    task: dict[str, Any],
    finding: dict[str, Any],
    file_name: str,
    risk_line: int | None,
) -> tuple[str, int | None, int | None, str]:
    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    explicit = (
        finding.get("vulnerable_snippet")
        or finding.get("code_snippet")
        or finding.get("snippet")
        or sink.get("snippet")
        or finding.get("evidence")
    )
    if isinstance(explicit, (dict, list)):
        explicit = json.dumps(explicit, ensure_ascii=False, indent=2, sort_keys=True)
    explicit_text = _safe_report_code(explicit)
    if explicit_text:
        line_start = _positive_report_line(finding.get("line_start")) or risk_line
        line_end = _positive_report_line(finding.get("line_end")) or line_start
        return explicit_text, line_start, line_end, "扫描引擎证据"

    source_context = _read_agent_source_context(task, file_name, risk_line)
    if source_context is not None:
        snippet, line_start, line_end = source_context
        return snippet, line_start, line_end, "工作区源码上下文"
    return "", None, None, ""


def _report_code_block_for_finding(
    code_blocks: list[dict[str, Any]] | None,
    finding: dict[str, Any],
    fallback_index: int,
) -> dict[str, Any] | None:
    blocks = [item for item in code_blocks or [] if isinstance(item, dict)]
    if not blocks:
        return None
    finding_id = str(finding.get("id") or finding.get("rule_id") or "").strip()
    if finding_id:
        exact = [item for item in blocks if str(item.get("finding_id") or "").strip() == finding_id]
        if len(exact) == 1:
            return exact[0]
    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    file_name = str(finding.get("file_name") or finding.get("file") or sink.get("file") or "").strip()
    risk_line = _positive_report_line(finding.get("line") or finding.get("risk_line") or sink.get("line"))
    location_matches = [
        item
        for item in blocks
        if str(item.get("file_name") or "").strip() == file_name
        and _positive_report_line(item.get("risk_line")) == risk_line
    ]
    if len(location_matches) == 1:
        return location_matches[0]
    return blocks[fallback_index] if 0 <= fallback_index < len(blocks) else None


def _report_code_block_markdown(code_block: dict[str, Any] | None) -> str:
    if not isinstance(code_block, dict):
        return ""
    parsed: list[tuple[int, str]] = []
    for item in code_block.get("lines") or []:
        if not isinstance(item, dict):
            return ""
        number = _positive_report_line(item.get("number"))
        if not number:
            return ""
        parsed.append((number, str(item.get("text") or "")))
    if not parsed:
        return ""
    width = max(len(str(number)) for number, _ in parsed)
    return "\n".join(f"{number:>{width}} | {text}" for number, text in parsed)


def _read_agent_source_context(
    task: dict[str, Any],
    file_name: str,
    risk_line: int | None,
    *,
    context_lines: int = 3,
) -> tuple[str, int, int] | None:
    if not risk_line:
        return None
    workspace_value = str(task.get("workspace_path") or "").strip()
    if not workspace_value:
        return None
    workspace = Path(workspace_value).expanduser()
    try:
        workspace_resolved = workspace.resolve(strict=True)
    except OSError:
        return None

    candidates: list[Path] = []
    finding_path = Path(file_name).expanduser()
    if finding_path.is_absolute():
        candidates.append(finding_path)
    elif workspace_resolved.is_file():
        candidates.append(workspace_resolved)
    else:
        candidates.append(workspace_resolved / finding_path)
        parts = finding_path.parts
        if workspace_resolved.name in parts:
            root_index = parts.index(workspace_resolved.name)
            candidates.append(workspace_resolved.joinpath(*parts[root_index + 1 :]))
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        language_results = result.get("language_results") if isinstance(result.get("language_results"), dict) else {}
        for language_result in language_results.values():
            if not isinstance(language_result, dict):
                continue
            for scanned_file in language_result.get("files") or []:
                scanned = str(scanned_file or "")
                if scanned == file_name or Path(scanned).name == finding_path.name:
                    candidates.append(workspace_resolved / scanned)

    allowed_root = workspace_resolved.parent if workspace_resolved.is_file() else workspace_resolved
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            if not resolved.is_file() or not resolved.is_relative_to(allowed_root):
                continue
            if workspace_resolved.is_file() and resolved != workspace_resolved:
                continue
            data = resolved.read_bytes()
        except OSError:
            continue
        if not data or len(data) > 2_000_000 or b"\x00" in data[:8_192]:
            continue
        source_lines = data.decode("utf-8", errors="replace").splitlines()
        if risk_line > len(source_lines):
            continue
        line_start = max(1, risk_line - max(0, context_lines))
        line_end = min(len(source_lines), risk_line + max(0, context_lines))
        width = len(str(line_end))
        rendered = "\n".join(
            f"{line_number:>{width}} | {source_lines[line_number - 1]}"
            for line_number in range(line_start, line_end + 1)
        )
        return _safe_report_code(rendered), line_start, line_end
    return None


def _positive_report_line(value: Any) -> int | None:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _agent_evidence_location(evidence: dict[str, Any], default_file: str) -> str:
    file_name = _report_inline_code(evidence.get("file") or evidence.get("file_name") or default_file)
    line = _positive_report_line(evidence.get("line") or evidence.get("risk_line"))
    return f"{file_name}:{line}" if line else file_name


def _safe_report_code(value: Any) -> str:
    return str(value or "").strip().replace("```", "` ` `")


def _agent_report_language_label(value: Any) -> str:
    return {
        "java": "Java",
        "python": "Python",
        "go": "Go",
        "c": "C",
        "cpp": "C++",
        "csharp": "C#",
        "rust": "Rust",
        "solidity": "Solidity",
    }.get(str(value).lower(), str(value).upper())


def _report_plain_text(value: Any) -> str:
    return re.sub(r"[\r\n]+", " ", str(value or "")).strip().replace("|", "\\|") or "-"


def _report_inline_code(value: Any) -> str:
    return re.sub(r"[\r\n`]+", " ", str(value or "")).strip() or "-"


def _build_localized_dependency_markdown_report(
    *,
    question: str,
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    summary: str,
    fields: dict[str, Any] | None,
    language: str,
    mcp_audit: dict[str, Any] | None,
    report_code_blocks: list[dict[str, Any]] | None,
) -> str:
    files = dependency_scan.get("files") or []
    dependencies = dependency_scan.get("dependencies") or []
    unresolved_dependencies = [dependency for dependency in dependencies if not dependency.get("version")]
    findings = static_analysis.get("findings") or []
    finding_count = int(static_analysis.get("finding_count") or len(findings))
    has_dependency_scope = _has_dependency_scope(files, dependencies, records)
    has_code_scope = _has_code_scope(files, static_analysis, findings)
    lines: list[str] = [
        f"# {_rt(language, 'title')}",
        "",
        f"- {_rt(language, 'generated_at')}: {_report_china_time(now_iso())}",
        f"- {_rt(language, 'question')}: {question.strip() or _rt(language, 'attachment_analysis')}",
        f"- {_rt(language, 'attachments')}: {len(files)}",
    ]
    if has_dependency_scope:
        lines.append(f"- {_rt(language, 'dependencies')}: {len(dependencies)}")
        lines.append(f"- {_rt(language, 'dependency_vulnerabilities')}: {len(records)}")
    if has_code_scope:
        lines.append(f"- {_rt(language, 'code_findings')}: {finding_count}")
    _append_report_mcp_audit(lines, mcp_audit, language)
    lines.append("")

    section_index = 1
    section_index = _append_section_heading(lines, section_index, _report_section_title(language, "summary"))
    lines.extend([summary.strip() or _rt(language, "no_summary"), ""])

    section_index = _append_section_heading(lines, section_index, _rt(language, "files_section"))
    _append_compact_scan_scope(
        lines,
        files=files,
        dependencies=dependencies,
        has_dependency_scope=has_dependency_scope,
        language=language,
    )

    if has_dependency_scope:
        section_index = _append_section_heading(lines, section_index, _rt(language, "dependency_section"))
        if records:
            for index, record in enumerate(records[:_REPORT_RECORD_LIMIT], start=1):
                lines.extend(_record_markdown(index, record, language=language))
            _append_truncation_notice(
                lines,
                omitted=len(records) - _REPORT_RECORD_LIMIT,
                language=language,
                item="dependency",
            )
        else:
            lines.append(_rt(language, "no_dependency_hits"))
            if unresolved_dependencies:
                lines.append(_rt(language, "unresolved") % len(unresolved_dependencies))

    if has_code_scope:
        section_index = _append_section_heading(lines, section_index, _rt(language, "code_section"))
        if findings:
            for index, finding in enumerate(findings[:_REPORT_FINDING_LIMIT], start=1):
                lines.extend(
                    _finding_markdown(
                        index,
                        finding,
                        language=language,
                        code_block=_report_code_block_for_finding(report_code_blocks, finding, index - 1),
                    )
                )
            _append_truncation_notice(
                lines,
                omitted=max(finding_count, len(findings)) - _REPORT_FINDING_LIMIT,
                language=language,
                item="code",
            )
        else:
            lines.append(_no_code_findings_message(files, static_analysis, language))

    if fields:
        section_index = _append_section_heading(lines, section_index, _rt(language, "runtime"))
        for key, value in fields.items():
            lines.append(f"- {key}: {value}")

    _append_section_heading(lines, section_index, _report_section_title(language, "method"))
    method_steps = _actual_execution_steps(
        files=files,
        dependencies=dependencies,
        records=records,
        findings=findings,
        unresolved_dependencies=unresolved_dependencies,
        fields=fields,
        language=language,
    )
    lines.extend([*(f"{index}. {step}" for index, step in enumerate(method_steps, start=1)), "", f"> {_report_limitation(language)}", ""])
    return "\n".join(lines)


def _record_markdown(index: int, record: dict[str, Any], language: str = "zh-Hans") -> list[str]:
    if _normalize_report_language(language) != "zh-Hans":
        lines = [
            f"### {index}. {record.get('id') or _rt(language, 'unknown')}",
            "",
            f"- {_rt(language, 'vuln_name')}: {record.get('title') or _rt(language, 'not_specified')}",
            f"- {_rt(language, 'severity')}: {_report_severity_label(record.get('severity'), language)}",
            f"- CVSS: {record.get('cvss_score') if record.get('cvss_score') is not None else _rt(language, 'not_specified')}",
            f"- {_rt(language, 'description')}: {record.get('summary_zh') or _rt(language, 'not_specified')}",
        ]
        component_ranges = _component_ranges(record, language)
        lines.append(f"- {_rt(language, 'component_range')}:")
        lines.extend(f"  - {item}" for item in (component_ranges or [_rt(language, "not_specified")]))
        fixed = record.get("fixed_versions") or []
        lines.append(f"- {_rt(language, 'fixed_version')}: " + ("; ".join(str(item) for item in fixed) if fixed else _rt(language, "not_specified")))
        links = record.get("reference_links") or []
        if links:
            lines.append(f"- {_rt(language, 'references')}:")
            lines.extend(f"  - {link}" for link in links[:8])
        lines.append("")
        return lines

    lines = [
        f"### {index}. {record.get('id') or '未知漏洞'}",
        "",
        f"- 漏洞名称：{record.get('title') or '未明确'}",
        f"- 严重等级：{_report_severity_label(record.get('severity'), language)}",
        f"- CVSS：{record.get('cvss_score') if record.get('cvss_score') is not None else '未明确'}",
        f"- 漏洞描述：{record.get('summary_zh') or '未明确'}",
    ]
    component_ranges = _component_ranges(record)
    lines.append("- 组件版本范围：")
    lines.extend(f"  - {item}" for item in (component_ranges or ["未明确"]))
    fixed = record.get("fixed_versions") or []
    lines.append("- 修复版本：" + ("；".join(str(item) for item in fixed) if fixed else "未明确"))
    links = record.get("reference_links") or []
    if links:
        lines.append("- 参考链接：")
        lines.extend(f"  - {link}" for link in links[:8])
    lines.append("")
    return lines


def _finding_markdown(
    index: int,
    finding: dict[str, Any],
    language: str = "zh-Hans",
    *,
    code_block: dict[str, Any] | None = None,
) -> list[str]:
    sink = finding.get("sink") or {}
    source = finding.get("source") or {}
    file_name = str(finding.get("file") or sink.get("file") or "未知文件")
    risk_line = int(finding.get("risk_line") or sink.get("line") or 0)
    line_start = int(finding.get("line_start") or risk_line)
    line_end = int(finding.get("line_end") or risk_line)
    line_range = str(line_start) if line_start == line_end else f"{line_start}-{line_end}"
    vulnerable_snippet = str(finding.get("vulnerable_snippet") or sink.get("snippet") or finding.get("evidence") or "").strip()
    structured_snippet = _report_code_block_markdown(code_block)
    if structured_snippet:
        vulnerable_snippet = structured_snippet
        line_start = _positive_report_line(code_block.get("line_start")) or line_start
        line_end = _positive_report_line(code_block.get("line_end")) or line_end
        line_range = str(line_start) if line_start == line_end else f"{line_start}-{line_end}"
    fixed_snippet = str(finding.get("fixed_snippet") or "").strip()
    if _normalize_report_language(language) != "zh-Hans":
        lines = [
            f"### {index}. {finding.get('title') or _rt(language, 'static_finding')}",
            "",
            f"- {_rt(language, 'risk_type')}: {finding.get('title') or _rt(language, 'static_risk')}",
            f"- {_rt(language, 'severity')}: {_report_severity_label(finding.get('severity'), language)}",
            f"- {_rt(language, 'related_vulnerability')}: {finding.get('record_id') or _rt(language, 'not_specified')}",
            f"- {_rt(language, 'related_component')}: {finding.get('component') or _rt(language, 'not_specified')}",
            f"- {_rt(language, 'risk_location')}: {file_name}:{risk_line}",
            f"- {_rt(language, 'code_range')}: {_rt(language, 'line') % line_range}",
            f"- {_rt(language, 'confidence')}: {finding.get('confidence') or 'medium'}",
            f"- {_rt(language, 'remediation')}: {_report_finding_remediation(finding, language)}",
            f"- CFG: {finding.get('cfg') or _rt(language, 'not_specified')}",
            f"- DFG: {finding.get('dfg') or _rt(language, 'not_specified')}",
        ]
        if finding.get("priority"):
            lines.insert(7, f"- {_rt(language, 'priority')}: {finding.get('priority')}")
        if finding.get("security_context"):
            lines.append(f"- {_rt(language, 'security_context')}: {finding.get('security_context')}")
        if finding.get("triage_note"):
            lines.append(f"- {_rt(language, 'triage_note')}: {finding.get('triage_note')}")
        if source:
            lines.append(f"- {_rt(language, 'input_location')}: {source.get('file') or file_name}:{source.get('line') or 0}")
        aggregated_sinks = [item for item in finding.get("aggregated_sinks") or [] if isinstance(item, dict)]
        if aggregated_sinks:
            lines.extend(["", f"{_rt(language, 'merged_sinks')}:"])
            for item in aggregated_sinks[:20]:
                lines.append(f"- {item.get('file') or file_name}:{item.get('line') or 0} | {item.get('snippet') or ''}")
        related_findings = [item for item in finding.get("related_findings") or [] if isinstance(item, dict)]
        if related_findings:
            lines.extend(["", f"{_rt(language, 'related_findings')}:"])
            for item in related_findings[:8]:
                lines.append(f"- {item.get('title') or item.get('scenario') or _rt(language, 'static_finding')}: {item.get('file') or file_name}:{item.get('line') or 0}")
        code_language = _code_fence_language(file_name)
        lines.extend(["", _rt(language, "vulnerable_snippet") % (line_range, risk_line), f"```{code_language}", vulnerable_snippet or _rt(language, "no_snippet"), "```"])
        lines.extend(["", _rt(language, "fixed_code"), f"```{code_language}", fixed_snippet or _rt(language, "no_fixed"), "```"])
        lines.extend(["", _rt(language, "path")])
        path = finding.get("path") or []
        if not path:
            lines.append(f"- {_rt(language, 'no_path')}")
        for step in path:
            lines.append(
                f"- {step.get('kind') or 'step'}: {step.get('file') or _rt(language, 'unknown_file')}:{step.get('line') or 0}"
                f" | {step.get('label') or ''}"
            )
            snippet = str(step.get("snippet") or "").strip()
            if snippet:
                lines.extend(["  ```", f"  {snippet}", "  ```"])
        lines.append("")
        return lines

    lines = [
        f"### {index}. {finding.get('title') or '静态分析发现'}",
        "",
        f"- 风险类型：{finding.get('title') or '静态代码风险'}",
        f"- 严重等级：{_report_severity_label(finding.get('severity'), language)}",
        f"- 关联依赖漏洞：{finding.get('record_id') or '未明确'}",
        f"- 关联组件：{finding.get('component') or '未明确'}",
        f"- 风险位置：{file_name}:{risk_line}",
        f"- 代码范围：第 {line_range} 行",
        f"- 置信度：{finding.get('confidence') or 'medium'}",
        f"- 修复方案：{_report_finding_remediation(finding)}",
        f"- CFG：{finding.get('cfg') or '未明确'}",
        f"- DFG：{finding.get('dfg') or '未明确'}",
    ]
    if finding.get("priority"):
        lines.insert(7, f"- 优先级：{finding.get('priority')}")
    if finding.get("security_context"):
        lines.append(f"- 安全上下文：{finding.get('security_context')}")
    if finding.get("triage_note"):
        lines.append(f"- 分析备注：{finding.get('triage_note')}")
    if source:
        lines.append(f"- 输入位置：{source.get('file') or file_name}:{source.get('line') or 0}")
    aggregated_sinks = [item for item in finding.get("aggregated_sinks") or [] if isinstance(item, dict)]
    if aggregated_sinks:
        lines.extend(["", "合并的资金更新点："])
        for item in aggregated_sinks[:20]:
            lines.append(f"- {item.get('file') or file_name}:{item.get('line') or 0}｜{item.get('snippet') or ''}")
    related_findings = [item for item in finding.get("related_findings") or [] if isinstance(item, dict)]
    if related_findings:
        lines.extend(["", "关联子风险："])
        for item in related_findings[:8]:
            aggregation = item.get("aggregation") if isinstance(item.get("aggregation"), dict) else {}
            suffix = ""
            if aggregation:
                suffix = f"（合并 {aggregation.get('merged_finding_count') or 1} 个发现）"
            lines.append(
                f"- {item.get('title') or item.get('scenario') or '子风险'}："
                f"{item.get('file') or file_name}:{item.get('line') or 0}{suffix}"
            )
    code_language = _code_fence_language(file_name)
    lines.extend(["", f"漏洞代码片段（第 {line_range} 行，风险点为第 {risk_line} 行）：", f"```{code_language}", vulnerable_snippet or "未返回代码片段", "```"])
    lines.extend(["", "修复后的代码：", f"```{code_language}", fixed_snippet or "未生成可核验的修复代码", "```"])
    lines.extend(["", "完整 Source→Sink 路径："])
    path = finding.get("path") or []
    if not path:
        lines.append("- 未返回路径。")
    for step in path:
        lines.append(
            f"- {step.get('kind') or 'step'}：{step.get('file') or '未知文件'}:{step.get('line') or 0}"
            f"｜{step.get('label') or ''}"
        )
        snippet = str(step.get("snippet") or "").strip()
        if snippet:
            lines.extend(["  ```", f"  {snippet}", "  ```"])
    lines.append("")
    return lines


def _code_fence_language(file_name: str) -> str:
    extension = Path(file_name).suffix.lower()
    return {
        ".java": "java",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".py": "python",
        ".js": "javascript",
        ".jsx": "jsx",
        ".ts": "typescript",
        ".tsx": "tsx",
        ".go": "go",
        ".rs": "rust",
        ".php": "php",
        ".rb": "ruby",
        ".swift": "swift",
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
    }.get(extension, "")


def _component_ranges(record: dict[str, Any], language: str = "zh-Hans") -> list[str]:
    rows: list[str] = []
    for component in record.get("components") or []:
        if not isinstance(component, dict):
            continue
        name = component.get("name") or ""
        ecosystem = component.get("ecosystem") or ""
        if _normalize_report_language(language) == "zh-Hans":
            affected = "；".join(str(item) for item in component.get("affected") or []) or "未明确"
            fixed = "；".join(str(item) for item in component.get("fixed") or []) or "未明确"
            rows.append(f"{ecosystem} / {name}：影响 {affected}；修复 {fixed}")
        else:
            affected = "; ".join(str(item) for item in component.get("affected") or []) or _rt(language, "not_specified")
            fixed = "; ".join(str(item) for item in component.get("fixed") or []) or _rt(language, "not_specified")
            impact = {"en": "affects", "ja": "影響", "ko": "영향"}.get(_normalize_report_language(language), "affects")
            fixed_label = {"en": "fixed", "ja": "修正", "ko": "수정"}.get(_normalize_report_language(language), "fixed")
            rows.append(f"{ecosystem} / {name}: {impact} {affected}; {fixed_label} {fixed}")
    if not rows:
        rows.extend(str(item) for item in record.get("affected_versions") or [])
    return rows


def _safe_report_id(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]", "-", value.strip())
    return clean[:160] or "report"


def report_input_fingerprint(attachments: list[dict[str, Any]]) -> str:
    normalized = sorted(
        (
            {
                "file_name": str(item.get("file_name") or item.get("fileName") or "").strip(),
                "content": str(item.get("content") or ""),
            }
            for item in attachments
        ),
        key=lambda item: (item["file_name"], item["content"]),
    )
    payload = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _public_report_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in summary.items() if not str(key).startswith("_")}


def _report_render_metadata(summary: dict[str, Any]) -> dict[str, Any]:
    nested = summary.get("metadata") if isinstance(summary.get("metadata"), dict) else {}
    return {**summary, **nested, "metadata": nested}


def _sanitize_report_content(content: str) -> str:
    sanitized = _strip_markdown_appendix(content)
    sanitized = _remove_deprecated_report_content(sanitized)
    sanitized = _localize_report_generation_time(sanitized)
    replacements = {
        "select_codeql_scenarios": "select_static_scenarios",
        "run_codeql_tool": "run_static_analysis",
        "run_static_analysis": "run_static_path_analysis",
    }
    for old, new in replacements.items():
        sanitized = re.sub(re.escape(old), new, sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(?m)^- 引擎：[^\n]*\n?", "", sanitized)
    sanitized = _ENGINE_NAME_PATTERN.sub("静态代码路径分析", sanitized)
    return _apply_download_markdown_style(sanitized)


def _remove_deprecated_report_content(content: str) -> str:
    result: list[str] = []
    skip_section = False
    section_number = 0
    heading_pattern = re.compile(r"^(##\s+)(?:(\d+)[.)、]?\s*)?(.+?)\s*$")
    mode_pattern = re.compile(
        r"^\s*-\s*(?:扫描模式|掃描模式|Scan mode|Mode|スキャンモード|스캔 모드)\s*[：:].*$",
        flags=re.IGNORECASE,
    )
    for line in str(content or "").splitlines():
        heading = heading_pattern.match(line)
        if heading:
            title = heading.group(3).strip()
            skip_section = title in _DEPRECATED_REPORT_SECTIONS
            if skip_section:
                continue
            section_number += 1
            if heading.group(2):
                line = f"## {section_number}. {title}"
        if skip_section or mode_pattern.match(line):
            continue
        result.append(line)
    return "\n".join(result).strip() + ("\n" if str(content or "").endswith("\n") else "")


def _localize_report_generation_time(content: str) -> str:
    labels = r"生成时间|產生時間|Generated at|生成時間|생성 시간"
    bullet_pattern = re.compile(rf"^(\s*-\s*(?:{labels})\s*[：:]\s*)(.+?)\s*$", flags=re.IGNORECASE)
    table_pattern = re.compile(rf"^(\s*\|\s*(?:{labels})\s*\|\s*)([^|]+?)(\s*\|\s*)$", flags=re.IGNORECASE)
    result: list[str] = []
    for line in str(content or "").splitlines():
        bullet = bullet_pattern.match(line)
        if bullet:
            line = f"{bullet.group(1)}{_report_china_time(bullet.group(2))}"
        else:
            table = table_pattern.match(line)
            if table:
                line = f"{table.group(1)}{_report_china_time(table.group(2))}{table.group(3)}"
        result.append(line)
    return "\n".join(result) + ("\n" if str(content or "").endswith("\n") else "")


def _apply_download_markdown_style(content: str) -> str:
    if _REPORT_STYLE_MARKER in content or not _looks_like_secflow_analysis_report(content):
        return content

    lines = content.splitlines()
    title_index = next((index for index, line in enumerate(lines) if line.strip().startswith("# ")), -1)
    if title_index < 0:
        return content

    title_line = lines[title_index].strip()
    cursor = title_index + 1
    while cursor < len(lines) and not lines[cursor].strip():
        cursor += 1

    metadata_rows: list[tuple[str, str]] = []
    while cursor < len(lines):
        line = lines[cursor].strip()
        if not line:
            cursor += 1
            break
        if line.startswith("## "):
            break
        if not line.startswith("- "):
            break
        key, value = _split_report_metadata_line(line[2:])
        metadata_rows.append((key, value))
        cursor += 1

    styled: list[str] = []
    styled.extend(lines[:title_index])
    style_language = _report_style_language(title_line, metadata_rows)
    style_copy = {
        "zh-Hans": ("安全智脑根据本次上传与扫描事实自动生成；章节会随实际依赖、源码和命中情况动态调整。", "扫描项", "结果"),
        "zh-Hant": ("安全智腦根據本次上傳與掃描事實自動產生；章節會隨實際相依套件、原始碼和命中情況動態調整。", "掃描項", "結果"),
        "ja": ("今回のアップロードとスキャン結果に基づいて自動生成され、章構成は実際の対象と検出結果に応じて調整されます。", "項目", "結果"),
        "ko": ("이번 업로드와 스캔 사실을 기반으로 자동 생성되며 실제 범위와 탐지 결과에 따라 구성이 조정됩니다.", "항목", "결과"),
        "en": ("Generated from the facts available in this upload and scan; sections adapt to the actual scope and findings.", "Item", "Result"),
    }.get(style_language, ("Generated from the facts available in this upload and scan; sections adapt to the actual scope and findings.", "Item", "Result"))
    styled.extend(
        [
            title_line,
            "",
            _REPORT_STYLE_MARKER,
            "",
            f"> {style_copy[0]}",
            "",
        ]
    )
    if metadata_rows:
        styled.extend([f"| {style_copy[1]} | {style_copy[2]} |", "| --- | --- |"])
        for key, value in metadata_rows:
            styled.append(f"| {_escape_markdown_table_cell(key)} | {_escape_markdown_table_cell(value)} |")
        styled.extend(["", "---", ""])

    body_lines = lines[cursor:]
    while body_lines and not body_lines[0].strip():
        body_lines.pop(0)
    for line in body_lines:
        if line.startswith("## ") and styled and styled[-1].strip() and styled[-1] != "---":
            styled.extend(["", "---", ""])
        styled.append(line)

    return "\n".join(styled).rstrip() + "\n"


def _report_style_language(title: str, metadata_rows: list[tuple[str, str]]) -> str:
    keys = {key for key, _ in metadata_rows}
    if keys & {"Generated at", "User question", "Attachments"}:
        return "en"
    if keys & {"生成時間", "ユーザー質問", "添付数"}:
        return "ja"
    if keys & {"생성 시간", "사용자 질문", "첨부 수"}:
        return "ko"
    if any(token in title for token in ("依存関係", "脆弱性")):
        return "ja"
    if any(token in title for token in ("의존성", "취약점")):
        return "ko"
    if any(token in title for token in ("Dependency", "Vulnerability", "vulnerability")):
        return "en"
    return "zh-Hans"


def _looks_like_secflow_analysis_report(content: str) -> bool:
    first_heading = next((line.strip() for line in content.splitlines() if line.strip().startswith("# ")), "")
    if not first_heading:
        return False
    heading_text = first_heading.lstrip("#").strip().lower()
    if not any(keyword in heading_text for keyword in ("漏洞", "vulnerability", "脆弱性", "취약점")):
        return False
    return bool(
        re.search(
            r"(?m)^##\s+\d+\.\s+(?:执行链路|执行摘要|執行摘要|Execution flow|Executive summary|実行チェーン|エグゼクティブサマリー|실행 흐름|요약)\s*$",
            content,
        )
        and re.search(
            r"(?m)^##\s+\d+\.\s+(?:结论摘要|方法与限制|方法與限制|Conclusion summary|Method and limitations|結論概要|分析方法と制限|결론 요약|분석 방법 및 제한 사항)\s*$",
            content,
        )
    )


def _split_report_metadata_line(value: str) -> tuple[str, str]:
    clean_value = value.strip()
    for separator in ("：", ":"):
        if separator in clean_value:
            key, rest = clean_value.split(separator, 1)
            return key.strip() or "项目", rest.strip() or "-"
    return "说明", clean_value or "-"


def _escape_markdown_table_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>").strip() or "-"


def _strip_markdown_appendix(content: str) -> str:
    appendix_heading = re.search(
        r"(?im)^#{1,6}\s*(?:\d+(?:\.\d+)*[.)、]?\s*)?"
        r"(?:附录|Appendix|Appendices|付録|부록|Ap[eé]ndice|Annexe|Anhang|Appendice|Приложение)"
        r"(?:\s|[:：]|$).*",
        content,
    )
    if not appendix_heading:
        return content
    return content[: appendix_heading.start()].rstrip() + "\n"


def _normalize_report_format(value: Any) -> str:
    clean = str(value or "md").strip().lower().lstrip(".")
    aliases = {"markdown": "md", "mdown": "md", "htm": "html"}
    clean = aliases.get(clean, clean)
    if clean not in _REPORT_FORMATS:
        raise ValueError(f"Unsupported report format: {value}")
    return clean


def _report_file_names(base_name: str) -> dict[str, str]:
    clean_base = _safe_report_file_stem(base_name)
    return {report_format: f"{clean_base}.{report_format}" for report_format in _REPORT_FORMATS}


def _coerce_report_file_names(metadata: dict[str, Any]) -> dict[str, str]:
    file_names = metadata.get("file_names")
    if isinstance(file_names, dict):
        names = {
            report_format: Path(str(file_names.get(report_format) or "")).name
            for report_format in _REPORT_FORMATS
            if file_names.get(report_format)
        }
        if all(names.get(report_format) for report_format in _REPORT_FORMATS):
            return names
    stem = Path(str(metadata.get("file_name") or metadata.get("id") or "secflow-report")).stem
    return _report_file_names(stem)


def _report_file_base_name(title: str, metadata: dict[str, Any], created_at: str) -> str:
    project_name = _infer_report_project_name(metadata) or title.strip() or "SecFlow安全报告"
    return f"{project_name}_{_report_timestamp_for_file(created_at)}"


def _infer_report_project_name(metadata: dict[str, Any]) -> str:
    candidates: list[str] = []
    project_name = str(metadata.get("project_name") or "").strip()
    if project_name:
        candidates.append(project_name)
    for item in metadata.get("files") or []:
        if not isinstance(item, dict):
            continue
        file_name = str(item.get("file_name") or "").replace("\\", "/").strip("/")
        if not file_name:
            continue
        parts = [part for part in file_name.split("/") if part and part not in {".", ".."}]
        if not parts:
            continue
        first = parts[0].strip()
        if first and "." not in first.lower() and first.lower() not in {"src", "app", "lib", "backend", "frontend"}:
            candidates.append(first)
        elif len(parts) > 1:
            second = parts[1].strip()
            if second and "." not in second.lower():
                candidates.append(second)
    if not candidates:
        session_id = str(metadata.get("session_id") or "").strip()
        if session_id and session_id != "default":
            candidates.append(session_id)
    if not candidates:
        return ""
    return candidates[0].replace("__", "-")


def _report_timestamp_for_file(created_at: str) -> str:
    try:
        parsed = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        return parsed.astimezone().strftime("%Y%m%d-%H%M%S")
    except Exception:  # noqa: BLE001
        return datetime.now().strftime("%Y%m%d-%H%M%S")


def _safe_report_file_stem(value: str) -> str:
    clean = str(value or "SecFlow安全报告").strip().replace("\\", "-").replace("/", "-")
    clean = re.sub(r"[^\w\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7a3 ._()（）-]+", "-", clean)
    clean = re.sub(r"\s+", "-", clean).strip(" ._-")
    return (clean or "SecFlow安全报告")[:120]


def _report_export_labels(language: str) -> dict[str, str]:
    normalized = _normalize_report_language(language)
    labels = {
        "zh-Hans": {
            "brand": "安全智脑报告",
            "security_report": "安全扫描报告",
            "critical_high": "严重/高危",
            "medium": "中危风险",
            "dependency": "依赖漏洞",
            "code": "代码发现",
            "generated": "生成时间",
            "score": "风险评分",
            "toc": "目录",
            "charts": "漏洞分布图表",
            "severity": "漏洞严重度分布",
            "risk_counts": "风险数量柱状图",
            "no_severity": "暂无明确等级",
            "total_risks": "总风险",
            "footer": "报告基于本次上传与扫描事实自动生成",
            "page": "第 %d 页",
        },
        "zh-Hant": {
            "brand": "安全智腦報告",
            "security_report": "安全掃描報告",
            "critical_high": "嚴重/高危",
            "medium": "中危風險",
            "dependency": "相依套件漏洞",
            "code": "程式碼發現",
            "generated": "產生時間",
            "score": "風險評分",
            "toc": "目錄",
            "charts": "漏洞分布圖表",
            "severity": "漏洞嚴重度分布",
            "risk_counts": "風險數量柱狀圖",
            "no_severity": "暫無明確等級",
            "total_risks": "總風險",
            "footer": "報告依據本次上傳與掃描事實自動產生",
            "page": "第 %d 頁",
        },
        "en": {
            "brand": "SecFlow security report",
            "security_report": "Security scan report",
            "critical_high": "Critical / high",
            "medium": "Medium risk",
            "dependency": "Dependency vulnerabilities",
            "code": "Code findings",
            "generated": "Generated at",
            "score": "Risk score",
            "toc": "Contents",
            "charts": "Risk distribution",
            "severity": "Severity distribution",
            "risk_counts": "Risk count chart",
            "no_severity": "No explicit severity",
            "total_risks": "Total risks",
            "footer": "Generated from the facts available in this upload and scan",
            "page": "Page %d",
        },
        "ja": {
            "brand": "SecFlow セキュリティレポート",
            "security_report": "セキュリティスキャンレポート",
            "critical_high": "重大 / 高",
            "medium": "中リスク",
            "dependency": "依存関係脆弱性",
            "code": "コード検出",
            "generated": "生成時間",
            "score": "リスクスコア",
            "toc": "目次",
            "charts": "リスク分布",
            "severity": "深刻度分布",
            "risk_counts": "リスク件数",
            "no_severity": "明確な深刻度なし",
            "total_risks": "総リスク",
            "footer": "今回のアップロードとスキャン結果に基づいて自動生成",
            "page": "%d ページ",
        },
        "ko": {
            "brand": "SecFlow 보안 보고서",
            "security_report": "보안 스캔 보고서",
            "critical_high": "심각 / 높음",
            "medium": "중간 위험",
            "dependency": "의존성 취약점",
            "code": "코드 발견",
            "generated": "생성 시간",
            "score": "위험 점수",
            "toc": "목차",
            "charts": "위험 분포",
            "severity": "심각도 분포",
            "risk_counts": "위험 개수",
            "no_severity": "명확한 심각도 없음",
            "total_risks": "전체 위험",
            "footer": "이번 업로드와 스캔 사실을 기반으로 자동 생성",
            "page": "%d페이지",
        },
    }
    return labels.get(normalized, labels["en"])


def _report_severity_labels(language: str) -> dict[str, str]:
    normalized = _normalize_report_language(language)
    values = {
        "zh-Hans": {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危"},
        "zh-Hant": {"CRITICAL": "嚴重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危"},
        "ja": {"CRITICAL": "重大", "HIGH": "高", "MEDIUM": "中", "LOW": "低"},
        "ko": {"CRITICAL": "심각", "HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음"},
        "es": {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"},
        "fr": {"CRITICAL": "Critique", "HIGH": "Élevée", "MEDIUM": "Moyenne", "LOW": "Faible"},
        "de": {"CRITICAL": "Kritisch", "HIGH": "Hoch", "MEDIUM": "Mittel", "LOW": "Niedrig"},
        "it": {"CRITICAL": "Critica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Bassa"},
        "ru": {"CRITICAL": "Критическая", "HIGH": "Высокая", "MEDIUM": "Средняя", "LOW": "Низкая"},
        "en": {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"},
    }
    return values.get(normalized, values["en"])


def _report_visual_labels(language: str) -> dict[str, str]:
    normalized = _normalize_report_language(language)
    values = {
        "zh-Hans": {
            "low": "低危风险",
            "scanned_files": "扫描文件",
            "overview": "扫描概览",
            "distribution": "漏洞分布图表",
            "severity_share": "漏洞严重度分布",
            "risk_categories": "风险类型分布",
            "report_badge": "静态代码安全扫描报告",
            "basis": "基于扫描事实与可验证分析链路生成",
        },
        "zh-Hant": {
            "low": "低危風險",
            "scanned_files": "掃描檔案",
            "overview": "掃描概覽",
            "distribution": "漏洞分佈圖表",
            "severity_share": "漏洞嚴重度分佈",
            "risk_categories": "風險類型分佈",
            "report_badge": "靜態程式碼安全掃描報告",
            "basis": "依據掃描事實與可驗證分析鏈路產生",
        },
        "ja": {
            "low": "低リスク",
            "scanned_files": "スキャンファイル",
            "overview": "スキャン概要",
            "distribution": "脆弱性分布",
            "severity_share": "深刻度分布",
            "risk_categories": "リスク種別分布",
            "report_badge": "静的コードセキュリティレポート",
            "basis": "検証可能なスキャン結果に基づき生成",
        },
        "ko": {
            "low": "낮은 위험",
            "scanned_files": "스캔 파일",
            "overview": "스캔 개요",
            "distribution": "취약점 분포",
            "severity_share": "심각도 분포",
            "risk_categories": "위험 유형 분포",
            "report_badge": "정적 코드 보안 스캔 보고서",
            "basis": "검증 가능한 스캔 사실을 기반으로 생성",
        },
        "en": {
            "low": "Low risk",
            "scanned_files": "Scanned files",
            "overview": "Scan overview",
            "distribution": "Vulnerability distribution",
            "severity_share": "Severity distribution",
            "risk_categories": "Risk category distribution",
            "report_badge": "Static code security scan report",
            "basis": "Generated from verified scan facts and analysis paths",
        },
    }
    return values.get(normalized, values["en"])


def _report_section_tone(index: int, title: str) -> str:
    normalized = str(title or "").casefold()
    if any(token in normalized for token in ("风险详情", "漏洞详情", "代码漏洞", "finding", "vulnerability")):
        return "danger"
    if any(token in normalized for token in ("依赖", "组件", "sbom", "dependency")):
        return "warning"
    if any(token in normalized for token in ("修复", "优先级", "remediation", "priority")):
        return "success"
    if any(token in normalized for token in ("附录", "方法", "限制", "appendix")):
        return "neutral"
    return "info" if index < 2 else "teal"


def _report_hero_metadata(
    metadata: dict[str, Any], metrics: dict[str, Any], language: str, labels: dict[str, str]
) -> list[str]:
    items = [f"{labels['generated']}: {_report_china_time(metrics.get('generated_at') or metadata.get('created_at') or '-')}" ]
    languages = [str(item).strip() for item in metadata.get("languages") or [] if str(item).strip()]
    if languages:
        items.append(("项目语言" if language.startswith("zh") else "Languages") + f": {', '.join(languages)}")
    branch = str(metadata.get("branch") or metadata.get("git_branch") or "").strip()
    commit = str(metadata.get("commit") or metadata.get("commit_sha") or "").strip()
    if branch or commit:
        label = "代码版本" if language.startswith("zh") else "Revision"
        items.append(f"{label}: {' / '.join(item for item in (branch, commit[:12]) if item)}")
    duration_ms = _non_negative_int(metadata.get("duration_ms") or (metadata.get("report_metrics") or {}).get("duration_ms"))
    if duration_ms:
        label = "耗时" if language.startswith("zh") else "Duration"
        items.append(f"{label}: {duration_ms / 1000:.2f}s")
    return items


def _build_html_report(
    markdown: str,
    metadata: dict[str, Any],
    *,
    document: dict[str, Any] | None = None,
    visuals: dict[str, Any] | None = None,
) -> str:
    document = _validated_render_document(document) if document is not None else _parse_report_document(markdown, metadata)
    metrics = document["metrics"]
    language = _normalize_report_language(
        metadata.get("language") or (metadata.get("report_metrics") or {}).get("language")
    )
    labels = _report_export_labels(language)
    visual_labels = _report_visual_labels(language)
    severity = _render_document_severity(document, markdown, metadata)
    toc_entries: list[tuple[str, str, str]] = []
    for index, section in enumerate(document["sections"], start=1):
        display_number = index if index == 1 else index + 1
        toc_entries.append((f"section-{index}", str(display_number), str(section["title"])))
        if index == 1:
            toc_entries.append(("section-distribution", "2", visual_labels["distribution"]))
    toc_items = "\n".join(
        f'<a href="#{html.escape(anchor)}"><span>{html.escape(number)}</span>{html.escape(title)}</a>'
        for anchor, number, title in toc_entries
    )
    metric_cards = "\n".join(
        _metric_card(label, value, tone, icon)
        for label, value, tone, icon in [
            (labels["critical_high"], metrics["high_risk"], "danger", "!"),
            (labels["medium"], severity["MEDIUM"], "warning", "△"),
            (visual_labels["low"], severity["LOW"], "amber", "○"),
            (visual_labels["scanned_files"], metrics["attachments"], "success", "✓"),
        ]
    )
    severity_names = _report_severity_labels(language)
    severity_total = sum(int(value) for value in severity.values())
    severity_rows = "\n".join(
        f"<li><b>{html.escape(severity_names[key])}</b><span>{count} · {_severity_percentage(count, severity_total)}</span></li>"
        for key, count in severity.items()
        if count
    ) or f"<li><b>{html.escape(labels['no_severity'])}</b><span>0 · 0.0%</span></li>"
    bars, bars_title, bar_count = _report_risk_bars_html(
        metadata, severity, visual_labels["risk_categories"], severity_names
    )
    degree_stops = _severity_degree_stops(severity)
    score = _risk_score(metrics, severity)
    project_name = html.escape(document["project_name"])
    title = html.escape(document["title"])
    hero_metadata = "".join(
        f"<span>{html.escape(item)}</span>" for item in _report_hero_metadata(metadata, metrics, language, labels)
    )
    chart_section = f"""
        <section class="report-card distribution-card tone-info" id="section-distribution">
          <div class="section-kicker"><span>2</span>{html.escape(visual_labels["distribution"])}</div>
          <div class="chart-grid">
            <div class="chart-card">
              <b>{html.escape(visual_labels["severity_share"])}</b>
              <div class="donut{' empty' if not sum(severity.values()) else ''}" data-total="{metrics["total_risks"]}" data-label="{html.escape(labels['total_risks'])}" style="--danger-end:{degree_stops["danger"]}deg;--warning-end:{degree_stops["warning"]}deg;--amber-end:{degree_stops["amber"]}deg;"></div>
              <ul class="severity-list">{severity_rows}</ul>
            </div>
            <div class="chart-card">
              <b>{html.escape(bars_title)}</b>
              <div class="bars" style="--bar-count:{bar_count}">{bars}</div>
            </div>
          </div>
        </section>
    """
    section_fragments: list[str] = []
    for index, section in enumerate(document["sections"], start=1):
        tone = _report_section_tone(index - 1, str(section["title"]))
        display_number = index if index == 1 else index + 1
        section_fragments.append(
            f"""
            <section class="report-card tone-{tone}" id="section-{index}">
              <div class="section-kicker"><span>{display_number}</span>{html.escape(str(section["title"]))}</div>
              {_report_blocks_to_html(section.get("blocks") or [], visuals or {})}
            </section>
            """
        )
        if index == 1:
            section_fragments.append(chart_section)
    sections_html = "\n".join(section_fragments)
    return f"""<!doctype html>
<html lang="{html.escape(language)}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{project_name} - {html.escape(labels["security_report"])}</title>
  <style>
    :root {{
      --page: #f3f6fa;
      --card: #ffffff;
      --text: #172033;
      --muted: #728096;
      --line: #e8edf4;
      --blue: #0487b8;
      --teal: #18b6a7;
      --danger: #ff4d4f;
      --warning: #ffae22;
      --amber: #f4c400;
      --success: #22c55e;
      --info: #168aad;
      --ink: #111936;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--page);
      color: var(--text);
      font: 14px/1.68 {_REPORT_WEB_FONT_FAMILY};
    }}
    .shell {{ width: min(1120px, calc(100vw - 48px)); margin: 40px auto 64px; }}
    .hero {{
      position: relative;
      min-height: 224px;
      padding: 40px 44px;
      border-radius: 12px;
      overflow: hidden;
      color: #fff;
      background: linear-gradient(128deg, #102c4d 0%, #086487 55%, #159db5 100%);
      box-shadow: 0 18px 38px rgba(5, 73, 112, .14);
    }}
    .brand {{ display: inline-flex; gap: 8px; align-items: center; padding: 5px 10px; border-radius: 5px; background: rgba(255,255,255,.14); font-size: 12px; font-weight: 700; }}
    .brand:before {{ content: "▣"; color: rgba(255,255,255,.9); }}
    .brand:after {{ content: "安全报告"; color: #ffd659; padding-left: 8px; margin-left: 2px; border-left: 1px solid rgba(255,255,255,.24); }}
    h1 {{ margin: 18px 0 8px; max-width: 760px; font-size: 31px; line-height: 1.18; letter-spacing: 0; overflow-wrap: anywhere; }}
    .subtitle {{ max-width: 660px; color: rgba(255,255,255,.82); margin: 0; }}
    .hero-meta {{ display: flex; flex-wrap: wrap; gap: 22px; margin-top: 22px; color: rgba(255,255,255,.76); font-size: 12px; }}
    .hero-meta span:before {{ content: "□"; margin-right: 7px; color: #7fe3ee; }}
    .score {{ position: absolute; right: 44px; top: 55px; width: 108px; height: 108px; border-radius: 50%; display: grid; place-items: center; text-align: center; background: rgba(255,255,255,.08); border: 3px solid rgba(255,255,255,.22); box-shadow: inset 0 0 0 6px rgba(255,255,255,.04); }}
    .score b {{ display: block; font-size: 26px; line-height: 1; }}
    .score span {{ display: block; margin-top: 4px; font-size: 11px; color: rgba(255,255,255,.74); }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 32px 0 34px; }}
    .metric {{ min-height: 144px; position: relative; background: var(--card); border: 1px solid var(--line); border-radius: 9px; padding: 20px 22px; box-shadow: 0 8px 22px rgba(19, 34, 66, .035); }}
    .metric .icon {{ width: 31px; height: 31px; display: grid; place-items: center; border-radius: 7px; margin-bottom: 14px; font-weight: 800; }}
    .metric strong {{ display: block; font-size: 26px; line-height: 1; margin-bottom: 8px; }}
    .metric span {{ color: var(--muted); font-size: 12px; }}
    .metric.danger strong, .metric.danger .delta {{ color: var(--danger); }}
    .metric.warning strong, .metric.warning .delta {{ color: var(--warning); }}
    .metric.amber strong, .metric.amber .delta {{ color: var(--amber); }}
    .metric.success strong, .metric.success .delta {{ color: var(--success); }}
    .metric.info strong, .metric.info .delta {{ color: var(--info); }}
    .metric.danger .icon {{ background: #fff1f0; color: var(--danger); }}
    .metric.warning .icon {{ background: #fff7e6; color: var(--warning); }}
    .metric.amber .icon {{ background: #fffbe6; color: #c69a00; }}
    .metric.success .icon {{ background: #ecfdf3; color: var(--success); }}
    .metric.info .icon {{ background: #e9f7fb; color: var(--info); }}
    .layout {{ display: grid; grid-template-columns: 240px minmax(0, 1fr); gap: 24px; align-items: start; }}
    .toc {{ position: sticky; top: 18px; background: var(--card); border: 1px solid var(--line); border-radius: 9px; padding: 18px; }}
    .toc h3 {{ margin: 0 0 10px; font-size: 13px; }}
    .toc a {{ display: flex; gap: 8px; align-items: center; padding: 9px 10px; border-radius: 5px; color: #3d4b63; text-decoration: none; font-size: 12px; }}
    .toc a:hover, .toc a:first-of-type {{ background: #e7f7fb; color: #04789d; }}
    .toc span {{ width: 18px; height: 18px; display: grid; place-items: center; border-radius: 6px; background: #eef4f8; font-size: 10px; }}
    .report-card {{ background: var(--card); border: 1px solid var(--line); border-radius: 9px; padding: 30px 32px; margin-bottom: 28px; box-shadow: 0 8px 24px rgba(19,34,66,.03); }}
    .mermaid-diagram {{ margin: 14px 0 20px; padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: #f7f9fb; }}
    .mermaid-diagram img {{ display: block; width: 100%; height: auto; object-fit: contain; }}
    .section-kicker {{ display: inline-flex; align-items: center; gap: 10px; margin-bottom: 24px; font-size: 17px; font-weight: 800; }}
    .section-kicker span {{ width: 24px; height: 24px; border-radius: 6px; color: #fff; background: #13a6c6; display: grid; place-items: center; font-size: 12px; }}
    .tone-danger .section-kicker span {{ background: var(--danger); }}
    .tone-warning .section-kicker span {{ background: #f59e0b; }}
    .tone-success .section-kicker span {{ background: var(--success); }}
    .tone-neutral .section-kicker span {{ background: #667386; }}
    .tone-teal .section-kicker span {{ background: #12aa91; }}
    .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-bottom: 0; }}
    .chart-card {{ border: 1px solid var(--line); background: #f9fbfd; border-radius: 9px; padding: 20px; min-height: 320px; }}
    .donut {{ width: 156px; height: 156px; border-radius: 50%; margin: 28px auto 20px; background: conic-gradient(var(--danger) 0deg var(--danger-end), var(--warning) var(--danger-end) var(--warning-end), var(--amber) var(--warning-end) var(--amber-end), var(--success) var(--amber-end) 360deg); position: relative; }}
    .donut.empty {{ background: #e8edf4; }}
    .donut:after {{ content: attr(data-total) "\\A" attr(data-label); white-space: pre; position: absolute; inset: 28px; border-radius: 50%; background: #fff; display: grid; place-items: center; text-align: center; font-weight: 800; color: #1d2a3d; }}
    .severity-list {{ list-style: none; margin: 10px 0 0; padding: 0; }}
    .severity-list li {{ display: flex; justify-content: space-between; padding: 6px 0; color: var(--muted); }}
    .bars {{ display: grid; grid-template-columns: repeat(var(--bar-count, 4), 1fr); gap: 10px; height: 244px; align-items: end; padding: 30px 8px 0; border-bottom: 1px solid #dce4ec; }}
    .bar {{ text-align: center; color: var(--muted); font-size: 11px; }}
    .bar i {{ display: block; width: min(32px, 68%); min-height: 4px; margin: 0 auto 8px; border-radius: 3px 3px 0 0; background: var(--bar-color, #ff4d4f); }}
    table {{ width: 100%; table-layout: fixed; border-collapse: collapse; margin: 12px 0 18px; overflow: hidden; border-radius: 8px; font-size: 12px; }}
    th {{ background: #f1f4f8; color: #29364a; font-weight: 700; text-align: left; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px 12px; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }}
    tr:last-child td {{ border-bottom: 0; }}
    h2, h3, h4 {{ color: #162033; line-height: 1.35; }}
    h3 {{ margin: 26px 0 12px; font-size: 16px; }}
    p {{ margin: 8px 0; }}
    ul {{ margin: 8px 0 14px; padding-left: 20px; }}
    li {{ margin: 4px 0; }}
    blockquote {{ margin: 12px 0; padding: 12px 14px; border-left: 4px solid #10a4bd; background: #eefaff; color: #365066; border-radius: 8px; }}
    pre {{ max-width: 100%; margin: 12px 0 18px; padding: 16px; overflow-x: hidden; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; border-radius: 8px; background: var(--ink); color: #dfe7ff; font: 12px/1.55 "SFMono-Regular", Consolas, monospace; }}
    pre.numbered-code {{ padding: 10px 0; white-space: normal; }}
    .code-row {{ display: grid; grid-template-columns: max-content minmax(0, 1fr); min-width: 0; }}
    .code-row.risk {{ background: rgba(255, 174, 34, .16); }}
    .code-line-number {{ min-width: 5.5em; padding: 2px 12px 2px 10px; color: #8ea0c5; text-align: right; user-select: none; border-right: 1px solid rgba(255,255,255,.12); }}
    .code-source {{ min-width: 0; padding: 2px 14px; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }}
    .code-evidence {{ margin: 12px 0 20px; border-radius: 8px; overflow: hidden; }}
    .code-evidence .code-label {{ padding: 8px 12px; font-size: 11px; font-weight: 700; }}
    .code-evidence.vulnerable {{ border: 1px solid #ffd6d2; }}
    .code-evidence.vulnerable .code-label {{ color: #d9363e; background: #fff1f0; }}
    .code-evidence.fixed {{ border: 1px solid #c8f0d8; }}
    .code-evidence.fixed .code-label {{ color: #168f5b; background: #ecfdf3; }}
    .code-evidence pre {{ margin: 0; border-radius: 0; }}
    code {{ max-width: 100%; font-family: "SFMono-Regular", Consolas, monospace; overflow-wrap: anywhere; word-break: break-word; }}
    .footer {{ margin-top: 28px; color: var(--muted); font-size: 12px; text-align: center; }}
    @media print {{
      body {{ background: #fff; }}
      .shell {{ width: auto; margin: 0; }}
      .toc {{ display: none; }}
      .layout {{ display: block; }}
      .report-card, .metric, .hero {{ box-shadow: none; break-inside: avoid; }}
    }}
    @media (max-width: 760px) {{
      .shell {{ width: min(100% - 24px, 1120px); margin-top: 12px; }}
      .layout {{ display: block; }}
      .toc {{ display: none; }}
      .report-card {{ padding: 18px 16px; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .chart-grid {{ grid-template-columns: 1fr; }}
      .code-line-number {{ min-width: 4.5em; padding-left: 6px; padding-right: 8px; }}
      .code-source {{ padding-left: 10px; padding-right: 8px; }}
    }}
  </style>
</head>
<body data-report-template="secure-code-scan-v1">
  <main class="shell" aria-label="{html.escape(visual_labels['report_badge'])}">
    <header class="hero">
      <div class="brand">{html.escape(labels["brand"])} · {html.escape(visual_labels["report_badge"])}</div>
      <h1>{project_name}</h1>
      <p class="subtitle">{html.escape(visual_labels["basis"])} · {title}</p>
      <div class="hero-meta">
        {hero_metadata}
      </div>
      <div class="score"><b>{score}</b><span>{html.escape(labels["score"])}</span></div>
    </header>
    <div class="metrics">{metric_cards}</div>
    <div class="layout">
      <aside class="toc"><h3>{html.escape(labels["toc"])}</h3>{toc_items}</aside>
      <div>
        {sections_html}
      </div>
    </div>
    <footer class="footer">© {datetime.now().year} SecFlow - {html.escape(labels["footer"])}</footer>
  </main>
</body>
</html>
"""


def _parse_report_document(markdown: str, metadata: dict[str, Any]) -> dict[str, Any]:
    lines = markdown.splitlines()
    title = next((line.lstrip("#").strip() for line in lines if line.startswith("# ")), "依赖漏洞与代码漏洞分析报告")
    metrics = _extract_report_metrics(markdown, metadata)
    sections: list[dict[str, str]] = []
    current_title = ""
    current_lines: list[str] = []
    for line in lines:
        match = re.match(r"^##\s+(?:\d+[.)、]?\s*)?(.+?)\s*$", line)
        if match:
            if current_title:
                content = "\n".join(current_lines).strip()
                sections.append({"title": current_title, "content": content, "blocks": _parse_report_blocks(content)})
            current_title = match.group(1).strip()
            current_lines = []
            continue
        if current_title:
            current_lines.append(line)
    if current_title:
        content = "\n".join(current_lines).strip()
        sections.append({"title": current_title, "content": content, "blocks": _parse_report_blocks(content)})
    if not sections:
        sections.append({"title": "扫描报告", "content": markdown, "blocks": _parse_report_blocks(markdown)})
    project_name = _infer_report_project_name(metadata) or _project_from_title_or_file(title, metadata)
    return {
        "title": title,
        "project_name": project_name,
        "metrics": metrics,
        "sections": sections,
        "content_model": "secflow.report-blocks/v1",
    }


def _parse_report_blocks(content: str) -> list[dict[str, Any]]:
    """Normalize Markdown once so every format MCP consumes the same JSON blocks."""

    lines = str(content or "").splitlines()
    blocks: list[dict[str, Any]] = []
    index = 0
    previous_text = ""
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped == "---" or stripped.startswith("<!--"):
            index += 1
            continue
        image = re.fullmatch(
            r"!\[([^\]]*)\]\(data:image/(png|jpeg);base64,([A-Za-z0-9+/=]+)\)",
            stripped,
        )
        if image:
            payload = base64.b64decode(image.group(3), validate=True)
            blocks.append(
                {
                    "type": "diagram",
                    "title": image.group(1),
                    "media_type": f"image/{image.group(2)}",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            index += 1
            continue
        heading = re.match(r"^(#{3,6})\s+(.+)$", stripped)
        if heading:
            previous_text = _plain_report_text(heading.group(2))
            blocks.append(
                {"type": "heading", "level": len(heading.group(1)) - 1, "text": previous_text}
            )
            index += 1
            continue
        if stripped.startswith("```"):
            language = stripped[3:].strip()
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            lower_previous = previous_text.lower()
            variant = "vulnerable" if any(
                token in previous_text for token in ("漏洞代码", "证据代码", "風險程式碼")
            ) or "vulnerable" in lower_previous else (
                "fixed" if "修复" in previous_text or "fixed" in lower_previous else ""
            )
            blocks.append(
                {
                    "type": "code",
                    "language": language,
                    "lines": code_lines,
                    "variant": variant,
                    "risk_line": _code_label_risk_line(previous_text),
                }
            )
            index += 1
            continue
        if stripped.startswith("|"):
            table_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index].strip())
                index += 1
            rows = [
                _split_markdown_table_row(line)
                for line in table_lines
                if not all(set(cell) <= {"-", ":", " "} for cell in _split_markdown_table_row(line))
            ]
            if rows:
                blocks.append({"type": "table", "columns": rows[0], "rows": rows[1:]})
            continue
        if stripped.startswith("- "):
            items: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("- "):
                items.append(_plain_report_text(lines[index].strip()[2:]))
                index += 1
            blocks.append({"type": "bullet_list", "items": items})
            if items:
                previous_text = items[-1]
            continue
        if re.match(r"^\d+[.)]\s+", stripped):
            items = []
            while index < len(lines) and re.match(r"^\d+[.)]\s+", lines[index].strip()):
                items.append(_plain_report_text(re.sub(r"^\d+[.)]\s+", "", lines[index].strip())))
                index += 1
            blocks.append({"type": "numbered_list", "items": items})
            if items:
                previous_text = items[-1]
            continue
        if stripped.startswith("> "):
            previous_text = _plain_report_text(stripped[2:])
            blocks.append({"type": "quote", "text": previous_text})
        else:
            previous_text = _plain_report_text(stripped)
            blocks.append({"type": "paragraph", "text": previous_text})
        index += 1
    return blocks


def _plain_report_text(value: Any) -> str:
    clean = re.sub(r"!\[([^]]*)\]\([^)]+\)", r"\1", str(value or ""))
    clean = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", clean)
    clean = re.sub(r"`([^`]+)`", r"\1", clean)
    clean = re.sub(r"\*\*([^*]+)\*\*", r"\1", clean)
    return clean.replace("<br>", "\n").strip()


def _validated_render_document(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Report JSON is missing the render document")
    sections = value.get("sections")
    metrics = value.get("metrics")
    if not isinstance(sections, list) or not sections or not isinstance(metrics, dict):
        raise ValueError("Report JSON render document is incomplete")
    normalized_sections = []
    for section in sections:
        if not isinstance(section, dict):
            raise ValueError("Report JSON contains an invalid section")
        title = str(section.get("title") or "").strip()
        if not title:
            raise ValueError("Report JSON section title is empty")
        if title in _DEPRECATED_REPORT_SECTIONS:
            continue
        content = re.sub(
            r"(?mi)^\s*-\s*(?:扫描模式|掃描模式|Scan mode|Mode|スキャンモード|스캔 모드)\s*[：:].*\n?",
            "",
            str(section.get("content") or ""),
        ).strip()
        supplied_blocks = section.get("blocks")
        blocks = (
            _validated_report_blocks(supplied_blocks)
            if isinstance(supplied_blocks, list)
            else _parse_report_blocks(content)
        )
        normalized_sections.append({"title": title, "content": content, "blocks": blocks})
    if not normalized_sections:
        raise ValueError("Report JSON render document has no visible sections")
    return {
        **value,
        "title": str(value.get("title") or "SecFlow 安全报告"),
        "project_name": str(value.get("project_name") or "SecFlow"),
        "metrics": {str(key): item for key, item in metrics.items()},
        "sections": normalized_sections,
        "content_model": "secflow.report-blocks/v1",
    }


def _infer_report_code_variants(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    previous_text = ""
    rendered: list[dict[str, Any]] = []
    for block in blocks:
        item = dict(block)
        kind = str(item.get("type") or "")
        if kind in {"heading", "paragraph", "quote"}:
            previous_text = str(item.get("text") or "")
        elif kind in {"bullet_list", "numbered_list"}:
            values = [str(value) for value in item.get("items") or []]
            if values:
                previous_text = values[-1]
        elif kind == "code" and not str(item.get("variant") or ""):
            lowered = previous_text.casefold()
            if any(token in previous_text for token in ("漏洞代码", "证据代码", "風險程式碼")) or "vulnerable" in lowered:
                item["variant"] = "vulnerable"
            elif "修复" in previous_text or "修復" in previous_text or "fixed" in lowered:
                item["variant"] = "fixed"
        rendered.append(item)
    return rendered


def _validated_report_blocks(value: list[Any]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for block in value:
        if not isinstance(block, dict):
            raise ValueError("Report JSON contains an invalid content block")
        kind = str(block.get("type") or "")
        if kind == "heading":
            blocks.append(
                {
                    "type": kind,
                    "level": min(3, max(1, int(block.get("level") or 2))),
                    "text": str(block.get("text") or ""),
                }
            )
        elif kind in {"paragraph", "quote"}:
            blocks.append({"type": kind, "text": str(block.get("text") or "")})
        elif kind in {"bullet_list", "numbered_list"}:
            blocks.append({"type": kind, "items": [str(item) for item in block.get("items") or []]})
        elif kind == "code":
            blocks.append(
                {
                    "type": kind,
                    "language": str(block.get("language") or ""),
                    "lines": [str(line) for line in block.get("lines") or []],
                    "variant": str(block.get("variant") or ""),
                    "risk_line": _positive_report_line(block.get("risk_line")),
                }
            )
        elif kind == "table":
            blocks.append(
                {
                    "type": kind,
                    "columns": [str(item) for item in block.get("columns") or []],
                    "rows": [
                        [str(cell) for cell in row]
                        for row in block.get("rows") or []
                        if isinstance(row, list)
                    ],
                }
            )
        elif kind == "diagram":
            digest = str(block.get("sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Report JSON diagram block has an invalid checksum")
            blocks.append(
                {
                    "type": kind,
                    "title": str(block.get("title") or "Diagram"),
                    "media_type": str(block.get("media_type") or "image/jpeg"),
                    "sha256": digest,
                }
            )
        else:
            raise ValueError(f"Report JSON contains an unsupported content block: {kind}")
    return blocks


def _render_document_severity(
    document: dict[str, Any], markdown: str, metadata: dict[str, Any]
) -> dict[str, int]:
    structured = document.get("severity") if isinstance(document.get("severity"), dict) else {}
    if structured:
        return {key: _non_negative_int(structured.get(key)) for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    return _severity_distribution(markdown, metadata)


def _project_from_title_or_file(title: str, metadata: dict[str, Any]) -> str:
    stem = Path(str(metadata.get("file_name") or "")).stem
    if stem and not stem.startswith("report-"):
        return stem.rsplit("_", 1)[0] or stem
    return title or "SecFlow 安全报告"


def _extract_report_metrics(markdown: str, metadata: dict[str, Any]) -> dict[str, Any]:
    structured = metadata.get("report_metrics") if isinstance(metadata.get("report_metrics"), dict) else {}
    if structured:
        severity = structured.get("severity") if isinstance(structured.get("severity"), dict) else {}
        critical = _non_negative_int(severity.get("CRITICAL"))
        high = _non_negative_int(severity.get("HIGH"))
        medium = _non_negative_int(severity.get("MEDIUM"))
        dependency_vulnerabilities = _non_negative_int(structured.get("dependency_vulnerabilities"))
        code_findings = _non_negative_int(structured.get("code_findings"))
        return {
            "generated_at": structured.get("generated_at") or metadata.get("created_at") or "-",
            "attachments": _non_negative_int(structured.get("attachments")),
            "dependencies": _non_negative_int(structured.get("dependencies")),
            "dependency_vulnerabilities": dependency_vulnerabilities,
            "code_findings": code_findings,
            "high_risk": _non_negative_int(structured.get("high_risk"), critical + high),
            "medium_risk": _non_negative_int(structured.get("medium_risk"), medium),
            "total_risks": _non_negative_int(
                structured.get("total_risks"), dependency_vulnerabilities + code_findings
            ),
        }

    table = _extract_markdown_summary_table(markdown)
    dependency_vulnerabilities = _metric_int_any(
        table,
        ["依赖漏洞", "Dependency vulnerabilities", "依存関係脆弱性", "의존성 취약점"],
        metadata.get("vulnerability_count"),
    )
    code_findings = _metric_int_any(
        table,
        ["代码漏洞", "Code findings", "コード脆弱性", "코드 취약점"],
        metadata.get("finding_count"),
    )
    attachments = _metric_int_any(table, ["附件数量", "Attachments", "添付数", "첨부 수"], 0)
    dependencies = _metric_int_any(
        table,
        ["识别依赖", "Identified dependencies", "識別した依存関係", "식별한 의존성"],
        0,
    )
    severity = _severity_distribution(markdown)
    high_risk = severity["CRITICAL"] + severity["HIGH"]
    medium_risk = severity["MEDIUM"]
    total_risks = dependency_vulnerabilities + code_findings
    return {
        "generated_at": _table_value_any(table, ["生成时间", "Generated at", "生成時間", "생성 시간"])
        or metadata.get("created_at")
        or "-",
        "attachments": attachments,
        "dependencies": dependencies,
        "dependency_vulnerabilities": dependency_vulnerabilities,
        "code_findings": code_findings,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "total_risks": total_risks,
    }


def _extract_markdown_summary_table(markdown: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in markdown.splitlines():
        if not line.startswith("|"):
            continue
        cells = _split_markdown_table_row(line)
        if len(cells) < 2 or cells[0] in {"扫描项", "掃描項", "Item", "項目", "항목", "---"} or set(cells[0]) <= {"-", " "}:
            continue
        rows[cells[0]] = cells[1]
    return rows


def _metric_int(table: dict[str, str], key: str, fallback: Any) -> int:
    value = table.get(key, fallback)
    match = re.search(r"-?\d+", str(value or ""))
    if not match:
        return 0
    return max(0, int(match.group(0)))


def _metric_int_any(table: dict[str, str], keys: list[str], fallback: Any) -> int:
    value = _table_value_any(table, keys)
    return _metric_int({"value": value}, "value", fallback)


def _table_value_any(table: dict[str, str], keys: list[str]) -> str:
    for key in keys:
        if key in table:
            return table[key]
    return ""


def _non_negative_int(value: Any, fallback: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return max(0, int(fallback))


def _severity_distribution(markdown: str, metadata: dict[str, Any] | None = None) -> dict[str, int]:
    report_charts = (metadata or {}).get("report_charts") if isinstance((metadata or {}).get("report_charts"), dict) else {}
    severity_ring = report_charts.get("severity_ring") if isinstance(report_charts.get("severity_ring"), list) else []
    if severity_ring:
        chart_values = {
            str(item.get("severity") or item.get("id") or "").strip().upper(): _non_negative_int(item.get("value"))
            for item in severity_ring
            if isinstance(item, dict)
        }
        if any(chart_values.values()):
            return {key: chart_values.get(key, 0) for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    structured = (metadata or {}).get("report_metrics") if isinstance((metadata or {}).get("report_metrics"), dict) else {}
    structured_severity = structured.get("severity") if isinstance(structured.get("severity"), dict) else {}
    if structured_severity:
        return {
            key: _non_negative_int(structured_severity.get(key))
            for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    severity_pattern = r"(?:严重等级|Severity|深刻度|심각도)[：:]\s*([A-Za-z\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7a3]+)"
    for raw in re.findall(severity_pattern, markdown, flags=re.IGNORECASE):
        key = _normalize_report_severity(raw)
        if key:
            severities[key] += 1
    if not any(severities.values()):
        for priority in re.findall(r"(?:优先级|Priority|優先度|우선순위)[：:]\s*(P[0-3])", markdown, flags=re.IGNORECASE):
            key = {"P0": "CRITICAL", "P1": "HIGH", "P2": "MEDIUM", "P3": "LOW"}.get(priority.upper())
            if key:
                severities[key] += 1
    return severities


def _risk_score(metrics: dict[str, Any], severity: dict[str, int]) -> int:
    score = (
        int(severity.get("CRITICAL") or 0) * 22
        + int(severity.get("HIGH") or 0) * 14
        + int(severity.get("MEDIUM") or 0) * 7
        + int(metrics.get("code_findings") or 0) * 4
        + int(metrics.get("dependency_vulnerabilities") or 0) * 3
    )
    return max(0, min(100, score))


def _share_degrees(severity: dict[str, int], key: str) -> int:
    total = sum(int(value) for value in severity.values()) or 1
    return int(round((int(severity.get(key) or 0) / total) * 360))


def _severity_degree_stops(severity: dict[str, int]) -> dict[str, int]:
    danger = _share_degrees(severity, "CRITICAL")
    warning = danger + _share_degrees(severity, "HIGH")
    amber = warning + _share_degrees(severity, "MEDIUM")
    return {"danger": danger, "warning": warning, "amber": min(360, amber)}


def _severity_percentage(value: Any, total: Any) -> str:
    try:
        count = max(0, int(value))
        denominator = max(0, int(total))
    except (TypeError, ValueError):
        return "0.0%"
    return f"{(count / denominator * 100) if denominator else 0.0:.1f}%"


def _severity_bars(severity: dict[str, int]) -> str:
    labels = [("CRITICAL", "严重"), ("HIGH", "高危"), ("MEDIUM", "中危"), ("LOW", "低危")]
    max_value = max([severity.get(key, 0) for key, _ in labels] + [1])
    return "\n".join(
        f'<div class="bar"><i style="height:{max(4, int((severity.get(key, 0) / max_value) * 132))}px"></i><b>{severity.get(key, 0)}</b><br>{label}</div>'
        for key, label in labels
    )


def _report_risk_bars_html(
    metadata: dict[str, Any],
    severity: dict[str, int],
    title: str,
    severity_names: dict[str, str],
) -> tuple[str, str, int]:
    charts = metadata.get("report_charts") if isinstance(metadata.get("report_charts"), dict) else {}
    risk_bars = [item for item in charts.get("risk_bars") or [] if isinstance(item, dict)]
    entries: list[tuple[str, int]] = []
    for item in risk_bars[:6]:
        label = str(item.get("label") or item.get("id") or "Risk").strip()
        entries.append((label, _non_negative_int(item.get("value"))))
    if not entries:
        entries = [(severity_names[key], _non_negative_int(severity.get(key))) for key in severity_names]
    maximum = max([value for _, value in entries] + [1])
    palette = ("#ff4d4f", "#ff7a45", "#ff9f1c", "#f4c400", "#22b8a7", "#1aa3c8")
    rendered = "\n".join(
        f'<div class="bar"><b>{value}</b><i style="height:{max(4, int(value / maximum * 178))}px;--bar-color:{palette[index % len(palette)]}"></i>{html.escape(label[:14])}</div>'
        for index, (label, value) in enumerate(entries)
    )
    return rendered, title, max(1, len(entries))


def _metric_card(label: str, value: Any, tone: str, icon: str = "!") -> str:
    return f"""
    <div class="metric {tone}">
      <div class="icon">{html.escape(icon)}</div>
      <strong>{html.escape(str(value))}</strong>
      <span>{html.escape(label)}</span>
    </div>
    """


def _report_blocks_to_html(blocks: list[dict[str, Any]], visuals: dict[str, Any]) -> str:
    blocks = _infer_report_code_variants(blocks)
    diagrams = {
        str(item.get("image_sha256") or ""): item
        for item in visuals.get("diagrams") or []
        if isinstance(item, dict)
    }
    rendered: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        kind = str(block.get("type") or "")
        if kind == "heading":
            level = min(6, max(3, int(block.get("level") or 2) + 1))
            rendered.append(f"<h{level}>{html.escape(str(block.get('text') or ''))}</h{level}>")
        elif kind == "paragraph":
            rendered.append(f"<p>{html.escape(str(block.get('text') or '')).replace(chr(10), '<br>')}</p>")
        elif kind == "quote":
            rendered.append(f"<blockquote>{html.escape(str(block.get('text') or '')).replace(chr(10), '<br>')}</blockquote>")
        elif kind in {"bullet_list", "numbered_list"}:
            tag = "ul" if kind == "bullet_list" else "ol"
            items = "".join(
                f"<li>{html.escape(str(item)).replace(chr(10), '<br>')}</li>"
                for item in block.get("items") or []
            )
            rendered.append(f"<{tag}>{items}</{tag}>")
        elif kind == "code":
            code_lines = [str(line) for line in block.get("lines") or []]
            if str(block.get("language") or "").casefold() == "mermaid":
                columns, rows = _mermaid_structured_rows("\n".join(code_lines))
                head_html = "".join(f"<th>{html.escape(value)}</th>" for value in columns)
                body_html = "".join(
                    "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
                    for row in rows
                )
                rendered.append(f"<table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>")
            else:
                rendered.append(
                    _html_code_block(
                        code_lines,
                        str(block.get("variant") or ""),
                        _positive_report_line(block.get("risk_line")),
                    )
                )
        elif kind == "table":
            columns = [str(item) for item in block.get("columns") or []]
            rows = [row for row in block.get("rows") or [] if isinstance(row, list)]
            head_html = "".join(f"<th>{html.escape(value)}</th>" for value in columns)
            body_html = "".join(
                "<tr>" + "".join(f"<td>{html.escape(str(cell)).replace(chr(10), '<br>')}</td>" for cell in row) + "</tr>"
                for row in rows
            )
            rendered.append(f"<table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>")
        elif kind == "diagram":
            digest = str(block.get("sha256") or "")
            diagram = diagrams.get(digest)
            if not diagram:
                raise ValueError("HTML report JSON references a missing diagram")
            media_type = str(diagram.get("image_media_type") or "")
            if media_type not in {"image/jpeg", "image/png"}:
                raise ValueError("HTML report JSON diagram media type is unsupported")
            title = str(block.get("title") or diagram.get("title") or "Diagram")
            rendered.append(
                '<figure class="mermaid-diagram">'
                f'<img src="data:{media_type};base64,{diagram.get("image_base64") or ""}" '
                f'alt="{html.escape(title, quote=True)}" />'
                f"<figcaption>{html.escape(title)}</figcaption>"
                "</figure>"
            )
    return "\n".join(rendered)


def _markdown_fragment_to_html(markdown: str) -> str:
    lines = markdown.splitlines()
    result: list[str] = []
    in_list = False
    in_code = False
    code_lines: list[str] = []
    code_class = ""
    code_risk_line: int | None = None
    table_lines: list[str] = []
    previous_text = ""

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            result.append("</ul>")
            in_list = False

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        result.append(_markdown_table_to_html(table_lines))
        table_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                result.append(_html_code_block(code_lines, code_class, code_risk_line))
                in_code = False
                code_lines = []
                code_class = ""
                code_risk_line = None
            else:
                close_list()
                flush_table()
                in_code = True
                code_lines = []
                lower_previous = previous_text.lower()
                if "漏洞代码" in previous_text or "vulnerable" in lower_previous:
                    code_class = "vulnerable"
                elif "修复" in previous_text or "fixed" in lower_previous:
                    code_class = "fixed"
                code_risk_line = _code_label_risk_line(previous_text)
            continue
        if in_code:
            code_lines.append(line)
            continue
        if stripped.startswith("|"):
            close_list()
            table_lines.append(stripped)
            continue
        flush_table()
        if not stripped:
            close_list()
            continue
        image_match = re.fullmatch(
            r"!\[([^\]]*)\]\((data:image/(?:png|jpeg);base64,[A-Za-z0-9+/=]+)\)",
            stripped,
        )
        if image_match:
            close_list()
            result.append(
                f'<figure class="mermaid-diagram"><img src="{image_match.group(2)}" '
                f'alt="{html.escape(image_match.group(1), quote=True)}" /></figure>'
            )
            continue
        if (
            stripped == _REPORT_STYLE_MARKER
            or stripped.startswith("<!-- secflow-report-style:")
            or stripped.startswith("<!-- secflow-mermaid-source:")
        ):
            continue
        if stripped == "---":
            close_list()
            result.append("<hr>")
            continue
        heading = re.match(r"^(#{3,6})\s+(.+)$", stripped)
        if heading:
            close_list()
            level = min(6, len(heading.group(1)) + 1)
            result.append(f"<h{level}>{_inline_markdown(heading.group(2))}</h{level}>")
            previous_text = heading.group(2)
            continue
        if stripped.startswith("> "):
            close_list()
            result.append(f"<blockquote>{_inline_markdown(stripped[2:])}</blockquote>")
            previous_text = stripped[2:]
            continue
        if stripped.startswith("- "):
            if not in_list:
                result.append("<ul>")
                in_list = True
            item = stripped[2:].strip()
            result.append(f"<li>{_inline_markdown(item)}</li>")
            previous_text = item
            continue
        close_list()
        result.append(f"<p>{_inline_markdown(stripped)}</p>")
        previous_text = stripped
    close_list()
    flush_table()
    if in_code:
        result.append(_html_code_block(code_lines, code_class, code_risk_line))
    return "\n".join(result)


def _html_code_block(code_lines: list[str], code_class: str, risk_line: int | None) -> str:
    numbered = _parse_numbered_code_lines(code_lines)
    if numbered is None:
        body = f'<pre class="{code_class}"><code>{html.escape(chr(10).join(code_lines))}</code></pre>'
    else:
        classes = " ".join(value for value in (code_class, "numbered-code") if value)
        rows = []
        for number, source in numbered:
            row_class = "code-row risk" if number == risk_line else "code-row"
            rows.append(
                f'<span class="{row_class}"><span class="code-line-number" aria-hidden="true">{number}</span>'
                f'<span class="code-source">{html.escape(source) or "&#8203;"}</span></span>'
            )
        body = f'<pre class="{classes}"><code>{"".join(rows)}</code></pre>'
    if code_class in {"vulnerable", "fixed"}:
        label = "修复建议代码" if code_class == "fixed" else "存在漏洞的代码"
        return f'<div class="code-evidence {code_class}"><div class="code-label">{label}</div>{body}</div>'
    return body


def _code_label_risk_line(value: str) -> int | None:
    match = re.search(r"(?:风险点为第|risk\s+line|危険行|위험\s*줄)\s*(\d+)", str(value), flags=re.IGNORECASE)
    return _positive_report_line(match.group(1)) if match else None


def _parse_numbered_code_lines(lines: list[str]) -> list[tuple[int, str]] | None:
    parsed: list[tuple[int, str]] = []
    for line in lines:
        match = re.match(r"^\s*(\d+)\s+\|(?:\s(.*)|$)", line)
        if not match:
            return None
        parsed.append((int(match.group(1)), match.group(2) or ""))
    return parsed or None


def _markdown_table_to_html(lines: list[str]) -> str:
    rows = []
    for line in lines:
        cells = _split_markdown_table_row(line)
        if not cells or all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    if not rows:
        return ""
    header, body = rows[0], rows[1:]
    head_html = "".join(f"<th>{_inline_markdown(cell)}</th>" for cell in header)
    body_html = "\n".join(
        "<tr>" + "".join(f"<td>{_inline_markdown(cell)}</td>" for cell in row) + "</tr>"
        for row in body
    )
    return f"<table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>"


def _split_markdown_table_row(line: str) -> list[str]:
    placeholder = "\x00SECFLOW_PIPE\x00"
    protected = line.strip().strip("|").replace("\\|", placeholder)
    return [cell.strip().replace(placeholder, "|") for cell in protected.split("|")]


def _inline_markdown(value: str) -> str:
    escaped = html.escape(str(value))
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"(https?://[^\s<]+)", r'<a href="\1">\1</a>', escaped)
    return escaped


def _write_pdf_report(
    path: Path,
    markdown: str,
    metadata: dict[str, Any],
    *,
    document: dict[str, Any] | None = None,
    visuals: dict[str, Any] | None = None,
) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics.shapes import Circle, Drawing, Rect, String, Wedge
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import Image as PlatypusImage
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("ReportLab is required for PDF export") from exc

    report_template = metadata.get("report_template") if isinstance(metadata.get("report_template"), dict) else {}
    template_tokens = report_template.get("style_tokens") if isinstance(report_template.get("style_tokens"), dict) else {}
    template_primary = _report_color_token(template_tokens.get("primary"), "#112C53")
    template_accent = _report_color_token(template_tokens.get("accent"), "#0BA3C4")
    template_text = _report_color_token(template_tokens.get("text"), "#15233A")
    language = _normalize_report_language(
        metadata.get("language") or (metadata.get("report_metrics") or {}).get("language")
    )
    labels = _report_export_labels(language)
    visual_labels = _report_visual_labels(language)
    font_name = _register_reportlab_cjk_font(pdfmetrics, TTFont, UnicodeCIDFont, language)
    latin_font_name = _register_reportlab_latin_font(pdfmetrics, TTFont)
    document = _validated_render_document(document) if document is not None else _parse_report_document(markdown, metadata)
    metrics = document["metrics"]
    severity = _render_document_severity(document, markdown, metadata)
    styles = getSampleStyleSheet()
    base = ParagraphStyle(
        "SecFlowBase",
        parent=styles["Normal"],
        fontName=font_name,
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor(template_text),
        splitLongWords=1,
        spaceAfter=5,
    )
    title_style = ParagraphStyle(
        "SecFlowTitle",
        parent=base,
        fontSize=20,
        leading=25,
        textColor=colors.white,
        alignment=TA_LEFT,
        spaceBefore=8,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "SecFlowSubtitle",
        parent=base,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#d8eef8"),
        alignment=TA_LEFT,
    )
    section_style = ParagraphStyle(
        "SecFlowSection",
        parent=base,
        fontSize=14,
        leading=18,
        textColor=colors.HexColor(template_primary),
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=1,
    )
    code_style = ParagraphStyle(
        "SecFlowCode",
        parent=base,
        fontName=font_name,
        fontSize=7.2,
        leading=9.5,
        textColor=colors.HexColor("#dce6ff"),
        backColor=colors.HexColor("#111936"),
        borderPadding=7,
        spaceBefore=4,
        spaceAfter=8,
        splitLongWords=1,
    )
    small = ParagraphStyle("SecFlowSmall", parent=base, fontSize=8, leading=11, textColor=colors.HexColor("#617089"))

    story: list[Any] = []
    score = _risk_score(metrics, severity)
    score_drawing = Drawing(72, 72)
    score_drawing.add(
        Circle(
            36,
            36,
            30,
            fillColor=colors.Color(1, 1, 1, alpha=0.06),
            strokeColor=colors.Color(1, 1, 1, alpha=0.35),
            strokeWidth=2.2,
        )
    )
    score_drawing.add(
        String(
            36,
            37,
            str(score),
            textAnchor="middle",
            fontName=latin_font_name,
            fontSize=19,
            fillColor=colors.white,
        )
    )
    score_drawing.add(
        String(
            36,
            24,
            labels["score"],
            textAnchor="middle",
            fontName=font_name,
            fontSize=6.5,
            fillColor=colors.HexColor("#d8eef8"),
        )
    )
    hero_meta = " · ".join(_report_hero_metadata(metadata, metrics, language, labels))
    hero_left = [
        Paragraph(
            f'<font size="7.5" color="#ffffff"><b>{_pdf_plain_text(labels["brand"] + " · " + visual_labels["report_badge"], latin_font_name)}</b></font>',
            subtitle_style,
        ),
        Paragraph(_pdf_plain_text(document["project_name"], latin_font_name), title_style),
        Paragraph(
            _pdf_plain_text(f"{visual_labels['basis']} · {document['title']}", latin_font_name),
            subtitle_style,
        ),
        Spacer(1, 7),
        Paragraph(_pdf_plain_text(hero_meta, latin_font_name), subtitle_style),
    ]
    hero = Table(
        [[hero_left, score_drawing]],
        colWidths=[136 * mm, 34 * mm],
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(template_primary)),
            ("BOX", (0, 0), (-1, -1), 0, colors.HexColor(template_primary)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (0, 0), 16),
            ("RIGHTPADDING", (0, 0), (0, 0), 8),
            ("LEFTPADDING", (1, 0), (1, 0), 4),
            ("RIGHTPADDING", (1, 0), (1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ],
        cornerRadii=[7, 7, 7, 7],
    )
    story.append(hero)
    story.append(Spacer(1, 8))
    metric_rows = [
        [
            _pdf_metric(labels["critical_high"], metrics["high_risk"], "#ff4d4f", Paragraph, base, latin_font_name),
            _pdf_metric(labels["medium"], metrics["medium_risk"], "#ffae22", Paragraph, base, latin_font_name),
            _pdf_metric(visual_labels["low"], severity["LOW"], "#f4b400", Paragraph, base, latin_font_name),
            _pdf_metric(visual_labels["scanned_files"], metrics["attachments"], template_accent, Paragraph, base, latin_font_name),
        ]
    ]
    metric_table = Table(metric_rows, colWidths=[42.5 * mm] * 4)
    metric_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e8edf4")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e8edf4")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(metric_table)
    story.append(Spacer(1, 8))
    for index, section in enumerate(document["sections"], start=1):
        display_number = index if index == 1 else index + 1
        tone = _report_section_tone(index - 1, str(section["title"]))
        story.append(Spacer(1, 9))
        story.append(
            _pdf_section_header(
                display_number,
                str(section["title"]),
                tone,
                Table,
                TableStyle,
                Paragraph,
                base,
                colors,
                latin_font_name,
            )
        )
        story.extend(
            _report_blocks_to_pdf_flowables(
                section.get("blocks") or [],
                visuals or {},
                base,
                code_style,
                Table,
                TableStyle,
                Paragraph,
                colors,
                latin_font_name,
                PlatypusImage,
            )
        )
        if index == 1:
            story.append(Spacer(1, 12))
            story.append(
                _pdf_section_header(
                    2,
                    visual_labels["distribution"],
                    "info",
                    Table,
                    TableStyle,
                    Paragraph,
                    base,
                    colors,
                    latin_font_name,
                )
            )
            story.append(
                _pdf_distribution_charts(
                    severity,
                    metadata,
                    visual_labels,
                    Drawing,
                    Circle,
                    Wedge,
                    VerticalBarChart,
                    Rect,
                    String,
                    Table,
                    TableStyle,
                    Paragraph,
                    base,
                    colors,
                    font_name,
                    latin_font_name,
                    language,
                )
            )
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=document["title"],
        author="SecFlow",
    )
    project_name = document["project_name"]

    def decorate_page(canvas: Any, doc_template: Any) -> None:
        _draw_pdf_page_chrome(
            canvas,
            doc_template,
            font_name=font_name,
            latin_font_name=latin_font_name,
            project_name=project_name,
            page_label=labels["page"],
            page_size=A4,
            colors=colors,
            mm=mm,
        )

    doc.build(story, onFirstPage=decorate_page, onLaterPages=decorate_page)


def _report_color_token(value: Any, fallback: str) -> str:
    clean = str(value or "").strip()
    if re.fullmatch(r"#[0-9A-Fa-f]{6}", clean):
        return clean.upper()
    return fallback


def _register_reportlab_cjk_font(
    pdfmetrics: Any, TTFont: Any, UnicodeCIDFont: Any, language: str = "zh-Hans"
) -> str:
    candidates = list(_macos_pingfang_candidates()) + [
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    ]
    for candidate in candidates:
        try:
            if Path(candidate).is_file():
                options = {"subfontIndex": 0} if str(candidate).lower().endswith(".ttc") else {}
                pdfmetrics.registerFont(TTFont("SecFlowCJK", candidate, **options))
                return "SecFlowCJK"
        except Exception:  # noqa: BLE001
            continue
    cid_font = {
        "ja": "HeiseiMin-W3",
        "ko": "HYSMyeongJo-Medium",
        "zh-Hant": "MSung-Light",
    }.get(_normalize_report_language(language), "STSong-Light")
    pdfmetrics.registerFont(UnicodeCIDFont(cid_font))
    return cid_font


def _macos_pingfang_candidates() -> tuple[str, ...]:
    candidates = [
        Path("/System/Library/Fonts/PingFang.ttc"),
        Path("/System/Library/Fonts/LanguageSupport/PingFang.ttc"),
    ]
    asset_root = Path("/System/Library/AssetsV2/com_apple_MobileAsset_Font8")
    if asset_root.is_dir():
        candidates.extend(sorted(asset_root.glob("*.asset/AssetData/PingFang.ttc")))
    return tuple(str(path) for path in candidates)


def _register_reportlab_latin_font(pdfmetrics: Any, TTFont: Any) -> str:
    candidates = [
        "/System/Library/Fonts/SFNS.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ]
    for candidate in candidates:
        try:
            if Path(candidate).is_file():
                pdfmetrics.registerFont(TTFont("SecFlowLatin", candidate))
                return "SecFlowLatin"
        except Exception:  # noqa: BLE001
            continue
    return "Helvetica"


def _draw_pdf_page_chrome(
    canvas: Any,
    document: Any,
    *,
    font_name: str,
    latin_font_name: str,
    project_name: str,
    page_label: str,
    page_size: tuple[float, float],
    colors: Any,
    mm: Any,
) -> None:
    width, height = page_size
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#f3f6fa"))
    canvas.rect(0, 0, width, height, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.roundRect(
        document.leftMargin - 5 * mm,
        14 * mm,
        width - document.leftMargin - document.rightMargin + 10 * mm,
        height - 28 * mm,
        4 * mm,
        stroke=0,
        fill=1,
    )
    canvas.setStrokeColor(colors.HexColor("#dbe3ec"))
    canvas.setLineWidth(0.5)
    canvas.line(document.leftMargin, 12 * mm, width - document.rightMargin, 12 * mm)
    canvas.setFillColor(colors.HexColor("#728096"))
    if document.page > 1:
        canvas.setFont(latin_font_name, 7.5)
        canvas.line(document.leftMargin, height - 12 * mm, width - document.rightMargin, height - 12 * mm)
        canvas.drawString(document.leftMargin, height - 9.5 * mm, str(project_name)[:90])
    canvas.setFont(latin_font_name if str(page_label).isascii() else font_name, 7.5)
    canvas.drawRightString(width - document.rightMargin, 8.5 * mm, page_label % document.page)
    canvas.restoreState()


def _pdf_section_header(
    number: int,
    title: str,
    tone: str,
    Table: Any,
    TableStyle: Any,
    Paragraph: Any,
    base: Any,
    colors: Any,
    latin_font_name: str,
) -> Any:
    color = {
        "danger": "#ff4d4f",
        "warning": "#f59e0b",
        "success": "#22b573",
        "neutral": "#667386",
        "teal": "#12aa91",
        "info": "#13a6c6",
    }.get(tone, "#13a6c6")
    badge_style = base.clone(
        f"SecFlowSectionBadge{number}",
        fontSize=8,
        leading=11,
        textColor=colors.white,
        alignment=1,
    )
    title_style = base.clone(
        f"SecFlowSectionTitle{number}",
        fontSize=12.5,
        leading=16,
        textColor=colors.HexColor("#172033"),
    )
    table = Table(
        [
            [
                Paragraph(str(number), badge_style),
                Paragraph(f"<b>{_pdf_plain_text(title, latin_font_name)}</b>", title_style),
            ]
        ],
        colWidths=[20, 460],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(color)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (0, 0), 0),
                ("RIGHTPADDING", (0, 0), (0, 0), 0),
                ("TOPPADDING", (0, 0), (0, 0), 4),
                ("BOTTOMPADDING", (0, 0), (0, 0), 4),
                ("LEFTPADDING", (1, 0), (1, 0), 8),
                ("RIGHTPADDING", (1, 0), (1, 0), 0),
                ("TOPPADDING", (1, 0), (1, 0), 2),
                ("BOTTOMPADDING", (1, 0), (1, 0), 2),
            ]
        )
    )
    return table


def _pdf_distribution_charts(
    severity: dict[str, int],
    metadata: dict[str, Any],
    visual_labels: dict[str, str],
    Drawing: Any,
    Circle: Any,
    Wedge: Any,
    VerticalBarChart: Any,
    Rect: Any,
    String: Any,
    Table: Any,
    TableStyle: Any,
    Paragraph: Any,
    base: Any,
    colors: Any,
    font_name: str,
    latin_font_name: str,
    language: str,
) -> Any:
    severity_labels = _report_severity_labels(language)
    keys = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    palette = ("#ff4d4f", "#ff7a45", "#f4c400", "#22b573")
    values = [_non_negative_int(severity.get(key)) for key in keys]
    total = sum(values)

    donut_drawing = Drawing(226, 176)
    if total:
        start_angle = 90.0
        for index, value in enumerate(values):
            if not value:
                continue
            sweep = 360.0 * value / total
            donut_drawing.add(
                Wedge(
                    83,
                    87,
                    63,
                    start_angle,
                    start_angle + sweep,
                    fillColor=colors.HexColor(palette[index]),
                    strokeColor=colors.white,
                    strokeWidth=0.8,
                )
            )
            start_angle += sweep
    else:
        donut_drawing.add(
            Circle(83, 87, 63, fillColor=colors.HexColor("#e6ebf1"), strokeColor=None)
        )
    donut_drawing.add(Circle(83, 87, 42, fillColor=colors.white, strokeColor=None))
    donut_drawing.add(
        String(
            83,
            91,
            str(total),
            textAnchor="middle",
            fontName=latin_font_name,
            fontSize=16,
            fillColor=colors.HexColor("#26364d"),
        )
    )
    donut_drawing.add(
        String(
            83,
            78,
            "总风险" if language.startswith("zh") else "Total",
            textAnchor="middle",
            fontName=font_name,
            fontSize=6.5,
            fillColor=colors.HexColor("#728096"),
        )
    )
    legend_y = 130
    for index, key in enumerate(keys):
        y = legend_y - index * 25
        donut_drawing.add(Rect(158, y, 7, 7, fillColor=colors.HexColor(palette[index]), strokeColor=None))
        donut_drawing.add(
            String(
                171,
                y,
                f"{severity_labels[key]} {values[index]} ({_severity_percentage(values[index], total)})",
                fontName=font_name,
                fontSize=6.4,
                fillColor=colors.HexColor("#4e5f75"),
            )
        )

    charts = metadata.get("report_charts") if isinstance(metadata.get("report_charts"), dict) else {}
    risk_items = [item for item in charts.get("risk_bars") or [] if isinstance(item, dict)][:6]
    risk_labels = [str(item.get("label") or item.get("id") or "Risk")[:10] for item in risk_items]
    risk_values = [_non_negative_int(item.get("value")) for item in risk_items]
    if not risk_items:
        risk_labels = [severity_labels[key] for key in keys]
        risk_values = values

    bar_drawing = Drawing(226, 176)
    chart = VerticalBarChart()
    chart.x = 26
    chart.y = 34
    chart.width = 178
    chart.height = 112
    chart.data = [risk_values]
    chart.categoryAxis.categoryNames = risk_labels
    chart.categoryAxis.labels.fontName = font_name
    chart.categoryAxis.labels.fontSize = 5.8
    chart.categoryAxis.labels.angle = 0
    chart.categoryAxis.strokeColor = colors.HexColor("#d9e2eb")
    chart.valueAxis.labels.fontName = latin_font_name
    chart.valueAxis.labels.fontSize = 5.5
    chart.valueAxis.strokeColor = colors.HexColor("#d9e2eb")
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(risk_values + [1])
    chart.valueAxis.valueStep = max(1, int((max(risk_values + [1]) + 3) / 4))
    chart.bars[0].fillColor = colors.HexColor("#ff4d4f")
    chart.bars[0].strokeColor = None
    chart.barWidth = 13
    chart.barSpacing = 5
    chart.groupSpacing = 8
    chart.barLabelFormat = "%d"
    chart.barLabels.fontName = latin_font_name
    chart.barLabels.fontSize = 6
    chart.barLabels.fillColor = colors.HexColor("#ff4d4f")
    bar_drawing.add(chart)

    heading_style = base.clone("SecFlowChartHeading", fontSize=8.2, leading=11, textColor=colors.HexColor("#26364d"))
    left = [
        Paragraph(f"<b>{_pdf_plain_text(visual_labels['severity_share'], latin_font_name)}</b>", heading_style),
        donut_drawing,
    ]
    right = [
        Paragraph(f"<b>{_pdf_plain_text(visual_labels['risk_categories'], latin_font_name)}</b>", heading_style),
        bar_drawing,
    ]
    table = Table([[left, right]], colWidths=[240, 240])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fbfd")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e1e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e1e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _pdf_severity_chart(
    severity: dict[str, int],
    Drawing: Any,
    Rect: Any,
    String: Any,
    colors: Any,
    font_name: str,
    latin_font_name: str,
    language: str,
) -> Any:
    drawing = Drawing(480, 82)
    entries = [
        ("CRITICAL", "#d9363e"),
        ("HIGH", "#f06b32"),
        ("MEDIUM", "#e5a000"),
        ("LOW", "#2d9d78"),
    ]
    labels = _report_severity_labels(language)
    total = sum(int(severity.get(key) or 0) for key, _ in entries)
    max_value = max([int(severity.get(key) or 0) for key, _ in entries] + [1])
    for index, (key, color) in enumerate(entries):
        x = 16 + index * 116
        value = int(severity.get(key) or 0)
        height = max(4, int((value / max_value) * 44))
        drawing.add(Rect(x, 20, 54, height, fillColor=colors.HexColor(color), strokeColor=None, rx=3, ry=3))
        drawing.add(
            String(
                x + 27,
                8,
                labels[key],
                textAnchor="middle",
                fontName=font_name,
                fontSize=7.5,
                fillColor=colors.HexColor("#617089"),
            )
        )
        drawing.add(
            String(
                x + 27,
                24 + height,
                f"{value} · {_severity_percentage(value, total)}",
                textAnchor="middle",
                fontName=latin_font_name,
                fontSize=8,
                fillColor=colors.HexColor("#26364d"),
            )
        )
    return drawing


def _pdf_metric(
    label: str, value: Any, color: str, Paragraph: Any, base: Any, latin_font_name: str
) -> Any:
    return Paragraph(
        f'<font color="{color}" size="18"><b>{_pdf_plain_text(value, latin_font_name)}</b></font>'
        f'<br/><font color="#617089" size="8">{_pdf_plain_text(label, latin_font_name)}</font>',
        base,
    )


def _pdf_plain_text(value: Any, latin_font_name: str) -> str:
    return _pdf_apply_latin_font(html.escape(str("" if value is None else value)), latin_font_name)


def _pdf_apply_latin_font(markup: str, latin_font_name: str) -> str:
    if not latin_font_name:
        return markup
    parts = re.split(r"(<[^>]+>)", markup)
    rendered: list[str] = []
    for part in parts:
        if not part or part.startswith("<"):
            rendered.append(part)
            continue
        rendered.append(
            re.sub(
                r"([\x20-\x7e]+)",
                lambda match: f'<font name="{latin_font_name}">{match.group(1)}</font>',
                part,
            )
        )
    return "".join(rendered)


def _pdf_inline_markdown(value: Any, latin_font_name: str = "") -> str:
    escaped = html.escape(str(value or ""))
    escaped = re.sub(r"`([^`]+)`", r'<font color="#087b9d">\1</font>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    return _pdf_apply_latin_font(escaped, latin_font_name)


def _mermaid_structured_rows(source: str) -> tuple[list[str], list[list[str]]]:
    text = str(source or "")
    chinese = bool(re.search(r"[\u4e00-\u9fff]", text))
    if re.search(r"(?m)^\s*pie\b", text):
        rows = [
            [match.group(1).strip(), match.group(2)]
            for match in re.finditer(r'^\s*"([^"]+)"\s*:\s*(\d+)\s*$', text, flags=re.MULTILINE)
        ]
        return (["严重等级", "数量"] if chinese else ["Severity", "Count"], rows)

    nodes = {
        match.group(1): match.group(2).strip()
        for match in re.finditer(r'(?m)^\s*([A-Za-z][A-Za-z0-9_]*)\["([^"]+)"\]\s*$', text)
    }
    rows: list[list[str]] = []
    for match in re.finditer(
        r"(?m)^\s*([A-Za-z][A-Za-z0-9_]*)\s*-->(?:\|([^|]*)\|)?\s*([A-Za-z][A-Za-z0-9_]*)\s*$",
        text,
    ):
        source_id, relation, target_id = match.groups()
        rows.append(
            [
                nodes.get(source_id, source_id),
                (relation or ("关联" if chinese else "related")).strip(),
                nodes.get(target_id, target_id),
            ]
        )
    if not rows:
        inline = re.search(
            r'([A-Za-z][A-Za-z0-9_]*)\["([^"]+)"\]\s*-->\s*([A-Za-z][A-Za-z0-9_]*)\["([^"]+)"\]',
            text,
        )
        if inline:
            rows.append([inline.group(2), "关联" if chinese else "related", inline.group(4)])
    headers = ["来源", "关系", "目标"] if chinese else ["Source", "Relationship", "Target"]
    return headers, rows


def _report_blocks_to_pdf_flowables(
    blocks: list[dict[str, Any]],
    visuals: dict[str, Any],
    base: Any,
    code_style: Any,
    Table: Any,
    TableStyle: Any,
    Paragraph: Any,
    colors: Any,
    latin_font_name: str = "",
    ImageFlowable: Any = None,
) -> list[Any]:
    blocks = _infer_report_code_variants(blocks)
    diagrams = {
        str(item.get("image_sha256") or ""): item
        for item in visuals.get("diagrams") or []
        if isinstance(item, dict)
    }
    flowables: list[Any] = []

    def add_table(columns: list[str], rows: list[list[str]]) -> None:
        values = [columns, *rows]
        if not values or not columns:
            return
        column_count = max(len(row) for row in values)
        if column_count == 2:
            column_widths = [135, 345]
        elif column_count == 5:
            column_widths = [32, 96, 112, 66, 174]
        elif column_count == 8:
            column_widths = [30, 42, 68, 52, 72, 70, 96, 50]
        elif column_count == 9:
            column_widths = [48, 34, 34, 48, 46, 55, 62, 42, 111]
        else:
            column_widths = [480 / column_count] * column_count
        row_groups = [values]
        if len(values) > 10:
            row_groups = [[values[0], *values[offset : offset + 8]] for offset in range(1, len(values), 8)]
        for row_group in row_groups:
            rendered_rows = [
                [
                    Paragraph(
                        _pdf_apply_latin_font(html.escape(str(cell)).replace("\n", "<br/>"), latin_font_name),
                        base,
                    )
                    for cell in [*row, *([""] * (column_count - len(row)))]
                ]
                for row in row_group
            ]
            table = Table(rendered_rows, colWidths=column_widths, repeatRows=1, splitByRow=1)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f4f8")),
                        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#e8edf4")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            flowables.append(table)

    def add_code(
        lines: list[str],
        variant: str = "",
        risk_line: int | None = None,
        intro_flowable: Any = None,
    ) -> None:
        header_flowable: Any = None
        if variant in {"vulnerable", "fixed"}:
            is_fixed = variant == "fixed"
            header_text = "修复建议代码" if is_fixed else "存在漏洞的代码"
            header_style = base.clone(
                f"SecFlowCodeHeader{variant}",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#168f5b" if is_fixed else "#d9363e"),
            )
            header = Table(
                [[Paragraph(f"<b>{_pdf_plain_text(header_text, latin_font_name)}</b>", header_style)]],
                colWidths=[480],
            )
            header.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            colors.HexColor("#ecfdf3" if is_fixed else "#fff1f0"),
                        ),
                        (
                            "BOX",
                            (0, 0),
                            (-1, -1),
                            0.45,
                            colors.HexColor("#c8f0d8" if is_fixed else "#ffd6d2"),
                        ),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            header_flowable = header
        numbered = _parse_numbered_code_lines(lines)
        if numbered is not None:
            code_cell_style = code_style.clone(
                "SecFlowJsonCodeCell", backColor=None, borderPadding=0, spaceBefore=0, spaceAfter=0
            )
            number_style = code_cell_style.clone("SecFlowJsonCodeNumber", textColor=colors.HexColor("#8ea0c5"))
            for offset in range(0, len(numbered), 16):
                table_rows = []
                highlighted_rows: list[int] = []
                for row_index, (number, raw_line) in enumerate(numbered[offset : offset + 16]):
                    expanded = raw_line.expandtabs(4)
                    leading_spaces = len(expanded) - len(expanded.lstrip(" "))
                    source_markup = "&#160;" * leading_spaces + html.escape(expanded[leading_spaces:])
                    table_rows.append(
                        [
                            Paragraph(str(number), number_style),
                            Paragraph(
                                _pdf_apply_latin_font(source_markup or "&#8203;", latin_font_name),
                                code_cell_style,
                            ),
                        ]
                    )
                    if risk_line and number == risk_line:
                        highlighted_rows.append(row_index)
                table = Table(table_rows, colWidths=[38, 442], splitByRow=1)
                style_commands = [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#111936")),
                    ("LINEAFTER", (0, 0), (0, -1), 0.35, colors.HexColor("#33405f")),
                    ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (0, -1), 5),
                    ("RIGHTPADDING", (0, 0), (0, -1), 7),
                    ("LEFTPADDING", (1, 0), (1, -1), 8),
                    ("RIGHTPADDING", (1, 0), (1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
                style_commands.extend(
                    ("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#2a263e"))
                    for row_index in highlighted_rows
                )
                table.setStyle(
                    TableStyle(style_commands)
                )
                if offset == 0 and len(numbered) <= 8:
                    from reportlab.platypus import KeepTogether

                    flowables.append(
                        KeepTogether(
                            [
                                item
                                for item in (intro_flowable, header_flowable, table)
                                if item is not None
                            ]
                        )
                    )
                elif header_flowable is not None and offset == 0:
                    if intro_flowable is not None:
                        intro_flowable.keepWithNext = True
                        flowables.append(intro_flowable)
                    header_flowable.keepWithNext = True
                    flowables.extend([header_flowable, table])
                else:
                    if intro_flowable is not None and offset == 0:
                        intro_flowable.keepWithNext = True
                        flowables.append(intro_flowable)
                    flowables.append(table)
            return
        for offset in range(0, len(lines), 20):
            rendered_lines = []
            for raw_line in lines[offset : offset + 20]:
                expanded = raw_line.expandtabs(4)
                leading_spaces = len(expanded) - len(expanded.lstrip(" "))
                rendered_lines.append("&#160;" * leading_spaces + html.escape(expanded[leading_spaces:]))
            code_paragraph = Paragraph(
                _pdf_apply_latin_font("<br/>".join(rendered_lines), latin_font_name), code_style
            )
            if offset == 0 and len(lines) <= 8:
                from reportlab.platypus import KeepTogether

                flowables.append(
                    KeepTogether(
                        [
                            item
                            for item in (intro_flowable, header_flowable, code_paragraph)
                            if item is not None
                        ]
                    )
                )
            elif header_flowable is not None and offset == 0:
                if intro_flowable is not None:
                    intro_flowable.keepWithNext = True
                    flowables.append(intro_flowable)
                header_flowable.keepWithNext = True
                flowables.extend([header_flowable, code_paragraph])
            else:
                if intro_flowable is not None and offset == 0:
                    intro_flowable.keepWithNext = True
                    flowables.append(intro_flowable)
                flowables.append(code_paragraph)

    for block_index, block in enumerate(blocks):
        if not isinstance(block, dict):
            continue
        kind = str(block.get("type") or "")
        if kind == "heading":
            flowables.append(Paragraph(f"<b>{_pdf_plain_text(block.get('text') or '', latin_font_name)}</b>", base))
        elif kind == "paragraph":
            paragraph = Paragraph(
                _pdf_plain_text(block.get("text") or "", latin_font_name).replace("\n", "<br/>"), base
            )
            next_block = blocks[block_index + 1] if block_index + 1 < len(blocks) else {}
            if isinstance(next_block, dict) and next_block.get("type") == "code":
                paragraph.keepWithNext = True
            flowables.append(paragraph)
        elif kind == "quote":
            text = _pdf_plain_text(block.get("text") or "", latin_font_name).replace("\n", "<br/>")
            flowables.append(Paragraph(f'<font color="#52677f">{text}</font>', base))
        elif kind in {"bullet_list", "numbered_list"}:
            for index, item in enumerate(block.get("items") or [], start=1):
                marker = "•" if kind == "bullet_list" else f"{index}."
                flowables.append(Paragraph(f"{marker} {_pdf_plain_text(item, latin_font_name)}", base))
        elif kind == "code":
            code_lines = [str(line) for line in block.get("lines") or []]
            if str(block.get("language") or "").casefold() == "mermaid":
                columns, rows = _mermaid_structured_rows("\n".join(code_lines))
                add_table(columns, rows)
            else:
                intro_flowable = None
                if (
                    block_index > 0
                    and isinstance(blocks[block_index - 1], dict)
                    and blocks[block_index - 1].get("type") == "paragraph"
                    and flowables
                ):
                    intro_flowable = flowables.pop()
                add_code(
                    code_lines,
                    str(block.get("variant") or ""),
                    _positive_report_line(block.get("risk_line")),
                    intro_flowable,
                )
        elif kind == "table":
            add_table(
                [str(item) for item in block.get("columns") or []],
                [[str(cell) for cell in row] for row in block.get("rows") or [] if isinstance(row, list)],
            )
        elif kind == "diagram":
            if ImageFlowable is None:
                raise RuntimeError("PDF renderer cannot embed report images")
            diagram = diagrams.get(str(block.get("sha256") or ""))
            if not diagram:
                raise ValueError("PDF report JSON references a missing diagram")
            payload = base64.b64decode(str(diagram.get("image_base64") or ""), validate=True)
            try:
                from PIL import Image as PillowImage

                with PillowImage.open(io.BytesIO(payload)) as bitmap:
                    pixel_width, pixel_height = bitmap.size
            except Exception as exc:  # noqa: BLE001
                raise ValueError("PDF report JSON diagram dimensions are invalid") from exc
            scale = min(480.0 / max(1, pixel_width), 620.0 / max(1, pixel_height))
            flowables.append(
                ImageFlowable(
                    io.BytesIO(payload),
                    width=max(1.0, pixel_width * scale),
                    height=max(1.0, pixel_height * scale),
                )
            )
    return flowables


def _markdown_to_pdf_flowables(
    markdown: str,
    base: Any,
    code_style: Any,
    Table: Any,
    TableStyle: Any,
    Paragraph: Any,
    colors: Any,
    latin_font_name: str = "",
    ImageFlowable: Any = None,
) -> list[Any]:
    flowables: list[Any] = []
    lines = markdown.splitlines()
    in_code = False
    code_language = ""
    code_lines: list[str] = []
    table_lines: list[str] = []

    def flush_code() -> None:
        nonlocal code_lines, code_language
        if code_language.casefold() == "mermaid":
            headers, structured_rows = _mermaid_structured_rows("\n".join(code_lines))
            if structured_rows:
                rendered_rows = [headers, *structured_rows]
                column_widths = [160, 110, 210] if len(headers) == 3 else [330, 150]
                diagram_table = Table(
                    [
                        [Paragraph(_pdf_inline_markdown(cell, latin_font_name), base) for cell in row]
                        for row in rendered_rows
                    ],
                    colWidths=column_widths,
                    repeatRows=1,
                    splitByRow=1,
                )
                diagram_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8f3f7")),
                            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d7e4eb")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 0), (-1, -1), 5),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                flowables.append(diagram_table)
            code_lines = []
            code_language = ""
            return
        numbered = _parse_numbered_code_lines(code_lines)
        if numbered is not None:
            code_cell_style = code_style.clone(
                "SecFlowCodeCell",
                backColor=None,
                borderPadding=0,
                spaceBefore=0,
                spaceAfter=0,
            )
            number_style = code_cell_style.clone("SecFlowCodeNumber", textColor=colors.HexColor("#8ea0c5"))
            for offset in range(0, len(numbered), 16):
                rows = []
                for number, raw_line in numbered[offset : offset + 16]:
                    expanded = raw_line.expandtabs(4)
                    leading_spaces = len(expanded) - len(expanded.lstrip(" "))
                    source_markup = "&#160;" * leading_spaces + html.escape(expanded[leading_spaces:])
                    rows.append(
                        [
                            Paragraph(str(number), number_style),
                            Paragraph(_pdf_apply_latin_font(source_markup or "&#8203;", latin_font_name), code_cell_style),
                        ]
                    )
                table = Table(rows, colWidths=[38, 442], splitByRow=1)
                table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#111936")),
                            ("LINEAFTER", (0, 0), (0, -1), 0.35, colors.HexColor("#33405f")),
                            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (0, -1), 5),
                            ("RIGHTPADDING", (0, 0), (0, -1), 7),
                            ("LEFTPADDING", (1, 0), (1, -1), 8),
                            ("RIGHTPADDING", (1, 0), (1, -1), 7),
                            ("TOPPADDING", (0, 0), (-1, -1), 2),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                        ]
                    )
                )
                flowables.append(table)
            code_lines = []
            code_language = ""
            return
        chunks = [code_lines[index : index + 20] for index in range(0, len(code_lines), 20)] or [[]]
        for chunk in chunks:
            rendered_lines = []
            for raw_line in chunk:
                expanded = raw_line.expandtabs(4)
                leading_spaces = len(expanded) - len(expanded.lstrip(" "))
                rendered_lines.append("&#160;" * leading_spaces + html.escape(expanded[leading_spaces:]))
            flowables.append(
                Paragraph(_pdf_apply_latin_font("<br/>".join(rendered_lines), latin_font_name), code_style)
            )
        code_lines = []
        code_language = ""

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        rows = []
        for raw in table_lines:
            cells = _split_markdown_table_row(raw)
            if cells and not all(set(cell) <= {"-", ":", " "} for cell in cells):
                rows.append(cells)
        if rows:
            column_count = max(len(row) for row in rows)
            if column_count == 2:
                column_widths = [135, 345]
            elif column_count == 5:
                column_widths = [32, 96, 112, 66, 174]
            elif column_count == 8:
                column_widths = [30, 42, 68, 52, 72, 70, 96, 50]
            elif column_count == 9:
                column_widths = [48, 34, 34, 48, 46, 55, 62, 42, 111]
            else:
                column_widths = [480 / column_count] * column_count
            # A section heading with keepWithNext treats one long Table as a single
            # neighbour and can push it to the next page before ReportLab splits it.
            # Bounded chunks keep the heading with the first rows and repeat headers.
            row_groups = [rows]
            if len(rows) > 10:
                row_groups = [[rows[0], *rows[offset : offset + 8]] for offset in range(1, len(rows), 8)]
            for row_group in row_groups:
                rendered_rows = [
                    [Paragraph(_pdf_inline_markdown(cell, latin_font_name), base) for cell in row]
                    for row in row_group
                ]
                table = Table(rendered_rows, colWidths=column_widths, repeatRows=1, splitByRow=1)
                table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f4f8")),
                            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#e8edf4")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 0), (-1, -1), 5),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                flowables.append(table)
        table_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                flush_table()
                in_code = True
                code_language = stripped[3:].strip()
            continue
        if in_code:
            code_lines.append(line)
            continue
        if stripped.startswith("|"):
            table_lines.append(stripped)
            continue
        flush_table()
        if not stripped or stripped == _REPORT_STYLE_MARKER or stripped.startswith("<!-- secflow-report-style:"):
            continue
        image_match = re.fullmatch(
            r"!\[[^\]]*\]\(data:image/(png|jpeg);base64,([A-Za-z0-9+/=]+)\)",
            stripped,
        )
        if image_match:
            if ImageFlowable is None:
                raise RuntimeError("PDF renderer cannot embed Mermaid images")
            try:
                payload = base64.b64decode(image_match.group(2), validate=True)
            except (TypeError, ValueError) as exc:
                raise ValueError("PDF report contains an invalid Mermaid image") from exc
            valid_signature = (
                payload.startswith(b"\x89PNG\r\n\x1a\n")
                if image_match.group(1) == "png"
                else payload.startswith(b"\xff\xd8\xff")
            )
            if len(payload) > 8 * 1024 * 1024 or not valid_signature:
                raise ValueError("PDF report Mermaid image failed validation")
            try:
                from PIL import Image as PillowImage

                with PillowImage.open(io.BytesIO(payload)) as bitmap:
                    pixel_width, pixel_height = bitmap.size
            except Exception as exc:  # noqa: BLE001
                raise ValueError("PDF report Mermaid image dimensions are invalid") from exc
            target_width = 480.0
            target_height = min(620.0, target_width * pixel_height / max(1, pixel_width))
            flowables.append(ImageFlowable(io.BytesIO(payload), width=target_width, height=target_height))
            continue
        if stripped.startswith("<!-- secflow-mermaid-source:"):
            continue
        if stripped.startswith("### "):
            flowables.append(Paragraph(f"<b>{_pdf_inline_markdown(stripped[4:], latin_font_name)}</b>", base))
        elif stripped.startswith("- "):
            flowables.append(Paragraph(f"• {_pdf_inline_markdown(stripped[2:], latin_font_name)}", base))
        elif stripped.startswith("> "):
            flowables.append(
                Paragraph(
                    f'<font color="#52677f">{_pdf_inline_markdown(stripped[2:], latin_font_name)}</font>',
                    base,
                )
            )
        elif stripped == "---":
            continue
        else:
            flowables.append(Paragraph(_pdf_inline_markdown(stripped, latin_font_name), base))
    flush_table()
    if in_code:
        flush_code()
    return flowables


def build_scan_result_json(
    scan_data: dict[str, Any],
    *,
    source_kind: str,
    language: str = "zh-Hans",
    completed_at: str | None = None,
) -> dict[str, Any]:
    clean_source_kind = str(source_kind or "assistant_scan").strip() or "assistant_scan"
    if clean_source_kind == "agent_task":
        payload = _materialize_agent_scan_json(scan_data, language=language)
    else:
        payload = _materialize_assistant_scan_json(scan_data, language=language)
    facts = _scan_result_facts(payload, clean_source_kind)
    document = {
        "$schema": _SCAN_RESULT_JSON_SCHEMA,
        "schema_version": 1,
        "source_kind": clean_source_kind,
        "language": _normalize_report_language(language),
        "completed_at": str(completed_at or now_iso()),
        "payload": payload,
        "facts": facts,
        "counts": {
            "dependencies": len(facts["dependencies"]),
            "licenses": len(facts["licenses"]),
            "dependency_vulnerabilities": len(facts["dependency_vulnerabilities"]),
            "code_findings": len(facts["code_findings"]),
        },
    }
    document["audit"] = {
        "normalizer": "secflow-scan-results-json",
        "payload_sha256": _scan_result_payload_sha256(document),
        "json_roundtrip_verified": True,
    }
    return validate_scan_result_json(document)


def validate_scan_result_json(value: dict[str, Any]) -> dict[str, Any]:
    document = _json_report_value(value)
    if document.get("$schema") != _SCAN_RESULT_JSON_SCHEMA or int(document.get("schema_version") or 0) != 1:
        raise ValueError("Unsupported SecFlow scan-result JSON schema")
    if not isinstance(document.get("payload"), dict) or not isinstance(document.get("facts"), dict):
        raise ValueError("SecFlow scan-result JSON is missing payload or facts")
    facts = document["facts"]
    for key in ("dependencies", "licenses", "dependency_vulnerabilities", "code_findings"):
        if not isinstance(facts.get(key), list):
            raise ValueError(f"SecFlow scan-result JSON facts.{key} must be an array")
    for finding in facts["code_findings"]:
        if not isinstance(finding, dict):
            raise ValueError("SecFlow scan-result JSON code finding must be an object")
        _validate_snippet_lines(finding)
        if not finding.get("snippet_lines"):
            raise ValueError("SecFlow scan-result JSON code finding is missing a verifiable evidence snippet")
        if not str(finding.get("remediation") or "").strip():
            raise ValueError("SecFlow scan-result JSON code finding is missing a remediation plan")
    audit = document.get("audit") if isinstance(document.get("audit"), dict) else {}
    expected = str(audit.get("payload_sha256") or "")
    actual = _scan_result_payload_sha256(document)
    if not expected or expected != actual:
        raise ValueError("SecFlow scan-result JSON checksum verification failed")
    return document


def _materialize_agent_scan_json(
    scan_data: dict[str, Any],
    *,
    language: str = "zh-Hans",
) -> dict[str, Any]:
    payload = _json_report_value(scan_data)
    original_task = scan_data.get("task") if isinstance(scan_data.get("task"), dict) else scan_data
    task = payload.get("task") if isinstance(payload.get("task"), dict) else payload
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    language_results = result.get("language_results") if isinstance(result.get("language_results"), dict) else {}
    for language_result in language_results.values():
        if not isinstance(language_result, dict):
            continue
        for key in ("findings", "review_findings"):
            findings = language_result.get(key) if isinstance(language_result.get(key), list) else []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
                file_name = str(finding.get("file_name") or finding.get("file") or sink.get("file") or "")
                risk_line = _positive_report_line(finding.get("line") or finding.get("risk_line") or sink.get("line"))
                snippet, line_start, line_end, snippet_source = _agent_finding_snippet(
                    original_task,
                    finding,
                    file_name,
                    risk_line,
                )
                if snippet:
                    _set_structured_snippet(finding, snippet, line_start, risk_line)
                    finding["snippet_source"] = snippet_source
                finding["remediation"] = _report_finding_remediation(finding, language)
    return payload


def _materialize_assistant_scan_json(
    scan_data: dict[str, Any],
    *,
    language: str = "zh-Hans",
) -> dict[str, Any]:
    payload = _json_report_value(scan_data)
    static_analysis = payload.get("static_analysis") if isinstance(payload.get("static_analysis"), dict) else {}
    findings = static_analysis.get("findings") if isinstance(static_analysis.get("findings"), list) else []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
        snippet = (
            finding.get("vulnerable_snippet")
            or finding.get("code_snippet")
            or finding.get("snippet")
            or sink.get("snippet")
            or finding.get("evidence")
        )
        if snippet:
            risk_line = _positive_report_line(finding.get("risk_line") or finding.get("line") or sink.get("line"))
            line_start = _positive_report_line(finding.get("line_start")) or risk_line
            _set_structured_snippet(finding, _safe_report_code(snippet), line_start, risk_line)
        finding["remediation"] = _report_finding_remediation(finding, language)
    return payload


def _set_structured_snippet(
    finding: dict[str, Any],
    snippet: str,
    line_start: int | None,
    risk_line: int | None,
) -> None:
    records = _structured_snippet_lines(snippet, line_start, risk_line)
    if not records:
        return
    finding["snippet_lines"] = records
    finding["vulnerable_snippet"] = _safe_report_code(snippet)
    finding["line_start"] = records[0]["number"]
    finding["line_end"] = records[-1]["number"]


def _structured_snippet_lines(
    snippet: str,
    line_start: int | None,
    risk_line: int | None,
) -> list[dict[str, Any]]:
    raw_lines = _safe_report_code(snippet).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if not raw_lines or raw_lines == [""]:
        return []
    prefixed = _parse_numbered_code_lines(raw_lines)
    if prefixed is not None:
        return [
            {"number": number, "text": text, "is_risk": number == risk_line}
            for number, text in prefixed
        ]
    first_number = line_start or risk_line or 1
    return [
        {"number": first_number + offset, "text": text, "is_risk": first_number + offset == risk_line}
        for offset, text in enumerate(raw_lines)
    ]


def _validate_snippet_lines(finding: dict[str, Any]) -> None:
    lines = finding.get("snippet_lines")
    if lines is None:
        return
    if not isinstance(lines, list) or not lines:
        raise ValueError("SecFlow scan-result JSON snippet_lines must be a non-empty array")
    numbers: list[int] = []
    for item in lines:
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            raise ValueError("SecFlow scan-result JSON snippet line must contain text")
        try:
            number = int(item.get("number"))
        except (TypeError, ValueError) as exc:
            raise ValueError("SecFlow scan-result JSON snippet line number is invalid") from exc
        if number <= 0:
            raise ValueError("SecFlow scan-result JSON snippet line number is invalid")
        numbers.append(number)
    if any(current != previous + 1 for previous, current in zip(numbers, numbers[1:])):
        raise ValueError("SecFlow scan-result JSON snippet line numbers are not contiguous")
    if _positive_report_line(finding.get("line_start")) != numbers[0]:
        raise ValueError("SecFlow scan-result JSON snippet line_start does not match snippet_lines")
    if _positive_report_line(finding.get("line_end")) != numbers[-1]:
        raise ValueError("SecFlow scan-result JSON snippet line_end does not match snippet_lines")


def _scan_result_facts(payload: dict[str, Any], source_kind: str) -> dict[str, list[dict[str, Any]]]:
    if source_kind == "agent_task":
        task = payload.get("task") if isinstance(payload.get("task"), dict) else payload
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        dependencies = [item for item in result.get("dependencies") or [] if isinstance(item, dict)]
        license_scan = result.get("license_scan") if isinstance(result.get("license_scan"), dict) else {}
        licenses = [item for item in result.get("licenses") or license_scan.get("licenses") or [] if isinstance(item, dict)]
        dependency_vulnerabilities = [
            item for item in result.get("dependency_vulnerabilities") or [] if isinstance(item, dict)
        ]
        code_findings: list[dict[str, Any]] = []
        language_results = result.get("language_results") if isinstance(result.get("language_results"), dict) else {}
        for language, language_result in language_results.items():
            if not isinstance(language_result, dict):
                continue
            for disposition, key in (("confirmed", "findings"), ("review", "review_findings")):
                for finding in language_result.get(key) or []:
                    if isinstance(finding, dict):
                        code_findings.append({**finding, "language": str(language), "disposition": disposition})
        return {
            "dependencies": dependencies,
            "licenses": licenses,
            "dependency_vulnerabilities": dependency_vulnerabilities,
            "code_findings": code_findings,
        }
    dependency_scan = payload.get("dependency_scan") if isinstance(payload.get("dependency_scan"), dict) else {}
    license_scan = dependency_scan.get("license_scan") if isinstance(dependency_scan.get("license_scan"), dict) else {}
    static_analysis = payload.get("static_analysis") if isinstance(payload.get("static_analysis"), dict) else {}
    return {
        "dependencies": [item for item in dependency_scan.get("dependencies") or [] if isinstance(item, dict)],
        "licenses": [item for item in license_scan.get("licenses") or [] if isinstance(item, dict)],
        "dependency_vulnerabilities": [item for item in payload.get("records") or [] if isinstance(item, dict)],
        "code_findings": [item for item in static_analysis.get("findings") or [] if isinstance(item, dict)],
    }


def _scan_result_payload_sha256(document: dict[str, Any]) -> str:
    signed = {
        key: document.get(key)
        for key in ("$schema", "schema_version", "source_kind", "language", "completed_at", "payload", "facts", "counts")
    }
    return hashlib.sha256(_canonical_report_json_bytes(signed)).hexdigest()


def refresh_scan_result_json(
    value: dict[str, Any],
    *,
    language: str | None = None,
) -> dict[str, Any]:
    """Rebuild derived facts and the checksum after a controlled JSON transform."""

    document = _json_report_value(value)
    if document.get("$schema") != _SCAN_RESULT_JSON_SCHEMA or int(document.get("schema_version") or 0) != 1:
        raise ValueError("Unsupported SecFlow scan-result JSON schema")
    payload = document.get("payload") if isinstance(document.get("payload"), dict) else None
    if payload is None:
        raise ValueError("SecFlow scan-result JSON is missing payload")
    source_kind = str(document.get("source_kind") or "assistant_scan")
    facts = _scan_result_facts(payload, source_kind)
    document["facts"] = facts
    document["counts"] = {
        "dependencies": len(facts["dependencies"]),
        "licenses": len(facts["licenses"]),
        "dependency_vulnerabilities": len(facts["dependency_vulnerabilities"]),
        "code_findings": len(facts["code_findings"]),
    }
    if language is not None:
        document["language"] = _normalize_report_language(language)
    audit = document.get("audit") if isinstance(document.get("audit"), dict) else {}
    document["audit"] = {
        **audit,
        "normalizer": "secflow-scan-results-json",
        "payload_sha256": _scan_result_payload_sha256(document),
        "json_roundtrip_verified": True,
    }
    return validate_scan_result_json(document)


def _build_report_json_document(
    markdown: str,
    metadata: dict[str, Any],
    *,
    report_source: dict[str, Any] | None = None,
    sarif: dict[str, Any] | None = None,
    visuals: dict[str, Any] | None = None,
    rendered_markdown: str | None = None,
) -> dict[str, Any]:
    source = validate_scan_result_json(report_source) if report_source is not None else build_scan_result_json(
        {}, source_kind="legacy_report", language=str(metadata.get("language") or "zh-Hans")
    )
    clean_markdown = _sanitize_report_content(str(markdown or ""))
    render_document = _parse_report_document(clean_markdown, metadata)
    visual_payload = _json_report_value(visuals or {})
    _append_visual_report_blocks(
        render_document,
        visual_payload,
        str(metadata.get("language") or "zh-Hans"),
    )
    render_document["markdown"] = _sanitize_report_content(
        str(rendered_markdown if rendered_markdown is not None else clean_markdown)
    )
    render_document["severity"] = _severity_distribution(clean_markdown, metadata)
    sarif_payload = _json_report_value(sarif or {})
    source_facts = source.get("facts") if isinstance(source.get("facts"), dict) else {}
    source_counts = source.get("counts") if isinstance(source.get("counts"), dict) else {}
    unified_findings = [
        *[item for item in source_facts.get("dependency_vulnerabilities") or [] if isinstance(item, dict)],
        *[item for item in source_facts.get("code_findings") or [] if isinstance(item, dict)],
    ]
    severity = _structured_severity_distribution(
        [item for item in source_facts.get("dependency_vulnerabilities") or [] if isinstance(item, dict)],
        [item for item in source_facts.get("code_findings") or [] if isinstance(item, dict)],
    )
    report_blocks = [
        {"title": section.get("title"), "blocks": section.get("blocks") or []}
        for section in render_document.get("sections") or []
        if isinstance(section, dict)
    ]
    document = {
        "$schema": _REPORT_DOCUMENT_JSON_SCHEMA,
        "schema_version": _REPORT_DOCUMENT_SCHEMA_VERSION,
        "generated_at": str(metadata.get("created_at") or now_iso()),
        "source": source,
        "summary": {
            "title": str(render_document.get("title") or metadata.get("title") or "SecFlow 企业安全报告"),
            "language": str(metadata.get("language") or source.get("language") or "zh-Hans"),
            "scan_type": str((metadata.get("report_plan") or {}).get("scan_type") or "full_scan"),
            "source_sha256": str((source.get("audit") or {}).get("payload_sha256") or ""),
        },
        "statistics": {
            "counts": _json_report_value(source_counts),
            "severity": severity,
            "total_findings": len(unified_findings),
        },
        "report": render_document,
        "charts": _json_report_value(metadata.get("report_charts") or {}),
        "findings": _json_report_value(unified_findings),
        "appendix": _json_report_value(metadata.get("report_mcps") or []),
        "template": _json_report_value(metadata.get("report_template") or {}),
        "qa": _json_report_value(metadata.get("report_qa") or {}),
        "sarif": sarif_payload,
        "visuals": visual_payload,
        "metadata": _json_report_value(metadata),
        "audit": {
            "source_payload_sha256": str((source.get("audit") or {}).get("payload_sha256") or ""),
            "report_blocks_sha256": hashlib.sha256(_canonical_report_json_bytes(report_blocks)).hexdigest(),
            "sarif_sha256": hashlib.sha256(_canonical_report_json_bytes(sarif_payload)).hexdigest(),
            "visuals_sha256": hashlib.sha256(_canonical_report_json_bytes(visual_payload)).hexdigest(),
            "input_format": "application/json",
            "processors": [
                "secflow-report-json",
                "secflow-report-sarif-mcp",
                "secflow-report-mermaid-mcp",
                "secflow-report-markdown-mcp",
                "secflow-html-renderer",
                "secflow-report-word-mcp",
                "secflow-report-excel-mcp",
                "secflow-report-pdf-mcp",
            ],
        },
    }
    return _json_report_value(document)


def _append_visual_report_blocks(
    report: dict[str, Any],
    visuals: dict[str, Any],
    language: str,
) -> None:
    diagrams = [item for item in visuals.get("diagrams") or [] if isinstance(item, dict)]
    if not diagrams:
        return
    chinese = _normalize_report_language(language) in {"zh-Hans", "zh-Hant"}
    section_title = "可验证污点分析图" if chinese else "Verified taint-analysis diagrams"
    section_content = (
        f"本节包含 {len(diagrams)} 张由已核验 SARIF 污点路径生成的 JPEG 图。"
        if chinese
        else f"This section contains {len(diagrams)} JPEG diagram(s) generated from verified SARIF taint paths."
    )
    blocks: list[dict[str, Any]] = []
    for diagram in diagrams:
        title = str(diagram.get("title") or "Diagram")
        blocks.extend(
            [
                {"type": "heading", "level": 2, "text": title},
                {
                    "type": "diagram",
                    "title": title,
                    "media_type": str(diagram.get("image_media_type") or "image/jpeg"),
                    "sha256": str(diagram.get("image_sha256") or ""),
                },
            ]
        )
    report.setdefault("sections", []).append(
        {
            "title": section_title,
            "content": section_content,
            "blocks": blocks,
        }
    )


def build_report_document_json(
    markdown: str,
    metadata: dict[str, Any],
    *,
    report_source: dict[str, Any],
    sarif: dict[str, Any] | None = None,
    visuals: dict[str, Any] | None = None,
    rendered_markdown: str | None = None,
) -> dict[str, Any]:
    """Build the canonical JSON contract consumed by format-specific report MCPs."""

    return _build_report_json_document(
        markdown,
        metadata,
        report_source=report_source,
        sarif=sarif,
        visuals=visuals,
        rendered_markdown=rendered_markdown,
    )


def validate_report_document_json(value: dict[str, Any]) -> dict[str, Any]:
    """Validate an in-memory report document without trusting renderer input."""

    document = _json_report_value(value)
    if document.get("$schema") != _REPORT_DOCUMENT_JSON_SCHEMA:
        raise ValueError("Unsupported SecFlow report JSON schema")
    if int(document.get("schema_version") or 0) < _REPORT_DOCUMENT_SCHEMA_VERSION:
        raise ValueError("SecFlow report JSON schema version is outdated")
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    validate_scan_result_json(source)
    document["report"] = _validated_render_document(document.get("report") or {})
    if not str(document["report"].get("markdown") or "").strip():
        raise ValueError("SecFlow report JSON is missing Markdown content")
    expected_hash = str((source.get("audit") or {}).get("payload_sha256") or "")
    recorded_hash = str((document.get("audit") or {}).get("source_payload_sha256") or "")
    if expected_hash and recorded_hash and expected_hash != recorded_hash:
        raise ValueError("SecFlow report source hash does not match its audit record")
    sarif = document.get("sarif") if isinstance(document.get("sarif"), dict) else {}
    if sarif:
        sarif_document = sarif.get("sarif") if isinstance(sarif.get("sarif"), dict) else sarif
        if sarif_document.get("version") != "2.1.0" or not isinstance(sarif_document.get("runs"), list):
            raise ValueError("SecFlow report SARIF is invalid")
        sarif_input_hash = str(sarif.get("input_sha256") or "")
        if expected_hash and sarif_input_hash and sarif_input_hash != expected_hash:
            raise ValueError("SecFlow report SARIF source hash does not match scan JSON")
        sarif_digest = hashlib.sha256(_canonical_report_json_bytes(sarif_document)).hexdigest()
        if sarif.get("output_sha256") and str(sarif.get("output_sha256")) != sarif_digest:
            raise ValueError("SecFlow report SARIF checksum verification failed")
    visuals = document.get("visuals") if isinstance(document.get("visuals"), dict) else {}
    visual_input_hash = str(visuals.get("input_sha256") or "")
    if expected_hash and visual_input_hash and visual_input_hash != expected_hash:
        raise ValueError("SecFlow report visual source hash does not match scan JSON")
    for diagram in visuals.get("diagrams") or []:
        if not isinstance(diagram, dict):
            raise ValueError("SecFlow report visual is invalid")
        try:
            payload = base64.b64decode(str(diagram.get("image_base64") or ""), validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("SecFlow report visual is not valid base64") from exc
        media_type = str(diagram.get("image_media_type") or "")
        valid_signature = (
            media_type == "image/jpeg" and payload.startswith(b"\xff\xd8\xff")
        ) or (
            media_type == "image/png" and payload.startswith(b"\x89PNG\r\n\x1a\n")
        )
        if not valid_signature or hashlib.sha256(payload).hexdigest() != str(diagram.get("image_sha256") or ""):
            raise ValueError("SecFlow report visual checksum verification failed")
    audit = document.get("audit") if isinstance(document.get("audit"), dict) else {}
    report_blocks = [
        {"title": section.get("title"), "blocks": section.get("blocks") or []}
        for section in document["report"].get("sections") or []
        if isinstance(section, dict)
    ]
    expected_blocks_hash = hashlib.sha256(_canonical_report_json_bytes(report_blocks)).hexdigest()
    if audit.get("report_blocks_sha256") and str(audit.get("report_blocks_sha256")) != expected_blocks_hash:
        raise ValueError("SecFlow report content-block checksum verification failed")
    expected_sarif_hash = hashlib.sha256(_canonical_report_json_bytes(sarif)).hexdigest()
    if audit.get("sarif_sha256") and str(audit.get("sarif_sha256")) != expected_sarif_hash:
        raise ValueError("SecFlow report SARIF-envelope checksum verification failed")
    expected_visuals_hash = hashlib.sha256(_canonical_report_json_bytes(visuals)).hexdigest()
    if audit.get("visuals_sha256") and str(audit.get("visuals_sha256")) != expected_visuals_hash:
        raise ValueError("SecFlow report visual-envelope checksum verification failed")
    available_diagrams = {
        str(item.get("image_sha256") or "")
        for item in visuals.get("diagrams") or []
        if isinstance(item, dict)
    }
    referenced_diagrams = {
        str(block.get("sha256") or "")
        for section in document["report"].get("sections") or []
        if isinstance(section, dict)
        for block in section.get("blocks") or []
        if isinstance(block, dict) and block.get("type") == "diagram"
    }
    if not referenced_diagrams.issubset(available_diagrams):
        raise ValueError("SecFlow report content blocks reference an unavailable diagram")
    return document


def render_report_pdf_file(path: Path, report_document: dict[str, Any]) -> None:
    """Render a validated report document for the dedicated PDF MCP."""

    document = validate_report_document_json(report_document)
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    report = document["report"]
    _write_pdf_report(
        path,
        str(report.get("markdown") or ""),
        metadata,
        document=report,
        visuals=document.get("visuals") if isinstance(document.get("visuals"), dict) else {},
    )


def _render_binary_report_artifacts_with_mcps(
    report_document: dict[str, Any],
    *,
    metadata: dict[str, Any],
) -> tuple[dict[str, bytes], dict[str, str]]:
    from app.mcp.protocol import call_mcp_tool, read_mcp_artifact, release_mcp_artifacts

    artifacts: dict[str, bytes] = {}
    errors: dict[str, str] = {}
    audits = metadata.get("report_mcps") if isinstance(metadata.get("report_mcps"), list) else []
    for report_format, server, tool, tool_id in (
        ("docx", "SecFlow Word MCP", "render_word_report", "mcp__report_word__render_word_report"),
        ("xlsx", "SecFlow Excel MCP", "render_excel_report", "mcp__report_excel__render_excel_report"),
        ("pdf", "SecFlow PDF MCP", "render_pdf_report", "mcp__report_pdf__render_pdf_report"),
    ):
        invoked_at = now_iso()
        try:
            result = call_mcp_tool(
                agent_id="report_agent",
                tool_id=tool_id,
                arguments={"report_document": report_document},
            )
            try:
                payload = read_mcp_artifact(result)
            finally:
                release_mcp_artifacts(result)
            expected_digest = str(result.get("output_sha256") or "")
            actual_digest = hashlib.sha256(payload).hexdigest()
            if not expected_digest or expected_digest != actual_digest:
                raise ValueError(f"{server} output hash verification failed")
            artifacts[report_format] = payload
            audits.append(
                {
                    "server": server,
                    "tool": tool,
                    "transport": str((result.get("_mcp_runtime") or {}).get("transport") or "stdio"),
                    "endpoint": "managed-child-process",
                    "status": "completed",
                    "invoked_at": invoked_at,
                    "input_sha256": str(result.get("input_sha256") or ""),
                    "output_sha256": actual_digest,
                    "media_type": str(result.get("media_type") or _REPORT_MEDIA_TYPES[report_format]),
                    "artifact_size": len(payload),
                }
            )
        except Exception as exc:  # noqa: BLE001
            errors[report_format] = str(exc)
            audits.append(
                {
                    "server": server,
                    "tool": tool,
                    "transport": "stdio",
                    "endpoint": "managed-child-process",
                    "status": "failed",
                    "invoked_at": invoked_at,
                    "error": str(exc),
                }
            )
    metadata["report_mcps"] = audits
    return artifacts, errors


def _load_report_json_document(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("SecFlow report JSON cannot be read") from exc
    if not isinstance(document, dict):
        raise ValueError("SecFlow report JSON root must be an object")
    return validate_report_document_json(document)


def _canonical_report_json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    safe_value = _json_report_value(value)
    return json.dumps(
        safe_value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    ).encode("utf-8")


def _json_report_value(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except (TypeError, ValueError) as exc:
        raise ValueError("Report input cannot be converted to JSON") from exc


report_artifact_store = ReportDownloadArtifactStore()
report_store = ReportStore()
