from __future__ import annotations

import hashlib
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

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text
from app.storage import DATA_DIR, now_iso


REPORT_INDEX_PURPOSE = "secflow-report-index"
REPORT_ARTIFACT_INDEX_PURPOSE = "secflow-report-artifact-index"
_ENGINE_NAME_PATTERN = re.compile(r"CodeQL|Semgrep", flags=re.IGNORECASE)
_REPORT_STYLE_MARKER = "<!-- secflow-report-style:v2 -->"
_REPORT_FORMATS = {"md", "html", "pdf", "docx"}
_SCAN_RESULT_JSON_SCHEMA = "secflow.scan-results/v1"
_REPORT_DOCUMENT_JSON_SCHEMA = "secflow.report-document/v1"
_REPORT_DOCUMENT_SCHEMA_VERSION = 4
_REPORT_FILE_PREVIEW_LIMIT = 8
_REPORT_DEPENDENCY_PREVIEW_LIMIT = 10
_REPORT_RECORD_LIMIT = 30
_REPORT_FINDING_LIMIT = 30
_REPORT_MEDIA_TYPES = {
    "md": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
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
        artifact_id = f"report-artifact-{digest[:24]}"
        safe_name = Path(str(file_name or "SecFlow-report.bin")).name
        suffix = Path(safe_name).suffix.lower() or ".bin"
        path = self.root / f"{artifact_id}{suffix}"
        generated_at = now_iso()
        item = {
            "id": artifact_id,
            "kind": "report",
            "file_name": safe_name,
            "media_type": media_type,
            "download_path": f"/api/assistant/artifacts/{artifact_id}",
            "sha256": digest,
            "size": len(content),
            "generated_at": generated_at,
            "user_id": str(user_id or "default"),
            "storage_name": path.name,
        }
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_bytes(content)
            temporary.chmod(0o600)
            os.replace(temporary, path)
            index = [entry for entry in self._read_index() if entry.get("id") != artifact_id]
            index.insert(0, item)
            stale = index[self.retain :]
            self._write_index(index[: self.retain])
            for entry in stale:
                stale_path = self.root / Path(str(entry.get("storage_name") or "")).name
                if stale_path.parent.resolve() == self.root.resolve():
                    stale_path.unlink(missing_ok=True)
        return {key: value for key, value in item.items() if key not in {"user_id", "storage_name"}}

    def resolve(self, artifact_id: str) -> tuple[Path, str, str]:
        clean_id = str(artifact_id or "").strip()
        if not re.fullmatch(r"report-artifact-[a-f0-9]{24}", clean_id):
            raise KeyError(artifact_id)
        with self._lock:
            item = next((entry for entry in self._read_index() if entry.get("id") == clean_id), None)
            if not item:
                raise KeyError(artifact_id)
            path = self.root / Path(str(item.get("storage_name") or "")).name
            if not path.is_file() or path.parent.resolve() != self.root.resolve():
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
    if re.search(r"(?:UTC\+08:00|\+08:00)$", text):
        return text
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(_CHINA_STANDARD_TIME).strftime("%Y-%m-%d %H:%M:%S UTC+08:00")
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
    return {
        "CRITICAL": "严重",
        "HIGH": "高危",
        "MEDIUM": "中危",
        "LOW": "低危",
    }.get(_normalize_report_severity(value), "未知")


def _report_finding_remediation(finding: dict[str, Any]) -> str:
    for key in ("remediation", "recommendation", "fix", "fix_recommendation"):
        value = _report_plain_text(finding.get(key) or "")
        if value and value != "-":
            return value
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
    ) -> dict[str, Any]:
        content = _sanitize_report_content(content)
        created_at = now_iso()
        digest = hashlib.sha256(f"{created_at}\n{title}\n{content}".encode("utf-8")).hexdigest()[:12]
        report_id = f"report-{created_at.replace(':', '').replace('+', 'z')}-{digest}"
        report_id = _safe_report_id(report_id)
        base_name = _report_file_base_name(title, metadata or {}, created_at)
        file_names = _report_file_names(base_name)
        source_json_file = f"{_safe_report_file_stem(base_name)}.json"
        summary = {
            "id": report_id,
            "title": title.strip() or "依赖漏洞与代码漏洞分析报告",
            "file_name": file_names["md"],
            "file_names": file_names,
            "source_json_file": source_json_file,
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
                    )
                    self._write_index(index)
                    return _public_report_summary(existing)
            self._write_report_artifacts(
                summary,
                content,
                report_source=report_source,
                rendered_artifacts=rendered_artifacts,
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
        )

    def _write_report_artifacts(
        self,
        metadata: dict[str, Any],
        markdown: str,
        *,
        report_source: dict[str, Any] | None = None,
        rendered_artifacts: dict[str, bytes | str] | None = None,
    ) -> None:
        metadata["file_names"] = _coerce_report_file_names(metadata)
        metadata["file_name"] = metadata["file_names"]["md"]
        metadata["source_json_file"] = Path(
            str(metadata.get("source_json_file") or f"{Path(metadata['file_name']).stem}.json")
        ).name
        metadata["render_pipeline"] = [
            "scan_results_to_json",
            "report_chart_mcp_json",
            "report_mermaid_mcp_json",
            "report_markdown_mcp_json",
            "report_word_mcp_docx",
            "report_pdf_mcp_pdf",
            "html_renderer_json",
        ]
        available_formats = {"md"}
        artifact_errors: dict[str, str] = {}
        render_metadata = _report_render_metadata(metadata)
        report_document = _build_report_json_document(markdown, render_metadata, report_source=report_source)
        report_json_bytes = _canonical_report_json_bytes(report_document, pretty=True)
        metadata["report_json_sha256"] = hashlib.sha256(report_json_bytes).hexdigest()
        source_json_path = self.root / metadata["source_json_file"]
        source_json_path.write_bytes(report_json_bytes)
        source_json_path.chmod(0o600)
        markdown = str((report_document.get("report") or {}).get("markdown") or markdown)
        if rendered_artifacts and isinstance(rendered_artifacts.get("md"), str):
            markdown = _sanitize_report_content(str(rendered_artifacts["md"]))
            report_document = _build_report_json_document(markdown, render_metadata, report_source=report_source)
            report_json_bytes = _canonical_report_json_bytes(report_document, pretty=True)
            metadata["report_json_sha256"] = hashlib.sha256(report_json_bytes).hexdigest()
            source_json_path.write_bytes(report_json_bytes)
            source_json_path.chmod(0o600)
        (self.root / metadata["file_names"]["md"]).write_text(markdown, encoding="utf-8")
        try:
            (self.root / metadata["file_names"]["html"]).write_text(
                _build_html_report(markdown, render_metadata, document=report_document.get("report")), encoding="utf-8"
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
        for report_format, signature in (("docx", b"PK"), ("pdf", b"%PDF")):
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
        metadata["render_pipeline"] = [
            "scan_results_to_json",
            "report_chart_mcp_json",
            "report_mermaid_mcp_json",
            "report_markdown_mcp_json",
            "report_word_mcp_docx",
            "report_pdf_mcp_pdf",
            "html_renderer_json",
        ]
        available_formats = {"md"}
        artifact_errors: dict[str, str] = {}
        html_path = self.root / metadata["file_names"]["html"]
        pdf_path = self.root / metadata["file_names"]["pdf"]
        docx_path = self.root / metadata["file_names"]["docx"]
        render_metadata = _report_render_metadata(metadata)
        source_json_path = self.root / metadata["source_json_file"]
        if source_json_path.is_file():
            report_document = _load_report_json_document(source_json_path)
        else:
            report_document = _build_report_json_document(markdown, render_metadata)
            source_json_path.write_bytes(_canonical_report_json_bytes(report_document, pretty=True))
            source_json_path.chmod(0o600)
        metadata["report_json_sha256"] = hashlib.sha256(source_json_path.read_bytes()).hexdigest()
        try:
            if not html_path.is_file():
                html_path.write_text(
                    _build_html_report(markdown, render_metadata, document=report_document.get("report")),
                    encoding="utf-8",
                )
            available_formats.add("html")
        except Exception as exc:  # noqa: BLE001
            artifact_errors["html"] = str(exc)
            html_path.unlink(missing_ok=True)
        missing_binary = not pdf_path.is_file() or not docx_path.is_file()
        generated: dict[str, bytes] = {}
        if missing_binary:
            generated, generated_errors = _render_binary_report_artifacts_with_mcps(
                report_document,
                metadata=metadata,
            )
            artifact_errors.update(generated_errors)
        for report_format, path, signature in (
            ("docx", docx_path, b"PK"),
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
    invoked_at = _single_line_report_value(audit.get("invoked_at") or "-")
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
                    time=_escape_markdown_table_cell(event.get("time") or "-"),
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
            f"- {_rt(language, 'severity')}: {record.get('severity') or 'UNKNOWN'}",
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
        f"- 严重等级：{record.get('severity') or 'UNKNOWN'}",
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
            f"- {_rt(language, 'related_vulnerability')}: {finding.get('record_id') or _rt(language, 'not_specified')}",
            f"- {_rt(language, 'related_component')}: {finding.get('component') or _rt(language, 'not_specified')}",
            f"- {_rt(language, 'risk_location')}: {file_name}:{risk_line}",
            f"- {_rt(language, 'code_range')}: {_rt(language, 'line') % line_range}",
            f"- {_rt(language, 'confidence')}: {finding.get('confidence') or 'medium'}",
            f"- {_rt(language, 'remediation')}: {_report_finding_remediation(finding)}",
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
        "en": {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"},
    }
    return values.get(normalized, values["en"])


def _build_html_report(
    markdown: str,
    metadata: dict[str, Any],
    *,
    document: dict[str, Any] | None = None,
) -> str:
    document = _validated_render_document(document) if document is not None else _parse_report_document(markdown, metadata)
    metrics = document["metrics"]
    language = _normalize_report_language(
        metadata.get("language") or (metadata.get("report_metrics") or {}).get("language")
    )
    labels = _report_export_labels(language)
    severity = _render_document_severity(document, markdown, metadata)
    toc_items = "\n".join(
        f'<a href="#section-{index + 1}"><span>{index + 1}</span>{html.escape(section["title"])}</a>'
        for index, section in enumerate(document["sections"])
    )
    metric_cards = "\n".join(
        _metric_card(label, value, tone)
        for label, value, tone in [
            (labels["critical_high"], metrics["high_risk"], "danger"),
            (labels["medium"], metrics["medium_risk"], "warning"),
            (labels["dependency"], metrics["dependency_vulnerabilities"], "amber"),
            (labels["code"], metrics["code_findings"], "info"),
        ]
    )
    sections_html = "\n".join(
        f"""
        <section class="report-card" id="section-{index + 1}">
          <div class="section-kicker"><span>{index + 1}</span>{html.escape(section["title"])}</div>
          {_markdown_fragment_to_html(section["content"])}
        </section>
        """
        for index, section in enumerate(document["sections"])
    )
    severity_names = _report_severity_labels(language)
    severity_total = sum(int(value) for value in severity.values())
    severity_rows = "\n".join(
        f"<li><b>{html.escape(severity_names[key])}</b><span>{count} · {_severity_percentage(count, severity_total)}</span></li>"
        for key, count in severity.items()
        if count
    ) or f"<li><b>{html.escape(labels['no_severity'])}</b><span>0 · 0.0%</span></li>"
    bars = _severity_bars(severity)
    degree_stops = _severity_degree_stops(severity)
    score = _risk_score(metrics, severity)
    generated = html.escape(_report_china_time(metrics.get("generated_at") or metadata.get("created_at") or "-"))
    project_name = html.escape(document["project_name"])
    title = html.escape(document["title"])
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
    .shell {{ width: min(920px, calc(100vw - 48px)); margin: 28px auto 48px; }}
    .hero {{
      position: relative;
      min-height: 184px;
      padding: 28px 32px;
      border-radius: 14px;
      overflow: hidden;
      color: #fff;
      background: radial-gradient(circle at 88% 18%, rgba(255,255,255,.22), transparent 24%),
                  linear-gradient(135deg, #0d355d 0%, #05617f 54%, #0f8da0 100%);
      box-shadow: 0 20px 44px rgba(5, 73, 112, .18);
    }}
    .hero:after {{ content: ""; position: absolute; inset: auto -60px -90px auto; width: 260px; height: 260px; border-radius: 50%; border: 1px solid rgba(255,255,255,.22); }}
    .brand {{ display: inline-flex; gap: 8px; align-items: center; padding: 5px 10px; border-radius: 8px; background: rgba(255,255,255,.16); font-size: 12px; font-weight: 700; }}
    h1 {{ margin: 18px 0 8px; max-width: 650px; font-size: 30px; line-height: 1.18; letter-spacing: 0; overflow-wrap: anywhere; }}
    .subtitle {{ max-width: 660px; color: rgba(255,255,255,.82); margin: 0; }}
    .hero-meta {{ display: flex; flex-wrap: wrap; gap: 16px; margin-top: 18px; color: rgba(255,255,255,.78); font-size: 12px; }}
    .score {{ position: absolute; right: 34px; top: 52px; width: 86px; height: 86px; border-radius: 50%; display: grid; place-items: center; text-align: center; background: rgba(255,255,255,.13); border: 1px solid rgba(255,255,255,.3); }}
    .score b {{ display: block; font-size: 26px; line-height: 1; }}
    .score span {{ display: block; margin-top: 4px; font-size: 11px; color: rgba(255,255,255,.74); }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 18px 0 22px; }}
    .metric {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; box-shadow: 0 8px 22px rgba(19, 34, 66, .04); }}
    .metric .icon {{ width: 26px; height: 26px; display: grid; place-items: center; border-radius: 8px; margin-bottom: 12px; font-weight: 800; }}
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
    .layout {{ display: grid; grid-template-columns: 190px minmax(0, 1fr); gap: 18px; align-items: start; }}
    .toc {{ position: sticky; top: 18px; background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px; }}
    .toc h3 {{ margin: 0 0 10px; font-size: 13px; }}
    .toc a {{ display: flex; gap: 8px; align-items: center; padding: 8px 10px; border-radius: 7px; color: #3d4b63; text-decoration: none; font-size: 12px; }}
    .toc a:hover, .toc a:first-of-type {{ background: #e7f7fb; color: #04789d; }}
    .toc span {{ width: 18px; height: 18px; display: grid; place-items: center; border-radius: 6px; background: #eef4f8; font-size: 10px; }}
    .report-card {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 22px 24px; margin-bottom: 18px; box-shadow: 0 8px 24px rgba(19,34,66,.035); }}
    .section-kicker {{ display: inline-flex; align-items: center; gap: 9px; margin-bottom: 18px; font-weight: 800; }}
    .section-kicker span {{ width: 22px; height: 22px; border-radius: 7px; color: #fff; background: linear-gradient(135deg, #00a6d6, #1fb6a6); display: grid; place-items: center; font-size: 12px; }}
    .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 18px; }}
    .chart-card {{ border: 1px solid var(--line); background: #f9fbfd; border-radius: 12px; padding: 18px; min-height: 230px; }}
    .donut {{ width: 142px; height: 142px; border-radius: 50%; margin: 18px auto; background: conic-gradient(var(--danger) 0deg var(--danger-end), var(--warning) var(--danger-end) var(--warning-end), var(--amber) var(--warning-end) var(--amber-end), var(--success) var(--amber-end) 360deg); position: relative; }}
    .donut.empty {{ background: #e8edf4; }}
    .donut:after {{ content: attr(data-total) "\\A" attr(data-label); white-space: pre; position: absolute; inset: 28px; border-radius: 50%; background: #fff; display: grid; place-items: center; text-align: center; font-weight: 800; color: #1d2a3d; }}
    .severity-list {{ list-style: none; margin: 10px 0 0; padding: 0; }}
    .severity-list li {{ display: flex; justify-content: space-between; padding: 6px 0; color: var(--muted); }}
    .bars {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; height: 170px; align-items: end; padding-top: 16px; }}
    .bar {{ text-align: center; color: var(--muted); font-size: 11px; }}
    .bar i {{ display: block; width: 28px; min-height: 4px; margin: 0 auto 8px; border-radius: 5px 5px 2px 2px; background: linear-gradient(180deg, #ff4d4f, #ff9f43); }}
    table {{ width: 100%; table-layout: fixed; border-collapse: collapse; margin: 12px 0 18px; overflow: hidden; border-radius: 8px; font-size: 12px; }}
    th {{ background: #f1f4f8; color: #29364a; font-weight: 700; text-align: left; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px 12px; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }}
    tr:last-child td {{ border-bottom: 0; }}
    h2, h3, h4 {{ color: #162033; line-height: 1.35; }}
    h3 {{ margin: 22px 0 10px; font-size: 17px; }}
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
    pre.vulnerable {{ border-top: 4px solid #ffccc7; }}
    pre.fixed {{ border-top: 4px solid #b7ebc6; }}
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
      .shell {{ width: min(100% - 24px, 920px); margin-top: 12px; }}
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
<body>
  <main class="shell">
    <header class="hero">
      <div class="brand">{html.escape(labels["brand"])}</div>
      <h1>{project_name}</h1>
      <p class="subtitle">{title}</p>
      <div class="hero-meta">
        <span>{html.escape(labels["generated"])}: {generated}</span>
      </div>
      <div class="score"><b>{score}</b><span>{html.escape(labels["score"])}</span></div>
    </header>
    <div class="metrics">{metric_cards}</div>
    <div class="layout">
      <aside class="toc"><h3>{html.escape(labels["toc"])}</h3>{toc_items}</aside>
      <div>
        <section class="report-card">
          <div class="section-kicker"><span>!</span>{html.escape(labels["charts"])}</div>
          <div class="chart-grid">
            <div class="chart-card">
              <b>{html.escape(labels["severity"])}</b>
              <div class="donut{' empty' if not sum(severity.values()) else ''}" data-total="{metrics["total_risks"]}" data-label="{html.escape(labels['total_risks'])}" style="--danger-end:{degree_stops["danger"]}deg;--warning-end:{degree_stops["warning"]}deg;--amber-end:{degree_stops["amber"]}deg;"></div>
              <ul class="severity-list">{severity_rows}</ul>
            </div>
            <div class="chart-card">
              <b>{html.escape(labels["risk_counts"])}</b>
              <div class="bars">{bars}</div>
            </div>
          </div>
        </section>
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
                sections.append({"title": current_title, "content": "\n".join(current_lines).strip()})
            current_title = match.group(1).strip()
            current_lines = []
            continue
        if current_title:
            current_lines.append(line)
    if current_title:
        sections.append({"title": current_title, "content": "\n".join(current_lines).strip()})
    if not sections:
        sections.append({"title": "扫描报告", "content": markdown})
    project_name = _infer_report_project_name(metadata) or _project_from_title_or_file(title, metadata)
    return {"title": title, "project_name": project_name, "metrics": metrics, "sections": sections}


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
        normalized_sections.append({"title": title, "content": content})
    if not normalized_sections:
        raise ValueError("Report JSON render document has no visible sections")
    return {
        **value,
        "title": str(value.get("title") or "SecFlow 安全报告"),
        "project_name": str(value.get("project_name") or "SecFlow"),
        "metrics": {str(key): item for key, item in metrics.items()},
        "sections": normalized_sections,
    }


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


def _metric_card(label: str, value: Any, tone: str) -> str:
    return f"""
    <div class="metric {tone}">
      <div class="icon">!</div>
      <strong>{html.escape(str(value))}</strong>
      <span>{html.escape(label)}</span>
    </div>
    """


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
        if stripped == _REPORT_STYLE_MARKER or stripped.startswith("<!-- secflow-report-style:"):
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
        return f'<pre class="{code_class}"><code>{html.escape(chr(10).join(code_lines))}</code></pre>'
    classes = " ".join(value for value in (code_class, "numbered-code") if value)
    rows = []
    for number, source in numbered:
        row_class = "code-row risk" if number == risk_line else "code-row"
        rows.append(
            f'<span class="{row_class}"><span class="code-line-number" aria-hidden="true">{number}</span>'
            f'<span class="code-source">{html.escape(source) or "&#8203;"}</span></span>'
        )
    return f'<pre class="{classes}"><code>{"".join(rows)}</code></pre>'


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
) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.graphics.shapes import Drawing, Rect, String
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("ReportLab is required for PDF export") from exc

    language = _normalize_report_language(
        metadata.get("language") or (metadata.get("report_metrics") or {}).get("language")
    )
    labels = _report_export_labels(language)
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
        textColor=colors.HexColor("#26364d"),
        splitLongWords=1,
    )
    title_style = ParagraphStyle("SecFlowTitle", parent=base, fontSize=20, leading=25, textColor=colors.white, alignment=TA_CENTER, spaceAfter=8)
    subtitle_style = ParagraphStyle("SecFlowSubtitle", parent=base, fontSize=9, leading=13, textColor=colors.HexColor("#d8eef8"), alignment=TA_CENTER)
    section_style = ParagraphStyle(
        "SecFlowSection",
        parent=base,
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#11233b"),
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
    hero = Table(
        [
            [Paragraph(_pdf_plain_text(document["project_name"], latin_font_name), title_style)],
            [Paragraph(_pdf_plain_text(document["title"], latin_font_name), subtitle_style)],
        ],
        colWidths=[170 * mm],
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#075e7e")),
            ("BOX", (0, 0), (-1, -1), 0, colors.HexColor("#075e7e")),
            ("TOPPADDING", (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ],
    )
    story.append(hero)
    story.append(Spacer(1, 8))
    metric_rows = [
        [
            _pdf_metric(labels["critical_high"], metrics["high_risk"], "#ff4d4f", Paragraph, base, latin_font_name),
            _pdf_metric(labels["medium"], metrics["medium_risk"], "#ffae22", Paragraph, base, latin_font_name),
            _pdf_metric(labels["dependency"], metrics["dependency_vulnerabilities"], "#f4b400", Paragraph, base, latin_font_name),
            _pdf_metric(labels["code"], metrics["code_findings"], "#168aad", Paragraph, base, latin_font_name),
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
    if any(severity.values()):
        story.append(Paragraph(_pdf_plain_text(labels["severity"], latin_font_name), small))
        story.append(
            _pdf_severity_chart(
                severity,
                Drawing,
                Rect,
                String,
                colors,
                font_name,
                latin_font_name,
                language,
            )
        )
        story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            _pdf_plain_text(
                f"{labels['generated']}: {_report_china_time(metrics.get('generated_at') or metadata.get('created_at') or '-')}",
                latin_font_name,
            ),
            small,
        )
    )
    story.append(Spacer(1, 10))
    for index, section in enumerate(document["sections"], start=1):
        story.append(Paragraph(_pdf_plain_text(f"{index}. {section['title']}", latin_font_name), section_style))
        story.extend(
            _markdown_to_pdf_flowables(
                section["content"],
                base,
                code_style,
                Table,
                TableStyle,
                Paragraph,
                colors,
                latin_font_name,
            )
        )
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
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
    escaped = re.sub(r"/([^/\s]+\.[A-Za-z0-9]+):(\d+)", r"/<br/>\1:&nbsp;\2", escaped)
    escaped = re.sub(r":(\d+)", r":&nbsp;\1", escaped)
    escaped = re.sub(r"`([^`]+)`", r'<font color="#087b9d">\1</font>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    return _pdf_apply_latin_font(escaped, latin_font_name)


def _markdown_to_pdf_flowables(
    markdown: str,
    base: Any,
    code_style: Any,
    Table: Any,
    TableStyle: Any,
    Paragraph: Any,
    colors: Any,
    latin_font_name: str = "",
) -> list[Any]:
    flowables: list[Any] = []
    lines = markdown.splitlines()
    in_code = False
    code_lines: list[str] = []
    table_lines: list[str] = []

    def flush_code() -> None:
        nonlocal code_lines
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
            for offset in range(0, len(numbered), 32):
                rows = []
                for number, raw_line in numbered[offset : offset + 32]:
                    expanded = raw_line.expandtabs(4)
                    leading_spaces = len(expanded) - len(expanded.lstrip(" "))
                    source_markup = "&#160;" * leading_spaces + html.escape(expanded[leading_spaces:])
                    rows.append(
                        [
                            Paragraph(str(number), number_style),
                            Paragraph(_pdf_apply_latin_font(source_markup or "&#8203;", latin_font_name), code_cell_style),
                        ]
                    )
                table = Table(rows, colWidths=[38, 442])
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
            return
        chunks = [code_lines[index : index + 32] for index in range(0, len(code_lines), 32)] or [[]]
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

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        rows = []
        for raw in table_lines:
            cells = _split_markdown_table_row(raw)
            if cells and not all(set(cell) <= {"-", ":", " "} for cell in cells):
                rows.append([Paragraph(_pdf_inline_markdown(cell, latin_font_name), base) for cell in cells])
        if rows:
            column_count = max(len(row) for row in rows)
            if column_count == 2:
                column_widths = [135, 345]
            elif column_count == 8:
                column_widths = [30, 42, 68, 52, 72, 70, 96, 50]
            elif column_count == 9:
                column_widths = [48, 34, 34, 48, 46, 55, 62, 42, 111]
            else:
                column_widths = [480 / column_count] * column_count
            table = Table(rows, colWidths=column_widths, repeatRows=1)
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
        payload = _materialize_agent_scan_json(scan_data)
    else:
        payload = _materialize_assistant_scan_json(scan_data)
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
    for key in ("dependencies", "dependency_vulnerabilities", "code_findings"):
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


def _materialize_agent_scan_json(scan_data: dict[str, Any]) -> dict[str, Any]:
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
                finding["remediation"] = _report_finding_remediation(finding)
    return payload


def _materialize_assistant_scan_json(scan_data: dict[str, Any]) -> dict[str, Any]:
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
        finding["remediation"] = _report_finding_remediation(finding)
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
            "dependency_vulnerabilities": dependency_vulnerabilities,
            "code_findings": code_findings,
        }
    dependency_scan = payload.get("dependency_scan") if isinstance(payload.get("dependency_scan"), dict) else {}
    static_analysis = payload.get("static_analysis") if isinstance(payload.get("static_analysis"), dict) else {}
    return {
        "dependencies": [item for item in dependency_scan.get("dependencies") or [] if isinstance(item, dict)],
        "dependency_vulnerabilities": [item for item in payload.get("records") or [] if isinstance(item, dict)],
        "code_findings": [item for item in static_analysis.get("findings") or [] if isinstance(item, dict)],
    }


def _scan_result_payload_sha256(document: dict[str, Any]) -> str:
    signed = {
        key: document.get(key)
        for key in ("$schema", "schema_version", "source_kind", "language", "completed_at", "payload", "facts", "counts")
    }
    return hashlib.sha256(_canonical_report_json_bytes(signed)).hexdigest()


def _build_report_json_document(
    markdown: str,
    metadata: dict[str, Any],
    *,
    report_source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = validate_scan_result_json(report_source) if report_source is not None else build_scan_result_json(
        {}, source_kind="legacy_report", language=str(metadata.get("language") or "zh-Hans")
    )
    clean_markdown = _sanitize_report_content(str(markdown or ""))
    render_document = _parse_report_document(clean_markdown, metadata)
    render_document["markdown"] = clean_markdown
    render_document["severity"] = _severity_distribution(clean_markdown, metadata)
    document = {
        "$schema": _REPORT_DOCUMENT_JSON_SCHEMA,
        "schema_version": _REPORT_DOCUMENT_SCHEMA_VERSION,
        "generated_at": str(metadata.get("created_at") or now_iso()),
        "source": source,
        "report": render_document,
        "charts": _json_report_value(metadata.get("report_charts") or {}),
        "metadata": _json_report_value(metadata),
        "audit": {
            "source_payload_sha256": str((source.get("audit") or {}).get("payload_sha256") or ""),
            "input_format": "application/json",
            "processors": [
                "secflow-report-json",
                "secflow-report-mermaid-mcp",
                "secflow-report-markdown-mcp",
                "secflow-html-renderer",
                "secflow-report-word-mcp",
                "secflow-report-pdf-mcp",
            ],
        },
    }
    return _json_report_value(document)


def build_report_document_json(
    markdown: str,
    metadata: dict[str, Any],
    *,
    report_source: dict[str, Any],
) -> dict[str, Any]:
    """Build the canonical JSON contract consumed by format-specific report MCPs."""

    return _build_report_json_document(markdown, metadata, report_source=report_source)


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
    )


def _render_binary_report_artifacts_with_mcps(
    report_document: dict[str, Any],
    *,
    metadata: dict[str, Any],
) -> tuple[dict[str, bytes], dict[str, str]]:
    import base64

    from app.mcp.report_pdf import invoke_report_pdf_mcp
    from app.mcp.report_word import invoke_report_word_mcp

    artifacts: dict[str, bytes] = {}
    errors: dict[str, str] = {}
    audits = metadata.get("report_mcps") if isinstance(metadata.get("report_mcps"), list) else []
    for report_format, server, tool, invoke in (
        ("docx", "SecFlow Word MCP", "render_word_report", invoke_report_word_mcp),
        ("pdf", "SecFlow PDF MCP", "render_pdf_report", invoke_report_pdf_mcp),
    ):
        invoked_at = now_iso()
        try:
            result = invoke({"report_document": report_document})
            payload = base64.b64decode(str(result.get("artifact_base64") or ""), validate=True)
            expected_digest = str(result.get("output_sha256") or "")
            actual_digest = hashlib.sha256(payload).hexdigest()
            if not expected_digest or expected_digest != actual_digest:
                raise ValueError(f"{server} output hash verification failed")
            artifacts[report_format] = payload
            audits.append(
                {
                    "server": server,
                    "tool": tool,
                    "transport": "in-process",
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
                    "transport": "in-process",
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
