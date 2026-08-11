from __future__ import annotations

import hashlib
import json
import re
import tempfile
from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterator

from app.llm import active_model_from_env, chat_readiness_error, diagnose_chat_completion


PROJECT_ADAPTIVE_SCAN_PROMPT_VERSION = "secflow-project-adaptive-scan-v1"
PROJECT_ADAPTIVE_SCAN_SKILL_NAME = "secflow-project-adaptive-scan"
MAX_ADAPTATION_ITERATIONS = 3
MAX_EVIDENCE_FINDINGS = 24
MAX_EVIDENCE_REVIEW_FINDINGS = 24
MAX_OVERLAY_TAINT_RULES = 8
MAX_OVERLAY_ACTIONS = 24

_SKILL_PATH = (
    Path(__file__).resolve().parents[1]
    / "resources"
    / "skills"
    / PROJECT_ADAPTIVE_SCAN_SKILL_NAME
    / "SKILL.md"
)
_LANGUAGES = {"java", "python", "go", "c", "cpp", "csharp", "rust", "solidity"}
_MACRO_NAME_RE = re.compile(r"[A-Za-z_]\w*\Z")
_RULE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}\Z")
_SIMPLE_PATTERN_RE = re.compile(r"[A-Za-z0-9_$.:>#<*\[\]'\" \t,(){}+\-/]+\Z")


PROJECT_ADAPTIVE_SCAN_SYSTEM_PROMPT = """你是 SecFlow 上传项目的自适应代码扫描节点。
先使用冻结的静态规则与 AST/CFG/调用图/DFG/污点证据，再决定是否需要项目级 Overlay。
只能依据输入中的 evidence_id；不得把模型推测写成已验证的漏报或误报，不得修改全局规则和冻结评测基线。
允许输出：项目级简单 Semgrep taint 规则、预处理宏、提升现有复核候选、把现有主告警降到复核区。
禁止输出可执行代码、命令、利用载荷、任意文件修改或删除告警的动作。
如果证据不足，decision 必须为 no_change。
只返回一个 JSON 对象，不要 Markdown。JSON 结构：
{
  "decision": "no_change|apply_overlay",
  "reason": "简短理由",
  "confidence": 0.0,
  "taint_rules": [{
    "id": "project-rule-id",
    "language": "java|python|go|c|cpp|csharp|rust|solidity",
    "message": "项目级污点路径说明",
    "sources": ["单行 Semgrep pattern"],
    "sinks": ["单行 Semgrep pattern"],
    "sanitizers": ["单行 Semgrep pattern"],
    "evidence_ids": ["当前项目 evidence_id"]
  }],
  "parser_definitions": [{
    "name": "MACRO_NAME",
    "value": "可选值",
    "languages": ["c|cpp"],
    "evidence_ids": ["当前项目 evidence_id"]
  }],
  "promote_review_finding_ids": ["现有复核候选 finding_id"],
  "demote_finding_ids": ["现有主告警 finding_id"]
}
"""


OverlaySynthesizer = Callable[[dict[str, Any]], dict[str, Any]]


@lru_cache(maxsize=1)
def load_project_adaptive_scan_skill() -> str:
    text = _SKILL_PATH.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("SecFlow project-adaptive skill frontmatter is missing")
    _, _, remainder = text.partition("\n---\n")
    body = remainder.strip()
    if not body:
        raise ValueError("SecFlow project-adaptive skill body is empty")
    return body


def project_adaptive_skill_metadata() -> dict[str, str]:
    skill = load_project_adaptive_scan_skill()
    return {
        "name": PROJECT_ADAPTIVE_SCAN_SKILL_NAME,
        "sha256": hashlib.sha256(skill.encode("utf-8")).hexdigest(),
        "prompt_version": PROJECT_ADAPTIVE_SCAN_PROMPT_VERSION,
    }


def build_project_profile(
    *,
    workspace_path: str,
    languages: list[str],
    manifest_files: list[str],
    dependency_scan: dict[str, Any],
    adaptive_enabled: bool,
) -> dict[str, Any]:
    manifest_names = [Path(value).name for value in manifest_files]
    build_systems: list[str] = []
    manifest_markers = {
        "pom.xml": "maven",
        "build.gradle": "gradle",
        "build.gradle.kts": "gradle",
        "go.mod": "go-modules",
        "cargo.toml": "cargo",
        "cmakelists.txt": "cmake",
        "compile_commands.json": "compile-database",
        "pyproject.toml": "python-project",
        "requirements.txt": "python-requirements",
        "directory.packages.props": "nuget-central-management",
    }
    for name in manifest_names:
        marker = manifest_markers.get(name.casefold())
        if marker and marker not in build_systems:
            build_systems.append(marker)
        suffix = Path(name).suffix.casefold()
        if suffix in {".csproj", ".sln", ".props"} and "dotnet" not in build_systems:
            build_systems.append("dotnet")

    dependencies = list(dependency_scan.get("dependencies") or [])
    frameworks = []
    for dependency in dependencies:
        name = str(dependency.get("name") or "").strip()
        if name and name not in frameworks:
            frameworks.append(name)
        if len(frameworks) >= 40:
            break
    workspace = Path(workspace_path)
    scope_material = json.dumps(
        {
            "workspace_name": workspace.name,
            "languages": languages,
            "manifests": manifest_files,
        },
        ensure_ascii=True,
        sort_keys=True,
    )
    return {
        "scope": "directory" if workspace.is_dir() else "file",
        "workspace_name": workspace.name,
        "scope_fingerprint": hashlib.sha256(scope_material.encode("utf-8")).hexdigest(),
        "languages": [value for value in languages if value in _LANGUAGES],
        "manifest_files": manifest_files[:80],
        "build_systems": build_systems,
        "frameworks": frameworks,
        "dependency_count": int(dependency_scan.get("dependency_count") or len(dependencies)),
        "adaptive_enabled": adaptive_enabled,
        "evaluation_isolation": not adaptive_enabled,
        "skill": project_adaptive_skill_metadata(),
    }


def fuse_project_evidence(
    project_profile: dict[str, Any],
    language_results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    review_findings: list[dict[str, Any]] = []
    syntax_gaps: list[dict[str, Any]] = []
    metrics = {
        "findings": 0,
        "review_findings": 0,
        "parsed_files": 0,
        "parse_error_files": 0,
        "cfg_edges": 0,
        "dfg_edges": 0,
    }
    for language in project_profile.get("languages") or []:
        result = language_results.get(language) or {}
        metrics["findings"] += int(result.get("finding_count") or 0)
        metrics["review_findings"] += int(result.get("review_finding_count") or 0)
        syntax = result.get("syntax_summary") or {}
        metrics["parsed_files"] += int(syntax.get("parsed_files") or 0)
        metrics["parse_error_files"] += int(syntax.get("parse_error_files") or 0)
        metrics["cfg_edges"] += int(syntax.get("cfg_edge_count") or 0)
        metrics["dfg_edges"] += int(syntax.get("dfg_edge_count") or 0)
        if int(syntax.get("parse_error_files") or 0):
            syntax_gaps.append(
                {
                    "evidence_id": f"syntax:{language}",
                    "language": language,
                    "parse_error_files": int(syntax.get("parse_error_files") or 0),
                    "raw_parse_error_files": int(syntax.get("raw_parse_error_files") or 0),
                    "files": list(syntax.get("parse_error_file_names") or [])[:20],
                }
            )
        for finding in list(result.get("findings") or [])[:MAX_EVIDENCE_FINDINGS]:
            findings.append(_evidence_finding(language, finding, "finding"))
        for finding in list(result.get("review_findings") or [])[:MAX_EVIDENCE_REVIEW_FINDINGS]:
            review_findings.append(_evidence_finding(language, finding, "review"))

    evidence_ids = {
        item["evidence_id"]
        for item in [*findings, *review_findings, *syntax_gaps]
    }
    return {
        "metrics": metrics,
        "findings": findings[:MAX_EVIDENCE_FINDINGS],
        "review_findings": review_findings[:MAX_EVIDENCE_REVIEW_FINDINGS],
        "syntax_gaps": syntax_gaps,
        "evidence_ids": sorted(evidence_ids),
        "verified_truth_available": False,
        "runtime_trace_available": False,
        "false_negative_claim_allowed": False,
        "interpretation": (
            "静态结果和语义候选可用于提出项目 Overlay；没有独立真值或运行轨迹时，"
            "不得声称已识别真实 FN/FP，也不得删除告警。"
        ),
    }


def build_overlay_request(
    *,
    project_profile: dict[str, Any],
    evidence: dict[str, Any],
    iteration: int,
    previous_overlay_fingerprints: list[str],
    user_id: str = "default",
) -> dict[str, Any]:
    return {
        "prompt_version": PROJECT_ADAPTIVE_SCAN_PROMPT_VERSION,
        "skill": project_adaptive_skill_metadata(),
        "iteration": iteration,
        "max_iterations": MAX_ADAPTATION_ITERATIONS,
        "project_profile": deepcopy(project_profile),
        "evidence": deepcopy(evidence),
        "previous_overlay_fingerprints": list(previous_overlay_fingerprints),
        "user_id": str(user_id or "default").strip() or "default",
    }


def default_overlay_synthesizer(request: dict[str, Any]) -> dict[str, Any]:
    model = active_model_from_env(str(request.get("user_id") or "default"))
    readiness_error = chat_readiness_error(model)
    if readiness_error:
        return {"status": "skipped", "reason": readiness_error, "overlay": empty_project_overlay("模型不可用。")}
    messages = [
        {
            "role": "system",
            "content": f"{PROJECT_ADAPTIVE_SCAN_SYSTEM_PROMPT}\n\n必须遵守以下 skill：\n{load_project_adaptive_scan_skill()}",
        },
        {
            "role": "user",
            "content": json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        },
    ]
    result = diagnose_chat_completion(
        model or {},
        messages,
        enable_thinking=True,
        json_mode=True,
        user_id=str(request.get("user_id") or "default"),
        session_id=str(request.get("session_id") or ""),
        source="project_adaptive_scan",
    )
    if result.get("status") != "success":
        return {
            "status": "failed",
            "reason": str(result.get("message") or "模型未返回可用 Overlay。"),
            "overlay": empty_project_overlay("模型调用失败。"),
        }
    try:
        candidate = _parse_json_object(str(result.get("answer") or ""))
        overlay = validate_project_overlay(candidate, request)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "status": "rejected",
            "reason": f"Overlay 未通过结构验证：{exc}",
            "overlay": empty_project_overlay("Overlay 结构无效。"),
        }
    return {
        "status": "ready" if overlay["decision"] == "apply_overlay" else "no_change",
        "reason": overlay["reason"],
        "model": {
            "provider": str((model or {}).get("provider") or ""),
            "model": str((model or {}).get("model") or ""),
            "latency_ms": result.get("latency_ms"),
        },
        "overlay": overlay,
    }


def validate_project_overlay(candidate: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise TypeError("Overlay must be a JSON object")
    decision = str(candidate.get("decision") or "no_change").strip()
    if decision not in {"no_change", "apply_overlay"}:
        raise ValueError("decision must be no_change or apply_overlay")
    reason = _bounded_text(candidate.get("reason"), 500) or "没有可验证的项目级调整。"
    confidence = _bounded_confidence(candidate.get("confidence"))
    evidence = request.get("evidence") or {}
    valid_evidence_ids = set(evidence.get("evidence_ids") or [])
    valid_findings = {
        str(item.get("finding_id") or "")
        for item in evidence.get("findings") or []
        if str(item.get("finding_id") or "")
    }
    valid_review_findings = {
        str(item.get("finding_id") or "")
        for item in evidence.get("review_findings") or []
        if str(item.get("finding_id") or "")
    }
    allowed_languages = set((request.get("project_profile") or {}).get("languages") or []) & _LANGUAGES

    taint_rules = []
    for raw_rule in list(candidate.get("taint_rules") or [])[:MAX_OVERLAY_TAINT_RULES]:
        if not isinstance(raw_rule, dict):
            continue
        language = str(raw_rule.get("language") or "").strip().lower()
        rule_id = str(raw_rule.get("id") or "").strip().lower()
        evidence_ids = _validated_evidence_ids(raw_rule.get("evidence_ids"), valid_evidence_ids)
        sources = _validated_patterns(raw_rule.get("sources"))
        sinks = _validated_patterns(raw_rule.get("sinks"))
        sanitizers = _validated_patterns(raw_rule.get("sanitizers"))
        if (
            language not in allowed_languages
            or not _RULE_ID_RE.fullmatch(rule_id)
            or not evidence_ids
            or not sources
            or not sinks
        ):
            continue
        taint_rules.append(
            {
                "id": rule_id,
                "language": language,
                "message": _bounded_text(raw_rule.get("message"), 240) or "SecFlow 项目级污点路径",
                "sources": sources,
                "sinks": sinks,
                "sanitizers": sanitizers,
                "evidence_ids": evidence_ids,
            }
        )

    parser_definitions = []
    for raw_definition in list(candidate.get("parser_definitions") or [])[:MAX_OVERLAY_ACTIONS]:
        if not isinstance(raw_definition, dict):
            continue
        name = str(raw_definition.get("name") or "").strip()
        languages = [
            str(value).strip().lower()
            for value in raw_definition.get("languages") or []
            if str(value).strip().lower() in {"c", "cpp"} & allowed_languages
        ]
        evidence_ids = _validated_evidence_ids(raw_definition.get("evidence_ids"), valid_evidence_ids)
        if not _MACRO_NAME_RE.fullmatch(name) or not languages or not evidence_ids:
            continue
        parser_definitions.append(
            {
                "name": name,
                "value": _bounded_text(raw_definition.get("value"), 80),
                "languages": list(dict.fromkeys(languages)),
                "evidence_ids": evidence_ids,
            }
        )

    promote_ids = _validated_action_ids(
        candidate.get("promote_review_finding_ids"), valid_review_findings
    )
    demote_ids = _validated_action_ids(candidate.get("demote_finding_ids"), valid_findings)
    has_actions = bool(taint_rules or parser_definitions or promote_ids or demote_ids)
    if decision == "apply_overlay" and (confidence < 0.8 or not has_actions):
        decision = "no_change"
        reason = "Overlay 置信度不足或没有可执行、可引用证据的动作。"
        taint_rules = []
        parser_definitions = []
        promote_ids = []
        demote_ids = []

    overlay = {
        "version": 1,
        "scope": "project-task-only",
        "decision": decision,
        "reason": reason,
        "confidence": confidence,
        "taint_rules": taint_rules,
        "parser_definitions": parser_definitions,
        "promote_review_finding_ids": promote_ids,
        "demote_finding_ids": demote_ids,
        "global_rule_changes": False,
        "evaluation_eligible": False,
    }
    overlay["fingerprint"] = project_overlay_fingerprint(overlay)
    return overlay


def empty_project_overlay(reason: str) -> dict[str, Any]:
    overlay = {
        "version": 1,
        "scope": "project-task-only",
        "decision": "no_change",
        "reason": reason,
        "confidence": 0.0,
        "taint_rules": [],
        "parser_definitions": [],
        "promote_review_finding_ids": [],
        "demote_finding_ids": [],
        "global_rule_changes": False,
        "evaluation_eligible": False,
    }
    overlay["fingerprint"] = project_overlay_fingerprint(overlay)
    return overlay


def project_overlay_fingerprint(overlay: dict[str, Any]) -> str:
    payload = {key: value for key, value in overlay.items() if key != "fingerprint"}
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def overlay_languages(overlay: dict[str, Any]) -> set[str]:
    languages = {
        str(rule.get("language") or "")
        for rule in overlay.get("taint_rules") or []
        if isinstance(rule, dict)
    }
    for definition in overlay.get("parser_definitions") or []:
        if isinstance(definition, dict):
            languages.update(str(value) for value in definition.get("languages") or [])
    return languages & _LANGUAGES


def overlay_preprocessor_definitions(overlay: dict[str, Any], language: str) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for item in overlay.get("parser_definitions") or []:
        if not isinstance(item, dict) or language not in set(item.get("languages") or []):
            continue
        name = str(item.get("name") or "")
        if _MACRO_NAME_RE.fullmatch(name):
            definitions[name] = str(item.get("value") or "")[:80]
    return definitions


@contextmanager
def project_overlay_rule_file(overlay: dict[str, Any], language: str) -> Iterator[str | None]:
    rules = []
    for item in overlay.get("taint_rules") or []:
        if not isinstance(item, dict) or item.get("language") != language:
            continue
        rule = {
            "id": f"secflow.project.{item['id']}",
            "languages": [_semgrep_language(language)],
            "message": str(item.get("message") or "SecFlow 项目级污点路径"),
            "severity": "WARNING",
            "mode": "taint",
            "pattern-sources": [{"pattern": value} for value in item.get("sources") or []],
            "pattern-sinks": [{"pattern": value} for value in item.get("sinks") or []],
            "metadata": {
                "secflow_scope": "project-task-only",
                "overlay_fingerprint": overlay.get("fingerprint"),
                "evidence_ids": item.get("evidence_ids") or [],
            },
        }
        sanitizers = list(item.get("sanitizers") or [])
        if sanitizers:
            rule["pattern-sanitizers"] = [{"pattern": value} for value in sanitizers]
        rules.append(rule)
    if not rules:
        yield None
        return
    path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            prefix="secflow-project-overlay-",
            delete=False,
        ) as handle:
            json.dump({"rules": rules}, handle, ensure_ascii=True, sort_keys=True)
            path = handle.name
        yield path
    finally:
        if path:
            Path(path).unlink(missing_ok=True)


def apply_overlay_classification(
    result: dict[str, Any],
    overlay: dict[str, Any],
) -> dict[str, Any]:
    adapted = deepcopy(result)
    findings = list(adapted.get("findings") or [])
    review_findings = list(adapted.get("review_findings") or [])
    promote_ids = set(overlay.get("promote_review_finding_ids") or [])
    demote_ids = set(overlay.get("demote_finding_ids") or [])

    retained = []
    for finding in findings:
        finding_id = str(finding.get("id") or "")
        if finding_id and finding_id in demote_ids:
            review_findings.append({**finding, "project_overlay_action": "demoted_for_review"})
        else:
            retained.append(finding)
    findings = retained

    retained_review = []
    for finding in review_findings:
        finding_id = str(finding.get("id") or "")
        if finding_id and finding_id in promote_ids:
            findings.append({**finding, "project_overlay_action": "promoted_from_review"})
        else:
            retained_review.append(finding)
    adapted["findings"] = _deduplicate_findings(findings)
    adapted["review_findings"] = _deduplicate_findings(retained_review)
    adapted["finding_count"] = len(adapted["findings"])
    adapted["review_finding_count"] = len(adapted["review_findings"])
    adapted["project_overlay"] = {
        "fingerprint": overlay.get("fingerprint"),
        "scope": overlay.get("scope"),
        "decision": overlay.get("decision"),
    }
    return adapted


def _evidence_finding(language: str, finding: dict[str, Any], category: str) -> dict[str, Any]:
    finding_id = str(finding.get("id") or "")
    stable_id = finding_id or hashlib.sha256(
        json.dumps(finding, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return {
        "evidence_id": f"{category}:{language}:{stable_id}",
        "finding_id": stable_id,
        "language": language,
        "category": category,
        "rule_id": _bounded_text(finding.get("rule_id"), 160),
        "title": _bounded_text(finding.get("title"), 240),
        "severity": _bounded_text(finding.get("severity"), 20),
        "file_name": _bounded_text(finding.get("file_name"), 500),
        "line": finding.get("line"),
        "description": _bounded_text(finding.get("description"), 800),
        "source": _bounded_json_value(finding.get("source"), 800),
        "sink": _bounded_json_value(finding.get("sink"), 800),
        "taint_path": _bounded_json_value(finding.get("taint_path"), 1_600),
    }


def _parse_json_object(value: str) -> dict[str, Any]:
    clean = value.strip()
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"\s*```$", "", clean)
    parsed = json.loads(clean)
    if not isinstance(parsed, dict):
        raise TypeError("model output is not a JSON object")
    return parsed


def _validated_patterns(values: Any) -> list[str]:
    result = []
    for raw in list(values or [])[:12]:
        value = str(raw).strip()
        if 3 <= len(value) <= 240 and "\n" not in value and _SIMPLE_PATTERN_RE.fullmatch(value):
            result.append(value)
    return list(dict.fromkeys(result))


def _validated_evidence_ids(values: Any, allowed: set[str]) -> list[str]:
    return [
        value
        for value in dict.fromkeys(str(raw).strip() for raw in list(values or [])[:MAX_OVERLAY_ACTIONS])
        if value in allowed
    ]


def _validated_action_ids(values: Any, allowed: set[str]) -> list[str]:
    return [
        value
        for value in dict.fromkeys(str(raw).strip() for raw in list(values or [])[:MAX_OVERLAY_ACTIONS])
        if value in allowed
    ]


def _bounded_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _bounded_confidence(value: Any) -> float:
    try:
        return round(max(0.0, min(float(value), 1.0)), 4)
    except (TypeError, ValueError):
        return 0.0


def _bounded_json_value(value: Any, limit: int) -> Any:
    if value is None or value == "" or value == [] or value == {}:
        return None
    serialized = json.dumps(value, ensure_ascii=False, default=str)
    if len(serialized) <= limit:
        return value
    return serialized[:limit]


def _semgrep_language(language: str) -> str:
    return {"cpp": "cpp", "csharp": "csharp"}.get(language, language)


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for finding in findings:
        key = (
            str(finding.get("id") or ""),
            str(finding.get("rule_id") or ""),
            str(finding.get("file_name") or finding.get("file") or ""),
            str(finding.get("line") or finding.get("risk_line") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
