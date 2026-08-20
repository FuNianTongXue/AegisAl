from __future__ import annotations

import json
import re
from calendar import monthrange
from datetime import date, timedelta
from typing import Any

from app.llm import active_model_from_env, chat_readiness_error, diagnose_chat_completion
from app.skills import runtime as skill_runtime


ASSISTANT_INTENT_PROMPT_VERSION = "secflow-assistant-intent-v9"
MULTI_AGENT_SUPERVISOR_SKILL_NAME = "secflow-multi-agent-supervisor"
ASSISTANT_INTENT_SKILL_NAME = "secflow-component-vulnerability-catalog"
COMPONENT_QUERY_SKILL_NAME = "secflow-component-vulnerability-query"
SBOM_SKILL_NAME = "secflow-project-sbom"
PROJECT_SCAN_SKILL_NAME = "secflow-project-scan"
REPORT_SKILL_NAME = "secflow-report-generation"
_ALLOWED_INTENTS = {
    "component_vulnerability_catalog",
    "component_vulnerability_query",
    "project_sbom_export",
    "sbom_result_follow_up",
    "project_scan",
    "project_rescan",
    "scan_result_follow_up",
    "vulnerability_year_lookup",
    "llm_direct",
}
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
_ECOSYSTEM_ALIASES = {
    "Maven": ("maven", "gradle"),
    "npm": ("npm", "node.js", "nodejs"),
    "PyPI": ("pypi", "python", "pip"),
    "Go": ("golang", "go module", "go.mod"),
    "crates.io": ("crates.io", "cargo", "rust"),
    "NuGet": ("nuget", ".net", "dotnet"),
    "RubyGems": ("rubygems", "gem", "ruby"),
    "Packagist": ("packagist", "composer", "php"),
}


ASSISTANT_INTENT_SYSTEM_PROMPT = """你是 SecFlow 的语义规划节点，不是关键词分类器。
根据用户真正希望完成的工作，从允许的能力中选择最合适的一项，并提取时间语义和筛选条件。
当输入明确提供项目工作区，并且用户目标是生成软件物料清单、项目组件/依赖资产清单、项目许可清单、供应链清单或对应 Excel 时，选择 project_sbom_export。应结合目标、工作区、期望产物和上下文理解，不要求用户必须说出“SBOM”这个缩写。
当输入提供最近一次、当前用户所有的 SBOM 操作上下文，并且用户追问已生成清单匹配了哪些漏洞、命中数量、覆盖状态、组件或许可结果时，选择 sbom_result_follow_up。该能力只读既有 SBOM checkpoint 或长期记忆快照，不得把追问当成下载确认，也不得重新匹配漏洞。
普通代码漏洞扫描、代码审计和生成扫描报告不属于 project_sbom_export；它们应保持原有扫描任务流程。
当同一目标同时要求实际扫描，并说明“扫描完成后询问、确认或生成报告”时，先选择 project_scan 或 project_rescan。报告只是完成扫描后的候选动作，不能抢占扫描；只有用户基于已经完成的固定扫描事实单独要求生成或下载报告时，才进入报告能力。
不要因为出现“组件”就强制要求单一组件版本：当用户要某个时间范围内的最新漏洞、清单、目录、列表、统计或导出时，选择 component_vulnerability_catalog。
只有用户明确询问某个组件的某个具体版本是否受影响时，才选择 component_vulnerability_query；该能力会使用 Component Detail MCP 生成结构化漏洞详情页，不要把它改成通用问答。
用户询问某年所有漏洞但没有强调组件清单时，选择 vulnerability_year_lookup。
当用户明确希望实际执行代码、依赖、AST、CFG、DFG、污点或安全扫描时，选择 project_scan，即使本轮没有显式附加工作区。工作区是否可恢复由确定性项目关联节点判断；不要因为只有历史 SBOM 文件名就把执行意图降级成普通问答，也不要根据文件名猜测本机路径。仅询问“代码扫描是什么”等概念问题时仍选择 llm_direct。
用户项目扫描确定后，由任务图按语言调用 Host 管理的本地 stdio Code Scan MCP 独立沙箱进程；项目许可识别属于 SBOM Agent 的专属能力，代码扫描 Agent 和报告 Agent 不得直接调用许可识别工具。语义规划节点只决定用户目标，不伪造 MCP 调用状态，也不把普通问答误路由为扫描。
当输入提供已完成的活动扫描任务且用户希望再次扫描、回归扫描或与上次结果对比时，选择 project_rescan。
当用户希望解释活动扫描结果、补充修复方案、修改代码示例、验证方法、优先级或风险判断时，选择 scan_result_follow_up。
同一次扫描内部的项目 Overlay 重扫不等于用户发起的 project_rescan。其他问题选择 llm_direct。
生成或下载扫描报告时必须遵守报告 skill：先使用同一份扫描 JSON，依次调用 Mermaid、Markdown、Word、PDF MCP，并保留生成前和下载前的人工确认；格式转换不得重新扫描或修改漏洞事实。
相对日期必须以输入的 current_date 为基准理解。不要虚构组件名称、版本、日期或筛选条件。
筛选条件只能提取问题中明确写出的条件：“优先”“紧急”“重点”“需要处置”“需要关注”等是排序与汇报措辞，不是筛选条件；问题没有明确写出严重性等级词（严重/高危/中危/低危 或 critical/high/medium/low）时，severities 必须为空数组。
只返回一个 JSON 对象，不要 Markdown。结构：
{
  "intent": "component_vulnerability_catalog|component_vulnerability_query|project_sbom_export|sbom_result_follow_up|project_scan|project_rescan|scan_result_follow_up|vulnerability_year_lookup|llm_direct",
  "reason": "简短语义理由",
  "confidence": 0.0,
  "time_scope": {
    "kind": "current_month|previous_month|year_month|year|recent_days|date_range|latest|unspecified",
    "year": null,
    "month": null,
    "days": null,
    "start_date": null,
    "end_date": null
  },
  "filters": {
    "ecosystems": [],
    "severities": [],
    "component_names": []
  },
  "destination_hint": "desktop|downloads|documents|choose|unspecified"
}
"""


def load_component_catalog_skill() -> str:
    return skill_runtime.load_skill(ASSISTANT_INTENT_SKILL_NAME)


def load_component_query_skill() -> str:
    return skill_runtime.load_skill(COMPONENT_QUERY_SKILL_NAME)


def load_sbom_skill() -> str:
    return skill_runtime.load_skill(SBOM_SKILL_NAME)


def load_project_scan_skill() -> str:
    return skill_runtime.load_skill(PROJECT_SCAN_SKILL_NAME)


def load_report_skill() -> str:
    return skill_runtime.load_skill(REPORT_SKILL_NAME)


def load_multi_agent_supervisor_skill() -> str:
    return skill_runtime.load_skill(MULTI_AGENT_SUPERVISOR_SKILL_NAME)


def multi_agent_supervisor_skill_metadata() -> dict[str, str]:
    return skill_runtime.skill_metadata(
        MULTI_AGENT_SUPERVISOR_SKILL_NAME,
        prompt_version=ASSISTANT_INTENT_PROMPT_VERSION,
    )


def assistant_intent_skill_metadata() -> dict[str, str]:
    return skill_runtime.skill_metadata(
        ASSISTANT_INTENT_SKILL_NAME,
        prompt_version=ASSISTANT_INTENT_PROMPT_VERSION,
    )


def component_query_skill_metadata() -> dict[str, str]:
    return skill_runtime.skill_metadata(
        COMPONENT_QUERY_SKILL_NAME,
        prompt_version=ASSISTANT_INTENT_PROMPT_VERSION,
    )


def sbom_skill_metadata() -> dict[str, str]:
    return skill_runtime.skill_metadata(
        SBOM_SKILL_NAME,
        prompt_version=ASSISTANT_INTENT_PROMPT_VERSION,
    )


def project_scan_skill_metadata() -> dict[str, str]:
    return skill_runtime.skill_metadata(
        PROJECT_SCAN_SKILL_NAME,
        prompt_version=ASSISTANT_INTENT_PROMPT_VERSION,
    )


def plan_assistant_intent(
    question: str,
    *,
    today: date | None = None,
    workspace_available: bool = False,
    active_task: dict[str, Any] | None = None,
    recent_sbom_operation: dict[str, Any] | None = None,
    user_id: str = "default",
    session_id: str = "",
) -> dict[str, Any]:
    clean_question = " ".join(str(question or "").split())
    current_date = today or date.today()
    task_context = _planner_task_context(active_task)
    fallback = heuristic_intent_plan(
        clean_question,
        today=current_date,
        workspace_available=workspace_available,
        active_task=task_context,
        recent_sbom_operation=recent_sbom_operation,
    )
    if fallback.get("intent") in {"project_scan", "project_rescan"}:
        return {
            **fallback,
            "planner": "deterministic-workspace-security-route",
            "supervisor_skill": multi_agent_supervisor_skill_metadata(),
        }
    if (
        fallback.get("intent") == "project_sbom_export"
        and str(fallback.get("scan_type_directive") or "") == "sbom"
    ):
        # An explicit SBOM-only scan-type selection must never be overridden by the model:
        # dependency/component identification runs instead of any code semantic scan.
        return {
            **fallback,
            "planner": "deterministic-workspace-sbom-route",
            "supervisor_skill": multi_agent_supervisor_skill_metadata(),
        }
    model = active_model_from_env(user_id)
    readiness_error = chat_readiness_error(model)
    if readiness_error:
        return {
            **fallback,
            "planner": "deterministic-fallback",
            "planner_error": readiness_error,
            "supervisor_skill": multi_agent_supervisor_skill_metadata(),
        }

    payload = {
        "current_date": current_date.isoformat(),
        "question": clean_question,
        "workspace_available": bool(workspace_available),
        "active_task": task_context,
        "recent_sbom_operation": _planner_sbom_context(recent_sbom_operation),
        "allowed_capabilities": sorted(_ALLOWED_INTENTS),
    }
    messages = [
        {
            "role": "system",
            "content": (
                f"{ASSISTANT_INTENT_SYSTEM_PROMPT}\n\n"
                f"必须遵守以下多 Agent Supervisor skill：\n{load_multi_agent_supervisor_skill()}\n\n"
                f"必须遵守以下组件目录 skill：\n{load_component_catalog_skill()}\n\n"
                f"必须遵守以下单组件核验 skill：\n{load_component_query_skill()}\n\n"
                f"必须遵守以下项目 SBOM skill：\n{load_sbom_skill()}\n\n"
                f"必须遵守以下项目扫描 skill：\n{load_project_scan_skill()}"
                f"\n\n必须遵守以下报告生成 skill：\n{load_report_skill()}"
            ),
        },
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, sort_keys=True)},
    ]
    result = diagnose_chat_completion(
        model or {},
        messages,
        enable_thinking=True,
        json_mode=True,
        user_id=user_id,
        session_id=session_id,
        source="intent_planner",
    )
    if result.get("status") != "success":
        return {
            **fallback,
            "planner": "deterministic-fallback",
            "planner_error": str(result.get("message") or "语义规划模型未返回结果"),
            "supervisor_skill": multi_agent_supervisor_skill_metadata(),
        }
    try:
        candidate = _parse_json_object(str(result.get("answer") or ""))
        planned = validate_intent_plan(
            candidate,
            clean_question,
            today=current_date,
            workspace_available=workspace_available,
            active_task_available=bool(task_context.get("available")),
            sbom_context_available=bool(recent_sbom_operation),
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            **fallback,
            "planner": "deterministic-fallback",
            "planner_error": str(exc),
            "supervisor_skill": multi_agent_supervisor_skill_metadata(),
        }
    return {
        **planned,
        "planner": "llm",
        "model": {
            "provider": str((model or {}).get("provider") or ""),
            "model": str((model or {}).get("model") or ""),
            "latency_ms": result.get("latency_ms"),
        },
        "supervisor_skill": multi_agent_supervisor_skill_metadata(),
    }


def validate_intent_plan(
    candidate: dict[str, Any],
    question: str,
    *,
    today: date,
    workspace_available: bool = False,
    active_task_available: bool = False,
    sbom_context_available: bool = False,
) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise TypeError("assistant intent plan must be an object")
    intent = str(candidate.get("intent") or "").strip()
    if intent not in _ALLOWED_INTENTS:
        raise ValueError("assistant intent plan selected an unsupported capability")
    if intent in {"project_rescan", "scan_result_follow_up"} and not active_task_available:
        raise ValueError("scan task action requires an active task")
    if intent == "sbom_result_follow_up" and not sbom_context_available:
        raise ValueError("SBOM result follow-up requires a user-owned SBOM operation")
    time_scope = candidate.get("time_scope") if isinstance(candidate.get("time_scope"), dict) else {}
    date_filter = resolve_catalog_date_range(question, time_scope, today=today) if intent == "component_vulnerability_catalog" else {}
    if intent == "component_vulnerability_catalog" and not date_filter:
        raise ValueError("component catalog intent is missing a valid time range")
    normalized = _normalize_filters(candidate.get("filters"))
    explicit = infer_explicit_filters(question)
    if normalized.get("severities") and not explicit.get("severities"):
        # “优先处置/重点关注/需要处理”等措辞是排序与汇报用语，不是筛选条件。
        # 严重性筛选只允许来自问题中明确出现的等级词（严重/高危/中危/低危），
        # 否则同一问题会因模型理解波动得到两份不同清单。
        normalized["severities"] = []
    filters = _merge_filters(normalized, explicit)
    return {
        "intent": intent,
        "reason": str(candidate.get("reason") or "已根据问题语义选择能力。").strip()[:240],
        "confidence": _bounded_confidence(candidate.get("confidence")),
        "time_scope": dict(time_scope),
        "date_filter": date_filter,
        "filters": filters,
        "destination_hint": normalize_destination_hint(candidate.get("destination_hint"), question=question),
        "skill": _intent_skill_metadata(intent),
    }


def heuristic_intent_plan(
    question: str,
    *,
    today: date | None = None,
    workspace_available: bool = False,
    active_task: dict[str, Any] | None = None,
    recent_sbom_operation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current_date = today or date.today()
    lowered = question.casefold()
    ecosystem_signal = any(
        re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered)
        for aliases in _ECOSYSTEM_ALIASES.values()
        for alias in aliases
    )
    component_signal = bool(
        re.search(r"组件|依赖|软件包|包|component|dependency|package|artifact", lowered)
    ) or ecosystem_signal
    catalog_signal = bool(
        re.search(
            r"清单|目录|列表|汇总|统计|最新|近期|最近|本月|当月|上月|月份|年月|近\s*\d+\s*天|"
            r"catalog|list|latest|current\s+month|last\s+month|recent",
            lowered,
        )
    )
    catalog_request_signal = bool(
        re.search(
            r"查询|查找|搜索|获取|列出|给我|有哪些|都有什么|"
            r"\b(?:find|show|list|get|query|search)\b",
            lowered,
        )
    )
    vulnerability_signal = bool(re.search(r"漏洞|cve|ghsa|vulnerab|安全风险|高危|严重", lowered))
    year_signal = bool(re.search(r"(?:19|20)\d{2}|今年|本年|去年|current\s+year|last\s+year", lowered))
    sbom_signal = bool(
        re.search(
            r"(?<![a-z0-9])sbom(?![a-z0-9])|software\s+bill\s+of\s+materials|软件物料|软件材料|供应链(?:资产)?清单|"
            r"(?:项目|仓库|代码库).{0,18}(?:许可|许可证|license).{0,18}(?:清单|盘点|excel|xlsx)|"
            r"(?:导出|生成|整理|列出).{0,18}(?:项目|仓库|代码库).{0,18}(?:依赖|组件|软件包).{0,18}(?:清单|excel|xlsx)|"
            r"(?:项目|仓库|代码库).{0,18}(?:依赖|组件|软件包).{0,18}(?:清单|excel|xlsx)",
            lowered,
        )
    )
    # Explicit scan-type directives (e.g. the client's scan-type confirmation prefixes or
    # unambiguous user phrasing) outrank every inferred signal, including scan keywords that
    # appear inside negations such as “不包含代码漏洞扫描”.
    sbom_only_directive = bool(
        re.search(
            r"(?:仅|只)(?:是)?(?:执行|进行|做|生成|导出)?\s*sbom|sbom[\s-]*only|only[\s-]+sbom",
            lowered,
        )
    )
    code_only_directive = bool(
        re.search(
            r"(?:仅|只)(?:是)?(?:执行|进行|做)?\s*代码(?:安全)?扫描|"
            r"code[\s-]*scan[\s-]*only|only[\s-]+code[\s-]*scan",
            lowered,
        )
    )
    full_scan_directive = bool(
        re.search(r"完整(?:安全)?扫描|全量(?:安全)?扫描|full\s+scan", lowered)
    )
    scan_type_directive = ""
    if sbom_only_directive and not code_only_directive and not full_scan_directive:
        scan_type_directive = "sbom"
    elif code_only_directive and not sbom_only_directive:
        scan_type_directive = "code"
    elif full_scan_directive and not sbom_only_directive:
        scan_type_directive = "full"
    scan_signal = bool(
        re.search(
            r"扫描|重扫|代码审计|安全审计|污点|静态分析|跨方法|重新分析|"
            r"\bscan\b|\brescan\b|code\s+audit|taint|static\s+analysis|cfg|dfg",
            lowered,
        )
    )
    project_scope_signal = bool(
        re.search(r"代码|源码|项目|仓库|代码库|应用|服务|工程|code|source|project|repository|repo", lowered)
    )
    rescan_signal = bool(
        re.search(
            r"重新扫描|再次扫描|再扫描|重扫|差异扫描|回归扫描|重新分析|"
            r"(?:再|再次|重新).{0,12}(?:检查|排查|检测|审查|分析|评估)|"
            r"(?:与|和).{0,8}(?:上次|上一次|之前).{0,12}(?:扫描|结果).{0,12}(?:比较|对比)|"
            r"\brescan\b|scan\s+again|(?:compare|diff).{0,40}(?:previous|last).{0,16}scan",
            lowered,
        )
    )
    follow_up_signal = bool(
        re.search(
            r"刚才|上次|扫描结果|发现的|这些风险|修复方案|修复建议|修改代码|代码示例|验证方法|如何验证|"
            r"优先级|误报|漏报|finding|scan\s+result|remediation|how\s+to\s+fix|verify",
            lowered,
        )
    )
    completed_scan_report_signal = bool(
        re.search(
            r"(?:基于|根据|使用).{0,16}(?:已完成|本次|刚才|上次|扫描结果|扫描事实)|"
            r"(?:已完成|本次|刚才|上次|上一次).{0,12}(?:扫描|审计).{0,16}(?:报告|report)|"
            r"(?:scan|audit)\s+(?:result|facts?).{0,24}(?:report|export|download)",
            lowered,
        )
    )
    execution_signal = bool(
        re.search(
            r"我想|我要|需要|请|帮我|开始|执行|进行|做(?:一次|个)?|完整|全量|全项目|"
            r"run|start|perform|execute|scan\s+(?:this|the|my)|audit\s+(?:this|the|my)",
            lowered,
        )
    )
    inspection_signal = bool(
        re.search(
            r"检查|排查|检测|审查|分析|评估|看看|确认|review|inspect|check|analy[sz]e|assess",
            lowered,
        )
    )
    security_flow_signal = bool(
        re.search(
            r"漏洞|风险|安全|依赖|组件|用户输入|外部输入|命令执行|代码执行|注入|传播|流向|到达|"
            r"vulnerab|security|dependency|component|user\s+input|command\s+execution|injection|"
            r"source|sink|data\s*flow",
            lowered,
        )
    )
    project_vulnerability_question_signal = bool(
        re.search(
            r"(?:这个|该|当前|本|我的)(?:项目|仓库|代码库|源码|代码|工程|应用|服务)"
            r".{0,12}(?:存在哪些|有哪些|有什么|是否存在|有没有).{0,8}(?:漏洞|安全风险|安全问题|风险)|"
            r"(?:what|which).{0,16}vulnerabilit(?:y|ies).{0,24}(?:this|current|my)"
            r".{0,8}(?:project|repository|repo|codebase)",
            lowered,
        )
    )
    active_task_available = bool((active_task or {}).get("available"))
    sbom_follow_up_signal = bool(
        re.search(
            r"存在哪些漏洞|有哪些漏洞|有什么漏洞|命中(?:了)?多少|漏洞匹配结果|匹配(?:了)?哪些|"
            r"这些组件.{0,12}漏洞|sbom.{0,18}漏洞|漏洞.{0,18}sbom|许可(?:结果|清单)|许可证(?:结果|清单)",
            lowered,
        )
    )
    if scan_type_directive == "sbom" and (workspace_available or execution_signal):
        intent = "project_sbom_export"
    elif scan_type_directive in {"code", "full"} and (
        workspace_available or (execution_signal and project_scope_signal)
    ):
        intent = "project_scan"
    elif active_task_available and rescan_signal:
        intent = "project_rescan"
    elif project_vulnerability_question_signal and workspace_available:
        intent = "project_scan"
    elif recent_sbom_operation and sbom_follow_up_signal and not project_vulnerability_question_signal:
        intent = "sbom_result_follow_up"
    elif sbom_signal and (workspace_available or execution_signal):
        intent = "project_sbom_export"
    elif (
        scan_signal or rescan_signal or (inspection_signal and security_flow_signal and project_scope_signal)
    ) and (workspace_available or (execution_signal and project_scope_signal)) and not completed_scan_report_signal:
        intent = "project_scan"
    elif vulnerability_signal and catalog_signal and (component_signal or catalog_request_signal):
        intent = "component_vulnerability_catalog"
    elif year_signal and vulnerability_signal:
        intent = "vulnerability_year_lookup"
    elif component_signal and vulnerability_signal:
        intent = "component_vulnerability_query"
    elif active_task_available and follow_up_signal:
        intent = "scan_result_follow_up"
    else:
        intent = "llm_direct"
    time_scope = infer_time_scope(question, today=current_date)
    return {
        "intent": intent,
        "reason": "模型不可用时使用可审计语义兜底。",
        "confidence": 0.72 if intent != "llm_direct" else 0.55,
        "scan_type_directive": scan_type_directive,
        "time_scope": time_scope,
        "date_filter": resolve_catalog_date_range(question, time_scope, today=current_date)
        if intent == "component_vulnerability_catalog"
        else {},
        "filters": infer_explicit_filters(question),
        "destination_hint": normalize_destination_hint(None, question=question),
        "skill": _intent_skill_metadata(intent),
    }


def _planner_task_context(active_task: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(active_task, dict) or not active_task:
        return {"available": False}
    result = active_task.get("result") if isinstance(active_task.get("result"), dict) else {}
    return {
        "available": True,
        "id": str(active_task.get("id") or ""),
        "status": str(active_task.get("status") or ""),
        "workspace_name": str(active_task.get("workspace_name") or ""),
        "has_scan_result": bool(result),
        "finding_count": int(result.get("total_findings") or 0),
        "baseline_task_id": str(active_task.get("baseline_task_id") or ""),
    }


def _planner_sbom_context(operation: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(operation, dict) or not operation:
        return {"available": False}
    matching = operation.get("matching") if isinstance(operation.get("matching"), dict) else {}
    interrupt = operation.get("interrupt") if isinstance(operation.get("interrupt"), dict) else {}
    return {
        "available": True,
        "thread_id": str(operation.get("threadId") or operation.get("thread_id") or ""),
        "project_name": str(operation.get("projectName") or operation.get("project_name") or ""),
        "component_count": int(operation.get("componentCount") or operation.get("component_count") or 0),
        "match_requested": bool(operation.get("matchRequested") or operation.get("match_requested")),
        "vulnerability_count": int(matching.get("vulnerability_count") or 0),
        "coverage_status": str(matching.get("coverage_status") or "not_requested"),
        "pending_interrupt": str(interrupt.get("kind") or ""),
    }


def _intent_skill_metadata(intent: str) -> dict[str, str]:
    if intent == "component_vulnerability_query":
        return component_query_skill_metadata()
    if intent in {"project_sbom_export", "sbom_result_follow_up"}:
        return sbom_skill_metadata()
    if intent in {"project_scan", "project_rescan", "scan_result_follow_up"}:
        return project_scan_skill_metadata()
    return assistant_intent_skill_metadata()


def normalize_destination_hint(value: Any, *, question: str = "") -> str:
    explicit = str(value or "").strip().lower().replace("-", "_")
    if explicit in {"desktop", "downloads", "documents", "choose", "unspecified"}:
        return explicit
    text = str(question or "").casefold()
    if re.search(r"桌面|desktop", text):
        return "desktop"
    if re.search(r"下载(?:文件夹|目录)|downloads?\s+(?:folder|directory)", text):
        return "downloads"
    if re.search(r"文稿|文档(?:文件夹|目录)|documents?\s+(?:folder|directory)", text):
        return "documents"
    if re.search(r"选择目录|指定目录|choose\s+(?:a\s+)?(?:folder|directory)", text):
        return "choose"
    return "unspecified"


def infer_explicit_filters(question: str) -> dict[str, list[str]]:
    text = " ".join(str(question or "").split())
    lowered = text.casefold()
    ecosystems = [
        canonical
        for canonical, aliases in _ECOSYSTEM_ALIASES.items()
        if any(re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered) for alias in aliases)
    ]
    severities: list[str] = []
    severity_patterns = {
        "CRITICAL": r"(?:严重|嚴重)(?:级别|級別|等级|等級|漏洞|风险|風險)?|critical",
        "HIGH": r"高危|高风险|high(?:[-\s]+severity|[-\s]+risk)?",
        "MEDIUM": r"中危|中风险|medium(?:[-\s]+severity|[-\s]+risk)?",
        "LOW": r"低危|低风险|low(?:[-\s]+severity|[-\s]+risk)?",
    }
    for severity, pattern in severity_patterns.items():
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            severities.append(severity)
    return {"ecosystems": ecosystems, "severities": severities, "component_names": []}


def infer_time_scope(question: str, *, today: date) -> dict[str, Any]:
    text = " ".join(str(question or "").split())
    explicit_range = re.search(
        r"(?P<start>20\d{2}-\d{1,2}-\d{1,2})\s*(?:到|至|~|—|-{2,}|through|to)\s*(?P<end>20\d{2}-\d{1,2}-\d{1,2})",
        text,
        flags=re.IGNORECASE,
    )
    if explicit_range:
        return {"kind": "date_range", "start_date": explicit_range.group("start"), "end_date": explicit_range.group("end")}
    year_month = re.search(r"(?P<year>20\d{2})\s*(?:年|[-/.])\s*(?P<month>1[0-2]|0?[1-9])\s*月?", text)
    if year_month:
        return {"kind": "year_month", "year": int(year_month.group("year")), "month": int(year_month.group("month"))}
    recent_days = re.search(r"(?:近|最近|过去|last|past)\s*(?P<days>\d{1,3})\s*(?:天|days?)", text, flags=re.IGNORECASE)
    if recent_days:
        return {"kind": "recent_days", "days": int(recent_days.group("days"))}
    if re.search(r"近期|最近|recent(?:ly)?", text, flags=re.IGNORECASE):
        return {"kind": "recent_days", "days": 7}
    if re.search(r"上月|上个月|上一月|last\s+month|previous\s+month", text, flags=re.IGNORECASE):
        return {"kind": "previous_month"}
    if re.search(r"本月|这个月|当月|current\s+month|this\s+month|最新.*(?:年月|月份|月)|最新年月份", text, flags=re.IGNORECASE):
        return {"kind": "current_month"}
    explicit_year = re.search(r"(?P<year>20\d{2})\s*年?", text)
    if explicit_year:
        return {"kind": "year", "year": int(explicit_year.group("year"))}
    if re.search(r"今年|本年|current\s+year|this\s+year", text, flags=re.IGNORECASE):
        return {"kind": "year", "year": today.year}
    if re.search(r"最新|latest|newest|recent", text, flags=re.IGNORECASE):
        return {"kind": "latest"}
    return {"kind": "unspecified"}


def resolve_catalog_date_range(question: str, time_scope: dict[str, Any] | None, *, today: date) -> dict[str, str]:
    inferred = infer_time_scope(question, today=today)
    scope = dict(time_scope or {})
    if inferred.get("kind") != "unspecified":
        scope = inferred
    kind = str(scope.get("kind") or "unspecified").strip().lower()
    if kind == "date_range":
        start = _parse_iso_date(scope.get("start_date"))
        end = _parse_iso_date(scope.get("end_date"))
    elif kind == "year_month":
        year = _safe_year(scope.get("year"), today)
        month = _safe_month(scope.get("month"))
        start = date(year, month, 1)
        end = date(year, month, monthrange(year, month)[1])
    elif kind == "previous_month":
        end = date(today.year, today.month, 1) - timedelta(days=1)
        start = date(end.year, end.month, 1)
    elif kind == "year":
        year = _safe_year(scope.get("year"), today)
        start = date(year, 1, 1)
        end = date(year, 12, 31)
    elif kind == "recent_days":
        days = max(1, min(int(scope.get("days") or 30), 366))
        end = today
        start = today - timedelta(days=days - 1)
    else:
        start = date(today.year, today.month, 1)
        end = today
        kind = "current_month" if kind in {"latest", "unspecified", ""} else kind
    if start > end:
        raise ValueError("assistant intent plan produced an inverted date range")
    if start > today:
        raise ValueError("assistant intent plan produced a future-only date range")
    end = min(end, today)
    if (end - start).days > 366:
        raise ValueError("component vulnerability catalog range cannot exceed 367 days")
    return {"kind": kind, "start_date": start.isoformat(), "end_date": end.isoformat()}


def _normalize_filters(value: Any) -> dict[str, list[str]]:
    raw = value if isinstance(value, dict) else {}
    ecosystems = _clean_list(raw.get("ecosystems"), limit=12)
    component_names = _clean_list(raw.get("component_names"), limit=20)
    severities = [item.upper() for item in _clean_list(raw.get("severities"), limit=5)]
    return {
        "ecosystems": ecosystems,
        "severities": [item for item in severities if item in _SEVERITIES],
        "component_names": component_names,
    }


def _merge_filters(*values: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for key in ("ecosystems", "severities", "component_names"):
        selected = next((value.get(key, []) for value in reversed(values) if value.get(key)), [])
        merged[key] = list(dict.fromkeys(item for item in selected if item))
    return merged


def _clean_list(value: Any, *, limit: int) -> list[str]:
    values = value if isinstance(value, list) else []
    cleaned = [" ".join(str(item or "").split())[:160] for item in values]
    return list(dict.fromkeys(item for item in cleaned if item))[:limit]


def _bounded_confidence(value: Any) -> float:
    try:
        return max(0.0, min(float(value), 1.0))
    except (TypeError, ValueError):
        return 0.5


def _parse_iso_date(value: Any) -> date:
    try:
        return date.fromisoformat(str(value or "")[:10])
    except ValueError as exc:
        raise ValueError("assistant intent plan contains an invalid ISO date") from exc


def _safe_year(value: Any, today: date) -> int:
    try:
        year = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("assistant intent plan is missing a year") from exc
    if year < 1999 or year > today.year:
        raise ValueError("assistant intent plan contains an unsupported year")
    return year


def _safe_month(value: Any) -> int:
    try:
        month = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("assistant intent plan is missing a month") from exc
    if not 1 <= month <= 12:
        raise ValueError("assistant intent plan contains an invalid month")
    return month


def _parse_json_object(text: str) -> dict[str, Any]:
    clean = str(text or "").strip()
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"\s*```$", "", clean)
    decoded = json.loads(clean)
    if not isinstance(decoded, dict):
        raise TypeError("assistant intent response must be a JSON object")
    return decoded
