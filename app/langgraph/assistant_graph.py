from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, TypedDict
from zoneinfo import ZoneInfo

try:
    from langgraph.graph import END, StateGraph
except Exception:  # noqa: BLE001
    END = "__end__"
    StateGraph = None

from app.dependencies import scan_dependency_attachments
from app.agent.assistant_intent import plan_assistant_intent
from app.agent.translation_agent import translation_agent
from app.agent.translation_policy import (
    catalog_partial_translation_audit_is_recoverable,
    catalog_translation_status_is_complete,
    catalog_translation_status_is_partial,
    fail_closed_translation_payload,
    failed_translation_audit,
    host_localization_attestation_is_publishable,
    issue_host_localization_attestation,
    issue_partial_catalog_translation_attestation,
    issue_stored_translation_attestation,
    partial_catalog_translation_attestation_is_publishable,
    partial_catalog_translation_status,
    public_catalog_records_are_partially_ready,
    public_catalog_records_are_ready,
    translation_audit_is_publishable,
    translation_unavailable_message,
)
from app.catalog_translation import (
    partial_catalog_summary,
    record_summary_for_language,
    recover_partial_catalog_records,
)
from app.langgraph.component_catalog_graph import (
    component_catalog_outcome_answer,
    component_vulnerability_catalog_subgraph,
)
from app.langgraph.component_query_graph import component_query_subgraph, parse_component_query
from app.langgraph.sbom_graph import project_sbom_subgraph, sbom_outcome_answer
from app.semgrep_tool import analyze_static_paths
from app.intelligence import intelligence_service
from app.llm import active_model_from_env, diagnose_chat_completion, llm_status
from app.memory import memory_service
from app.privacy import public_answer_payload, sanitize_public_text, severity_cn
from app.langgraph.report_graph import looks_like_report_request, report_capability_subgraph, report_outcome_answer
from app.reports import build_dependency_markdown_report, build_report_metrics, report_input_fingerprint, report_store
from app.secure_storage import storage_crypto_status
from app.storage import now_iso
from app.trace_ui import prompt_diff_presentation, tool_call_presentation


ASSISTANT_IDENTITY = "我是小安，您的信息安全专家助手。"
ASSISTANT_TIMEZONE = ZoneInfo("Asia/Shanghai")


def _is_information_session(session_id: Any) -> bool:
    return str(session_id or "").startswith("information:")


SYSTEM_PROMPT_TEMPLATE = """你是小安，定位是用户的信息安全专家助手。
表情符号策略：{emoji_style}
当用户询问你是谁、你的名字或身份时，必须回答“我是小安，您的信息安全专家助手。”，不要使用模型名称、平台名称或其他身份。
请使用{language_name}原创回答用户问题，语气专业、简洁、可落地。你只负责安全分析与内容生成，不承担跨语言翻译；上下文中与目标语言不一致的已有内容由 Translation Agent 和离线 Translation MCP 处理。
系统当前日期为 {current_date}，当前时间为 {current_time}，时区为 Asia/Shanghai（中国标准时间）。用户询问“今天”“当前日期”或相对日期时，必须严格以这里提供的日期时间为准，不得使用模型自身日期或其他时区猜测。
先根据用户措辞、会话上下文、附件和可用能力理解实际目标，再规划是否检索、扫描、分析、制图或生成报告；不要仅凭关键词把意图固定到某个节点。
如果问题包含 CVE 或 GHSA 编号，优先结合实时漏洞接口查询结果回答，并说明影响、利用条件、组件版本范围、涉及版本、修复版本、修复建议和缓释措施。
如果问题包含年份并询问漏洞、CVE、高危漏洞或最新漏洞，必须先结合实时漏洞接口查询结果完成事实核验再回答。
如果用户语义上需要某个时间范围内的组件或依赖漏洞清单、统计、可视化或导出，使用组件漏洞目录能力；不要因为只出现“组件”就要求用户提供单一版本。
只有用户明确询问某个组件的具体安装版本是否受影响时，才使用单组件版本核验能力。
单组件版本核验必须调用 Component Detail MCP，将已核验事实转换为组件、漏洞标题、严重度、发布日期、中文描述、影响包与版本、修复版本、CVSS 向量细项和公开参考链接的结构化页面模型。MCP 未返回的字段必须显示“未明确”，禁止模型补造。
组件漏洞目录必须先展示固定查询结果，并分别在生成 Excel 前和选择下载位置前等待用户确认。
当用户为授权项目请求软件物料、依赖资产、供应链组件清单或 SBOM Excel 时，使用项目 SBOM 能力；先生成 CycloneDX 兼容 JSON，再询问是否匹配组件漏洞情报，并分别在生成 Excel 和下载前等待确认。SBOM 漏洞匹配结果中的漏洞描述由 Translation Agent 和离线 Translation MCP 转换为完整简体中文，同时保留 CVE/GHSA、组件名、版本号和 URL 原文；模型不得执行该翻译。不要要求用户必须使用固定关键词。
用户说下载到桌面、下载目录或文稿目录时，只输出系统目录语义，不得猜测或生成当前用户的绝对路径；原生客户端负责解析。
只有 Excel/报告工具已经返回真实制品，且原生客户端确认写盘成功后，才能声称文件“已生成”“已下载”或“已保存”。不得根据用户给出的文件名和目录编造成功状态；没有真实制品或下载结果时，必须继续走对应 Interrupt，或明确说明尚未生成/尚未保存。
扫描报告生成必须消费已校验的扫描 JSON，并分别调用 Mermaid MCP、Markdown MCP、Word MCP 和 PDF MCP；DOCX、PDF、MD 不得由同一个通用格式函数伪装生成。格式转换不得重新扫描、重新查询漏洞情报或改写扫描事实。生成前和下载前都必须等待用户确认。
如果问题不是具体漏洞查询，不要编造漏洞库记录；应结合长期记忆、上下文和通用安全工程经验回答。
如果问题与漏洞、依赖扫描或代码分析无关，直接按用户问题调用大模型回答，不要强行加入漏洞情报、代码审计或安全知识库内容。
当模型上下文中提供了长期记忆时，只把它作为偏好和历史背景，不要泄露内部存储结构。
安全类回答应根据已有事实选择“漏洞摘要、影响范围、漏洞详情、利用条件、风险分析、修复建议、参考来源”等 Markdown 章节；只保留与当前问题相关且有事实支撑的章节，不要机械输出空标题或重复漏洞卡片。
允许在“参考来源”中展示公开权威来源的名称和 URL，例如 NVD、GitHub Advisory、OSV、CISA 或厂商安全公告；禁止披露凭证、内部集合名、私有接口、完整请求载荷、模型调用链或内部检索实现。
不要输出模型的私有推理过程；用户可见的 Thinking 只应来自 LangGraph 提供的高层任务名称和真实执行状态。
涉及版本、组件版本范围与修复版本必须忠实使用上下文中的结构化事实；不得把通配符解释为“所有版本”，不得猜测修复版本。
代码片段只能来自上下文中已核验的漏洞记录 code_snippets 字段，用于展示脆弱代码模式；修复代码片段只能来自 fixed_code_snippets 字段；禁止生成 PoC、利用载荷或攻击步骤。
"""


VULNERABILITY_CARD_PROMPT_TEMPLATE = """你是安全漏洞结构化整理子节点。请根据给定事实和分析结果输出严格 JSON，不要输出 Markdown 或解释。
必须包含且只包含这些中文键名：漏洞编号、漏洞名称、漏洞描述、CVSS评分、严重等级、组件版本范围、涉及版本、修复版本、修复方案、缓释措施、代码片段、修复代码片段、参考链接。
键名必须保持中文不变，这是前端字段协议；只整理输入中已使用{language_name}的字段值，漏洞编号、产品名、包名、版本号、URL 和代码保持原文。
漏洞描述必须完整保留输入中的 description 事实，不得用省略号截断，不得只输出摘要。
不得执行跨语言翻译。如果 description 与{language_name}不一致，将该字段标记为译文不可用，由 Translation Agent 和离线 Translation MCP 处理。
涉及版本只能整理输入中的 affected_versions，不能把 * 改成所有版本。
组件版本范围只能整理输入中的 components、affected_versions 和 fixed_versions。
修复版本只能使用输入中的 fixed_versions；如果没有明确修复版本，使用{language_name}表达“未明确”。
代码片段只能使用输入中的 code_snippets；如果没有 code_snippets，使用{language_name}说明未找到可核验代码片段。
修复代码片段只能使用输入中的 fixed_code_snippets；如果没有 fixed_code_snippets，使用{language_name}说明未找到可核验修复代码片段。
参考链接只能使用输入中的 reference_links；如果没有 reference_links，使用{language_name}表达“未明确”。参考链接只输出 URL，不要添加来源名称或解释。
禁止输出情报来源名称、供应商、接口、集合名、检索链路或模型信息；除“参考链接”字段中的 URL 外，不要在其他字段输出链接。
"""

# Backward-compatible default prompt for tests and legacy importers. Runtime code
# uses VULNERABILITY_CARD_PROMPT_TEMPLATE through vulnerability_card_prompt().
VULNERABILITY_CARD_PROMPT = VULNERABILITY_CARD_PROMPT_TEMPLATE.format(language_name="简体中文")


class AssistantState(TypedDict, total=False):
    question: str
    top_k: int
    user_id: str
    session_id: str
    exchange_id: str
    response_language: str
    intent: str
    intent_plan: dict[str, Any]
    vulnerability_id: str
    year_filter: list[int]
    date_filter: dict[str, str]
    filters: dict[str, list[str]]
    attachments: list[dict[str, Any]]
    workspace_path: str
    task_context: dict[str, Any]
    destination_hint: str
    dependency_scan: dict[str, Any]
    static_analysis: dict[str, Any]
    evidence_sources: list[dict[str, Any]]
    component_query: dict[str, Any]
    component_result: dict[str, Any]
    component_detail: dict[str, Any]
    component_error: str
    records: list[dict[str, Any]]
    knowledge_graph: dict[str, Any]
    chart_data: dict[str, Any]
    artifacts: list[dict[str, Any]]
    memory_context: dict[str, Any]
    llm_result: dict[str, Any]
    llm_error: str
    vulnerability_card: dict[str, Any]
    markdown_report: dict[str, Any]
    report_operation: dict[str, Any]
    catalog_operation: dict[str, Any]
    sbom_operation: dict[str, Any]
    answer: dict[str, Any]
    translation: dict[str, Any]
    catalog_translation_ready: bool
    catalog_translation_partial_verified: bool
    host_localization_verified: bool
    trace: list[dict[str, Any]]
    event_sink: Callable[[dict[str, Any]], None]
    content_sink: Callable[[str], None]


class KnowledgeSecurityGraph:
    def __init__(self) -> None:
        self._component_subgraph = component_query_subgraph
        self._component_catalog_subgraph = component_vulnerability_catalog_subgraph
        self._report_subgraph = report_capability_subgraph
        self._graph = self._build_graph()

    def invoke(
        self,
        question: str,
        top_k: int = 5,
        user_id: str = "default",
        session_id: str = "default",
        response_language: str = "zh-Hans",
        emoji_mode: str = "moderate",
        attachments: list[dict[str, Any]] | None = None,
        workspace_path: str = "",
        task_context: dict[str, Any] | None = None,
        intent_plan: dict[str, Any] | None = None,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        content_sink: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        language = normalize_response_language(response_language)
        state: AssistantState = {
            "question": question,
            "top_k": top_k,
            "user_id": user_id or "default",
            "session_id": session_id or "default",
            "response_language": language,
            "emoji_mode": emoji_mode if emoji_mode in {"off", "moderate", "active"} else "moderate",
            "intent": "security_knowledge",
            "intent_plan": dict(intent_plan or {}),
            "vulnerability_id": "",
            "year_filter": [],
            "date_filter": {},
            "filters": {},
            "attachments": attachments or [],
            "workspace_path": str(workspace_path or ""),
            "task_context": dict(task_context or {}),
            "destination_hint": str((intent_plan or {}).get("destination_hint") or "unspecified"),
            "dependency_scan": {"files": [], "dependencies": [], "dependency_count": 0, "rejected_files": []},
            "static_analysis": {"status": "skipped", "findings": [], "finding_count": 0, "diagnostics": []},
            "evidence_sources": [],
            "component_query": {},
            "component_result": {},
            "component_detail": {},
            "component_error": "",
            "records": [],
            "knowledge_graph": empty_knowledge_graph(),
            "chart_data": {},
            "artifacts": [],
            "memory_context": {},
            "llm_result": {},
            "llm_error": "",
            "vulnerability_card": {},
            "markdown_report": {},
            "report_operation": {},
            "catalog_operation": {},
            "sbom_operation": {},
            "translation": {},
            "catalog_translation_ready": False,
            "catalog_translation_partial_verified": False,
            "host_localization_verified": False,
            "trace": [],
        }
        if event_sink is not None:
            state["event_sink"] = event_sink
        if content_sink is not None:
            state["content_sink"] = content_sink
        if self._graph is None:
            state = self._classify_query(state)
            state = self._load_memory_context(state)
            if state.get("intent") == "component_vulnerability_query":
                state = self._component_subgraph.invoke(state)
                state = self._compose_answer(state)
                if not self._can_use_catalog_translation(state):
                    state = self._translate_answer(state)
                state = self._persist_memory(state)
                return self._final_answer(state)
            if state.get("intent") == "component_vulnerability_catalog":
                state = self._run_component_catalog_subgraph(state)
                if not self._can_use_catalog_translation(state):
                    state = self._translate_answer(state)
                state = self._persist_memory(state)
                return self._final_answer(state)
            if state.get("intent") == "project_sbom_export":
                state = self._run_sbom_subgraph(state)
                state = self._translate_answer(state)
                state = self._persist_memory(state)
                return self._final_answer(state)
            if state.get("intent") == "report_operation":
                state = self._run_report_subgraph(state)
                state = self._translate_answer(state)
                state = self._persist_memory(state)
                return self._final_answer(state)
            if self._should_retrieve(state):
                state = self._query_intelligence(state)
                if self._should_run_static_analysis(state):
                    state = self._run_static_analysis(state)
                state = self._graph_enriched(state)
            state = self._call_llm(state)
            state = self._translate_vulnerability_card(state)
            state = self._compose_answer(state)
            report_requested = self._should_generate_report(state)
            if report_requested:
                state = self._run_report_subgraph(state)
            if report_requested or not self._can_use_catalog_translation(state):
                state = self._translate_answer(state)
            state = self._persist_memory(state)
            return self._final_answer(state)
        final = self._graph.invoke(state)
        return self._final_answer(final)

    @classmethod
    def _final_answer(cls, state: AssistantState) -> dict[str, Any]:
        answer = dict(state["answer"])
        target_language = state.get("response_language", "zh-Hans")
        host_localized = bool(state.get("host_localization_verified")) or (
            host_localization_attestation_is_publishable(answer, target_language)
        )
        localization = answer.get("translation") if isinstance(answer.get("translation"), dict) else {}
        partial_catalog = bool(state.get("catalog_translation_partial_verified")) or (
            partial_catalog_translation_attestation_is_publishable(answer, target_language)
        )
        host_source = str(localization.get("source") or "component-catalog-preview")
        answer["trace"] = state.get("trace", [])
        answer = public_answer_payload(answer)
        if cls._can_use_catalog_translation(state):
            if host_localized:
                answer["translation"] = issue_host_localization_attestation(
                    answer,
                    target_language=target_language,
                    source=host_source,
                )
            elif partial_catalog:
                answer["translation"] = issue_partial_catalog_translation_attestation(
                    answer,
                    target_language=target_language,
                    catalog_status=localization,
                    source=str(localization.get("source") or "component-vulnerability-catalog"),
                )
            else:
                record_count = cls._stored_catalog_record_count(state)
                answer["translation"] = issue_stored_translation_attestation(
                    answer,
                    target_language=target_language,
                    record_count=record_count,
                    source="vulnerability-catalog",
                )
        answer["session_id"] = str(state.get("session_id") or "default")
        if state.get("exchange_id"):
            answer["exchange_id"] = str(state["exchange_id"])
        return answer

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "AegisAl LangGraph",
            "nodes": [
                {"id": "classify_query", "label": "识别问题意图"},
                {"id": "load_memory_context", "label": "加载长期记忆"},
                {"id": "component_query_subgraph", "label": "组件查询子图"},
                {"id": "component_catalog_subgraph", "label": "按时间查询组件漏洞目录子图"},
                {"id": "project_sbom_subgraph", "label": "项目 SBOM 与组件漏洞匹配子图"},
                {"id": "report_capability_subgraph", "label": "报告中心能力子图"},
                {"id": "query_intelligence", "label": "查询漏洞事实与附件依赖"},
                {"id": "run_static_path_analysis", "label": "执行静态代码路径分析"},
                {"id": "enrich_knowledge_graph", "label": "富化知识图谱关联"},
                {"id": "call_llm", "label": "调用安全专家模型"},
                {"id": "translate_vulnerability_card", "label": "中文整理漏洞卡片"},
                {"id": "compose_answer", "label": "生成回答"},
                {"id": "translation_agent", "label": "Translation Agent 调用翻译 MCP"},
                {"id": "persist_memory", "label": "保存长期记忆"},
            ],
            "edges": [
                {"source": "classify_query", "target": "load_memory_context", "label": "问题分类"},
                {"source": "load_memory_context", "target": "component_query_subgraph", "label": "明确组件与版本"},
                {"source": "load_memory_context", "target": "component_catalog_subgraph", "label": "时间范围组件漏洞清单"},
                {"source": "load_memory_context", "target": "project_sbom_subgraph", "label": "项目 SBOM 与可选漏洞匹配"},
                {"source": "load_memory_context", "target": "report_capability_subgraph", "label": "生成或下载报告"},
                {"source": "load_memory_context", "target": "query_intelligence", "label": "CVE/GHSA/年份/依赖漏洞"},
                {"source": "load_memory_context", "target": "call_llm", "label": "通用安全问题"},
                {"source": "component_query_subgraph", "target": "compose_answer", "label": "组件事实、Excel 与桑基图"},
                {"source": "component_catalog_subgraph", "target": "translation_agent", "label": "清单预览、Interrupt 或 Excel 制品"},
                {"source": "component_catalog_subgraph", "target": "persist_memory", "label": "复用情报库入库译文"},
                {"source": "project_sbom_subgraph", "target": "translation_agent", "label": "SBOM JSON、Interrupt 或 Excel 制品"},
                {"source": "query_intelligence", "target": "run_static_path_analysis", "label": "存在代码附件"},
                {"source": "query_intelligence", "target": "enrich_knowledge_graph", "label": "无代码附件或普通漏洞查询"},
                {"source": "run_static_path_analysis", "target": "enrich_knowledge_graph", "label": "Source/Sink 路径返回"},
                {"source": "enrich_knowledge_graph", "target": "call_llm", "label": "图谱富化完成"},
                {"source": "call_llm", "target": "translate_vulnerability_card", "label": "整理客户可见字段"},
                {"source": "translate_vulnerability_card", "target": "compose_answer", "label": "中文结构化卡片"},
                {"source": "compose_answer", "target": "report_capability_subgraph", "label": "扫描完成后确认生成"},
                {"source": "compose_answer", "target": "translation_agent", "label": "结构化回答 JSON"},
                {"source": "compose_answer", "target": "persist_memory", "label": "复用入库译文"},
                {"source": "report_capability_subgraph", "target": "translation_agent", "label": "Interrupt 或报告制品"},
                {"source": "translation_agent", "target": "persist_memory", "label": "目标语言回复"},
            ],
            "subgraphs": [
                component_query_subgraph.graph_spec(),
                component_vulnerability_catalog_subgraph.graph_spec(),
                project_sbom_subgraph.graph_spec(),
                report_capability_subgraph.graph_spec(),
            ],
        }

    def _build_graph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(AssistantState)
        graph.add_node("classify_query", self._classify_query)
        graph.add_node("load_memory_context", self._load_memory_context)
        graph.add_node(
            "component_query_subgraph",
            self._component_subgraph.graph or self._component_subgraph.invoke,
        )
        graph.add_node("component_catalog_subgraph", self._run_component_catalog_subgraph)
        graph.add_node("project_sbom_subgraph", self._run_sbom_subgraph)
        graph.add_node("report_capability_subgraph", self._run_report_subgraph)
        graph.add_node("query_intelligence", self._query_intelligence)
        graph.add_node("run_static_analysis", self._run_static_analysis)
        graph.add_node("enrich_knowledge_graph", self._graph_enriched)
        graph.add_node("call_llm", self._call_llm)
        graph.add_node("translate_vulnerability_card", self._translate_vulnerability_card)
        graph.add_node("compose_answer", self._compose_answer)
        graph.add_node("translation_agent", self._translate_answer)
        graph.add_node("persist_memory", self._persist_memory)
        graph.set_entry_point("classify_query")
        graph.add_edge("classify_query", "load_memory_context")
        graph.add_conditional_edges(
            "load_memory_context",
            self._route_after_memory,
            {
                "component_query_subgraph": "component_query_subgraph",
                "component_catalog_subgraph": "component_catalog_subgraph",
                "project_sbom_subgraph": "project_sbom_subgraph",
                "report_capability_subgraph": "report_capability_subgraph",
                "query_intelligence": "query_intelligence",
                "call_llm": "call_llm",
            },
        )
        graph.add_edge("component_query_subgraph", "compose_answer")
        graph.add_conditional_edges(
            "component_catalog_subgraph",
            lambda state: "persist_memory" if self._can_use_catalog_translation(state) else "translation_agent",
            {"persist_memory": "persist_memory", "translation_agent": "translation_agent"},
        )
        graph.add_edge("project_sbom_subgraph", "translation_agent")
        graph.add_edge("report_capability_subgraph", "translation_agent")
        graph.add_conditional_edges(
            "query_intelligence",
            lambda state: "run_static_analysis" if self._should_run_static_analysis(state) else "enrich_knowledge_graph",
            {
                "run_static_analysis": "run_static_analysis",
                "enrich_knowledge_graph": "enrich_knowledge_graph",
            },
        )
        graph.add_edge("run_static_analysis", "enrich_knowledge_graph")
        graph.add_edge("enrich_knowledge_graph", "call_llm")
        graph.add_edge("call_llm", "translate_vulnerability_card")
        graph.add_edge("translate_vulnerability_card", "compose_answer")
        graph.add_conditional_edges(
            "compose_answer",
            self._route_after_compose,
            {
                "report_capability_subgraph": "report_capability_subgraph",
                "translation_agent": "translation_agent",
                "persist_memory": "persist_memory",
            },
        )
        graph.add_edge("translation_agent", "persist_memory")
        graph.add_edge("persist_memory", END)
        return graph.compile()

    def _classify_query(self, state: AssistantState) -> AssistantState:
        question = state["question"]
        vuln_id = extract_vulnerability_id(question)
        component_query = parse_component_query(question)
        intent_plan: dict[str, Any] = dict(state.get("intent_plan") or {})
        if intent_plan:
            state["intent"] = str(intent_plan.get("intent") or "llm_direct")
            state["destination_hint"] = str(intent_plan.get("destination_hint") or "unspecified")
        elif state.get("workspace_path"):
            intent_plan = plan_assistant_intent(
                question,
                workspace_available=True,
                user_id=state.get("user_id", "default"),
                session_id=state.get("session_id", "default"),
            )
            state["intent_plan"] = intent_plan
            state["intent"] = str(intent_plan.get("intent") or "llm_direct")
            state["destination_hint"] = str(intent_plan.get("destination_hint") or "unspecified")
        elif state.get("attachments"):
            state["intent"] = "dependency_vulnerability_report"
        elif looks_like_report_request(question):
            state["intent"] = "report_operation"
        elif is_identity_question(question):
            state["intent"] = "identity"
        elif not is_meaningful_question(question):
            state["intent"] = "clarification"
        elif vuln_id:
            state["intent"] = "vulnerability_lookup"
            state["vulnerability_id"] = vuln_id
        elif component_query:
            state["intent"] = "component_vulnerability_query"
            state["component_query"] = component_query
        else:
            intent_plan = plan_assistant_intent(
                question,
                user_id=state.get("user_id", "default"),
                session_id=state.get("session_id", "default"),
            )
            state["intent_plan"] = intent_plan
            state["intent"] = str(intent_plan.get("intent") or "llm_direct")
            if state["intent"] == "component_vulnerability_catalog":
                state["date_filter"] = dict(intent_plan.get("date_filter") or {})
                state["filters"] = dict(intent_plan.get("filters") or {})
            elif state["intent"] == "component_vulnerability_query":
                state["component_query"] = parse_component_query(question) or {}
            elif state["intent"] == "vulnerability_year_lookup":
                state["year_filter"] = extract_year_filter(question)
        if intent_plan and state.get("intent") == "component_vulnerability_catalog":
            state["date_filter"] = dict(intent_plan.get("date_filter") or {})
            state["filters"] = dict(intent_plan.get("filters") or {})
        elif intent_plan and state.get("intent") == "component_vulnerability_query":
            state["component_query"] = parse_component_query(question) or {}
        elif intent_plan and state.get("intent") == "vulnerability_year_lookup":
            state["year_filter"] = extract_year_filter(question)
        presentation = None
        if intent_plan:
            skill = intent_plan.get("skill") if isinstance(intent_plan.get("skill"), dict) else {}
            presentation = tool_call_presentation(
                "plan_assistant_intent",
                state="completed",
                title="LLM semantic intent planner",
                input_summary={"question": question},
                output={
                    "intent": state["intent"],
                    "reason": intent_plan.get("reason", ""),
                    "confidence": intent_plan.get("confidence"),
                    "date_filter": state.get("date_filter") or {},
                    "filters": state.get("filters") or {},
                    "planner": intent_plan.get("planner", ""),
                    "prompt_version": skill.get("prompt_version", ""),
                    "skill_sha256": skill.get("sha256", ""),
                },
            )
        return add_trace(
            state,
            "classify_query",
            f"已根据问题语义选择 {state['intent']} 能力。",
            presentation=presentation,
        )

    def _load_memory_context(self, state: AssistantState) -> AssistantState:
        try:
            if _is_information_session(state.get("session_id")):
                context = memory_service.build_short_term_context(
                    state.get("user_id", "default"),
                    state.get("session_id", "default"),
                    state["question"],
                )
            else:
                context = memory_service.build_context(state.get("user_id", "default"), state["question"])
            state["memory_context"] = context
            stats = context.get("stats", {})
            if context.get("scope") == "short-term":
                return add_trace(
                    state,
                    "load_memory_context",
                    f"已加载当前咨询的短期记忆：最近 {stats.get('recentCount', 0)} 条。",
                )
            return add_trace(
                state,
                "load_memory_context",
                f"已召回长期记忆：历史 {stats.get('historyCount', 0)} 条，相关 {stats.get('retrievedCount', 0)} 条。",
            )
        except Exception as exc:  # noqa: BLE001
            state["memory_context"] = {"enabled": False, "error": str(exc)}
            return add_trace(state, "load_memory_context", f"长期记忆读取失败：{exc}", status="warning")

    def _query_intelligence(self, state: AssistantState) -> AssistantState:
        try:
            if state.get("intent") == "dependency_vulnerability_report":
                scan = scan_dependency_attachments(state.get("attachments", []))
                state["dependency_scan"] = scan
                dependencies = scan.get("dependencies", [])
                if not dependencies:
                    state["records"] = []
                    state["knowledge_graph"] = empty_knowledge_graph("dependency-scan")
                    return add_trace(
                        state,
                        "query_intelligence",
                        "附件已读取，但未识别到可用于漏洞匹配的依赖。",
                        status="warning",
                    )
                result = intelligence_service.query_dependencies(
                    dependencies,
                    limit_per_dependency=max(1, min(state.get("top_k", 5), 10)),
                    response_language=state.get("response_language", "zh-Hans"),
                    user_id=state.get("user_id", "default"),
                )
                state["records"] = result.get("records", [])
                state["knowledge_graph"] = result.get("graph", {})
                state["evidence_sources"] = public_evidence_sources(result.get("source_status"))
                state["catalog_translation_ready"] = catalog_translation_status_is_complete(
                    result.get("catalog_translation"),
                    state.get("response_language", "zh-Hans"),
                )
                status = "completed" if state["records"] else "warning"
                return add_trace(
                    state,
                    "query_intelligence",
                    f"已扫描 {scan.get('dependency_count', 0)} 个依赖，命中 {len(state['records'])} 条漏洞记录。",
                    status=status,
                    presentation=tool_call_presentation(
                        "query_dependency_vulnerabilities",
                        state="completed",
                        title="Dependency vulnerability query",
                        input_summary={
                            "dependency_count": scan.get("dependency_count", 0),
                            "result_limit": max(1, min(state.get("top_k", 5), 10)),
                        },
                        output={"matched_records": len(state["records"])},
                    ),
                )

            result = intelligence_service.query(
                state["question"],
                limit=state.get("top_k", 5),
                response_language=state.get("response_language", "zh-Hans"),
                user_id=state.get("user_id", "default"),
            )
            state["records"] = result.get("records", [])
            state["knowledge_graph"] = result.get("graph", {})
            state["evidence_sources"] = public_evidence_sources(result.get("source_status"))
            state["catalog_translation_ready"] = catalog_translation_status_is_complete(
                result.get("catalog_translation"),
                state.get("response_language", "zh-Hans"),
            )
            status = "completed" if result.get("records") else "warning"
            return add_trace(
                state,
                "query_intelligence",
                f"实时接口返回 {len(state['records'])} 条归并记录。",
                status=status,
                presentation=tool_call_presentation(
                    "query_vulnerability_intelligence",
                    state="completed",
                    title="Vulnerability intelligence query",
                    input_summary={"query": state["question"], "result_limit": state.get("top_k", 5)},
                    output={"merged_records": len(state["records"])},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["records"] = []
            state["knowledge_graph"] = empty_knowledge_graph()
            state["evidence_sources"] = []
            state["catalog_translation_ready"] = False
            return add_trace(
                state,
                "query_intelligence",
                f"实时情报查询失败：{exc}",
                status="warning",
                presentation=tool_call_presentation(
                    "query_vulnerability_intelligence",
                    state="error",
                    title="Vulnerability intelligence query",
                    input_summary={"result_limit": state.get("top_k", 5)},
                    error=exc,
                ),
            )

    @staticmethod
    def _graph_enriched(state: AssistantState) -> AssistantState:
        graph = state.get("knowledge_graph", {})
        return add_trace(
            state,
            "enrich_knowledge_graph",
            f"已关联 {graph.get('node_count', 0)} 个图节点和 {graph.get('edge_count', 0)} 条边。",
            status="completed" if graph.get("node_count") else "warning",
        )

    @staticmethod
    def _run_static_analysis(state: AssistantState) -> AssistantState:
        try:
            analysis = analyze_static_paths(
                state.get("attachments", []),
                state.get("dependency_scan", {}),
                state.get("records", []),
            )
            state["static_analysis"] = analysis
            finding_count = int(analysis.get("finding_count") or len(analysis.get("findings") or []))
            status = "completed" if finding_count else "warning"
            return add_trace(
                state,
                "run_static_path_analysis",
                f"已完成静态代码路径分析，返回 {finding_count} 条 source/sink 路径。",
                status=status,
                presentation=tool_call_presentation(
                    "run_static_path_analysis",
                    state="completed",
                    title="Static path analysis",
                    input_summary={
                        "attachment_count": len(state.get("attachments", [])),
                        "vulnerability_record_count": len(state.get("records", [])),
                    },
                    output={"source_sink_paths": finding_count},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["static_analysis"] = {
                "status": "failed",
                "findings": [],
                "finding_count": 0,
                "diagnostics": [str(exc)],
            }
            return add_trace(
                state,
                "run_static_path_analysis",
                f"静态代码路径分析失败：{exc}",
                status="warning",
                presentation=tool_call_presentation(
                    "run_static_path_analysis",
                    state="error",
                    title="Static path analysis",
                    input_summary={"attachment_count": len(state.get("attachments", []))},
                    error=exc,
                ),
            )

    def _call_llm(self, state: AssistantState) -> AssistantState:
        if state.get("intent") == "identity":
            state["llm_result"] = {
                "status": "success",
                "message": "已返回本地配置的助手身份。",
                "latency_ms": 0,
                "answer": ASSISTANT_IDENTITY,
            }
            return add_trace(state, "call_llm", "已返回小安的助手身份。")
        if state.get("intent") == "clarification":
            state["llm_result"] = {
                "status": "skipped",
                "message": "问题缺少可分析的文字或数字，未调用模型。",
                "latency_ms": 0,
                "answer": "",
            }
            return add_trace(
                state,
                "call_llm",
                "问题缺少有效语义，已跳过模型调用。",
                status="warning",
            )
        if state.get("intent") in {
            "vulnerability_lookup",
            "vulnerability_year_lookup",
            "dependency_vulnerability_report",
        }:
            state["llm_result"] = {
                "status": "skipped",
                "message": "漏洞内容已使用可核验事实、本地模板与 Translation MCP 生成。",
                "latency_ms": 0,
                "answer": "",
            }
            return add_trace(
                state,
                "call_llm",
                "漏洞展示由可核验事实和离线翻译生成，未调用用户模型。",
            )

        model = active_model_from_env(state.get("user_id", "default"))
        messages = self._build_messages(state)
        result = (
            diagnose_chat_completion(
                model,
                messages,
                json_mode=state.get("intent") == "vulnerability_lookup" and bool(state.get("records")),
                # Customer-visible content is streamed only after the structured
                # response has passed through Translation Agent + Translation MCP.
                on_delta=None,
                user_id=state.get("user_id", "default"),
                session_id=state.get("session_id", "default"),
                source="assistant_answer",
            )
            if model
            else {"status": "failed", "message": "未配置可用模型。"}
        )
        state["llm_result"] = result
        prompt_presentation = prompt_diff_presentation(
            title="系统提示词变更",
            before=SYSTEM_PROMPT_TEMPLATE,
            after=system_prompt(state.get("response_language", "zh-Hans"), emoji_mode=state.get("emoji_mode", "moderate")),
        )
        if result.get("status") == "success":
            return add_trace(
                state,
                "call_llm",
                f"模型调用成功，耗时 {result.get('latency_ms', 0)}ms。",
                presentation=prompt_presentation,
            )
        state["llm_error"] = str(result.get("message") or "模型未返回可用结果。")
        return add_trace(
            state,
            "call_llm",
            state["llm_error"],
            status="warning",
            presentation=prompt_presentation,
        )

    def _translate_vulnerability_card(self, state: AssistantState) -> AssistantState:
        language = state.get("response_language", "zh-Hans")
        if state.get("intent") not in {"vulnerability_lookup", "vulnerability_year_lookup", "dependency_vulnerability_report"}:
            return add_trace(state, "translate_vulnerability_card", "当前问题无需生成漏洞卡片。")

        records = state.get("records", [])
        if not records:
            state["vulnerability_card"] = (
                {}
                if state.get("intent") == "dependency_vulnerability_report"
                else build_empty_vulnerability_card(state.get("vulnerability_id", ""), language)
            )
            return add_trace(state, "translate_vulnerability_card", "未找到可整理的漏洞事实。", status="warning")

        record = records[0]
        fallback = build_vulnerability_card(
            record,
            language,
            user_id=state.get("user_id", "default"),
        )
        state["vulnerability_card"] = fallback
        return add_trace(
            state,
            "translate_vulnerability_card",
            "已使用 Translation MCP 译文和后端事实模板生成结构化漏洞卡片。",
        )

    def _compose_answer(self, state: AssistantState) -> AssistantState:
        language = state.get("response_language", "zh-Hans")
        records = state.get("records", [])
        llm_result = state.get("llm_result", {})
        memory_context = state.get("memory_context", {})
        memory_field = "短期记忆" if memory_context.get("scope") == "short-term" else "长期记忆"
        fields = {
            "意图": state.get("intent", "security_knowledge"),
            memory_field: self._memory_label(memory_context),
            "模型调用状态": (
                "成功"
                if llm_result.get("status") == "success"
                else _public_model_failure_status(state.get("llm_error"), language)
            ),
        }
        if state.get("task_context"):
            task_context = state["task_context"]
            fields["扫描任务"] = str(task_context.get("task_id") or "")
            fields["扫描轮次"] = str(task_context.get("run_number") or 1)
            fields["扫描证据"] = f"{len(task_context.get('findings') or [])} 条结构化 finding"
        if state.get("year_filter"):
            fields["年份过滤"] = "、".join(str(year) for year in state.get("year_filter", []))
            fields["漏洞数据策略"] = "年份问题通过实时 API 接口获取，并在请求内完成知识图谱富化"
        if state.get("intent") == "dependency_vulnerability_report":
            scan = state.get("dependency_scan", {})
            fields["附件数量"] = str(len(scan.get("files") or []))
            fields["依赖数量"] = str(scan.get("dependency_count") or 0)
            static_analysis = state.get("static_analysis", {})
            fields["依赖漏洞数量"] = str(len(records))
            fields["代码漏洞数量"] = str(static_analysis.get("finding_count") or len(static_analysis.get("findings") or []))
            fields["扫描策略"] = "解析 pom.xml、Gradle 构建文件与代码中的导入或引用语句，按依赖包和版本匹配漏洞事实，并关联污点源与汇路径"
        if state.get("intent") == "component_vulnerability_query":
            component = state.get("component_result", {}).get("component") or state.get("component_query", {})
            fields["组件名称"] = str(component.get("name") or "")
            fields["组件版本"] = str(component.get("version") or "")
            fields["组件生态"] = str(component.get("ecosystem") or "自动识别")
            fields["确认漏洞数量"] = str(int(state.get("component_result", {}).get("total") or 0))
        card = state.get("vulnerability_card", {})

        if state.get("intent") == "component_vulnerability_query":
            summary = build_component_query_answer(
                state.get("component_result", {}),
                state.get("component_query", {}),
                state.get("component_error", ""),
                language,
            )
            confidence = 0.94 if state.get("component_result") else 0.58
            chart_data = state.get("chart_data", {})
        elif state.get("intent") == "dependency_vulnerability_report":
            summary = build_dependency_vulnerability_answer(records, state.get("dependency_scan", {}), state.get("static_analysis", {}), language)
            confidence = 0.86 if records else 0.58
            chart_data = build_dependency_chart_data(
                state.get("dependency_scan", {}),
                records,
                state.get("static_analysis", {}),
            )
        elif card and state.get("intent") == "vulnerability_lookup":
            summary = build_card_summary(card, language)
            confidence = 0.9 if records else 0.5
            chart_data = {}
        elif llm_result.get("status") == "success":
            summary = str(llm_result.get("answer", "")).strip()
            confidence = 0.82 if not records else 0.9
            chart_data = {}
        elif records and state.get("intent") == "vulnerability_year_lookup":
            summary = build_year_vulnerability_answer(records, state.get("year_filter", []), language)
            confidence = 0.76
            chart_data = {}
        elif records:
            primary = records[0]
            summary = build_record_answer(primary, language)
            confidence = 0.72
            chart_data = {}
        elif state.get("task_context"):
            summary = build_task_scan_follow_up_answer(state["task_context"], language)
            confidence = 0.8 if (state["task_context"].get("findings") or []) else 0.5
            chart_data = {}
        else:
            summary = fallback_answer(state, language)
            confidence = 0.46
            chart_data = {}

        answer = {
            "mode": state.get("intent", "security_knowledge"),
            "summary": summary,
            "records": records,
            "fields": fields,
            "vulnerability_card": card,
            "knowledge_graph": normalize_knowledge_graph(state.get("knowledge_graph")),
            "evidence_sources": list(state.get("evidence_sources") or []),
            "chart_data": chart_data,
            "artifacts": list(state.get("artifacts") or []),
            "token_usage": llm_token_usage(llm_result),
            "confidence": confidence,
            "trace": state.get("trace", []),
            "generated_at": now_iso(),
        }
        component_detail = dict(state.get("component_detail") or {})
        if component_detail:
            answer["component_detail"] = component_detail
        state["answer"] = public_answer_payload(answer)
        return add_trace(state, "compose_answer", "已生成最终回答。")

    def _translate_answer(self, state: AssistantState) -> AssistantState:
        answer = dict(state.get("answer") or {})
        if not answer:
            return add_trace(
                state,
                "translation_agent",
                "当前节点没有可翻译的结构化回复。",
                status="warning",
            )
        target_language = str(state.get("response_language") or "zh-Hans")
        try:
            result = translation_agent.translate_json(
                answer,
                target_language=target_language,
                user_id=str(state.get("user_id") or "default"),
                session_id=str(state.get("session_id") or "default"),
                content_scope="assistant_response",
            )
            audit = dict(result.audit)
            state["translation"] = audit
            translation_completed = translation_audit_is_publishable(audit)
            translation_partial = (
                answer.get("mode") == "component_vulnerability_catalog"
                and isinstance(answer.get("records"), list)
                and bool(answer["records"])
                and catalog_partial_translation_audit_is_recoverable(
                    audit,
                    target_language,
                )
            )
            if translation_completed:
                translated = public_answer_payload(result.payload)
                translated["translation"] = audit
                state["answer"] = translated
            elif translation_partial:
                candidate_records = (
                    result.payload.get("records")
                    if isinstance(result.payload.get("records"), list)
                    else []
                )
                records = recover_partial_catalog_records(
                    answer["records"],
                    candidate_records,
                    target_language=target_language,
                )
                ready_records = sum(
                    record.get("translation_status") == "translated"
                    for record in records
                )
                translated = dict(answer)
                translated["summary"] = partial_catalog_summary(
                    result.payload.get("summary"),
                    answer.get("summary"),
                    target_language=target_language,
                )
                translated["records"] = records
                translated["trace"] = []
                translated["translation"] = partial_catalog_translation_status(
                    audit,
                    target_language=target_language,
                    record_count=len(records),
                    ready_records=ready_records,
                )
                state["answer"] = public_answer_payload(translated)
                state["translation"] = dict(state["answer"]["translation"])
                state["catalog_translation_partial_verified"] = False
                state["trace"] = []
            else:
                state["answer"] = public_answer_payload(
                    fail_closed_translation_payload(
                        result.payload,
                        target_language=state.get("response_language") or "zh-Hans",
                        audit=audit,
                    )
                )
                state["translation"] = dict(state["answer"]["translation"])
                state["trace"] = []
            return add_trace(
                state,
                "translation_agent",
                (
                    "Translation Agent 已调用翻译 MCP 处理回复 JSON："
                    f"目标语言 {audit['target_language']}，翻译 {audit['translated_fields']} 个字段。"
                ) if translation_completed else (
                    "Translation Agent 返回部分离线译文；已保留核验记录，待补译字段使用中文占位。"
                    if translation_partial
                    else translation_unavailable_message(target_language)
                ),
                status="completed" if translation_completed else "warning",
                presentation=tool_call_presentation(
                    "translate_json_payload",
                    state="completed" if (translation_completed or translation_partial) else "error",
                    title="Translation MCP",
                    input_summary={
                        "content_scope": "assistant_response",
                        "target_language": audit["target_language"],
                        "candidate_fields": audit["candidate_fields"],
                    },
                    output={
                        "translated_fields": audit["translated_fields"],
                        "translation_status": audit["translation_status"],
                        "output_sha256": audit["output_sha256"],
                    },
                    error=(
                        ""
                        if translation_completed
                        else "部分字段待补译，目录记录未标记为完整翻译。"
                        if translation_partial
                        else "翻译结果不可用。"
                    ),
                ),
            )
        except Exception as exc:  # noqa: BLE001 - preserve the verified response on translation outages.
            message = sanitize_public_text(str(exc)).strip() or "翻译 MCP 未返回可用结果"
            target_language = str(state.get("response_language") or "zh-Hans")
            state["translation"] = failed_translation_audit(target_language, message)
            state["answer"] = public_answer_payload(
                fail_closed_translation_payload(
                    answer,
                    target_language=target_language,
                    audit=state["translation"],
                )
            )
            state["trace"] = []
            return add_trace(
                state,
                "translation_agent",
                translation_unavailable_message(target_language),
                status="warning",
                presentation=tool_call_presentation(
                    "translate_json_payload",
                    state="error",
                    title="Translation MCP",
                    input_summary={"content_scope": "assistant_response"},
                    error=message,
                ),
            )

    def _run_report_subgraph(self, state: AssistantState) -> AssistantState:
        language = state.get("response_language", "zh-Hans")
        payload: dict[str, Any] = {
            "question": state.get("question", ""),
            "user_id": state.get("user_id", "default"),
            "session_id": state.get("session_id", "default"),
            "response_language": language,
            "source_kind": "report_center",
            "report_store_root": str(report_store.root),
        }
        task_context = state.get("task_context") or {}
        if task_context.get("report_store_root"):
            payload["report_store_root"] = str(task_context["report_store_root"])
        report_task = task_context.get("report_task")
        if (
            state.get("intent") == "report_operation"
            and isinstance(report_task, dict)
            and isinstance(report_task.get("result"), dict)
        ):
            report_metrics = task_context.get("report_metrics")
            if not isinstance(report_metrics, dict) or not report_metrics:
                from app.agent.task_agent import agent_task_report_metrics

                report_metrics = agent_task_report_metrics(report_task)
            payload.update(
                {
                    "source_kind": "agent_task",
                    "scan_data": {
                        "task": report_task,
                        "report_metrics": report_metrics,
                    },
                }
            )
        if self._should_generate_report(state):
            report_records: list[dict[str, Any]] = []
            for record in state.get("records", []):
                report_record = dict(record)
                report_record["summary_zh"] = localized_vulnerability_description(
                    record,
                    language,
                    user_id=state.get("user_id", "default"),
                )
                report_records.append(report_record)
            report_metrics = build_report_metrics(
                dependency_scan=state.get("dependency_scan", {}),
                records=report_records,
                static_analysis=state.get("static_analysis", {}),
                language=language,
            )
            finding_count = int((state.get("static_analysis", {}) or {}).get("finding_count") or 0)
            payload.update(
                {
                    "action": "generate",
                    "source_kind": "assistant_scan",
                    "scan_data": {
                        "question": state.get("question", ""),
                        "dependency_scan": state.get("dependency_scan", {}),
                        "records": report_records,
                        "static_analysis": state.get("static_analysis", {}),
                        "summary": build_report_conclusion(
                            len(report_records),
                            finding_count,
                            sum(
                                1
                                for dependency in (state.get("dependency_scan", {}) or {}).get("dependencies", [])
                                if not dependency.get("version")
                            ),
                            language,
                            has_dependency_scope=bool(report_metrics["has_dependency_scope"]),
                            has_code_scope=bool(report_metrics["has_code_scope"]),
                        ),
                        "fields": dict((state.get("answer") or {}).get("fields") or {}),
                        "title": tr(language, "dependency_report_title")
                        if normalize_response_language(language) != "zh-Hans"
                        else "依赖漏洞与代码漏洞分析报告",
                        "report_metrics": report_metrics,
                        "input_fingerprint": report_input_fingerprint(state.get("attachments", [])),
                    },
                }
            )
        outcome = self._report_subgraph.start(payload)
        state["report_operation"] = outcome
        answer = dict(state.get("answer") or report_outcome_answer(outcome))
        if not answer:
            answer = report_outcome_answer(outcome)
        answer["interrupt"] = outcome.get("interrupt")
        if outcome.get("report"):
            answer["report"] = outcome["report"]
            state["markdown_report"] = outcome["report"]
        if outcome.get("artifacts"):
            answer["artifacts"] = [*answer.get("artifacts", []), *outcome["artifacts"]]
        if state.get("intent") == "report_operation":
            answer.update(report_outcome_answer(outcome))
        state["answer"] = public_answer_payload(answer)
        status = "warning" if outcome.get("error") else "completed"
        return add_trace(
            state,
            "report_capability_subgraph",
            str((outcome.get("interrupt") or {}).get("question") or outcome.get("summary") or "报告子图已执行。"),
            status=status,
        )

    def _run_component_catalog_subgraph(self, state: AssistantState) -> AssistantState:
        outcome = self._component_catalog_subgraph.start(
            {
                "question": state.get("question", ""),
                "top_k": state.get("top_k", 5),
                "user_id": state.get("user_id", "default"),
                "session_id": state.get("session_id", "default"),
                "response_language": state.get("response_language", "zh-Hans"),
                "date_filter": dict(state.get("date_filter") or {}),
                "filters": dict(state.get("filters") or {}),
                "intent_plan": dict(state.get("intent_plan") or {}),
                "trace": list(state.get("trace") or []),
                "event_sink": state.get("event_sink"),
            }
        )
        state["catalog_operation"] = outcome
        state["chart_data"] = dict(outcome.get("chart_data") or {})
        state["artifacts"] = list(outcome.get("artifacts") or [])
        state["trace"] = list(outcome.get("trace") or state.get("trace") or [])
        catalog_translation = (
            outcome.get("catalog_translation") if isinstance(outcome.get("catalog_translation"), dict) else {}
        )
        state["catalog_translation_ready"] = catalog_translation_status_is_complete(
            catalog_translation,
            state.get("response_language", "zh-Hans"),
        )
        answer = public_answer_payload(component_catalog_outcome_answer(outcome))
        if (
            not isinstance(answer.get("translation"), dict)
            and catalog_translation_status_is_partial(
                catalog_translation,
                state.get("response_language", "zh-Hans"),
            )
            and public_catalog_records_are_partially_ready(
                answer.get("records"),
                state.get("response_language", "zh-Hans"),
            )
            and len(answer.get("records") or []) == catalog_translation.get("record_count")
        ):
            answer["translation"] = issue_partial_catalog_translation_attestation(
                answer,
                target_language=state.get("response_language", "zh-Hans"),
                catalog_status=catalog_translation,
                source="component-vulnerability-catalog",
            )
        if isinstance(answer.get("translation"), dict):
            state["translation"] = dict(answer["translation"])
        state["catalog_translation_partial_verified"] = (
            partial_catalog_translation_attestation_is_publishable(
                answer,
                state.get("response_language", "zh-Hans"),
            )
        )
        state["host_localization_verified"] = host_localization_attestation_is_publishable(
            answer,
            state.get("response_language", "zh-Hans"),
        )
        state["answer"] = answer
        return add_trace(
            state,
            "component_catalog_subgraph",
            str((outcome.get("interrupt") or {}).get("question") or outcome.get("summary") or "组件漏洞目录子图已执行。"),
            status="warning" if outcome.get("error") else "completed",
        )

    def _run_sbom_subgraph(self, state: AssistantState) -> AssistantState:
        outcome = project_sbom_subgraph.start(
            {
                "question": state.get("question") or "",
                "workspace_path": state.get("workspace_path") or "",
                "user_id": state.get("user_id") or "default",
                "session_id": state.get("session_id") or "default",
                "response_language": state.get("response_language") or "zh-Hans",
                "destination_hint": state.get("destination_hint") or "unspecified",
                "trace": list(state.get("trace") or []),
                "event_sink": state.get("event_sink"),
            }
        )
        operation_context = dict(outcome.pop("_operation_context", {}) or {})
        if operation_context:
            try:
                memory_service.remember_sbom_operation(
                    state.get("user_id", "default"),
                    state.get("session_id", "default"),
                    operation_context,
                )
            except Exception:  # noqa: BLE001 - the current SBOM response remains usable.
                pass
        state["sbom_operation"] = outcome
        state["artifacts"] = list(outcome.get("artifacts") or [])
        state["trace"] = list(outcome.get("trace") or state.get("trace") or [])
        state["answer"] = sbom_outcome_answer(outcome)
        return add_trace(
            state,
            "project_sbom_subgraph",
            str((outcome.get("interrupt") or {}).get("question") or outcome.get("summary") or "项目 SBOM 子图已执行。"),
            status="warning" if outcome.get("error") else "completed",
        )

    def _generate_markdown_report(self, state: AssistantState) -> AssistantState:
        answer = dict(state.get("answer", {}))
        fields = dict(answer.get("fields") or {})
        language = state.get("response_language", "zh-Hans")
        try:
            report_records = []
            for record in state.get("records", []):
                report_record = dict(record)
                report_record["summary_zh"] = localized_vulnerability_description(
                    record,
                    language,
                    user_id=state.get("user_id", "default"),
                )
                report_records.append(report_record)
            report_metrics = build_report_metrics(
                dependency_scan=state.get("dependency_scan", {}),
                records=report_records,
                static_analysis=state.get("static_analysis", {}),
                language=language,
            )
            content = build_dependency_markdown_report(
                question=sanitize_public_text(state.get("question", "")),
                dependency_scan=state.get("dependency_scan", {}),
                records=report_records,
                static_analysis=state.get("static_analysis", {}),
                summary=build_report_conclusion(
                    len(report_records),
                    int((state.get("static_analysis", {}) or {}).get("finding_count") or 0),
                    sum(
                        1
                        for dependency in (state.get("dependency_scan", {}) or {}).get("dependencies", [])
                        if not dependency.get("version")
                    ),
                    language,
                    has_dependency_scope=bool(report_metrics["has_dependency_scope"]),
                    has_code_scope=bool(report_metrics["has_code_scope"]),
                ),
                fields=fields,
                language=language,
            )
            saved = report_store.save_markdown(
                tr(language, "dependency_report_title") if normalize_response_language(language) != "zh-Hans" else "依赖漏洞与代码漏洞分析报告",
                content,
                mode=str(state.get("intent") or "dependency_vulnerability_report"),
                vulnerability_count=len(state.get("records", [])),
                finding_count=int((state.get("static_analysis", {}) or {}).get("finding_count") or 0),
                metadata={
                    "session_id": state.get("session_id", "default"),
                    "user_id": state.get("user_id", "default"),
                    "files": state.get("dependency_scan", {}).get("files", []),
                    "language": report_metrics["language"],
                    "report_metrics": report_metrics,
                },
                input_fingerprint=report_input_fingerprint(state.get("attachments", [])),
            )
            state["markdown_report"] = saved
            fields["报告编号"] = str(saved.get("id") or "")
            fields["报告文件"] = str(saved.get("file_name") or "")
            answer["fields"] = fields
            answer["report"] = saved
            state["answer"] = public_answer_payload(answer)
            state = add_trace(state, "generate_markdown_report", f"已生成或复用完整 Markdown 报告：{saved.get('file_name')}")
            state["answer"]["trace"] = state.get("trace", [])
            return state
        except Exception as exc:  # noqa: BLE001
            state = add_trace(state, "generate_markdown_report", f"Markdown 报告生成失败：{exc}", status="warning")
            if answer:
                answer["fields"] = fields
                answer["trace"] = state.get("trace", [])
                state["answer"] = public_answer_payload(answer)
            return state

    def _persist_memory(self, state: AssistantState) -> AssistantState:
        answer = dict(state.get("answer", {}))
        answer["trace"] = list(state.get("trace") or answer.get("trace") or [])
        if state.get("intent") == "clarification":
            state["answer"] = public_answer_payload(answer)
            return add_trace(state, "persist_memory", "无有效语义的问题未写入长期记忆。")
        public_answer = public_answer_payload(answer)
        if state.get("host_localization_verified"):
            localization = answer.get("translation") if isinstance(answer.get("translation"), dict) else {}
            public_answer["translation"] = issue_host_localization_attestation(
                public_answer,
                target_language=state.get("response_language", "zh-Hans"),
                source=str(localization.get("source") or "component-catalog-preview"),
            )
        elif state.get("catalog_translation_partial_verified"):
            localization = answer.get("translation") if isinstance(answer.get("translation"), dict) else {}
            public_answer["translation"] = issue_partial_catalog_translation_attestation(
                public_answer,
                target_language=state.get("response_language", "zh-Hans"),
                catalog_status=localization,
                source=str(localization.get("source") or "component-vulnerability-catalog"),
            )
        try:
            workspace_path = str(state.get("workspace_path") or "").strip()
            if workspace_path:
                memory_service.remember_project_link(
                    state.get("user_id", "default"),
                    state.get("session_id", "default"),
                    project_name=Path(workspace_path).name,
                    workspace_path=workspace_path,
                    artifact_ids=[
                        str(item.get("id") or "")
                        for item in state.get("artifacts") or []
                        if isinstance(item, dict)
                    ],
                    artifact_names=[
                        str(item.get("file_name") or "")
                        for item in state.get("artifacts") or []
                        if isinstance(item, dict)
                    ],
                )
            if _is_information_session(state.get("session_id")):
                stored = memory_service.add_short_term_exchange(
                    state.get("user_id", "default"),
                    state.get("session_id", "default"),
                    state["question"],
                    public_answer,
                )
                if isinstance(stored, dict) and stored.get("id"):
                    state["exchange_id"] = str(stored["id"])
                state["answer"] = public_answer
                return add_trace(state, "persist_memory", "已写入当前咨询的短期记忆，不进入历史归档。")
            stored = memory_service.add_exchange(
                state.get("user_id", "default"),
                state["question"],
                public_answer,
                session_id=state.get("session_id", "default"),
            )
            if isinstance(stored, dict) and stored.get("id"):
                state["exchange_id"] = str(stored["id"])
            state["answer"] = public_answer
            return add_trace(state, "persist_memory", "已写入长期记忆。")
        except Exception as exc:  # noqa: BLE001
            state["answer"] = public_answer
            return add_trace(state, "persist_memory", f"长期记忆保存失败：{exc}", status="warning")

    @staticmethod
    def _should_retrieve(state: AssistantState) -> bool:
        return state.get("intent") in {"vulnerability_lookup", "vulnerability_year_lookup", "dependency_vulnerability_report"}

    @classmethod
    def _route_after_memory(cls, state: AssistantState) -> str:
        if state.get("intent") == "component_vulnerability_query":
            return "component_query_subgraph"
        if state.get("intent") == "component_vulnerability_catalog":
            return "component_catalog_subgraph"
        if state.get("intent") == "project_sbom_export":
            return "project_sbom_subgraph"
        if state.get("intent") == "report_operation":
            return "report_capability_subgraph"
        return "query_intelligence" if cls._should_retrieve(state) else "call_llm"

    @staticmethod
    def _should_run_static_analysis(state: AssistantState) -> bool:
        if state.get("intent") != "dependency_vulnerability_report":
            return False
        for item in state.get("dependency_scan", {}).get("files") or []:
            if item.get("kind") == "code":
                return True
        return False

    @staticmethod
    def _should_generate_report(state: AssistantState) -> bool:
        return state.get("intent") == "dependency_vulnerability_report" and bool(state.get("attachments"))

    @staticmethod
    def _can_use_catalog_translation(state: AssistantState) -> bool:
        if normalize_response_language(state.get("response_language", "zh-Hans")) != "zh-Hans":
            return False
        if state.get("intent") == "component_vulnerability_catalog":
            operation = state.get("catalog_operation")
            status = operation.get("catalog_translation") if isinstance(operation, dict) else None
            return (
                bool(operation)
                and catalog_translation_status_is_complete(
                    status,
                    state.get("response_language", "zh-Hans"),
                )
            ) or bool(state.get("host_localization_verified")) or (
                host_localization_attestation_is_publishable(
                    state.get("answer"),
                    state.get("response_language", "zh-Hans"),
                )
            ) or bool(state.get("catalog_translation_partial_verified")) or (
                partial_catalog_translation_attestation_is_publishable(
                    state.get("answer"),
                    state.get("response_language", "zh-Hans"),
                )
            )
        if not state.get("catalog_translation_ready"):
            return False
        return (
            state.get("intent") in {
            "vulnerability_lookup",
            "vulnerability_year_lookup",
            "dependency_vulnerability_report",
            "component_vulnerability_query",
            }
            and bool(state.get("records"))
            and public_catalog_records_are_ready(
                state.get("records"),
                state.get("response_language", "zh-Hans"),
            )
        )

    @staticmethod
    def _stored_catalog_record_count(state: AssistantState) -> int:
        if state.get("intent") == "component_vulnerability_catalog":
            operation = state.get("catalog_operation")
            status = operation.get("catalog_translation") if isinstance(operation, dict) else {}
            count = status.get("record_count") if isinstance(status, dict) else 0
            return count if type(count) is int and count >= 0 else 0
        return len(state.get("records") or [])

    @classmethod
    def _route_after_compose(cls, state: AssistantState) -> str:
        if cls._should_generate_report(state):
            return "report_capability_subgraph"
        return "persist_memory" if cls._can_use_catalog_translation(state) else "translation_agent"

    def _build_messages(self, state: AssistantState) -> list[dict[str, str]]:
        records = state.get("records", [])
        memory_context = state.get("memory_context", {})
        context_parts: list[str] = []
        if memory_context.get("promptContext"):
            context_parts.append(str(memory_context["promptContext"]))
        if state.get("task_context"):
            context_parts.append(format_task_scan_context(state["task_context"]))
        if state.get("intent") == "dependency_vulnerability_report":
            context_parts.append(format_dependency_scan_context(state.get("dependency_scan", {}), records))
            static_context = format_static_analysis_context(state.get("static_analysis", {}))
            if static_context:
                context_parts.append(static_context)
        if records:
            context_parts.append("API 实时查询与图谱富化记录：\n" + "\n".join(format_record_context(record) for record in records[:5]))
        context_text = "\n\n".join(context_parts) or "暂无额外上下文。"
        prompt = system_prompt(state.get("response_language", "zh-Hans"), emoji_mode=state.get("emoji_mode", "moderate"))
        if state.get("task_context"):
            prompt += (
                "\n当前问题关联一个已持久化的神盾扫描任务。"
                "只能使用输入中的结构化任务证据回答；证据不足时必须明确说明，禁止虚构路径、代码、调用链、修复结果或验证结果。"
                "修复建议必须结合实际用途，并提供可执行的修改、验证步骤和回归扫描建议。"
            )
        messages = [{"role": "system", "content": prompt}]
        messages.extend(memory_context.get("injectedMessages", [])[:6])
        messages.append(
            {
                "role": "user",
                "content": f"上下文：\n{context_text}\n\n用户问题：{state['question']}",
            }
        )
        return messages

    @staticmethod
    def _memory_label(memory_context: dict[str, Any]) -> str:
        if not memory_context.get("enabled", True):
            return "未启用"
        stats = memory_context.get("stats", {})
        return f"{memory_context.get('backend', 'json')} · 历史 {stats.get('historyCount', 0)} 条 · 相关 {stats.get('retrievedCount', 0)} 条"


def format_task_scan_context(task_context: dict[str, Any]) -> str:
    facts = {
        "task_id": task_context.get("task_id"),
        "baseline_task_id": task_context.get("baseline_task_id"),
        "run_number": task_context.get("run_number"),
        "status": task_context.get("status"),
        "workspace_name": task_context.get("workspace_name"),
        "objective": task_context.get("objective"),
        "summary": task_context.get("summary"),
        "metrics": task_context.get("metrics") or {},
        "findings": task_context.get("findings") or [],
        "finding_context_truncated": bool(task_context.get("finding_context_truncated")),
        "result_diff": task_context.get("result_diff") or {},
        "workspace_fingerprint": task_context.get("workspace_fingerprint"),
        "ruleset_fingerprint": task_context.get("ruleset_fingerprint"),
        "engine_fingerprint": task_context.get("engine_fingerprint"),
    }
    return "神盾扫描任务可验证事实 JSON：\n" + json.dumps(
        facts,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def add_trace(
    state: AssistantState,
    node: str,
    message: str,
    status: str = "completed",
    presentation: dict[str, Any] | None = None,
) -> AssistantState:
    item = {"node": node, "status": status, "message": sanitize_public_text(message), "time": now_iso()}
    if presentation:
        item["presentation"] = presentation
    state["trace"] = [*state.get("trace", []), item]
    event_sink = state.get("event_sink")
    if event_sink is not None:
        try:
            event_sink(dict(item))
        except Exception:  # noqa: BLE001 - progress delivery must never break the graph.
            pass
    return state


LANGUAGE_NAMES = {
    "zh-Hans": "简体中文",
    "zh-Hant": "繁體中文",
    "en": "English",
    "ko": "한국어",
    "ja": "日本語",
    "es": "Español",
    "fr": "Français",
    "de": "Deutsch",
    "it": "Italiano",
    "ru": "Русский",
}


BACKEND_TEXT = {
    "en": {
        "not_specified": "Not specified",
        "unknown": "Unknown",
        "no_verified_description": "No verifiable vulnerability description is available.",
        "no_verified_code": "No verifiable code snippet was found in the vulnerability record",
        "no_verified_fix_code": "No verifiable fixed code snippet was found in the vulnerability record",
        "fix_limit_exposure": "Before remediation is complete, restrict network exposure and access permissions for affected components, enable abnormal behavior monitoring, and temporarily block high-risk entry points.",
        "fix_unset_version": "The current knowledge record does not specify a fixed version. Verify asset versions and use the first vendor-confirmed safe version; do not guess version numbers.",
        "use_confirmed_commit": "Use the confirmed fix commit %s, then complete workflow and business regression testing in a test environment.",
        "upgrade_fixed_version": "Upgrade to the confirmed fixed version: %s, then complete compatibility and regression testing in a test environment.",
        "clarification": "Please enter a specific security question, such as a vulnerability ID, component name, code risk, or remediation advice.",
        "year_no_facts": "There are not enough verified facts to answer the vulnerability question for %s. Check API connectivity, query settings, and upstream response status.",
        "supply_chain": "The model is currently unavailable. Local fallback advice: start supply-chain governance with a dependency inventory, SBOM, pinned versions, trusted source verification, vulnerability intelligence monitoring, CI blocking for high-risk dependencies, artifact signing, exception approvals, and remediation SLAs.",
        "code_audit": "The model is currently unavailable. Local fallback advice: review entry points, authorization boundaries, data flow, dangerous functions, dependency risks, and historical vulnerability patterns. Prioritize SAST findings by reachability, exploitability, and business impact.",
        "threat_model": "The model is currently unavailable. Local fallback advice: map assets, data flows, trust boundaries, and external entry points first, then use STRIDE to review spoofing, tampering, repudiation, information disclosure, denial of service, and privilege escalation.",
        "default_fallback": "The model did not return a usable result. Check the LLM API Key, endpoint, model name, and network connectivity. For non-CVE questions, the system injects memory and context into the model before answering.",
        "dependency_report_title": "Dependency and code vulnerability analysis report",
        "scan_files": "Scanned files: %s",
        "dependency_count": "Identified dependencies: %d; dependency vulnerabilities: %d.",
        "code_findings": "Code findings: %d.",
        "ignored_files": "Ignored unsupported attachments: %s.",
        "detected_dependencies": "Detected dependencies:",
        "remaining_dependencies": "%d additional dependencies were included in backend matching.",
        "no_dependencies": "No dependencies usable for vulnerability matching were identified. Upload a pom.xml or Gradle build file with dependencies, or code files containing third-party import/require statements.",
        "no_version_hits": "No vulnerabilities were confirmed from explicit component versions.",
        "unresolved_dependencies": "%d dependencies have unspecified versions and were not counted as vulnerability hits; this does not prove the project is safe. Add complete version information and analyze again.",
        "risk_distribution": "Risk distribution: %s.",
        "dependency_details": "Dependency vulnerability details:",
        "related_dependency": "Related dependency",
        "vulnerability_description": "Vulnerability description",
        "component_range": "Component version range",
        "fixed_version": "Fixed version",
        "fix_advice": "Remediation",
        "references": "References",
        "more_records": "%d additional matched records were added to the knowledge graph. Expand by vulnerability ID for details.",
        "code_details": "Code finding details:",
        "static_finding": "Static analysis finding",
        "risk_code": "Risk code",
        "fixed_code": "Fixed code",
        "cfg": "CFG",
        "dfg": "DFG",
        "impact": "Affects %s",
        "fixed": "Fixed %s",
        "range_unknown": "Version range not specified",
    },
    "ja": {
        "not_specified": "未指定",
        "unknown": "不明",
        "no_verified_description": "検証済みの脆弱性説明はありません。",
        "no_verified_code": "脆弱性レコード内に検証済みコード片は見つかりませんでした",
        "no_verified_fix_code": "脆弱性レコード内に検証済み修正コード片は見つかりませんでした",
        "fix_limit_exposure": "修正完了までは、影響を受けるコンポーネントのネットワーク露出とアクセス権限を制限し、異常動作の監視を有効化し、高リスク入口を一時的に遮断してください。",
        "fix_unset_version": "現在の知識レコードには修正バージョンが明記されていません。資産バージョンを確認し、ベンダーが確認した最初の安全バージョンを採用してください。推測でバージョンを決めないでください。",
        "use_confirmed_commit": "確認済みの修正コミット %s を適用し、テスト環境でワークフローと業務回帰検証を完了してください。",
        "upgrade_fixed_version": "確認済みの修正バージョン %s へアップグレードし、互換性と回帰検証を完了してください。",
        "clarification": "脆弱性番号、コンポーネント名、コードリスク、修正提案など、具体的なセキュリティ質問を入力してください。",
        "year_no_facts": "%s 年の脆弱性回答に必要な検証済み事実が不足しています。API 接続、クエリ設定、上流レスポンス状態を確認してください。",
        "supply_chain": "現在モデルは利用できません。ローカル代替提案：依存関係インベントリ、SBOM、バージョン固定、信頼できる取得元の検証、脆弱性情報監視、CI での高リスク依存ブロック、成果物署名、例外承認、修復 SLA から始めてください。",
        "code_audit": "現在モデルは利用できません。ローカル代替提案：入口点、認可境界、データフロー、危険関数、依存リスク、過去の脆弱性パターンを確認し、到達可能性・悪用条件・業務影響で SAST 結果を優先順位付けしてください。",
        "threat_model": "現在モデルは利用できません。ローカル代替提案：資産、データフロー、信頼境界、外部入口を整理し、STRIDE でなりすまし、改ざん、否認、情報漏えい、DoS、権限昇格を確認してください。",
        "default_fallback": "モデルから利用可能な結果が返りませんでした。LLM API Key、Endpoint、モデル名、ネットワーク接続を確認してください。CVE 以外の質問では、長期記憶とコンテキストを注入して回答します。",
        "dependency_report_title": "依存関係脆弱性とコード脆弱性の分析レポート",
        "scan_files": "スキャンファイル：%s",
        "dependency_count": "識別した依存関係：%d 個；依存関係脆弱性：%d 件。",
        "code_findings": "コード脆弱性：%d 件。",
        "ignored_files": "未対応の添付を無視しました：%s。",
        "detected_dependencies": "識別された依存関係：",
        "remaining_dependencies": "残り %d 個の依存関係もバックエンド照合に使用しました。",
        "no_dependencies": "脆弱性照合に使える依存関係を識別できませんでした。dependencies を含む pom.xml または Gradle ビルドファイル、または第三者 import/require を含むコードファイルをアップロードしてください。",
        "no_version_hits": "明確なコンポーネントバージョンから確認できた脆弱性はありません。",
        "unresolved_dependencies": "%d 個の依存関係はバージョン未指定のため脆弱性ヒットに含めていません。これは安全を証明するものではありません。完全なバージョン情報を追加して再分析してください。",
        "risk_distribution": "リスク分布：%s。",
        "dependency_details": "依存関係脆弱性の詳細：",
        "related_dependency": "関連依存関係",
        "vulnerability_description": "脆弱性説明",
        "component_range": "コンポーネントバージョン範囲",
        "fixed_version": "修正バージョン",
        "fix_advice": "修正提案",
        "references": "参考リンク",
        "more_records": "残り %d 件の命中レコードはナレッジグラフに追加されています。脆弱性番号で展開して確認できます。",
        "code_details": "コード脆弱性の詳細：",
        "static_finding": "静的分析の検出",
        "risk_code": "リスクコード",
        "fixed_code": "修正後コード",
        "cfg": "CFG",
        "dfg": "DFG",
        "impact": "%s に影響",
        "fixed": "%s で修正",
        "range_unknown": "バージョン範囲は未指定",
    },
    "ko": {
        "not_specified": "명확하지 않음",
        "unknown": "알 수 없음",
        "no_verified_description": "검증된 취약점 설명이 없습니다.",
        "no_verified_code": "취약점 기록에서 검증 가능한 코드 조각을 찾지 못했습니다",
        "no_verified_fix_code": "취약점 기록에서 검증 가능한 수정 코드 조각을 찾지 못했습니다",
        "fix_limit_exposure": "수정이 완료될 때까지 영향받는 컴포넌트의 네트워크 노출과 접근 권한을 제한하고, 이상 행위 모니터링을 활성화하며, 고위험 진입점을 임시 차단하세요.",
        "fix_unset_version": "현재 지식 기록에는 수정 버전이 명시되어 있지 않습니다. 자산 버전을 확인하고 공급사가 확인한 최초의 안전 버전을 사용하세요. 버전 번호를 추측하지 마세요.",
        "use_confirmed_commit": "확인된 수정 커밋 %s 을 적용하고 테스트 환경에서 워크플로와 업무 회귀 검증을 완료하세요.",
        "upgrade_fixed_version": "확인된 수정 버전 %s 으로 업그레이드하고 호환성 및 회귀 검증을 완료하세요.",
        "clarification": "취약점 번호, 컴포넌트 이름, 코드 위험, 수정 제안 등 구체적인 보안 질문을 입력하세요.",
        "year_no_facts": "%s년 취약점 답변에 필요한 검증된 사실이 부족합니다. API 연결, 쿼리 설정, 상위 응답 상태를 확인하세요.",
        "supply_chain": "현재 모델을 사용할 수 없습니다. 로컬 대체 제안: 의존성 인벤토리, SBOM, 버전 고정, 신뢰 가능한 출처 검증, 취약점 정보 모니터링, CI 단계의 고위험 의존성 차단, 산출물 서명, 예외 승인, 수정 SLA부터 시작하세요.",
        "code_audit": "현재 모델을 사용할 수 없습니다. 로컬 대체 제안: 진입점, 인가 경계, 데이터 흐름, 위험 함수, 의존성 위험, 과거 취약점 패턴을 점검하고 도달 가능성, 악용 조건, 비즈니스 영향으로 SAST 결과 우선순위를 정하세요.",
        "threat_model": "현재 모델을 사용할 수 없습니다. 로컬 대체 제안: 자산, 데이터 흐름, 신뢰 경계, 외부 진입점을 정리한 뒤 STRIDE로 스푸핑, 변조, 부인, 정보 노출, 서비스 거부, 권한 상승을 점검하세요.",
        "default_fallback": "모델이 사용할 수 있는 결과를 반환하지 않았습니다. LLM API Key, Endpoint, 모델 이름, 네트워크 연결을 확인하세요. CVE 이외 질문은 장기 기억과 컨텍스트를 모델에 주입한 뒤 답변합니다.",
        "dependency_report_title": "의존성 취약점 및 코드 취약점 분석 보고서",
        "scan_files": "스캔 파일: %s",
        "dependency_count": "식별한 의존성: %d개; 의존성 취약점: %d건.",
        "code_findings": "코드 취약점: %d건.",
        "ignored_files": "지원하지 않는 첨부를 무시했습니다: %s.",
        "detected_dependencies": "식별된 의존성:",
        "remaining_dependencies": "나머지 %d개 의존성도 백엔드 매칭에 포함되었습니다.",
        "no_dependencies": "취약점 매칭에 사용할 수 있는 의존성을 식별하지 못했습니다. dependencies가 포함된 pom.xml 또는 Gradle 빌드 파일, 또는 서드파티 import/require가 포함된 코드 파일을 업로드하세요.",
        "no_version_hits": "명확한 컴포넌트 버전으로 확인된 취약점은 없습니다.",
        "unresolved_dependencies": "%d개 의존성은 버전이 명확하지 않아 취약점 명중에 포함하지 않았습니다. 이는 안전함을 의미하지 않습니다. 완전한 버전 정보를 추가해 다시 분석하세요.",
        "risk_distribution": "위험 분포: %s.",
        "dependency_details": "의존성 취약점 상세:",
        "related_dependency": "관련 의존성",
        "vulnerability_description": "취약점 설명",
        "component_range": "컴포넌트 버전 범위",
        "fixed_version": "수정 버전",
        "fix_advice": "수정 제안",
        "references": "참고 링크",
        "more_records": "나머지 %d건의 명중 기록은 지식 그래프에 추가되었습니다. 취약점 번호로 펼쳐 확인할 수 있습니다.",
        "code_details": "코드 취약점 상세:",
        "static_finding": "정적 분석 발견",
        "risk_code": "위험 코드",
        "fixed_code": "수정 코드",
        "cfg": "CFG",
        "dfg": "DFG",
        "impact": "%s 영향",
        "fixed": "%s 수정",
        "range_unknown": "버전 범위 명확하지 않음",
    },
}


def normalize_response_language(value: Any) -> str:
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


def language_name(language: str) -> str:
    return LANGUAGE_NAMES.get(normalize_response_language(language), LANGUAGE_NAMES["zh-Hans"])


def system_prompt(language: str, *, emoji_mode: str = "moderate", now: datetime | None = None) -> str:
    local_now = now or datetime.now(ASSISTANT_TIMEZONE)
    if local_now.tzinfo is None:
        local_now = local_now.replace(tzinfo=ASSISTANT_TIMEZONE)
    else:
        local_now = local_now.astimezone(ASSISTANT_TIMEZONE)
    return SYSTEM_PROMPT_TEMPLATE.format(
        language_name=language_name(language),
        current_date=local_now.strftime("%Y年%m月%d日"),
        current_time=local_now.strftime("%H:%M:%S"),
        emoji_style={"off": "不要使用任何表情符号。", "moderate": "在问候、感谢、鼓励或祝贺时必须自然使用 1 个相关表情符号；其他普通回答最多 2 个。专业、安全、代码和错误内容默认不使用。", "active": "在问候、感谢、鼓励或祝贺时必须使用 1 个相关表情符号；其他内容可自然使用少量相关表情符号，每次最多 4 个；代码、命令、URL、文件名和结构化字段中禁止使用。"}.get(emoji_mode, "在问候、感谢、鼓励或祝贺时使用 1 个相关表情符号。"),
    )


def public_evidence_sources(values: Any) -> list[dict[str, Any]]:
    """Project source health to the small public provenance contract."""

    allowed = {"nvd", "github_advisory", "osv"}
    output: list[dict[str, Any]] = []
    for item in values if isinstance(values, list) else []:
        if not isinstance(item, dict):
            continue
        source_id = str(item.get("id") or "").strip().lower()
        if source_id not in allowed:
            continue
        output.append(
            {
                "id": source_id,
                "status": str(item.get("status") or "unknown").strip().lower(),
                "count": max(0, int(item.get("count") or 0)),
            }
        )
    return output


def llm_token_usage(result: Any) -> int:
    """Return only the public aggregate token count from supported provider responses."""

    if not isinstance(result, dict):
        return 0
    data = result.get("data")
    if not isinstance(data, dict):
        return 0
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return 0
    for key in ("total_tokens", "total_token_count"):
        try:
            value = int(usage.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    total = 0
    for key in ("input_tokens", "output_tokens", "prompt_tokens", "completion_tokens"):
        try:
            total += max(0, int(usage.get(key) or 0))
        except (TypeError, ValueError):
            continue
    return total


def vulnerability_card_prompt(language: str) -> str:
    return VULNERABILITY_CARD_PROMPT_TEMPLATE.format(language_name=language_name(language))


def tr(language: str, key: str) -> str:
    language = normalize_response_language(language)
    if language in {"zh-Hans", "zh-Hant"}:
        zh = {
            "not_specified": "未明确",
            "unknown": "未知",
        }
        return zh.get(key, key)
    return BACKEND_TEXT.get(language, BACKEND_TEXT["en"]).get(key, BACKEND_TEXT["en"].get(key, key))


def severity_label_for_language(value: Any, language: str) -> str:
    normalized = str(value or "").strip().upper()
    language = normalize_response_language(language)
    if normalized in {"CRITICAL", "SEVERE", "严重"}:
        return {"zh-Hans": "严重", "zh-Hant": "嚴重", "en": "Critical", "ko": "심각", "ja": "重大", "es": "Crítica", "fr": "Critique", "de": "Kritisch", "it": "Critica", "ru": "Критическая"}.get(language, "严重")
    if normalized in {"HIGH", "高危"}:
        return {"zh-Hans": "高危", "zh-Hant": "高危", "en": "High", "ko": "높음", "ja": "高", "es": "Alta", "fr": "Élevée", "de": "Hoch", "it": "Alta", "ru": "Высокая"}.get(language, "高危")
    if normalized in {"MEDIUM", "MODERATE", "中危"}:
        return {"zh-Hans": "中危", "zh-Hant": "中危", "en": "Medium", "ko": "중간", "ja": "中", "es": "Media", "fr": "Moyenne", "de": "Mittel", "it": "Media", "ru": "Средняя"}.get(language, "中危")
    if normalized in {"LOW", "低危"}:
        return {"zh-Hans": "低危", "zh-Hant": "低危", "en": "Low", "ko": "낮음", "ja": "低", "es": "Baja", "fr": "Faible", "de": "Niedrig", "it": "Bassa", "ru": "Низкая"}.get(language, "低危")
    return tr(language, "unknown")


def empty_knowledge_graph(query: str = "") -> dict[str, Any]:
    return {"query": query, "nodes": [], "edges": [], "node_count": 0, "edge_count": 0}


def normalize_knowledge_graph(graph: Any) -> dict[str, Any]:
    if not isinstance(graph, dict):
        return empty_knowledge_graph()
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(edges, list):
        edges = []
    return {
        "query": str(graph.get("query") or ""),
        "nodes": nodes,
        "edges": edges,
        "node_count": int(graph.get("node_count") if graph.get("node_count") is not None else len(nodes)),
        "edge_count": int(graph.get("edge_count") if graph.get("edge_count") is not None else len(edges)),
    }


def extract_vulnerability_id(text: str) -> str:
    cve = re.search(r"CVE-\d{4}-\d{4,8}", text, flags=re.IGNORECASE)
    if cve:
        return cve.group(0).upper()
    ghsa = re.search(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", text, flags=re.IGNORECASE)
    if ghsa:
        return ghsa.group(0).upper()
    return ""


def is_meaningful_question(text: Any) -> bool:
    return any(character.isalnum() for character in str(text or ""))


def is_identity_question(text: Any) -> bool:
    normalized = re.sub(r"[\s，。！？、,.!?：:；;‘’'\"“”]", "", str(text or "")).lower()
    if not normalized or len(normalized) > 80:
        return False
    identity_phrases = (
        "你是谁",
        "你是誰",
        "你叫什么",
        "你叫什麼",
        "你的名字",
        "你的身份",
        "你是什么助手",
        "你是什麼助手",
        "介绍一下你自己",
        "介紹一下你自己",
        "自我介绍",
        "自我介紹",
        "whoareyou",
        "whatisyourname",
        "introduceyourself",
    )
    return any(phrase in normalized for phrase in identity_phrases)


def extract_year_filter(text: str) -> list[int]:
    now_year = datetime.now().year
    years = {int(item) for item in re.findall(r"(?<!\d)(20\d{2}|19\d{2})(?!\d)", text)}
    if re.search(r"今年|本年|current year|this year", text, flags=re.IGNORECASE):
        years.add(now_year)
    if re.search(r"去年|上一年|last year", text, flags=re.IGNORECASE):
        years.add(now_year - 1)
    recent = re.search(r"近\s*([两二三四五2-5])\s*年|最近\s*([两二三四五2-5])\s*年", text)
    if recent:
        raw = next(group for group in recent.groups() if group)
        count = {"两": 2, "二": 2, "三": 3, "四": 4, "五": 5}.get(raw, int(raw) if raw.isdigit() else 2)
        years.update(now_year - offset for offset in range(count))
    return sorted((year for year in years if 1999 <= year <= now_year + 1), reverse=True)


def is_vulnerability_year_question(text: str) -> bool:
    lowered = text.lower()
    security_keywords = [
        "cve",
        "漏洞",
        "高危",
        "严重",
        "rce",
        "0day",
        "zero-day",
        "vulnerability",
        "exploit",
        "安全",
        "修复",
        "补丁",
        "最新",
    ]
    return bool(extract_year_filter(text)) and any(keyword in lowered for keyword in security_keywords)


def build_record_answer(record: dict[str, Any], language: str = "zh-Hans") -> str:
    summary = str(record.get("summary") or record.get("title") or "").strip().rstrip(".")
    normalized_language = normalize_response_language(language)
    if normalized_language == "ja":
        return (
            f"{record.get('id')} の深刻度は {severity_label_for_language(record.get('severity'), language)} です。"
            f"{summary}。影響を受けるコンポーネントバージョン、露出面、悪用条件を優先確認し、確認済みの修正バージョンまたは緩和策を適用してください。"
        )
    if normalized_language == "ko":
        return (
            f"{record.get('id')}의 심각도는 {severity_label_for_language(record.get('severity'), language)}입니다. "
            f"{summary}. 영향받는 컴포넌트 버전, 노출면, 악용 조건을 우선 확인하고 확인된 수정 버전 또는 완화 조치를 적용하세요."
        )
    if normalized_language == "en":
        return (
            f"{record.get('id')} severity is {severity_label_for_language(record.get('severity'), language)}. "
            f"{summary}. Prioritize checking affected component versions, exposure, exploitability, and apply confirmed fixed versions or mitigations."
        )
    return (
        f"{record.get('id')} 的严重等级为 {severity_cn(record.get('severity'))}。"
        f"{summary}。建议优先核查受影响组件版本、暴露面、可利用条件，并按明确的修复版本或缓解方案处置。"
    )


def build_component_query_answer(
    result: dict[str, Any],
    requested: dict[str, Any],
    error: str,
    language: str = "zh-Hans",
) -> str:
    if error and not result:
        return error
    component = result.get("component") if isinstance(result.get("component"), dict) else requested
    name = str(component.get("name") or requested.get("name") or "").strip()
    version = str(component.get("version") or requested.get("version") or "").strip()
    ecosystem = str(component.get("ecosystem") or requested.get("ecosystem") or "").strip()
    coordinate = " / ".join(value for value in (ecosystem, name, version) if value)
    records = [record for record in result.get("records") or [] if isinstance(record, dict)]
    total = int(result.get("total") or len(records))
    normalized_language = normalize_response_language(language)

    if normalized_language == "ja":
        if not total:
            return f"{coordinate} を確認しました。現在の検証可能な記録では、この明確なバージョンに影響する脆弱性は確認されませんでした。"
        lines = [f"{coordinate} を確認し、{total} 件の影響する脆弱性を確認しました："]
        fixed_label = "修正"
    elif normalized_language == "ko":
        if not total:
            return f"{coordinate}을(를) 확인했습니다. 현재 검증 가능한 기록에서 이 명확한 버전에 영향을 주는 취약점은 확인되지 않았습니다."
        lines = [f"{coordinate}을(를) 확인하여 영향받는 취약점 {total}건을 확인했습니다:"]
        fixed_label = "수정"
    elif normalized_language == "en":
        if not total:
            return f"Verified {coordinate}. No vulnerability affecting this concrete version was confirmed in the currently verifiable records."
        lines = [f"Verified {coordinate} and confirmed {total} affecting vulnerability record(s):"]
        fixed_label = "Fixed"
    else:
        if not total:
            return f"已核验 {coordinate}。当前可验证记录中，未确认该明确版本受到漏洞影响。"
        lines = [f"已核验 {coordinate}，确认 {total} 条影响当前版本的漏洞记录："]
        fixed_label = "修复"

    for record in records[:8]:
        fixed = _component_fixed_versions(record, name)
        fixed_text = "、".join(fixed[:4]) if fixed else tr(language, "not_specified")
        lines.append(
            f"- {record.get('id') or tr(language, 'unknown')} | "
            f"{severity_label_for_language(record.get('severity'), language)} | {fixed_label}: {fixed_text}"
        )
    if total > len(records):
        if normalized_language == "en":
            lines.append(f"The preview shows {len(records)} of {total} records; use the attached workbook for the complete result.")
        else:
            lines.append(f"当前预览展示 {len(records)}/{total} 条，完整结果见随附工作簿。")
    return "\n".join(lines)


def _component_fixed_versions(record: dict[str, Any], component_name: str) -> list[str]:
    values: list[str] = []
    target = component_name.strip().lower()
    for component in record.get("components") or []:
        if not isinstance(component, dict):
            continue
        if target and str(component.get("name") or "").strip().lower() != target:
            continue
        values.extend(str(value).strip() for value in component.get("fixed") or [] if str(value).strip())
    if not values:
        values.extend(str(value).strip() for value in record.get("fixed_versions") or [] if str(value).strip())
    return list(dict.fromkeys(values))


def build_year_vulnerability_answer(records: list[dict[str, Any]], years: list[int], language: str = "zh-Hans") -> str:
    year_text = "、".join(str(year) for year in years) or "指定年份"
    normalized_language = normalize_response_language(language)
    if normalized_language == "ja":
        year_text = "、".join(str(year) for year in years) or "指定年"
        lines = [f"{year_text} の脆弱性事実確認が完了しました。候補脆弱性は次のとおりです："]
        for record in records[:8]:
            lines.append(
                f"- {record.get('id')} | {severity_label_for_language(record.get('severity'), language)} | "
                f"{record.get('title') or record.get('summary') or tr(language, 'not_specified')}"
            )
        lines.append("資産の露出、影響バージョン、既知の悪用状況、パッチ状態に基づいて優先順位を継続してください。")
        return "\n".join(lines)
    if normalized_language == "ko":
        year_text = ", ".join(str(year) for year in years) or "지정 연도"
        lines = [f"{year_text} 취약점 사실 확인을 완료했습니다. 후보 취약점은 다음과 같습니다:"]
        for record in records[:8]:
            lines.append(
                f"- {record.get('id')} | {severity_label_for_language(record.get('severity'), language)} | "
                f"{record.get('title') or record.get('summary') or tr(language, 'not_specified')}"
            )
        lines.append("자산 노출, 영향 버전, 알려진 악용 여부, 패치 상태를 기준으로 계속 우선순위를 정하세요.")
        return "\n".join(lines)
    if normalized_language == "en":
        joiner = ", "
        year_text = joiner.join(str(year) for year in years) or "the selected years"
        lines = [f"Verified vulnerability facts for {year_text}. Candidate vulnerabilities:"]
        for record in records[:8]:
            lines.append(
                f"- {record.get('id')} | {severity_label_for_language(record.get('severity'), language)} | "
                f"{record.get('title') or record.get('summary') or tr(language, 'not_specified')}"
            )
        lines.append("Continue prioritization based on asset exposure, affected versions, known exploitation, and patch status.")
        return "\n".join(lines)
    lines = [f"已完成 {year_text} 年漏洞事实核验。当前候选漏洞如下："]
    for record in records[:8]:
        lines.append(
            f"- {record.get('id')} | {severity_cn(record.get('severity'))} | "
            f"{record.get('title') or record.get('summary') or '暂无标题'}"
        )
    lines.append("请结合资产暴露面、受影响版本、是否已有利用代码和官方补丁状态继续排序处置。")
    return "\n".join(lines)


def build_dependency_vulnerability_answer(
    records: list[dict[str, Any]],
    scan: dict[str, Any],
    static_analysis: dict[str, Any] | None = None,
    language: str = "zh-Hans",
) -> str:
    files = scan.get("files") or []
    dependencies = scan.get("dependencies") or []
    rejected = scan.get("rejected_files") or []
    static_analysis = static_analysis or {}
    findings = static_analysis.get("findings") or []
    file_text = "、".join(str(item.get("file_name") or "") for item in files if item.get("file_name")) or "未识别到有效附件"
    if normalize_response_language(language) != "zh-Hans":
        file_text = ", ".join(str(item.get("file_name") or "") for item in files if item.get("file_name")) or tr(language, "not_specified")
        lines = [
            tr(language, "dependency_report_title"),
            "",
            tr(language, "scan_files") % file_text,
            tr(language, "dependency_count") % (len(dependencies), len(records)),
            tr(language, "code_findings") % len(findings),
        ]
        if rejected:
            lines.append(tr(language, "ignored_files") % ", ".join(str(item) for item in rejected))
        if dependencies:
            lines.extend(["", tr(language, "detected_dependencies")])
            for dependency in dependencies[:12]:
                lines.append(f"- {format_dependency_label(dependency, language)}")
            if len(dependencies) > 12:
                lines.append(f"- {tr(language, 'remaining_dependencies') % (len(dependencies) - 12)}")
        if not dependencies:
            lines.extend(["", tr(language, "no_dependencies")])
            return "\n".join(lines)
        if not records:
            lines.extend(["", tr(language, "no_version_hits")])
            unresolved_dependency_count = sum(1 for dependency in dependencies if not dependency.get("version"))
            if unresolved_dependency_count:
                lines.append(tr(language, "unresolved_dependencies") % unresolved_dependency_count)
            return "\n".join(lines)
        severity_counts: dict[str, int] = {}
        for record in records:
            severity = severity_label_for_language(record.get("severity"), language)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        severity_text = ", ".join(f"{key} {value}" for key, value in severity_counts.items())
        lines.extend(["", tr(language, "risk_distribution") % (severity_text or tr(language, "unknown")), "", tr(language, "dependency_details")])
        for index, record in enumerate(records[:8], start=1):
            reference_links = select_reference_links(record, limit=4, language=language)
            lines.extend(
                [
                    f"{index}. {record.get('id') or tr(language, 'unknown')} | {severity_label_for_language(record.get('severity'), language)} | CVSS {record.get('cvss_score') if record.get('cvss_score') is not None else tr(language, 'not_specified')}",
                    f"   {tr(language, 'related_dependency')}: {format_matched_dependencies(record, language) or format_component_version_ranges(record, language) or tr(language, 'not_specified')}",
                    f"   {tr(language, 'vulnerability_description')}: {localized_vulnerability_description(record, language)}",
                    f"   {tr(language, 'component_range')}: {format_component_version_ranges(record, language) or tr(language, 'not_specified')}",
                    f"   {tr(language, 'fixed_version')}: {join_card_values(record.get('fixed_versions') or [], language) or tr(language, 'not_specified')}",
                    f"   {tr(language, 'fix_advice')}: {_record_fix_instruction(record, language)}",
                    f"   {tr(language, 'references')}:\n{indent_multiline(reference_links)}",
                ]
            )
        if len(records) > 8:
            lines.append(tr(language, "more_records") % (len(records) - 8))
        if findings:
            lines.extend(["", tr(language, "code_details")])
            for index, finding in enumerate(findings[:6], start=1):
                sink = finding.get("sink") or {}
                file_name = finding.get("file") or sink.get("file") or tr(language, "unknown")
                risk_line = finding.get("risk_line") or sink.get("line") or 0
                lines.append(f"{index}. {finding.get('title') or tr(language, 'static_finding')} | {file_name}:{risk_line} | {finding.get('record_id') or tr(language, 'not_specified')}")
                lines.append(
                    f"   {tr(language, 'risk_code')}:\n```text\n"
                    f"{finding.get('vulnerable_snippet') or sink.get('snippet') or tr(language, 'not_specified')}\n```"
                )
                lines.append(
                    f"   {tr(language, 'fixed_code')}:\n```text\n"
                    f"{finding.get('fixed_snippet') or tr(language, 'no_verified_fix_code')}\n```"
                )
                lines.append(f"   {tr(language, 'fix_advice')}: {finding.get('remediation') or tr(language, 'fix_limit_exposure')}")
                lines.append(f"   {tr(language, 'cfg')}: {finding.get('cfg') or tr(language, 'not_specified')}")
                lines.append(f"   {tr(language, 'dfg')}: {finding.get('dfg') or tr(language, 'not_specified')}")
        return sanitize_public_text("\n".join(lines))

    lines = [
        "依赖漏洞与代码漏洞分析报告",
        "",
        f"扫描文件：{file_text}",
        f"识别依赖：{len(dependencies)} 个；依赖漏洞：{len(records)} 条。",
        f"代码漏洞：{len(findings)} 条。",
    ]
    if rejected:
        lines.append(f"已忽略不支持的附件：{'、'.join(str(item) for item in rejected)}。")
    if dependencies:
        lines.append("")
        lines.append("识别到的依赖：")
        for dependency in dependencies[:12]:
            lines.append(f"- {format_dependency_label(dependency)}")
        if len(dependencies) > 12:
            lines.append(f"- 其余 {len(dependencies) - 12} 个依赖已参与后端匹配。")
    if not dependencies:
        lines.append("")
        lines.append("未从附件中识别到可用于漏洞匹配的依赖。请上传包含 dependencies 的 pom.xml 或 Gradle 构建文件，或包含第三方 import/require 的代码文件。")
        return "\n".join(lines)
    if not records:
        lines.append("")
        unresolved_dependency_count = sum(1 for dependency in dependencies if not dependency.get("version"))
        lines.append("当前未基于明确组件版本确认漏洞。")
        if unresolved_dependency_count:
            lines.append(
                f"另有 {unresolved_dependency_count} 个依赖版本未明确，未计入漏洞命中；不能据此判定为安全。"
                "建议补充包含完整版本信息的 pom.xml 或 Gradle 构建文件后重新分析。"
            )
        return "\n".join(lines)

    severity_counts: dict[str, int] = {}
    for record in records:
        severity_counts[severity_cn(record.get("severity"))] = severity_counts.get(severity_cn(record.get("severity")), 0) + 1
    severity_text = "、".join(f"{key} {value} 条" for key, value in severity_counts.items())
    lines.append("")
    lines.append(f"风险分布：{severity_text or '未知'}。")
    lines.append("")
    lines.append("依赖漏洞明细：")
    for index, record in enumerate(records[:8], start=1):
        reference_links = select_reference_links(record, limit=4)
        lines.extend(
            [
                f"{index}. {record.get('id') or '未知漏洞'}｜{severity_cn(record.get('severity'))}｜CVSS {record.get('cvss_score') if record.get('cvss_score') is not None else '未明确'}",
                f"   关联依赖：{format_matched_dependencies(record) or format_component_version_ranges(record) or '未明确'}",
                f"   漏洞描述：{localized_vulnerability_description(record)}",
                f"   组件版本范围：{format_component_version_ranges(record) or '未明确'}",
                f"   修复版本：{join_card_values(record.get('fixed_versions') or []) or '未明确'}",
                f"   修复建议：{_record_fix_instruction(record)}",
                f"   参考链接：\n{indent_multiline(reference_links)}",
            ]
        )
    if len(records) > 8:
        lines.append(f"其余 {len(records) - 8} 条命中记录已纳入知识图谱，可继续按漏洞编号展开查看。")

    if findings:
        lines.append("")
        lines.append("代码漏洞明细：")
        for index, finding in enumerate(findings[:6], start=1):
            sink = finding.get("sink") or {}
            file_name = finding.get("file") or sink.get("file") or "未知文件"
            risk_line = finding.get("risk_line") or sink.get("line") or 0
            lines.append(f"{index}. {finding.get('title') or '静态分析发现'}｜{file_name}:{risk_line}｜关联依赖漏洞 {finding.get('record_id') or '未明确'}")
            lines.append(
                f"   风险代码：\n```text\n"
                f"{finding.get('vulnerable_snippet') or sink.get('snippet') or '未返回'}\n```"
            )
            lines.append(
                f"   修复后代码：\n```text\n"
                f"{finding.get('fixed_snippet') or '未生成可核验的修复代码'}\n```"
            )
            lines.append(f"   修复建议：{finding.get('remediation') or '校验外部输入并收敛危险调用。'}")
            lines.append(f"   CFG：{finding.get('cfg') or '未明确'}")
            lines.append(f"   DFG：{finding.get('dfg') or '未明确'}")
            for step in (finding.get("path") or [])[:6]:
                lines.append(
                    f"   - {step.get('kind') or 'step'}：{step.get('file') or '未知文件'}:{step.get('line') or 0}"
                    f"｜{step.get('label') or ''}"
                )
    return sanitize_public_text("\n".join(lines))


def build_dependency_chart_data(
    scan: dict[str, Any],
    records: list[dict[str, Any]],
    static_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    dependencies = [item for item in scan.get("dependencies") or [] if isinstance(item, dict)]
    files = [item for item in scan.get("files") or [] if isinstance(item, dict)]
    findings = [item for item in (static_analysis or {}).get("findings") or [] if isinstance(item, dict)]

    sankey_nodes: dict[str, dict[str, Any]] = {}
    sankey_links: dict[tuple[str, str, str], dict[str, Any]] = {}
    dag_nodes: dict[str, dict[str, Any]] = {}
    dag_edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_node(container: dict[str, dict[str, Any]], node_id: str, label: str, node_type: str, **extra: Any) -> None:
        if not node_id or node_id in container:
            return
        container[node_id] = {"id": node_id, "label": sanitize_public_text(label), "type": node_type, **extra}

    def add_link(
        container: dict[tuple[str, str, str], dict[str, Any]],
        from_id: str,
        to_id: str,
        edge_type: str,
        *,
        value: int = 1,
        severity: str = "UNKNOWN",
    ) -> None:
        if not from_id or not to_id or from_id == to_id:
            return
        key = (from_id, to_id, edge_type)
        if key in container:
            container[key]["value"] = int(container[key].get("value") or 0) + max(1, int(value))
            container[key]["severity"] = _stronger_chart_severity(container[key].get("severity"), severity)
        else:
            container[key] = {
                "from": from_id,
                "to": to_id,
                "type": edge_type,
                "value": max(1, int(value)),
                "severity": _normalize_chart_severity(severity),
            }

    file_ids: dict[str, str] = {}
    for file in files[:80]:
        file_name = str(file.get("file_name") or "").strip()
        if not file_name:
            continue
        node_id = f"file:{file_name}"
        file_ids[file_name] = node_id
        file_type = str(file.get("kind") or "file")
        add_node(sankey_nodes, node_id, _display_chart_file_name(file_name), file_type)
        add_node(dag_nodes, node_id, _display_chart_file_name(file_name), file_type, column=0)

    dependency_ids: dict[str, str] = {}
    dependency_name_index: dict[str, list[str]] = {}
    for dependency in dependencies[:80]:
        dep_key = _chart_dependency_key(dependency)
        if not dep_key:
            continue
        node_id = f"dependency:{dep_key}"
        dependency_ids[dep_key] = node_id
        dependency_name_index.setdefault(_chart_dependency_name_key(dependency), []).append(node_id)
        label = _chart_dependency_label(dependency)
        add_node(
            sankey_nodes,
            node_id,
            label,
            "dependency",
            version=str(dependency.get("version") or ""),
            ecosystem=str(dependency.get("ecosystem") or ""),
        )
        add_node(
            dag_nodes,
            node_id,
            label,
            "dependency",
            column=1,
            version=str(dependency.get("version") or ""),
            ecosystem=str(dependency.get("ecosystem") or ""),
        )
        file_id = file_ids.get(str(dependency.get("source_file") or "").strip())
        if file_id:
            add_link(sankey_links, file_id, node_id, "declares")
            add_link(dag_edges, file_id, node_id, "declares")

    record_hits_by_dependency: dict[str, int] = {}
    for record in records[:120]:
        record_id = str(record.get("id") or "").upper()
        if not record_id:
            continue
        severity = _normalize_chart_severity(record.get("severity"))
        vulnerability_id = f"vulnerability:{record_id}"
        add_node(sankey_nodes, vulnerability_id, record_id, "vulnerability", severity=severity)
        add_node(dag_nodes, vulnerability_id, record_id, "vulnerability", column=2, severity=severity)

        matched_dependency_ids = _matched_chart_dependency_node_ids(record, dependency_ids, dependency_name_index)
        for dependency_id in matched_dependency_ids:
            record_hits_by_dependency[dependency_id] = record_hits_by_dependency.get(dependency_id, 0) + 1
            add_link(sankey_links, dependency_id, vulnerability_id, "has_vulnerability", severity=severity)
            add_link(dag_edges, dependency_id, vulnerability_id, "has_vulnerability", severity=severity)

        fixed_versions = [str(item or "").strip() for item in record.get("fixed_versions") or [] if str(item or "").strip()]
        fixed_label = fixed_versions[0] if fixed_versions else "Not specified"
        fixed_id = f"fix:{record_id}:{fixed_label}"
        add_node(sankey_nodes, fixed_id, fixed_label, "fix")
        add_node(dag_nodes, fixed_id, fixed_label, "fix", column=3)
        add_link(
            sankey_links,
            vulnerability_id,
            fixed_id,
            "fixed_by",
            value=max(1, len(matched_dependency_ids)),
            severity=severity,
        )
        add_link(dag_edges, vulnerability_id, fixed_id, "fixed_by", severity=severity)

    for finding in findings[:60]:
        title = str(finding.get("title") or "Code finding").strip()
        file_name = str(finding.get("file") or (finding.get("sink") or {}).get("file") or "").strip()
        finding_id = f"finding:{file_name}:{finding.get('risk_line') or title}"
        add_node(dag_nodes, finding_id, sanitize_public_text(title), "code_finding", column=2, severity="CODE")
        if file_name:
            file_id = file_ids.get(file_name) or f"file:{file_name}"
            add_node(dag_nodes, file_id, _display_chart_file_name(file_name), "code", column=0)
            add_link(dag_edges, file_id, finding_id, "contains_code_risk", severity="CODE")

    severity_counts = {key: 0 for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]}
    for record in records:
        severity_counts[_normalize_chart_severity(record.get("severity"))] += 1
    if findings:
        severity_counts["CODE"] = len(findings)

    risk_bars = sorted(
        (
            {
                "id": dependency_id,
                "label": sankey_nodes.get(dependency_id, {}).get("label", dependency_id),
                "value": count,
            }
            for dependency_id, count in record_hits_by_dependency.items()
        ),
        key=lambda item: int(item["value"]),
        reverse=True,
    )[:10]

    return {
        "schema_version": 1,
        "sankey": {"nodes": list(sankey_nodes.values())[:220], "links": list(sankey_links.values())[:360]},
        "severity_ring": [{"key": key, "value": value} for key, value in severity_counts.items() if value > 0],
        "risk_bars": risk_bars,
        "dag": {"nodes": list(dag_nodes.values())[:220], "edges": list(dag_edges.values())[:360]},
    }


def _chart_dependency_key(dependency: dict[str, Any]) -> str:
    ecosystem = str(dependency.get("ecosystem") or "").strip().lower()
    name = str(dependency.get("name") or "").strip().lower()
    version = str(dependency.get("version") or "").strip().lower()
    return "|".join(part for part in [ecosystem, name, version] if part)


def _chart_dependency_name_key(dependency: dict[str, Any]) -> str:
    ecosystem = str(dependency.get("ecosystem") or "").strip().lower()
    name = str(dependency.get("name") or "").strip().lower()
    return f"{ecosystem}|{name}"


def _chart_dependency_label(dependency: dict[str, Any]) -> str:
    name = str(dependency.get("name") or "dependency").strip()
    artifact = name.split(":")[-1] if ":" in name else name
    version = str(dependency.get("version") or "").strip()
    return f"{artifact}@{version}" if version else artifact


def _display_chart_file_name(file_name: str) -> str:
    parts = [part for part in str(file_name or "").split("/") if part]
    if len(parts) <= 2:
        return "/".join(parts) or "file"
    return f"{parts[-2]}/{parts[-1]}"


def _matched_chart_dependency_node_ids(
    record: dict[str, Any],
    dependency_ids: dict[str, str],
    dependency_name_index: dict[str, list[str]],
) -> list[str]:
    matches: list[str] = []
    for dependency in record.get("matched_dependencies") or []:
        if not isinstance(dependency, dict):
            continue
        dep_key = _chart_dependency_key(dependency)
        if dep_key in dependency_ids:
            matches.append(dependency_ids[dep_key])
            continue
        matches.extend(dependency_name_index.get(_chart_dependency_name_key(dependency), []))
    for component in record.get("components") or []:
        if not isinstance(component, dict):
            continue
        lookup = f"{str(component.get('ecosystem') or '').strip().lower()}|{str(component.get('name') or '').strip().lower()}"
        matches.extend(dependency_name_index.get(lookup, []))
    return list(dict.fromkeys(matches))


def _normalize_chart_severity(value: Any) -> str:
    normalized = str(value or "UNKNOWN").strip().upper()
    if normalized in {"CRITICAL", "SEVERE", "严重"}:
        return "CRITICAL"
    if normalized in {"HIGH", "高危"}:
        return "HIGH"
    if normalized in {"MEDIUM", "MODERATE", "中危"}:
        return "MEDIUM"
    if normalized in {"LOW", "低危"}:
        return "LOW"
    if normalized == "CODE":
        return "CODE"
    return "UNKNOWN"


def _stronger_chart_severity(left: Any, right: Any) -> str:
    rank = {"CODE": 5, "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    left_key = _normalize_chart_severity(left)
    right_key = _normalize_chart_severity(right)
    return left_key if rank.get(left_key, 0) >= rank.get(right_key, 0) else right_key


def build_report_conclusion(
    dependency_vulnerability_count: int,
    code_vulnerability_count: int,
    unresolved_dependency_count: int = 0,
    language: str = "zh-Hans",
    *,
    has_dependency_scope: bool = True,
    has_code_scope: bool = True,
) -> str:
    normalized_language = normalize_response_language(language)
    if normalized_language == "ja":
        counts = []
        guidance = []
        if has_dependency_scope:
            counts.append(f"依存関係脆弱性 {dependency_vulnerability_count} 件")
            guidance.append("依存関係脆弱性はコンポーネントバージョン範囲に基づいてアップグレードまたは緩和してください。")
        if has_code_scope:
            counts.append(f"コード脆弱性 {code_vulnerability_count} 件")
            guidance.append("コード脆弱性はファイル、行番号、修正コードに従って修正し、回帰検証を実行してください。")
        conclusion = ("本分析では、" + "、".join(counts) + "を識別しました。" if counts else "分析可能な依存関係またはソースコードは確認できませんでした。")
        conclusion += "".join(guidance)
        if has_dependency_scope and unresolved_dependency_count:
            conclusion += f" さらに {unresolved_dependency_count} 個の依存関係はバージョン未指定のため命中に含まれておらず、安全性の証明にはなりません。"
        return conclusion
    if normalized_language == "ko":
        counts = []
        guidance = []
        if has_dependency_scope:
            counts.append(f"의존성 취약점 {dependency_vulnerability_count}건")
            guidance.append("의존성 취약점은 컴포넌트 버전 범위에 따라 업그레이드하거나 완화해야 합니다. ")
        if has_code_scope:
            counts.append(f"코드 취약점 {code_vulnerability_count}건")
            guidance.append("코드 취약점은 파일, 줄 번호, 수정 코드를 기준으로 수정하고 회귀 검증을 수행하세요.")
        conclusion = ("이번 분석에서 " + "과 ".join(counts) + "을 식별했습니다. " if counts else "분석 가능한 의존성 또는 소스 코드를 확인하지 못했습니다. ")
        conclusion += "".join(guidance)
        if has_dependency_scope and unresolved_dependency_count:
            conclusion += f" 또한 {unresolved_dependency_count}개 의존성은 버전이 명확하지 않아 명중에 포함되지 않았으므로 안전하다는 증거로 볼 수 없습니다."
        return conclusion
    if normalized_language == "en":
        counts = []
        guidance = []
        if has_dependency_scope:
            counts.append(f"{dependency_vulnerability_count} dependency vulnerabilities")
            guidance.append("Dependency vulnerabilities should be upgraded or mitigated according to component version ranges. ")
        if has_code_scope:
            counts.append(f"{code_vulnerability_count} code findings")
            guidance.append("Code findings should be remediated using the file, line, and fixed-code guidance, followed by regression validation.")
        conclusion = ("This analysis identified " + " and ".join(counts) + ". " if counts else "No analyzable dependency or source-code scope was identified. ")
        conclusion += "".join(guidance)
        if has_dependency_scope and unresolved_dependency_count:
            conclusion += (
                f" {unresolved_dependency_count} dependencies have unspecified versions and were not counted as hits; "
                "the result must not be treated as proof of safety."
            )
        return conclusion
    counts = []
    guidance = []
    if has_dependency_scope:
        counts.append(f"{dependency_vulnerability_count} 条依赖漏洞")
        guidance.append("依赖漏洞应按组件版本范围完成升级或缓释。")
    if has_code_scope:
        counts.append(f"{code_vulnerability_count} 条代码漏洞")
        guidance.append("代码漏洞应按报告给出的文件、行号和修复代码逐项整改，并执行回归验证。")
    conclusion = ("本次共识别：" + "，".join(counts) + "。" if counts else "本次未识别到可分析的依赖或源码范围。")
    conclusion += "".join(guidance)
    if has_dependency_scope and unresolved_dependency_count:
        conclusion += (
            f"另有 {unresolved_dependency_count} 个依赖版本未明确，未计入漏洞命中；"
            "当前结果不能据此判定为安全。"
        )
    return conclusion


def format_dependency_scan_context(scan: dict[str, Any], records: list[dict[str, Any]]) -> str:
    dependencies = scan.get("dependencies") or []
    files = scan.get("files") or []
    lines = [
        "附件依赖扫描事实：",
        f"- 文件数量: {len(files)}",
        f"- 依赖数量: {len(dependencies)}",
        f"- 命中漏洞数量: {len(records)}",
    ]
    for dependency in dependencies[:20]:
        lines.append(f"- 依赖: {format_dependency_label(dependency)}")
    return "\n".join(lines)


def format_static_analysis_context(static_analysis: dict[str, Any]) -> str:
    findings = static_analysis.get("findings") or []
    if not findings:
        return ""
    lines = [
        "静态代码路径分析事实：",
        f"- 路径数量: {len(findings)}",
    ]
    for finding in findings[:8]:
        lines.append(
            f"- {finding.get('title') or '静态分析发现'} | 漏洞 {finding.get('record_id') or '未明确'} | "
            f"CFG: {finding.get('cfg') or '未明确'} | DFG: {finding.get('dfg') or '未明确'}"
        )
        for step in (finding.get("path") or [])[:5]:
            lines.append(
                f"  - {step.get('kind') or 'step'} {step.get('file') or '未知文件'}:{step.get('line') or 0} "
                f"{step.get('label') or ''}"
            )
    return "\n".join(lines)


def format_dependency_label(dependency: dict[str, Any], language: str = "zh-Hans") -> str:
    ecosystem = str(dependency.get("ecosystem") or "").strip()
    name = str(dependency.get("name") or "").strip()
    version = str(dependency.get("version") or "").strip()
    source_file = str(dependency.get("source_file") or "").strip()
    confidence = str(dependency.get("confidence") or "").strip()
    version_text = f" @ {version}" if version else f" @ {tr(language, 'not_specified') if normalize_response_language(language) != 'zh-Hans' else '版本未明确'}"
    source_text = f"（{source_file}）" if source_file else ""
    confidence_label = "confidence" if normalize_response_language(language) != "zh-Hans" else "置信度"
    confidence_text = f" · {confidence_label} {confidence}" if confidence else ""
    return f"{ecosystem} / {name}{version_text}{source_text}{confidence_text}"


def format_matched_dependencies(record: dict[str, Any], language: str = "zh-Hans") -> str:
    dependencies = record.get("matched_dependencies") or []
    if not isinstance(dependencies, list):
        return ""
    separator = "；" if normalize_response_language(language) == "zh-Hans" else "; "
    return separator.join(format_dependency_label(item, language) for item in dependencies if isinstance(item, dict))


def _record_fix_instruction(record: dict[str, Any], language: str = "zh-Hans") -> str:
    fixed = join_card_values(record.get("fixed_versions") or [], language)
    if normalize_response_language(language) != "zh-Hans":
        if fixed:
            if "修复提交" in fixed:
                return tr(language, "use_confirmed_commit") % fixed
            return tr(language, "upgrade_fixed_version") % fixed
        return tr(language, "fix_unset_version")
    if fixed:
        if "修复提交" in fixed:
            return f"采用已确认的{fixed}，并完成工作流与业务回归验证。"
        return f"升级到已确认的修复版本：{fixed}，并完成兼容性与回归验证。"
    return "当前漏洞记录未明确修复版本；请先核验受影响版本，优先采用官方确认的安全版本或临时缓释措施。"


def indent_multiline(value: Any, prefix: str = "     ") -> str:
    text = str(value or "").strip() or "未明确"
    return "\n".join(prefix + line for line in text.splitlines())


def format_record_context(record: dict[str, Any]) -> str:
    return (
        f"- 漏洞编号: {record.get('id')} | 严重等级: {severity_cn(record.get('severity'))} | "
        f"CVSS: {record.get('cvss_score') if record.get('cvss_score') is not None else '未明确'} | "
        f"漏洞描述: {record.get('summary') or record.get('title') or ''} | "
        f"组件版本范围: {format_component_version_ranges(record) or '未明确'} | "
        f"涉及版本: {'；'.join(record.get('affected_versions') or []) or '未明确'} | "
        f"修复版本: {'；'.join(record.get('fixed_versions') or []) or '未明确'}"
    )


def format_component_version_ranges(record: dict[str, Any], language: str = "zh-Hans") -> str:
    rows: list[str] = []
    for component in record.get("components") or []:
        if not isinstance(component, dict):
            continue
        name = str(component.get("name") or "").strip()
        ecosystem = str(component.get("ecosystem") or "").strip()
        if not name:
            continue
        affected = join_card_values(component.get("affected") or [], language)
        fixed = join_card_values(component.get("fixed") or [], language)
        label = f"{ecosystem} / {name}" if ecosystem else name
        details = []
        if affected:
            details.append((tr(language, "impact") % affected) if normalize_response_language(language) != "zh-Hans" else f"影响 {affected}")
        if fixed:
            details.append((tr(language, "fixed") % fixed) if normalize_response_language(language) != "zh-Hans" else f"修复 {fixed}")
        separator = "；" if normalize_response_language(language) == "zh-Hans" else "; "
        rows.append(f"{label}: {separator.join(details) if details else (tr(language, 'range_unknown') if normalize_response_language(language) != 'zh-Hans' else '版本范围未明确')}")
        if len(rows) >= 8:
            break

    if rows:
        return "\n".join(rows)

    affected_versions = join_card_values(record.get("affected_versions") or [], language)
    fixed_versions = join_card_values(record.get("fixed_versions") or [], language)
    fallback_parts = []
    if affected_versions:
        fallback_parts.append((tr(language, "impact") % affected_versions) if normalize_response_language(language) != "zh-Hans" else f"影响 {affected_versions}")
    if affected_versions and fixed_versions:
        fallback_parts.append((tr(language, "fixed") % fixed_versions) if normalize_response_language(language) != "zh-Hans" else f"修复 {fixed_versions}")
    return ("；" if normalize_response_language(language) == "zh-Hans" else "; ").join(fallback_parts)


def join_card_values(values: Any, language: str = "zh-Hans") -> str:
    if not isinstance(values, list):
        values = [values]
    separator = "；" if normalize_response_language(language) == "zh-Hans" else "; "
    return separator.join(str(value).strip() for value in values if str(value).strip())


def select_vulnerable_code_snippet(record: dict[str, Any], language: str = "zh-Hans") -> str:
    snippets = record.get("code_snippets") or []
    if not isinstance(snippets, list):
        snippets = [snippets]
    for snippet in snippets:
        value = str(snippet or "").strip()
        if value:
            return value
    return tr(language, "no_verified_code") if normalize_response_language(language) != "zh-Hans" else "未在漏洞记录中找到可核验代码片段"


def select_fixed_code_snippet(record: dict[str, Any], language: str = "zh-Hans") -> str:
    snippets = record.get("fixed_code_snippets") or []
    if not isinstance(snippets, list):
        snippets = [snippets]
    for snippet in snippets:
        value = str(snippet or "").strip()
        if value:
            return value
    return tr(language, "no_verified_fix_code") if normalize_response_language(language) != "zh-Hans" else "未在漏洞记录中找到可核验修复代码片段"


def select_reference_links(record: dict[str, Any], limit: int = 6, language: str = "zh-Hans") -> str:
    raw_values = [*list_values(record.get("reference_links")), *list_values(record.get("references"))]
    links: list[str] = []
    for value in raw_values:
        for match in re.findall(r"https?://[^\s,，；;）)]+", str(value or "")):
            links.append(match.rstrip("。.,，；;"))
    unique: list[str] = []
    seen: set[str] = set()
    for link in links:
        if link and link not in seen:
            unique.append(link)
            seen.add(link)
        if len(unique) >= limit:
            break
    return "\n".join(unique) if unique else (tr(language, "not_specified") if normalize_response_language(language) != "zh-Hans" else "未明确")


def list_values(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def record_for_card_prompt(
    record: dict[str, Any],
    language: str = "zh-Hans",
    *,
    user_id: str = "default",
) -> dict[str, Any]:
    return {
        "id": record.get("id") or "",
        "title": record.get("title") or "",
        "description": localized_vulnerability_description(record, language, user_id=user_id),
        "cvss_score": record.get("cvss_score"),
        "severity": severity_label_for_language(record.get("severity"), language),
        "affected_versions": record.get("affected_versions") or [],
        "fixed_versions": record.get("fixed_versions") or [],
        "components": record.get("components") or [],
        "component_version_ranges": format_component_version_ranges(record, language),
        "code_snippets": record.get("code_snippets") or [],
        "vulnerable_code_snippet": select_vulnerable_code_snippet(record, language),
        "fixed_code_snippets": record.get("fixed_code_snippets") or [],
        "fixed_code_snippet": select_fixed_code_snippet(record, language),
        "reference_links": record.get("reference_links") or [],
        "reference_links_text": select_reference_links(record, language=language),
    }


def build_vulnerability_card(
    record: dict[str, Any],
    language: str = "zh-Hans",
    *,
    user_id: str = "default",
) -> dict[str, Any]:
    facts = record_for_card_prompt(record, language, user_id=user_id)
    missing = tr(language, "not_specified") if normalize_response_language(language) != "zh-Hans" else "未明确"
    separator = "；" if normalize_response_language(language) == "zh-Hans" else "; "
    affected = separator.join(str(value) for value in facts["affected_versions"] if value) or missing
    fixed = separator.join(str(value) for value in facts["fixed_versions"] if value) or missing
    component_ranges = str(facts.get("component_version_ranges") or "").strip() or affected
    if fixed != missing and "修复提交" in fixed:
        fixed_instruction = (tr(language, "use_confirmed_commit") % fixed) if normalize_response_language(language) != "zh-Hans" else f"采用已确认的{fixed}，并在测试环境完成工作流与业务回归验证。"
    elif fixed != missing:
        fixed_instruction = (tr(language, "upgrade_fixed_version") % fixed) if normalize_response_language(language) != "zh-Hans" else f"升级到已确认的修复版本：{fixed}，并在测试环境完成兼容性与回归验证。"
    else:
        fixed_instruction = tr(language, "fix_unset_version") if normalize_response_language(language) != "zh-Hans" else "当前知识记录未明确给出修复版本；请完成资产版本核验并采用厂商确认的首个安全版本，禁止猜测版本号。"
    return {
        "漏洞编号": facts["id"] or missing,
        "漏洞名称": facts["title"] or facts["id"] or missing,
        "漏洞描述": facts["description"] or (tr(language, "no_verified_description") if normalize_response_language(language) != "zh-Hans" else "暂无可核验的漏洞描述。"),
        "CVSS评分": facts["cvss_score"] if facts["cvss_score"] is not None else missing,
        "严重等级": facts["severity"],
        "组件版本范围": component_ranges,
        "涉及版本": affected,
        "修复版本": fixed,
        "修复方案": fixed_instruction,
        "缓释措施": tr(language, "fix_limit_exposure") if normalize_response_language(language) != "zh-Hans" else "修复完成前限制受影响组件的网络暴露和访问权限，启用异常行为监控，并对高风险入口实施临时阻断。",
        "代码片段": facts["vulnerable_code_snippet"],
        "修复代码片段": facts["fixed_code_snippet"],
        "参考链接": facts["reference_links_text"],
    }


def localized_vulnerability_description(
    record: dict[str, Any],
    language: str = "zh-Hans",
    *,
    user_id: str = "default",
) -> str:
    language = normalize_response_language(language)
    original = str(record.get("summary_original") or record.get("summary") or "").strip()
    simplified = str(record.get("summary_zh") or "").strip()
    traditional = str(record.get("summary_zh_hant") or "").strip()
    if language == "en" and original and not _contains_cjk(original):
        return sanitize_public_text(original)
    if language == "zh-Hans" and simplified and _contains_cjk(simplified):
        return sanitize_public_text(simplified)
    if language == "zh-Hant" and traditional and _contains_cjk(traditional):
        return sanitize_public_text(traditional)
    source = simplified if language == "zh-Hant" and simplified else original
    translated = _translate_card_description(source, language, user_id=user_id) if source else ""
    if translated:
        return translated
    return _fallback_card_description(record, language)


def _translate_card_description(
    summary: str,
    language: str = "zh-Hans",
    *,
    user_id: str = "default",
) -> str:
    source = str(summary or "").strip()
    if not source:
        return ""
    try:
        result = translation_agent.translate_json(
            {"description": source},
            target_language=language,
            user_id=user_id,
            session_id="vulnerability-card",
            content_scope="vulnerability_description",
        )
    except Exception:  # noqa: BLE001 - preserve verified facts with a local fallback.
        return ""
    if result.audit.get("status") != "completed" or int(result.audit.get("unresolved_fields") or 0):
        return ""
    translated = sanitize_public_text(str(result.payload.get("description") or "").strip())
    if normalize_response_language(language) in {"zh-Hans", "zh-Hant"} and not _contains_cjk(translated):
        return ""
    return translated


def _fallback_card_description(record: dict[str, Any], language: str = "zh-Hans") -> str:
    language = normalize_response_language(language)
    if language == "ja":
        record_id = str(record.get("id") or "この脆弱性").strip() or "この脆弱性"
        severity = severity_label_for_language(record.get("severity", "UNKNOWN"), language)
        score = record.get("cvss_score")
        score_text = f"CVSS スコアは {score} です。" if score is not None else f"CVSS スコアは {tr(language, 'not_specified')}です。"
        component_ranges = format_component_version_ranges(record, language)
        affected = join_card_values(record.get("affected_versions") or [], language)
        fixed = join_card_values(record.get("fixed_versions") or [], language)
        if component_ranges and component_ranges != tr(language, "not_specified"):
            affected_text = f"既知の影響範囲：{component_ranges}。"
        elif affected:
            affected_text = f"既知の影響バージョン：{affected}。"
        else:
            affected_text = "資産台帳に基づき、影響を受けるコンポーネント、バージョン、露出面を確認してください。"
        if fixed and "修復提交" in fixed:
            fixed_text = f"確認済みの修正コミット {fixed} を適用してください。"
        elif fixed:
            fixed_text = f"確認済みの修正バージョン {fixed} へアップグレードしてください。"
        else:
            fixed_text = "修正バージョンは明記されていません。露出を減らし、パッチを継続追跡してください。"
        return sanitize_public_text(f"{record_id} は {severity} の脆弱性です。{score_text}{affected_text}{fixed_text}")
    if language == "ko":
        record_id = str(record.get("id") or "이 취약점").strip() or "이 취약점"
        severity = severity_label_for_language(record.get("severity", "UNKNOWN"), language)
        score = record.get("cvss_score")
        score_text = f"CVSS 점수는 {score}입니다. " if score is not None else f"CVSS 점수는 {tr(language, 'not_specified')}입니다. "
        component_ranges = format_component_version_ranges(record, language)
        affected = join_card_values(record.get("affected_versions") or [], language)
        fixed = join_card_values(record.get("fixed_versions") or [], language)
        if component_ranges and component_ranges != tr(language, "not_specified"):
            affected_text = f"알려진 영향 범위: {component_ranges}. "
        elif affected:
            affected_text = f"알려진 영향 버전: {affected}. "
        else:
            affected_text = "자산 목록을 기준으로 영향받는 컴포넌트, 버전, 노출면을 확인하세요. "
        if fixed and "修復提交" in fixed:
            fixed_text = f"확인된 수정 커밋 {fixed}을 적용하세요. "
        elif fixed:
            fixed_text = f"확인된 수정 버전 {fixed}으로 업그레이드하세요. "
        else:
            fixed_text = "수정 버전이 명시되지 않았습니다. 노출을 줄이고 패치를 계속 추적하세요. "
        return sanitize_public_text(f"{record_id}은(는) {severity} 취약점입니다. {score_text}{affected_text}{fixed_text}")
    if language == "en":
        record_id = str(record.get("id") or "This vulnerability").strip() or "This vulnerability"
        severity = severity_label_for_language(record.get("severity", "UNKNOWN"), language)
        score = record.get("cvss_score")
        score_text = f"CVSS score is {score}. " if score is not None else f"CVSS score is {tr(language, 'not_specified')}. "
        component_ranges = format_component_version_ranges(record, language)
        affected = join_card_values(record.get("affected_versions") or [], language)
        fixed = join_card_values(record.get("fixed_versions") or [], language)
        if component_ranges and component_ranges != tr(language, "not_specified"):
            affected_text = f"Known affected range: {component_ranges}. "
        elif affected:
            affected_text = f"Known affected versions: {affected}. "
        else:
            affected_text = "Verify affected components, versions, and exposure against the asset inventory. "
        if fixed and "修复提交" in fixed:
            fixed_text = f"Use the confirmed fix commit {fixed}. "
        elif fixed:
            fixed_text = f"Upgrade to the confirmed fixed version: {fixed}. "
        else:
            fixed_text = "No fixed version is specified; reduce exposure and continue tracking patches. "
        return sanitize_public_text(f"{record_id} is a {severity} vulnerability. {score_text}{affected_text}{fixed_text}")

    record_id = str(record.get("id") or "该漏洞").strip() or "该漏洞"
    severity = severity_cn(record.get("severity", "UNKNOWN"))
    score = record.get("cvss_score")
    score_text = f"CVSS 评分为 {score}。" if score is not None else "CVSS 评分未明确。"
    component_ranges = format_component_version_ranges(record)
    affected = join_card_values(record.get("affected_versions") or [])
    fixed = join_card_values(record.get("fixed_versions") or [])
    if component_ranges and component_ranges != "未明确":
        affected_text = f"已知影响范围包括：{component_ranges}。"
    elif affected:
        affected_text = f"已知影响版本包括：{affected}。"
    else:
        affected_text = "请结合资产清单核查受影响组件、版本和暴露面。"
    if fixed and "修复提交" in fixed:
        fixed_text = f"建议采用已确认的{fixed}。"
    elif fixed:
        fixed_text = f"建议升级到已确认的修复版本：{fixed}。"
    else:
        fixed_text = "当前记录未明确修复版本，应优先收敛暴露面并持续跟进补丁。"
    return sanitize_public_text(f"{record_id} 是一个{severity}漏洞。{score_text}{affected_text}{fixed_text}")


def _contains_cjk(text: Any) -> bool:
    return bool(re.search(r"[\u3400-\u9fff]", str(text or "")))


def build_empty_vulnerability_card(vulnerability_id: str, language: str = "zh-Hans") -> dict[str, Any]:
    language = normalize_response_language(language)
    if language != "zh-Hans":
        missing = tr(language, "not_specified")
        messages = {
            "en": {
                "name": "No verifiable vulnerability record found",
                "description": "There are not enough verified facts in the current security knowledge to generate a reliable conclusion.",
                "fix": "Verify the vulnerability ID and asset versions first, then plan an upgrade based on the confirmed safe version.",
                "mitigation": "Reduce the related component exposure and strengthen access monitoring until fact verification is complete.",
            },
            "ja": {
                "name": "検証可能な脆弱性レコードが見つかりません",
                "description": "現在のセキュリティ知識には、信頼できる結論を生成するための検証済み事実が不足しています。",
                "fix": "まず脆弱性番号と資産バージョンを確認し、確認済みの安全バージョンに基づいてアップグレード計画を立ててください。",
                "mitigation": "事実確認が完了するまで、関連コンポーネントの露出を減らし、アクセス監視を強化してください。",
            },
            "ko": {
                "name": "검증 가능한 취약점 기록을 찾지 못했습니다",
                "description": "현재 보안 지식에는 신뢰할 수 있는 결론을 생성하기 위한 검증된 사실이 충분하지 않습니다.",
                "fix": "먼저 취약점 번호와 자산 버전을 확인한 뒤, 확인된 안전 버전을 기준으로 업그레이드 계획을 세우세요.",
                "mitigation": "사실 확인이 완료될 때까지 관련 컴포넌트 노출을 줄이고 접근 모니터링을 강화하세요.",
            },
        }[language]
        return {
            "漏洞编号": vulnerability_id or missing,
            "漏洞名称": messages["name"],
            "漏洞描述": messages["description"],
            "CVSS评分": missing,
            "严重等级": tr(language, "unknown"),
            "组件版本范围": missing,
            "涉及版本": missing,
            "修复版本": missing,
            "修复方案": messages["fix"],
            "缓释措施": messages["mitigation"],
            "代码片段": tr(language, "no_verified_code"),
            "修复代码片段": tr(language, "no_verified_fix_code"),
            "参考链接": missing,
        }
    return {
        "漏洞编号": vulnerability_id or "未明确",
        "漏洞名称": "未找到可核验的漏洞记录",
        "漏洞描述": "当前安全知识中没有足够事实生成可靠结论。",
        "CVSS评分": "未明确",
        "严重等级": "未知",
        "组件版本范围": "未明确",
        "涉及版本": "未明确",
        "修复版本": "未明确",
        "修复方案": "请先核验漏洞编号及资产版本，再根据确认后的安全版本制定升级计划。",
        "缓释措施": "在事实核验完成前收敛相关组件暴露面并加强访问监控。",
        "代码片段": "未在漏洞记录中找到可核验代码片段",
        "修复代码片段": "未在漏洞记录中找到可核验修复代码片段",
        "参考链接": "未明确",
    }


def parse_json_object(text: str) -> dict[str, Any]:
    value = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", value, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        value = fenced.group(1)
    else:
        match = re.search(r"\{.*\}", value, flags=re.DOTALL)
        value = match.group(0) if match else ""
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def merge_translated_card(parsed: dict[str, Any], fallback: dict[str, Any], record: dict[str, Any], language: str = "zh-Hans") -> dict[str, Any]:
    keys = tuple(fallback)
    merged = {key: parsed.get(key) or fallback[key] for key in keys}

    # Fact fields are authoritative and may not be invented by the model.
    merged["漏洞编号"] = fallback["漏洞编号"]
    merged["CVSS评分"] = fallback["CVSS评分"]
    merged["严重等级"] = fallback["严重等级"]
    if _looks_truncated(merged.get("漏洞描述")):
        merged["漏洞描述"] = fallback["漏洞描述"]
    merged["组件版本范围"] = fallback["组件版本范围"]
    merged["涉及版本"] = fallback["涉及版本"]
    merged["修复版本"] = fallback["修复版本"]
    # Keep code snippets deterministic and defensive. Do not let the model
    # introduce exploit payloads or unverified remediation commands.
    merged["代码片段"] = fallback["代码片段"]
    merged["修复代码片段"] = fallback["修复代码片段"]
    merged["参考链接"] = fallback["参考链接"]
    if not record.get("fixed_versions"):
        merged["修复版本"] = tr(language, "not_specified") if normalize_response_language(language) != "zh-Hans" else "未明确"
    return {key: sanitize_card_value(key, merged[key]) for key in keys}


def sanitize_card_value(key: str, value: Any) -> str:
    if key == "参考链接":
        return select_reference_links({"reference_links": str(value).splitlines()})
    return sanitize_public_text(value)


def _looks_truncated(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    return text.endswith(("...", "…")) or bool(re.search(r"\.\.\.\s*(?:$|[，。,；;])", text))


def build_card_summary(card: dict[str, Any], language: str = "zh-Hans") -> str:
    if normalize_response_language(language) != "zh-Hans":
        labels = {
            "en": {
                "漏洞编号": "Vulnerability ID",
                "漏洞名称": "Name",
                "漏洞描述": "Description",
                "CVSS评分": "CVSS score",
                "严重等级": "Severity",
                "组件版本范围": "Component version range",
                "涉及版本": "Affected versions",
                "修复版本": "Fixed versions",
                "修复方案": "Remediation",
                "缓释措施": "Mitigation",
                "代码片段": "Code snippet",
                "修复代码片段": "Fixed code snippet",
                "参考链接": "References",
            },
            "ja": {
                "漏洞编号": "脆弱性 ID",
                "漏洞名称": "名称",
                "漏洞描述": "説明",
                "CVSS评分": "CVSS スコア",
                "严重等级": "深刻度",
                "组件版本范围": "コンポーネントバージョン範囲",
                "涉及版本": "影響バージョン",
                "修复版本": "修正バージョン",
                "修复方案": "修正方法",
                "缓释措施": "緩和策",
                "代码片段": "コード片",
                "修复代码片段": "修正コード片",
                "参考链接": "参考リンク",
            },
            "ko": {
                "漏洞编号": "취약점 ID",
                "漏洞名称": "이름",
                "漏洞描述": "설명",
                "CVSS评分": "CVSS 점수",
                "严重等级": "심각도",
                "组件版本范围": "컴포넌트 버전 범위",
                "涉及版本": "영향 버전",
                "修复版本": "수정 버전",
                "修复方案": "수정 방법",
                "缓释措施": "완화 조치",
                "代码片段": "코드 조각",
                "修复代码片段": "수정 코드 조각",
                "参考链接": "참고 링크",
            },
        }.get(normalize_response_language(language), {})
        return "\n".join(
            f"{labels.get(key, key)}: {card.get(key, '')}"
            for key in (
                "漏洞编号",
                "漏洞名称",
                "漏洞描述",
                "CVSS评分",
                "严重等级",
                "组件版本范围",
                "涉及版本",
                "修复版本",
                "修复方案",
                "缓释措施",
                "代码片段",
                "修复代码片段",
                "参考链接",
            )
            if card.get(key) not in {None, ""}
        )
    return "\n".join(
        f"{key}：{card.get(key, '')}"
        for key in (
            "漏洞编号",
            "漏洞名称",
            "漏洞描述",
            "CVSS评分",
            "严重等级",
            "组件版本范围",
            "涉及版本",
            "修复版本",
            "修复方案",
            "缓释措施",
            "代码片段",
            "修复代码片段",
            "参考链接",
        )
        if card.get(key) not in {None, ""}
    )


def build_task_scan_follow_up_answer(task_context: dict[str, Any], language: str = "zh-Hans") -> str:
    findings = [item for item in task_context.get("findings") or [] if isinstance(item, dict)]
    normalized_language = normalize_response_language(language)
    if not findings:
        if normalized_language == "zh-Hans":
            return "当前扫描任务没有保存可引用的结构化 finding，因此无法提供与项目代码对应的修复代码或验证结论。请先确认扫描已完成并产生结果。"
        return "The scan task has no persisted structured findings, so project-specific fix code or validation conclusions cannot be provided. Confirm that the scan completed with findings first."

    task_id = str(task_context.get("task_id") or "").strip()
    run_number = max(1, int(task_context.get("run_number") or 1))
    visible_findings = findings[:20]
    if normalized_language == "zh-Hans":
        lines = [
            "## 扫描证据结论",
            "",
            f"以下内容来自任务 `{task_id or '未提供任务编号'}` 第 {run_number} 轮保存的 {len(findings)} 条结构化 finding。",
        ]
    else:
        lines = [
            "## Scan Evidence",
            "",
            f"The following guidance uses {len(findings)} persisted structured findings from task `{task_id or 'unknown'}`, run {run_number}.",
        ]

    diff_counts = ((task_context.get("result_diff") or {}).get("counts") or {})
    if diff_counts:
        if normalized_language == "zh-Hans":
            lines.extend(
                [
                    "",
                    "重扫差异："
                    f"新增 {int(diff_counts.get('new') or 0)}、"
                    f"已修复 {int(diff_counts.get('resolved') or 0)}、"
                    f"未变化 {int(diff_counts.get('unchanged') or 0)}、"
                    f"证据变化 {int(diff_counts.get('changed') or 0)}。",
                ]
            )
        else:
            lines.extend(
                [
                    "",
                    "Rescan diff: "
                    f"{int(diff_counts.get('new') or 0)} new, "
                    f"{int(diff_counts.get('resolved') or 0)} resolved, "
                    f"{int(diff_counts.get('unchanged') or 0)} unchanged, and "
                    f"{int(diff_counts.get('changed') or 0)} changed.",
                ]
            )

    for index, finding in enumerate(visible_findings, start=1):
        title = _task_evidence_text(finding.get("title") or finding.get("message") or f"Finding {index}")
        severity = severity_label_for_language(finding.get("severity"), language)
        path = _task_evidence_text(finding.get("path") or finding.get("file_name") or "")
        line = finding.get("line") or ((finding.get("location") or {}).get("line_start") if isinstance(finding.get("location"), dict) else None)
        location = f"{path}:{line}" if path and line else path or ("未提供" if normalized_language == "zh-Hans" else "not provided")
        description = _task_evidence_text(finding.get("message") or finding.get("description") or "")
        rule_id = _task_evidence_text(finding.get("rule_id") or "")
        snippet = _task_evidence_text(finding.get("vulnerable_snippet") or "")
        remediation = _task_evidence_text(finding.get("remediation") or "")
        fixed_snippet = _task_evidence_text(finding.get("fixed_snippet") or "")
        source = _task_evidence_text(finding.get("source"))
        sink = _task_evidence_text(finding.get("sink"))
        taint_path = _task_evidence_text(finding.get("taint_path"))
        verification = _task_evidence_lines(finding.get("verification_steps"))

        lines.extend(["", f"### {index}. {title}", ""])
        if normalized_language == "zh-Hans":
            lines.extend([f"- 严重等级：{severity}", f"- 位置：`{_markdown_inline(location)}`"])
            if rule_id:
                lines.append(f"- 规则：`{_markdown_inline(rule_id)}`")
            if description:
                lines.extend(["", "#### 风险说明", "", description])
            if source or sink or taint_path:
                lines.extend(["", "#### 数据流证据", ""])
                if source:
                    lines.append(f"- Source：{source}")
                if sink:
                    lines.append(f"- Sink：{sink}")
                if taint_path:
                    lines.append(f"- 污点路径：{taint_path}")
            lines.extend(["", "#### 证据代码", ""])
            lines.append(_markdown_code_block(snippet, path) if snippet else "任务证据中没有可核验代码片段。")
            lines.extend(["", "#### 修复方案", ""])
            lines.append(remediation or "任务证据中没有专用修复方案；需要人工结合该路径的输入约束、权限边界和业务用途制定修改。")
            lines.extend(["", "#### 修复代码", ""])
            lines.append(
                _markdown_code_block(fixed_snippet, path)
                if fixed_snippet
                else "任务证据中没有可核验修复代码，因此不生成可能与项目不符的代码。"
            )
            lines.extend(["", "#### 验证方法", ""])
            if verification:
                lines.extend(f"{step_index}. {step}" for step_index, step in enumerate(verification, start=1))
            else:
                lines.extend(
                    [
                        "1. 为该输入路径补充正向、边界和恶意输入测试，确认危险 Sink 不再接收未经约束的数据。",
                        "2. 执行受影响模块的单元测试与集成回归，确认修复没有改变正常业务行为。",
                        "3. 使用相同项目、规则集和分析引擎重新扫描；该 finding 应进入 `resolved`，不能只依赖规则抑制。",
                        "4. 人工复核 Source 到 Sink 的调用链以及运行时权限，确认不存在等价旁路。",
                    ]
                )
        else:
            lines.extend([f"- Severity: {severity}", f"- Location: `{_markdown_inline(location)}`"])
            if rule_id:
                lines.append(f"- Rule: `{_markdown_inline(rule_id)}`")
            if description:
                lines.extend(["", "#### Risk", "", description])
            lines.extend(["", "#### Evidence", "", _markdown_code_block(snippet, path) if snippet else "No verified code snippet is present in the task evidence."])
            lines.extend(["", "#### Remediation", "", remediation or "No finding-specific remediation is present; review input constraints, authorization boundaries, and the business use of this code path."])
            lines.extend(["", "#### Fix Code", "", _markdown_code_block(fixed_snippet, path) if fixed_snippet else "No verified fix snippet is present, so project-specific code is not fabricated."])
            lines.extend(["", "#### Verification", ""])
            lines.extend(
                f"{step_index}. {step}"
                for step_index, step in enumerate(
                    verification
                    or [
                        "Add positive, boundary, and hostile-input tests for this path.",
                        "Run unit and integration regression tests for the affected module.",
                        "Rescan with the same project, ruleset, and engine; the finding should move to `resolved`.",
                        "Manually review the source-to-sink path and runtime privileges for equivalent bypasses.",
                    ],
                    start=1,
                )
            )

    if len(findings) > len(visible_findings) or task_context.get("finding_context_truncated"):
        remaining = max(0, len(findings) - len(visible_findings))
        if normalized_language == "zh-Hans":
            lines.extend(["", f"当前回答仅展开前 {len(visible_findings)} 条 finding；另有 {remaining} 条或更多证据需要按任务结果继续分页查看。"])
        else:
            lines.extend(["", f"This answer expands the first {len(visible_findings)} findings; {remaining} or more remain available in the task results."])
    return "\n".join(lines).strip()


def _task_evidence_text(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).strip()


def _task_evidence_lines(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [text for item in value if (text := _task_evidence_text(item))]
    text = _task_evidence_text(value)
    return [line.strip(" -") for line in text.splitlines() if line.strip(" -")] if text else []


def _markdown_inline(value: str) -> str:
    return str(value or "").replace("`", "'")


def _markdown_code_block(value: str, path: str = "") -> str:
    clean = str(value or "").rstrip()
    suffix = Path(str(path or "")).suffix.lower()
    language = {
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cs": "csharp",
        ".go": "go",
        ".java": "java",
        ".js": "javascript",
        ".kt": "kotlin",
        ".php": "php",
        ".py": "python",
        ".rb": "ruby",
        ".rs": "rust",
        ".sol": "solidity",
        ".swift": "swift",
        ".ts": "typescript",
    }.get(suffix, "text")
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", clean)), default=0)
    fence = "`" * max(3, longest_run + 1)
    return f"{fence}{language}\n{clean}\n{fence}"


def fallback_answer(state: AssistantState, language: str = "zh-Hans") -> str:
    question = state.get("question", "")
    lowered = question.lower()
    normalized_language = normalize_response_language(language)
    model_notice = _public_model_failure_notice(state.get("llm_error"), language)
    if state.get("intent") == "clarification":
        return tr(language, "clarification") if normalized_language != "zh-Hans" else "请输入需要分析的具体安全问题，例如漏洞编号、组件名称、代码风险或修复建议。"
    if state.get("intent") == "dependency_vulnerability_report":
        return build_dependency_vulnerability_answer(state.get("records", []), state.get("dependency_scan", {}), language=language)
    if state.get("intent") == "vulnerability_year_lookup":
        years = "、".join(str(year) for year in state.get("year_filter", [])) or "指定年份"
        if normalized_language != "zh-Hans":
            years = ", ".join(str(year) for year in state.get("year_filter", [])) or "the selected years"
            return tr(language, "year_no_facts") % years
        return (
            f"当前没有足够事实完成 {years} 年漏洞回答。请检查漏洞查询接口配置、网络连通性和 API 返回状态。"
        )
    if any(token in lowered for token in ["供应链", "supply chain", "dependency", "sbom", "sca"]):
        if normalized_language != "zh-Hans":
            return tr(language, "supply_chain")
        return (
            "当前模型不可用，先给出本地安全专家建议：供应链治理应从依赖资产清单、SBOM、锁定版本、来源可信校验、"
            "漏洞情报订阅、CI 阶段阻断高危依赖和制品签名验证开始，并把例外审批与修复 SLA 固化到研发流程。"
        )
    if any(token in lowered for token in ["代码审计", "sast", "semgrep", "codeql"]):
        if normalized_language != "zh-Hans":
            return tr(language, "code_audit")
        return (
            "当前模型不可用，先给出本地安全专家建议：代码审计应按入口点、鉴权边界、数据流、危险函数、依赖风险和历史漏洞模式"
            "分层排查；SAST 结果需要结合可达性、利用条件和业务影响做优先级排序。"
        )
    if any(token in lowered for token in ["威胁建模", "stride", "攻击面"]):
        if normalized_language != "zh-Hans":
            return tr(language, "threat_model")
        return (
            "当前模型不可用，先给出本地安全专家建议：威胁建模建议先画清资产、数据流、信任边界和外部入口，"
            "再按 STRIDE 检查身份伪造、篡改、抵赖、信息泄露、拒绝服务和权限提升风险。"
        )
    if any(token in lowered for token in ["合规", "标准", "等保", "金融", "数据安全", "privacy", "compliance"]):
        if normalized_language != "zh-Hans":
            return tr(language, "default_fallback")
        return (
            "金融业数据安全通常需要按四层框架核对：\n\n"
            "1. **法律法规**：网络安全、数据安全、个人信息保护以及关键信息基础设施保护要求。\n"
            "2. **等级保护与数据治理**：落实系统定级、备案、测评，并建立数据分类分级、最小权限、加密脱敏和审计留痕。\n"
            "3. **金融监管要求**：结合所属机构类型，核对人民银行、金融监管机构及证券监管机构发布的行业数据安全、科技风险和业务连续性要求。\n"
            "4. **国际及支付场景**：跨境或银行卡业务还需评估 ISO/IEC 27001、PCI DSS 等适用要求。\n\n"
            "落地时建议先形成“数据目录—分类分级—控制措施—责任人—检查证据”的合规矩阵，再以监管机构最新正式文本确认具体版本和适用范围。"
            + model_notice
        )
    if normalized_language != "zh-Hans":
        return tr(language, "default_fallback")
    memory_name = "当前会话短期记忆" if _is_information_session(state.get("session_id")) else "长期记忆"
    return (
        "当前模型未返回可用结果，先给出本地安全专家降级建议。请检查 LLM API Key、Endpoint、模型名称和网络连通性；"
        f"对于非 CVE 问题，系统会优先把{memory_name}与上下文注入模型后回答。"
        + model_notice
    )


def _public_model_failure_status(error: Any, language: str) -> str:
    if not str(error or "").strip():
        return "未调用" if normalize_response_language(language) == "zh-Hans" else "Not called"
    messages = {
        "zh-Hans": "模型请求失败",
        "zh-Hant": "模型請求失敗",
        "en": "Model request failed",
        "ja": "モデル要求に失敗しました",
        "ko": "모델 요청 실패",
    }
    normalized = normalize_response_language(language)
    return messages.get(normalized, messages["en"])


def _public_model_failure_notice(error: Any, language: str) -> str:
    raw = sanitize_public_text(str(error or "")).strip()
    if not raw:
        return ""
    normalized = normalize_response_language(language)
    if normalized != "zh-Hans":
        return ""
    lowered = raw.casefold()
    if "only allows codex official clients" in lowered:
        message = "当前模型服务拒绝了非官方客户端请求（HTTP 403）。请更换允许第三方客户端调用的接口密钥或接口地址。"
    elif "insufficient balance" in lowered or "insufficient quota" in lowered:
        message = "模型服务余额不足或调用额度已用完，请充值或更换可用的接口密钥。"
    elif "http 401" in lowered or "unauthorized" in lowered or "invalid api key" in lowered:
        message = "模型服务鉴权失败（HTTP 401）。请检查接口密钥是否有效，并确认接口地址与密钥匹配。"
    elif "http 403" in lowered or "forbidden" in lowered:
        message = "模型服务拒绝了当前请求（HTTP 403）。请检查账号权限、模型访问范围和接口地址配置。"
    else:
        message = "模型连接失败。请检查接口密钥、接口地址、模型名称和网络连通性。"
    return f"\n\n> {message}"


def runtime_status(user_id: str = "default") -> dict[str, Any]:
    resolved_user_id = str(user_id or "default").strip() or "default"
    return {
        "llm": llm_status(resolved_user_id),
        "memory": memory_service.status(resolved_user_id),
        "storageCrypto": storage_crypto_status(),
    }


knowledge_graph = KnowledgeSecurityGraph()
