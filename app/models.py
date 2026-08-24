from __future__ import annotations

import json
from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.dependencies import MAX_ASK_ATTACHMENTS, is_allowed_attachment_name


CollectorId = Literal["cve", "github_advisory"]
SupportedLanguage = Literal["zh-Hans", "zh-Hant", "en", "ko", "ja", "es", "fr", "de", "it", "ru"]
SubscriptionPaymentMethod = Literal["alipay", "wechat", "unionpay"]
SubscriptionPaymentEventType = Literal["payment.succeeded", "payment.failed", "refund.succeeded"]


class ApiResponse(BaseModel):
    status: str = "success"
    message: str = ""
    data: Any = None


class CollectorConfigUpdate(BaseModel):
    enabled: bool | None = None
    api_url: str | None = None
    api_key: str | None = None
    token: str | None = None
    collection_name: str | None = None
    severity_filter: list[str] | None = None
    ecosystem: str | None = None
    max_results: int | None = Field(default=None, ge=1, le=5000)
    sync_interval_minutes: int | None = Field(default=None, ge=5, le=10080)


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    top_k: int = Field(default=5, ge=1, le=20)
    user_id: str = Field(default="default", min_length=1, max_length=120)
    session_id: str = Field(default="default", min_length=1, max_length=120)
    response_language: str = Field(default="zh-Hans", max_length=24)
    emoji_mode: Literal["off", "moderate", "active"] = "moderate"
    intent_hint: Literal[
        "component_vulnerability_catalog",
        "recent_high_vulnerability_lookup",
        "information_consultation",
    ] | None = None
    attachments: list["AskAttachment"] = Field(default_factory=list, max_length=MAX_ASK_ATTACHMENTS)


class AskAttachment(BaseModel):
    file_name: str = Field(min_length=1, max_length=1024)
    content: str = Field(min_length=1, max_length=120000)
    mime_type: str | None = Field(default=None, max_length=120)

    @field_validator("file_name")
    @classmethod
    def validate_file_name(cls, value: str) -> str:
        clean_value = value.strip()
        if not is_allowed_attachment_name(clean_value):
            raise ValueError("仅支持上传受支持的项目依赖清单或代码文件")
        return clean_value


class AgentTaskCreateRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=4000)
    workspace_path: str = Field(min_length=1, max_length=4096)
    user_id: str = Field(default="default", min_length=1, max_length=120)

    @field_validator("objective", "workspace_path", "user_id")
    @classmethod
    def normalize_agent_task_fields(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("任务目标、工作区和用户标识不能为空")
        return clean


class AssistantWorkspaceActionRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=4000)
    workspace_path: str = Field(min_length=1, max_length=4096)
    user_id: str = Field(default="default", min_length=1, max_length=120)
    session_id: str = Field(default="default", min_length=1, max_length=120)
    response_language: str = Field(default="zh-Hans", max_length=24)

    @field_validator("objective", "workspace_path", "user_id", "session_id")
    @classmethod
    def normalize_workspace_action_fields(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("工作区动作目标、项目路径和用户上下文不能为空")
        return clean


class AssistantTaskActionRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=4000)
    user_id: str = Field(default="default", min_length=1, max_length=120)
    session_id: str = Field(default="default", min_length=1, max_length=120)
    response_language: str = Field(default="zh-Hans", max_length=24)

    @field_validator("objective", "user_id", "session_id")
    @classmethod
    def normalize_task_action_fields(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("任务动作目标和用户上下文不能为空")
        return clean


class AgentTaskReportDecisionRequest(BaseModel):
    generate: bool
    response_language: str = Field(default="zh-Hans", max_length=24)


class ReportActionRequest(BaseModel):
    action: Literal["generate", "download_report", "download_report_all_formats", "download_all"]
    report_ids: list[str] = Field(default_factory=list, max_length=100)
    formats: list[Literal["md", "html", "docx", "xlsx", "pdf"]] = Field(default_factory=list, max_length=5)
    user_id: str = Field(default="default", min_length=1, max_length=120)
    session_id: str = Field(default="default", min_length=1, max_length=120)
    response_language: str = Field(default="zh-Hans", max_length=24)


class ReportActionResumeRequest(BaseModel):
    thread_id: str = Field(min_length=8, max_length=160)
    interrupt_id: str = Field(default="", max_length=160)
    decision: Literal["confirm", "cancel"]
    format: Literal["md", "html", "docx", "xlsx", "pdf", "all"] | None = None
    user_id: str = Field(default="default", min_length=1, max_length=120)
    session_id: str = Field(default="default", min_length=1, max_length=120)
    response_language: str = Field(default="zh-Hans", max_length=24)


class AssistantInterruptResumeRequest(ReportActionResumeRequest):
    """Resume any assistant-owned LangGraph interrupt without coupling the client to one subgraph."""


class AgentTaskReportDownloadDecisionRequest(BaseModel):
    confirm: bool
    format: Literal["md", "html", "docx", "xlsx", "pdf", "all"] = "pdf"


class AgentTaskArchiveRequest(BaseModel):
    archived: bool


class AssistantConversationArchiveRequest(BaseModel):
    archived: bool


class AssistantDataTableEditColumn(BaseModel):
    key: str = Field(min_length=1, max_length=160)
    label: str = Field(min_length=1, max_length=240)
    kind: Literal["date", "link", "number", "status", "tags", "text"] | None = None
    editable: bool | None = None


class AssistantDataTableEdit(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    type: str = Field(default="records-table", max_length=80)
    title: str | None = Field(default=None, max_length=500)
    caption: str | None = Field(default=None, max_length=500)
    columns: list[AssistantDataTableEditColumn] = Field(min_length=1, max_length=64)
    rows: list[dict[str, Any]] = Field(default_factory=list, max_length=200)
    total: int | None = Field(default=None, ge=0)
    edited: bool = True

    @field_validator("rows")
    @classmethod
    def validate_rows(cls, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if any(len(row) > 64 for row in rows):
            raise ValueError("每条记录最多包含 64 个字段")
        return rows


class AssistantStructuredDataEditRequest(BaseModel):
    tables: list[AssistantDataTableEdit] = Field(min_length=1, max_length=12)

    @field_validator("tables")
    @classmethod
    def validate_payload_size(cls, tables: list[AssistantDataTableEdit]) -> list[AssistantDataTableEdit]:
        encoded = json.dumps([table.model_dump(mode="json") for table in tables], ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 1_000_000:
            raise ValueError("记录表修改内容不能超过 1 MB")
        return tables


class IntelligenceQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=1000)
    limit: int = Field(default=10, ge=1, le=50)
    response_language: str | None = Field(default=None, max_length=24)
    sources: list[Literal["nvd", "github_advisory", "osv"]] | None = None


class ComponentVulnerabilityRequest(BaseModel):
    name: str = Field(min_length=1, max_length=240)
    version: str = Field(min_length=1, max_length=120)
    ecosystem: str | None = Field(default=None, max_length=80)
    include_realtime: bool = True

    @field_validator("name", "version", "ecosystem")
    @classmethod
    def normalize_component_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return " ".join(value.split())


class VulnerabilityComponentExportRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=40)

    @field_validator("identifier")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        return " ".join(value.split()).upper()


class DashboardRefreshRequest(BaseModel):
    start_date: date | None = None
    end_date: date | None = None


class InformationSourceUpdate(BaseModel):
    enabled: bool


class InformationSourcesUpdate(BaseModel):
    source_ids: list[str] = Field(min_length=1, max_length=600)
    enabled: bool

    @field_validator("source_ids")
    @classmethod
    def validate_source_ids(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
        if not cleaned:
            raise ValueError("至少选择一个资讯来源")
        if any(len(value) > 120 for value in cleaned):
            raise ValueError("资讯来源编号长度无效")
        return cleaned


class UserProfileSettingsUpdate(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=1, max_length=160)
    phone: str = Field(default="", max_length=80)
    department: str = Field(default="", max_length=120)
    role: str = Field(default="", max_length=120)
    employee_id: str = Field(default="", max_length=80)
    bio: str = Field(default="", max_length=200)


class AvatarUploadRequest(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1, max_length=3_000_000)
    content_type: str | None = Field(default=None, max_length=80)


class AppPreferenceSettingsUpdate(BaseModel):
    language: SupportedLanguage = "zh-Hans"
    dark_mode: bool = False
    font_size: Literal["small", "default", "large"] = "default"
    emoji_mode: Literal["off", "moderate", "active"] = "moderate"
    launch_at_login: bool = False
    auto_check_updates: bool = True


class LegalDocumentSectionUpdate(BaseModel):
    heading: str = Field(min_length=1, max_length=120)
    paragraphs: list[str] = Field(min_length=1, max_length=40)

    @field_validator("paragraphs")
    @classmethod
    def validate_paragraphs(cls, values: list[str]) -> list[str]:
        cleaned = [str(value).strip() for value in values if str(value).strip()]
        if not cleaned:
            raise ValueError("协议章节内容不能为空")
        if any(len(value) > 2000 for value in cleaned):
            raise ValueError("协议单段内容过长")
        return cleaned


class LegalDocumentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=80)
    heading: str | None = Field(default=None, min_length=1, max_length=120)
    updated_at: str | None = Field(default=None, min_length=1, max_length=40)
    effective_at: str | None = Field(default=None, min_length=1, max_length=40)
    intro: str | None = Field(default=None, min_length=1, max_length=3000)
    sections: list[LegalDocumentSectionUpdate] | None = Field(default=None, min_length=1, max_length=30)


class SubscriptionCheckoutRequest(BaseModel):
    user_id: str = Field(default="local-user", min_length=1, max_length=120)
    plan_id: str = Field(min_length=1, max_length=80)
    payment_method: SubscriptionPaymentMethod
    idempotency_key: str = Field(min_length=8, max_length=160)

    @field_validator("user_id", "plan_id", "idempotency_key")
    @classmethod
    def normalize_subscription_checkout_fields(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("订阅参数不能为空")
        return clean


class SubscriptionCancelRequest(BaseModel):
    user_id: str = Field(default="local-user", min_length=1, max_length=120)
    reason: str | None = Field(default=None, max_length=300)

    @field_validator("user_id", "reason")
    @classmethod
    def normalize_subscription_cancel_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


class SubscriptionPaymentEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=160)
    event_type: SubscriptionPaymentEventType
    order_id: str = Field(min_length=1, max_length=160)
    provider_transaction_id: str | None = Field(default=None, max_length=200)
    occurred_at: str | None = Field(default=None, max_length=80)

    @field_validator("event_id", "order_id", "provider_transaction_id", "occurred_at")
    @classmethod
    def normalize_subscription_event_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


class ReportDeleteRequest(BaseModel):
    report_ids: list[str] = Field(min_length=1, max_length=100)

    @field_validator("report_ids")
    @classmethod
    def validate_report_ids(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
        if not cleaned:
            raise ValueError("至少选择一份报告")
        if any(len(value) > 160 for value in cleaned):
            raise ValueError("报告编号长度无效")
        return cleaned


class LLMConfigRequest(BaseModel):
    provider: Literal["openai", "claude", "deepseek", "custom"]
    catalog_provider: str | None = Field(default=None, min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=120)
    endpoint: str | None = Field(default=None, max_length=300)
    api_key: str | None = Field(default=None, max_length=8192)
    clear_api_key: bool = False
    enabled: bool = True
    max_tokens: int = Field(default=1800, ge=128, le=8192)
    temperature: float = Field(default=0.25, ge=0, le=2)
    top_p: float = Field(default=0.9, ge=0, le=1)
    timeout_ms: int = Field(default=60000, ge=1000, le=180000)
    wire_api: Literal["chat", "responses"] | None = None
    reasoning_effort: Literal["none", "low", "medium", "high", "xhigh", "max"] | None = None
    disable_response_storage: bool | None = None

    @field_validator("reasoning_effort", mode="before")
    @classmethod
    def normalize_optional_reasoning_effort(cls, value: Any) -> Any:
        if isinstance(value, str):
            cleaned = value.strip()
            return cleaned or None
        return value


class LLMModelsRequest(BaseModel):
    provider: Literal["openai", "claude", "deepseek", "custom"]
    catalog_provider: str | None = Field(default=None, min_length=1, max_length=80)
    endpoint: str | None = Field(default=None, max_length=300)
    api_key: str | None = Field(default=None, max_length=8192)
    clear_api_key: bool = False
    timeout_ms: int = Field(default=30000, ge=1000, le=180000)


class MemoryClearRequest(BaseModel):
    user_id: str = Field(default="default", min_length=1, max_length=120)


class VulnerabilityRecord(BaseModel):
    id: str
    title: str
    severity: str = "Unknown"
    cvss_score: float | None = None
    source: str = "local"
    summary: str = ""
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    collection: str = "cve"
    updated_at: str = ""
