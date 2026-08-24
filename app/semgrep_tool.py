from __future__ import annotations

import json
import os
import re
import shlex
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.dependencies import MAX_ASK_ATTACHMENTS, attachment_kind, is_allowed_attachment_name
from app.go_semantic_analyzer import analyze_go_semantics
from app.java_flow_analyzer import analyze_java_interprocedural
from app.language_support import analyze_source_structure, control_flow_steps, language_for_file, supported_flow_languages
from app.source_filter import SEMGREP_EXCLUDE_PATTERNS, is_analyzable_source_path, is_symlink_like_source_stub
from app.storage import DATA_DIR, now_iso


AST_CFG_DFG_ANALYSIS_PROMPT = """你是神盾静态分析节点。
任务：基于用户上传代码、pom 依赖、漏洞情报组件信息和静态数据流 source→sink 路径，输出中文可审计结论。
必须按照 AST / CFG / DFG 三层组织证据：
1. AST：列出类、方法、调用表达式、import 与危险 API。
2. CFG：说明 source 到 sink 是否处于同一可执行分支、是否经过 if/try/loop 等控制条件。
3. DFG：说明不可信输入、依赖 API、变量赋值、方法参数到危险 sink 的完整传播路径。
只允许引用上传代码与后端已核验漏洞事实；禁止生成 PoC、利用载荷或攻击步骤。
输出字段：风险场景、命中漏洞、组件版本范围、source、sink、完整路径、置信度、修复建议、修复代码片段。
"""

DEFAULT_SEMGREP_RULES = "config/semgrep"
LANGUAGE_SEMGREP_RULE_FILES: dict[str, tuple[str, ...]] = {
    "java": ("java-security.yml",),
    "python": ("python-security.yml",),
    "go": ("go-security.yml", "go-security-recall.yml"),
    "c": ("c-cpp-security.yml",),
    "cpp": ("c-cpp-security.yml",),
    "csharp": ("csharp-security.yml",),
    "rust": ("rust-security.yml",),
    "solidity": ("solidity-security.yml",),
}


SCENARIO_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "log_injection_lookup",
        "label": "日志/表达式注入路径",
        "condition": "组件或代码命中日志框架，且外部输入进入日志 sink。",
        "ast": ["import 日志组件", "logger.* 调用表达式"],
        "cfg": ["controller/handler 方法内直接调用", "异常分支或条件分支内记录外部输入"],
        "dfg": ["HTTP 参数/请求体", "局部变量", "logger sink"],
    },
    {
        "id": "deserialization",
        "label": "反序列化/对象绑定路径",
        "condition": "组件或代码命中对象反序列化、YAML/Jackson 绑定、readObject 等 sink。",
        "ast": ["ObjectInputStream/readObject", "ObjectMapper/readValue", "Yaml/load"],
        "cfg": ["上传/接口处理分支", "异常恢复分支"],
        "dfg": ["外部字节流/请求体", "解析器", "对象构造 sink"],
    },
    {
        "id": "command_execution",
        "label": "命令执行路径",
        "condition": "外部输入进入 Runtime.exec 或 ProcessBuilder。",
        "ast": ["Runtime.exec", "ProcessBuilder"],
        "cfg": ["命令拼接所在分支"],
        "dfg": ["HTTP 参数/环境变量/命令参数", "字符串拼接", "命令执行 sink"],
    },
    {
        "id": "sql_injection",
        "label": "SQL 注入路径",
        "condition": "外部输入进入 Statement.execute/query 或字符串拼接 SQL。",
        "ast": ["Statement.execute", "createQuery", "字符串 SQL"],
        "cfg": ["DAO/Repository 查询分支"],
        "dfg": ["HTTP 参数", "SQL 字符串", "数据库执行 sink"],
    },
    {
        "id": "path_traversal",
        "label": "路径穿越路径",
        "condition": "外部输入进入文件路径或文件读写接口。",
        "ast": ["File/Path/Files 调用表达式"],
        "cfg": ["文件读取、上传或下载分支"],
        "dfg": ["文件名/请求参数", "路径拼接", "文件系统 sink"],
    },
    {
        "id": "cross_site_scripting",
        "label": "跨站脚本路径",
        "condition": "外部输入未经上下文编码写入 HTTP 响应。",
        "ast": ["HttpServletResponse/PrintWriter 输出调用"],
        "cfg": ["HTTP 响应输出分支"],
        "dfg": ["请求参数", "页面数据", "响应输出 sink"],
    },
    {
        "id": "ssrf",
        "label": "服务端请求伪造路径",
        "condition": "外部输入控制服务端请求地址。",
        "ast": ["URL/URI/HTTP 客户端调用"],
        "cfg": ["远程请求执行分支"],
        "dfg": ["请求参数", "URL 构造", "网络请求 sink"],
    },
    {
        "id": "xml_external_entity",
        "label": "XML 外部实体风险",
        "condition": "XML 解析器未完整关闭外部实体能力。",
        "ast": ["DocumentBuilderFactory/XML parser 配置"],
        "cfg": ["XML 解析分支"],
        "dfg": ["XML 输入", "解析器配置", "XML 解析 sink"],
    },
    {
        "id": "generic_reachability",
        "label": "组件可达性路径",
        "condition": "已命中漏洞依赖，但未能确认专用 source/sink 场景。",
        "ast": ["import/调用与漏洞组件相关 API"],
        "cfg": ["上传代码中的可执行方法"],
        "dfg": ["依赖声明", "组件 API 调用", "潜在危险能力"],
    },
    {
        "id": "idempotency_missing",
        "label": "资金操作幂等性缺失",
        "condition": "支付、转账、退款、提现等资金请求缺少幂等键或业务流水去重。",
        "ast": ["Controller POST 方法", "支付/转账/退款服务调用"],
        "cfg": ["重复请求、回调重放或网络重试分支"],
        "dfg": ["请求流水/订单号", "幂等记录", "资金状态更新"],
    },
    {
        "id": "funds_precision",
        "label": "资金金额精度风险",
        "condition": "资金、余额、手续费、价格等金额使用 float/double 或从 double 构造 BigDecimal。",
        "ast": ["float/double 金额字段", "BigDecimal 构造表达式"],
        "cfg": ["金额计算、订单结算或费用计算分支"],
        "dfg": ["用户金额/订单金额", "浮点计算", "入账/扣款金额"],
    },
    {
        "id": "funds_transaction_boundary",
        "label": "资金事务边界缺失",
        "condition": "资金类方法更新余额、订单或交易状态时未看到事务边界。",
        "ast": ["资金服务方法", "Repository/Mapper/JDBC 更新调用"],
        "cfg": ["扣款、入账、状态变更的组合执行路径"],
        "dfg": ["资金请求", "账户/订单状态", "数据库更新"],
    },
)

SOURCE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("http_parameter", r"\bgetParameter\s*\(|@RequestParam\b|@PathVariable\b|@RequestBody\b"),
    ("http_request", r"\bHttpServletRequest\b|\bServletRequest\b|\brequest\.get(?:Header|InputStream|Reader|Parameter)"),
    ("cli_argument", r"\bargs\s*\[|\bSystem\.getenv\s*\("),
    ("stream_reader", r"\breadLine\s*\(|\bScanner\s*\("),
    ("file_upload", r"\bMultipartFile\b|\bgetInputStream\s*\("),
    ("method_parameter", r"\b(?:String|CharSequence|byte\s*\[\s*\]|InputStream|Reader)\s+[A-Za-z_]\w*\s*[,)]"),
    ("python_http_input", r"\brequest\.(?:args|form|values)\.get\s*\(|\b(?:GET|POST|query_params|path_params)\.get\s*\("),
    ("go_http_input", r"\.URL\.Query\s*\(\s*\)\.Get\s*\(|\.(?:FormValue|PostFormValue|Query|Param|PostForm)\s*\("),
    ("native_cli_input", r"\b(?:argv|ARGV)\s*\[|\bgetenv\s*\("),
    ("rust_environment_input", r"\b(?:std::)?env::(?:var|args)\s*\("),
)

SINK_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("logger_sink", r"\b[A-Za-z_][\w]*\.(?:trace|debug|info|warn|error|fatal)\s*\(", "log_injection_lookup"),
    ("jndi_lookup", r"\bInitialContext\s*\(|\.lookup\s*\(", "log_injection_lookup"),
    (
        "deserialization_sink",
        r"\breadObject\s*\(|\bObjectInputStream\b|\breadValue\s*\(|\bYaml\s*\(|\b(?:yaml|[A-Za-z_]\w*Yaml\w*)\.load\s*\(",
        "deserialization",
    ),
    ("command_sink", r"\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcessBuilder\s*\(", "command_execution"),
    (
        "sql_sink",
        r"(?<![\w.])(?:java\.sql\.)?Statement\s+[A-Za-z_]\w*\s*="
        r"|\b(?:statement|stmt|[A-Za-z_]\w*(?:Statement|Stmt))\.execute(?:Query|Update)?\s*\("
        r"|\bcreateQuery\s*\(",
        "sql_injection",
    ),
    ("script_sink", r"\bScriptEngine\b|\.eval\s*\(", "command_execution"),
)

FINANCE_ACTION_RE = re.compile(
    r"pay|payment|refund|transfer|fund|money|withdraw|deposit|deposite|recharge|settle|checkout|"
    r"charge|topup|topUp|order|trade|debit|credit|freeze|thaw|remit|remittance|bill|dividend|payout|"
    r"stopLoss|pledge|matching|repay|repayment|disburse|disbursement|chargeback|capture",
    flags=re.IGNORECASE,
)
FINANCE_AMOUNT_RE = re.compile(
    r"amount|money|balance|price|fee|total|pay|paid|refund|charge|withdraw|deposit|deposite|"
    r"debit|credit|settle|wallet|bill|interestRate|feeRate|exchangeRate|\brate\b|"
    r"loan|repay|repayment|disburse|disbursement|chargeback|capture",
    flags=re.IGNORECASE,
)
FINANCE_MUTATING_HTTP_ANNOTATION_RE = re.compile(
    r"@\s*(?:PostMapping|PutMapping|PatchMapping)\b"
    r"|@\s*RequestMapping\s*\([^)]*RequestMethod\.(?:POST|PUT|PATCH)",
    flags=re.IGNORECASE | re.DOTALL,
)
IDEMPOTENCY_GUARD_RE = re.compile(
    r"Idempotency-Key|X-Idempotency-Key|\bidempotenc\w*\b|\bidempotent\w*\b|"
    r"\bclientOrderId\b|client[_-]?order[_-]?id|"
    r"\brequestNo\b|\brequestId\b|\brequestIdempotency\b|\bpaymentId\b|payment[_-]?id|\btransactionNo\b|\btransactionId\b|"
    r"\borderNo\b|\bbizNo\b|\bserialNo\b|\bdedup\w*\b|\bisDuplicate\b|\bduplicate\b|"
    r"\bsetIfAbsent\b|\btryLock\b|\blockKey\b|\bnonce\b|\bmatchRecord\b|\balready processed\b|"
    r'"PENDING"\.equals\([^)]*\.getStatus\s*\(|幂等|业务流水',
    flags=re.IGNORECASE,
)
EXPLICIT_IDEMPOTENCY_GUARD_RE = re.compile(
    r"Idempotency-Key|X-Idempotency-Key|\bidempotenc\w*\b|\bidempotent\w*\b|"
    r"\bclientOrderId\b|client[_-]?order[_-]?id|\bdedup\w*\b|\bisDuplicate\b|\bduplicate\b|"
    r"\bunique(?:Key|Request|Constraint|Index)\b|"
    r"\b(?:existsBy|findBy)[A-Za-z0-9_$]*(?:Idempot|ClientOrder|Request|Event|Stripe)[A-Za-z0-9_$]*\b|"
    r"\bsetIfAbsent\b|\btryLock\b|\blockKey\b|\bnonce\b|\bmatchRecord\b|\balready processed\b|"
    r'"PENDING"\.equals\([^)]*\.getStatus\s*\(|幂等|业务流水',
    flags=re.IGNORECASE,
)
TRANSACTION_GUARD_RE = re.compile(
    r"@\s*(?:org\.springframework\.transaction\.annotation\.)?Transactional\b|"
    r"\btransactionTemplate\b|\bplatformTransactionManager\b|\.setAutoCommit\s*\(\s*false\s*\)|"
    r"\bbeginTransaction\s*\(|\.commit\s*\(",
    flags=re.IGNORECASE,
)
FINANCE_SERVICE_CALL_RE = re.compile(
    r"\b[A-Za-z_$][\w$]*(?:Service|ServiceImpl|Repository|Dao|DAO|Mapper|Gateway|Client)?"
    r"\s*\.\s*(?P<call>[A-Za-z_$][\w$]*)\s*\(",
    flags=re.IGNORECASE,
)
FINANCE_READ_ONLY_CALL_RE = re.compile(
    r"^(?:get|find|query|list|show|load|fetch|read|count|exists|generate|authenticate|login|register)",
    flags=re.IGNORECASE,
)
FINANCE_PROFILE_CALL_RE = re.compile(
    r"(?:detail|details|profile|auth|token|jwt|email|watchlist|password|login|customer)",
    flags=re.IGNORECASE,
)
FINANCE_NON_FUNDS_METHOD_RE = re.compile(
    r"^(?:get|find|query|list|search|show|page|count|exists|check|validate|verify).*$|"
    r".*(?:List|Status|Details?|Profile|Config|Settings?|Statistics|Chart|Password|Login|Customer|User|Auth)$|"
    r".*(?:RobotConfig|InitPlate|Limit)$|"
    r"^(?:add|create|update|delete)?(?:payment)?details?$|^(?:create|update|delete)Plan$|"
    r"^(?:create|update)(?:Wallet)?$|"
    r"^(?:lock|unlock)Wallet$|^startGame$|"
    r"^(?:createExchange|addStock|addNewStock|changeStockStatus|transferPrimaryContact|assignRepresentative|revokeRepresentative|createInstruction|declineTrade|submitIpoOffer|createPortfolio)$",
    flags=re.IGNORECASE,
)
FINANCE_PERSISTENCE_CALL_RE = re.compile(r"^(?:save|insert|update|delete|submit|create)$", flags=re.IGNORECASE)
FINANCE_STRONG_MUTATION_RE = re.compile(
    r"(?:amount|balance|wallet|order|withdraw|deposit|transfer|credit|debit|refund|charge|settle|payout|bill|trade|batch|"
    r"transaction|dividend|thaw|increase|decrease|repay|repayment|disburse|disbursement|chargeback|capture)",
    flags=re.IGNORECASE,
)
FINANCE_STATE_MUTATION_RE = re.compile(
    r"\.\s*(?:setBalance|setFrozenBalance|increaseBalance|decreaseBalance|thawBalance|save|insert|update|delete)\s*\(",
    flags=re.IGNORECASE,
)
FINANCE_UTILITY_CALL_RE = re.compile(
    r"^(?:isTrue|notNull|equals|compareTo|format|parse\w*|valueOf|toString|getMessage|"
    r"sendCustomMessage|info|warn|error|debug|trace)$",
    flags=re.IGNORECASE,
)
FINANCE_NON_FUNDS_CONTEXT_RE = re.compile(
    r"FinanceStatistics|StatisticsController|统计|aggregation|mongoTemplate\.aggregate|turnover_statistics|"
    r"RobotConfig|createRobotConfig|PriceRobotParams|ROBOT-TRADE|机器人|robot config|"
    r"startExchangeCoinEngine|stopExchangeCoinEngine|start-trader|stop-trader|启动交易引擎|暂停交易引擎|"
    r"RewardPromotionSetting|邀请奖励设置|TransferAddress|transfer-address|转账地址|"
    r"CtcAcceptor|acceptorService|承兑商|"
    r"BusinessAuthDeposit|businessAuthDeposit|保证金策略|保证金配置|"
    r"ParticipantManagement|ProductManagement|addBroker|addEquity|participantManagmentService|productManagmentService|"
    r"meshGossip|gossipOnce|MeshSimulator|deviceCounts|packetCount|"
    r"Notification|Watchlist|watchlist|自选|提醒设置|"
    r"BacktestingController|backtesting|TrainingResult|PredictionResult|PredictionForm|djlTrainingService|trainReactive|"
    r"Login_Details|changePassword|checkPassword|password|login|authenticate|认证|登录|密码|"
    r"CompanyRepresentative|PrimaryContact|representatives/primary-contact|transferPrimaryContact|"
    r"CreateExchangeRequest|createExchange|ExchangeMarketClock|CreateStockRequest|addStock|addNewStock|changeStockStatus|declineTrade|"
    r"FrontOfficeDeltaHedge|FrontOfficeStressTest|FrontOfficeWhatIf|RUN_DELTA_HEDGE|RUN_STRESS_TEST|RUN_PRE_TRADE_ANALYSIS|"
    r"DeltaHedgeAnalysis|StressTest|WhatIf|RiskRun|valuationDate|hypotheticalTrade|"
    r"OperationalControl|updateSettings|operational-control|CreatePortfolioRequest|createPortfolio|Portfolio created|"
    r"HoldingController|createHolding|HoldingService|holdings|holdingRepository|"
    r"MediaReading|MeterReading|media-reading|meter reading|uploadInitialReading|uploadFinalReading|processInitialReadingUpload|processFinalReadingUpload|"
    r"freezeAccount|unfreezeAccount|updateOrder\(|updateOrder\s*$|"
    r"lockWallet|unlockWallet|lock-wallet|unlock-wallet|锁定钱包|解锁钱包|"
    r"GameController|GameSessionService|startNewGame|startingCash|GameSnapshot|game simulation|tradingTicks|"
    r"BackOfficeEod|PortfolioEod|EodBatch|EodCorrection|EOD_BATCH|EOD_RUN|RUN_EOD_BATCH|"
    r"captureAll|voidRun|recapture|businessDate|EOD run|end-of-day|"
    r"createWallet|create-wallet|"
    r"alterActivity(?:FreezeAmount|TradedAmount)|modify-freezeamount|modify-tradedamount|"
    r"活动冻结总资产|活动成交总数",
    flags=re.IGNORECASE,
)
FINANCE_WALLET_CREATION_CONTEXT_RE = re.compile(r"\bcreateWallet\b|create-wallet|创建钱包", flags=re.IGNORECASE)
FINANCE_WALLET_CRUD_CONTEXT_RE = re.compile(
    r"\b(?:create|update)(?:Wallet)?\b|walletService\s*\.\s*(?:create|update)\s*\(",
    flags=re.IGNORECASE,
)
FINANCE_ACCOUNT_CREATION_WITH_BUSINESS_KEY_RE = re.compile(
    r"\b(?:create|createAccount)\b|POST\s+/accounts\b|accountService\s*\.\s*create\s*\(",
    flags=re.IGNORECASE,
)
FINANCE_REAL_MONEY_CONTEXT_RE = re.compile(
    r"memberWallet|walletService|memberTransaction|hotTransferRecord|"
    r"exchangeOrder|forceCancelOrder|thawBalance|increaseBalance|decreaseBalance|setFrozenBalance|"
    r"setBalance|updateByMemberIdAndCoinId|rpc/transfer|startDividend|"
    r"chargeback|Chargeback|disbursement|Disbursement|repayment|makeRepayment|"
    r"accountFundsService|addFunds|DepositDTO|提现|打款|充值|退回保证金|扣除保证金|分发活动币",
    flags=re.IGNORECASE,
)
FINANCE_AUDIT_ONLY_METHOD_RE = re.compile(r"^audit(?:Pass|NoPass|Reject|Approve)?$", flags=re.IGNORECASE)
FINANCE_WALLET_LOCK_METHOD_RE = re.compile(r"^(?:lock|unlock)Wallet$", flags=re.IGNORECASE)
FINANCE_CANCEL_STATE_METHOD_RE = re.compile(r"^cancel(?:Order|Trade|Request)?$", flags=re.IGNORECASE)
FINANCE_FLOAT_DECLARATION_RE = re.compile(
    r"\b(?:double|float|Double|Float)\s+(?P<name>[A-Za-z_$][\w$]*)\b",
    flags=re.IGNORECASE,
)

COMPONENT_SCENARIO_HINTS: tuple[tuple[str, str], ...] = (
    ("log4j", "log_injection_lookup"),
    ("snakeyaml", "deserialization"),
    ("jackson", "deserialization"),
    ("commons-collections", "deserialization"),
    ("spring", "generic_reachability"),
)


@dataclass(frozen=True)
class CodeLine:
    file_name: str
    line: int
    text: str


@dataclass(frozen=True)
class JavaMethodSpan:
    name: str
    start: int
    end: int


class SemgrepTool:
    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or os.getenv("SECFLOW_SEMGREP_BIN", "").strip()

    def status(self) -> dict[str, Any]:
        path = self._cli_path()
        return {
            "available": True,
            "internalAnalyzer": True,
            "userInstallRequired": False,
            "cliAvailable": bool(path),
            "path": path or "",
            "mode": "bundled-cli+internal" if path else "internal",
            "message": "应用内静态分析引擎可用，用户无需安装额外工具。",
            "supportedLanguages": supported_flow_languages(),
            "prompts": {
                "ast_cfg_dfg": AST_CFG_DFG_ANALYSIS_PROMPT,
                "scenarios": [item["id"] for item in SCENARIO_DEFINITIONS],
            },
        }

    def validate_rule_paths(self, rule_paths: list[str]) -> dict[str, Any]:
        """Compile-check project-scoped rules before they can replace a good scan.

        Structural validation of an LLM-produced overlay is not enough: a pattern
        may be safe text while still being invalid for Semgrep's language parser.
        Keep this check in the same bundled runtime used for the real scan so the
        validation result cannot diverge from the packaged client.
        """

        cli_path = self._cli_path()
        if not cli_path:
            return {
                "status": "unavailable",
                "valid": False,
                "diagnostics": ["静态分析 CLI 不可用，项目 Overlay 未应用。"],
            }
        selected_rules = [Path(path) for path in rule_paths if Path(path).is_file()]
        if not selected_rules or len(selected_rules) != len(rule_paths):
            return {
                "status": "failed",
                "valid": False,
                "diagnostics": ["项目 Overlay 规则文件缺失，未应用该 Overlay。"],
            }
        timeout = max(1, int(os.getenv("SECFLOW_SEMGREP_VALIDATE_TIMEOUT_SECONDS", "60")))
        command = [cli_path, "validate", *(str(path) for path in selected_rules)]
        try:
            validated = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=_semgrep_subprocess_env(),
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "valid": False,
                "diagnostics": [f"Overlay 规则预检超过 {timeout}s，已保留首轮扫描结果。"],
            }
        except Exception as exc:  # noqa: BLE001 - fail closed to the verified baseline.
            return {
                "status": "failed",
                "valid": False,
                "diagnostics": [f"Overlay 规则预检执行失败：{exc}"],
            }
        if validated.returncode == 0:
            return {"status": "completed", "valid": True, "diagnostics": []}
        detail = (validated.stderr or validated.stdout or "").strip().splitlines()[-8:]
        return {
            "status": "failed",
            "valid": False,
            "diagnostics": ["Overlay 规则未通过 Semgrep 语法预检：" + " / ".join(detail)],
        }

    def analyze(
        self,
        attachments: list[dict[str, Any]],
        dependency_scan: dict[str, Any],
        records: list[dict[str, Any]],
        *,
        rule_paths: list[str] | None = None,
        cancelled: Callable[[], bool] | None = None,
        language_hint: str | None = None,
        include_all_attachments: bool = False,
    ) -> dict[str, Any]:
        code_files = _code_attachments(
            attachments,
            include_all_attachments=include_all_attachments,
        )
        if language_hint in set(supported_flow_languages()):
            for item in code_files:
                item["language_hint"] = language_hint
        project_files = _project_attachments(
            attachments,
            include_all_attachments=include_all_attachments,
        )
        compile_definitions = _compile_definitions_by_source_file(project_files)
        project_preprocessor_definitions = {
            **_project_preprocessor_definitions(project_files),
            **_project_overlay_preprocessor_definitions(dependency_scan),
        }
        diagnostics: list[str] = []
        syntax_analysis: list[dict[str, Any]] = []
        for item in code_files:
            # Every per-file phase must honor user cancellation so a stopped task
            # cannot keep parsing or analyzing in the background.
            if _analysis_cancelled(cancelled):
                diagnostics.append("静态分析已由用户停止。")
                return _cancelled_analysis_result(rule_paths, diagnostics)
            syntax_analysis.append(
                analyze_source_structure(
                    item["file_name"],
                    item["content"],
                    language_hint=item.get("language_hint"),
                    preprocessor_definitions={
                        **project_preprocessor_definitions,
                        **_compile_definitions_for_file(item["file_name"], compile_definitions),
                    },
                )
            )
        scenarios = _select_scenarios(dependency_scan, records, code_files)
        if _analysis_cancelled(cancelled):
            diagnostics.append("静态分析已由用户停止。")
            return _cancelled_analysis_result(rule_paths, diagnostics)
        heuristic_findings = _heuristic_findings(code_files, dependency_scan, records, scenarios)
        interprocedural_findings: list[dict[str, Any]] = []
        go_semantic_findings: list[dict[str, Any]] = []
        cli_findings: list[dict[str, Any]] = []
        cli_status = "skipped"
        cli_path = self._cli_path()
        if code_files and cli_path:
            cli_status, cli_findings, cli_diagnostics = self._run_cli(
                code_files,
                project_files,
                dependency_scan,
                records,
                rule_paths=rule_paths,
                cancelled=cancelled,
                complete_scan=include_all_attachments,
            )
            diagnostics.extend(cli_diagnostics)
            if cli_status == "cancelled":
                return _cancelled_analysis_result(rule_paths, diagnostics)
        elif not code_files:
            diagnostics.append("未上传代码文件，静态 source/sink 分析已跳过，仅生成依赖情报报告。")
        else:
            diagnostics.append("已使用内置 AST/CFG/DFG 分析，用户无需安装额外工具。")

        java_files = [item for item in code_files if _language_for_file(item["file_name"]) == "java"]
        if java_files and not _analysis_cancelled(cancelled):
            try:
                path_analysis = analyze_java_interprocedural(
                    java_files,
                    complete_analysis=include_all_attachments,
                    cancelled=cancelled,
                )
                diagnostics.extend(str(item) for item in path_analysis.get("diagnostics") or [] if item)
                interprocedural_findings = [
                    item
                    for item in path_analysis.get("findings") or []
                    if str(item.get("confidence") or "").lower() == "high"
                ]
            except Exception as exc:  # noqa: BLE001
                diagnostics.append(f"跨方法数据流分析失败，已保留基础扫描结果：{exc}")

        go_files = [item for item in code_files if _language_for_file(item["file_name"]) == "go"]
        if go_files and not _analysis_cancelled(cancelled):
            try:
                go_analysis = analyze_go_semantics(go_files)
                diagnostics.extend(str(item) for item in go_analysis.get("diagnostics") or [] if item)
                go_semantic_findings = list(go_analysis.get("findings") or [])
            except Exception as exc:  # noqa: BLE001
                diagnostics.append(f"Go 语义分析失败，已保留 Semgrep 结果：{exc}")
        if _analysis_cancelled(cancelled):
            diagnostics.append("静态分析已由用户停止。")
            return _cancelled_analysis_result(rule_paths, diagnostics)

        primary_findings = cli_findings if cli_status == "completed" else heuristic_findings
        correlated_paths = _correlate_interprocedural_findings(
            interprocedural_findings,
            dependency_scan,
            records,
        )
        selected_findings = _merge_cross_engine_findings(
            [*primary_findings, *correlated_paths, *go_semantic_findings]
        )
        review_candidates = [item for item in selected_findings if _is_review_finding(item)]
        primary_candidates = [item for item in selected_findings if not _is_review_finding(item)]
        findings = _enrich_code_findings(primary_candidates, code_files)
        review_findings = _enrich_code_findings(review_candidates, code_files)
        return {
            "status": "completed" if findings or cli_status == "completed" else "warning",
            "tool": "AegisAl Static Analyzer",
            "cli_status": cli_status,
            "mode": "bundled-cli" if cli_status == "completed" else "internal-fallback",
            "rule_paths": list(rule_paths or []),
            "generated_at": now_iso(),
            "files": [
                {
                    "file_name": item["file_name"],
                    "language": syntax_analysis[index]["language"],
                    "syntax": syntax_analysis[index],
                }
                for index, item in enumerate(code_files)
            ],
            "syntax_summary": {
                "languages": sorted({item.get("language", "unknown") for item in syntax_analysis}),
                "parsed_files": sum(1 for item in syntax_analysis if item.get("parser") == "tree-sitter"),
                "parse_error_files": sum(1 for item in syntax_analysis if item.get("parse_error")),
                "raw_parse_error_files": sum(1 for item in syntax_analysis if item.get("raw_parse_error")),
                "recovered_parse_error_files": sum(
                    1 for item in syntax_analysis if item.get("recovered_parse_error")
                ),
                "parse_error_file_names": [
                    str(item.get("file") or "") for item in syntax_analysis if item.get("parse_error")
                ],
                "ast_node_count": sum(int(item.get("ast_node_count") or 0) for item in syntax_analysis),
                "cfg_node_count": sum(int(item.get("cfg_node_count") or 0) for item in syntax_analysis),
                "cfg_edge_count": sum(int(item.get("cfg_edge_count") or 0) for item in syntax_analysis),
                "dfg_edge_count": sum(int(item.get("dfg_edge_count") or 0) for item in syntax_analysis),
            },
            "scenario_nodes": _scenario_nodes(scenarios),
            "conditional_edges": _scenario_edges(scenarios, bool(code_files)),
            "findings": findings,
            "finding_count": len(findings),
            "review_findings": review_findings,
            "review_finding_count": len(review_findings),
            "prompts": {
                "ast_cfg_dfg": AST_CFG_DFG_ANALYSIS_PROMPT,
                "selected_scenarios": [scenario["id"] for scenario in scenarios],
            },
            "diagnostics": diagnostics,
        }

    def _run_cli(
        self,
        code_files: list[dict[str, str]],
        project_files: list[dict[str, str]],
        dependency_scan: dict[str, Any],
        records: list[dict[str, Any]],
        *,
        rule_paths: list[str] | None = None,
        cancelled: Callable[[], bool] | None = None,
        complete_scan: bool = False,
    ) -> tuple[str, list[dict[str, Any]], list[str]]:
        cli_path = self._cli_path()
        if not cli_path:
            return "skipped", [], ["未包含随包静态分析 CLI，已使用内置 AST/CFG/DFG 分析。"]
        languages = {_language_for_file(item["file_name"]) for item in code_files}
        supported = set(supported_flow_languages())
        if not languages & supported:
            return "skipped", [], ["当前附件语言没有对应的离线 AST/CFG/DFG 规则，已使用内置分析。"]

        timeout = None if complete_scan else int(os.getenv("SECFLOW_SEMGREP_TIMEOUT_SECONDS", "180"))
        rule_timeout = 0 if complete_scan else int(os.getenv("SECFLOW_SEMGREP_RULE_TIMEOUT_SECONDS", "15"))
        rules_path = _semgrep_rules_path()
        if not rules_path:
            return "failed", [], ["离线多语言安全规则缺失，已使用内置 AST/CFG/DFG 分析。"]
        selected_rules = [Path(path) for path in (rule_paths or []) if Path(path).is_file()]
        if rule_paths and not selected_rules:
            return "failed", [], ["当前语言对应的离线安全规则缺失，已使用内置 AST/CFG/DFG 分析。"]
        configs = selected_rules or [rules_path]
        diagnostics: list[str] = []
        with tempfile.TemporaryDirectory(
            prefix="secflow-semgrep-",
            dir=_scan_temp_parent(),
        ) as temp_dir:
            root = Path(temp_dir)
            source_root = root / "src"
            result_path = root / "results.json"
            _write_code_files(source_root, project_files)
            analyze_cmd = [cli_path, "scan"]
            for config in configs:
                analyze_cmd.extend(["--config", str(config)])
            analyze_cmd.extend([
                "--json-output",
                str(result_path),
                "--dataflow-traces",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--project-root",
                str(source_root),
                "--timeout",
                str(rule_timeout if complete_scan else max(1, rule_timeout)),
                "--timeout-threshold",
                "3",
                "--max-target-bytes",
                "0" if complete_scan else "5000000",
                ".",
            ])
            for pattern in SEMGREP_EXCLUDE_PATTERNS:
                analyze_cmd.extend(["--exclude", pattern])
            try:
                if cancelled is None:
                    analyzed = subprocess.run(
                        analyze_cmd,
                        cwd=source_root,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=False,
                        env=_semgrep_subprocess_env(),
                    )
                else:
                    analyzed = _run_cancelable_process(
                        analyze_cmd,
                        cwd=source_root,
                        timeout=timeout,
                        env=_semgrep_subprocess_env(),
                        cancelled=cancelled,
                    )
                    if analyzed is None:
                        return "cancelled", [], ["静态分析已由用户停止。"]
            except subprocess.TimeoutExpired:
                return "timeout", [], [f"静态分析超过 {timeout}s，已使用内置分析结果。"]
            except Exception as exc:  # noqa: BLE001
                return "failed", [], [f"静态分析 CLI 执行失败：{exc}"]
            if analyzed.returncode != 0 or not result_path.exists():
                detail = (analyzed.stderr or analyzed.stdout or "").strip().splitlines()[-3:]
                diagnostics.append("静态分析 CLI 未返回 JSON：" + " / ".join(detail))
                return "failed", [], diagnostics
            findings, parse_diagnostics = _parse_semgrep_json(result_path, code_files, dependency_scan, records)
            diagnostics.extend(parse_diagnostics)
            return "completed", findings, diagnostics

    def _cli_path(self) -> str:
        if os.getenv("SECFLOW_SEMGREP_DISABLE_CLI", "").strip().lower() in {"1", "true", "yes", "on"}:
            return ""
        explicit = self.executable or os.getenv("SECFLOW_BUNDLED_SEMGREP_BIN", "").strip()
        if explicit:
            explicit_path = Path(explicit).expanduser()
            if explicit_path.exists():
                return str(explicit_path.resolve())
            resolved = shutil.which(explicit)
            return resolved or ""

        bundled = _bundled_semgrep_path()
        return str(bundled) if bundled else ""


def _analysis_cancelled(cancelled: Callable[[], bool] | None) -> bool:
    if cancelled is None:
        return False
    try:
        return bool(cancelled())
    except Exception:  # noqa: BLE001 - a broken cancel callback must not crash the scan.
        return False


def _cancelled_analysis_result(rule_paths: list[str] | None, diagnostics: list[str]) -> dict[str, Any]:
    return {
        "status": "cancelled",
        "tool": "AegisAl Static Analyzer",
        "cli_status": "cancelled",
        "mode": "cancelled",
        "rule_paths": list(rule_paths or []),
        "generated_at": now_iso(),
        "files": [],
        "syntax_summary": {
            "languages": [],
            "parsed_files": 0,
            "parse_error_files": 0,
            "raw_parse_error_files": 0,
            "recovered_parse_error_files": 0,
            "parse_error_file_names": [],
            "ast_node_count": 0,
            "cfg_node_count": 0,
            "cfg_edge_count": 0,
            "dfg_edge_count": 0,
        },
        "scenario_nodes": [],
        "conditional_edges": [],
        "findings": [],
        "finding_count": 0,
        "review_findings": [],
        "review_finding_count": 0,
        "prompts": {
            "ast_cfg_dfg": AST_CFG_DFG_ANALYSIS_PROMPT,
            "selected_scenarios": [],
        },
        "diagnostics": list(diagnostics),
    }


def analyze_static_paths(
    attachments: list[dict[str, Any]],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    return semgrep_tool.analyze(attachments, dependency_scan, records)


def semgrep_rule_paths_for_language(language: str) -> list[str]:
    root = _semgrep_rules_path()
    if root is None:
        return []
    if root.is_file():
        return [str(root)]
    return [
        str(path)
        for file_name in LANGUAGE_SEMGREP_RULE_FILES.get(language, ())
        if (path := root / file_name).is_file()
    ]


def _semgrep_subprocess_env() -> dict[str, str]:
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    if getattr(sys, "frozen", False):
        # The backend and Semgrep are separate PyInstaller applications. Without
        # this reset the child may reuse the backend's archive metadata and fail
        # before validating or scanning any rules.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def _run_cancelable_process(
    command: list[str],
    *,
    cwd: Path,
    timeout: int | None,
    env: dict[str, str],
    cancelled: Callable[[], bool],
) -> subprocess.CompletedProcess[str] | None:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=sys.platform != "win32",
    )
    deadline = time.monotonic() + timeout if timeout is not None else None
    while process.poll() is None:
        if cancelled():
            _stop_process(process)
            return None
        if deadline is not None and time.monotonic() >= deadline:
            _stop_process(process)
            stdout, stderr = process.communicate()
            raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
        time.sleep(0.1)
    stdout, stderr = process.communicate()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        if sys.platform != "win32":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if sys.platform != "win32":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _scan_temp_parent() -> str | None:
    configured = os.getenv("SECFLOW_SCAN_TEMP_ROOT", "").strip()
    if not configured:
        return None
    try:
        path = Path(configured).resolve(strict=True)
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        path.relative_to(temp_root)
    except (OSError, RuntimeError, ValueError):
        return None
    if not path.is_dir() or not path.name.startswith("secflow-code-scan-runtime-"):
        return None
    return str(path)


def _code_attachments(
    attachments: list[dict[str, Any]],
    *,
    include_all_attachments: bool = False,
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    selected = attachments if include_all_attachments else attachments[:MAX_ASK_ATTACHMENTS]
    for attachment in selected:
        file_name = str(attachment.get("file_name") or attachment.get("fileName") or "").strip()
        content = str(attachment.get("content") or "")
        if not file_name or not content or not is_allowed_attachment_name(file_name):
            continue
        if not is_analyzable_source_path(file_name):
            continue
        if is_symlink_like_source_stub(file_name, content):
            continue
        if attachment_kind(file_name) == "code":
            result.append({"file_name": file_name, "content": content})
    return result


def _project_attachments(
    attachments: list[dict[str, Any]],
    *,
    include_all_attachments: bool = False,
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    selected = attachments if include_all_attachments else attachments[:MAX_ASK_ATTACHMENTS]
    for attachment in selected:
        file_name = str(attachment.get("file_name") or attachment.get("fileName") or "").strip()
        content = str(attachment.get("content") or "")
        if not file_name or not content or not is_allowed_attachment_name(file_name):
            continue
        kind = attachment_kind(file_name)
        if kind != "code" or is_analyzable_source_path(file_name):
            result.append({"file_name": file_name, "content": content})
    return result


def _compile_definitions_by_source_file(project_files: list[dict[str, str]]) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    for project_file in project_files:
        file_name = str(project_file.get("file_name") or "").replace("\\", "/")
        if Path(file_name).name.lower() != "compile_commands.json":
            continue
        try:
            payload = json.loads(str(project_file.get("content") or ""))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, list):
            continue
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            source_file = str(entry.get("file") or "").replace("\\", "/").strip()
            if not source_file:
                continue
            definitions = _compile_command_definitions(entry)
            if definitions:
                contexts.append({"file_name": source_file, "definitions": definitions})
    return contexts


def _project_preprocessor_definitions(project_files: list[dict[str, str]]) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for project_file in project_files:
        file_name = str(project_file.get("file_name") or "").replace("\\", "/")
        if Path(file_name).name.lower() != "cmakelists.txt":
            continue
        definitions.update(_cmake_preprocessor_definitions(str(project_file.get("content") or "")))
    return definitions


def _project_overlay_preprocessor_definitions(dependency_scan: dict[str, Any]) -> dict[str, str]:
    values = dependency_scan.get("project_preprocessor_definitions") or {}
    if not isinstance(values, dict):
        return {}
    return {
        str(name): str(value)[:80]
        for name, value in values.items()
        if re.fullmatch(r"[A-Za-z_]\w*", str(name))
    }


def _cmake_preprocessor_definitions(content: str) -> dict[str, str]:
    definitions: dict[str, str] = {}
    clean_content = _strip_cmake_comments(content)
    for command, body in _cmake_command_bodies(clean_content):
        command_name = command.casefold()
        tokens = _cmake_tokens(body)
        if command_name == "add_definitions":
            definitions.update(_definition_tokens(tokens, require_prefix=True))
        elif command_name == "add_compile_definitions":
            definitions.update(_definition_tokens(tokens, require_prefix=False))
        elif command_name == "target_compile_definitions":
            scoped_tokens = [token for token in tokens[1:] if token.upper() not in {"PRIVATE", "PUBLIC", "INTERFACE"}]
            definitions.update(_definition_tokens(scoped_tokens, require_prefix=False))
    return definitions


def _strip_cmake_comments(content: str) -> str:
    lines: list[str] = []
    for line in content.splitlines():
        in_quote = False
        escaped = False
        end = len(line)
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_quote = not in_quote
                continue
            if char == "#" and not in_quote:
                end = index
                break
        lines.append(line[:end])
    return "\n".join(lines)


def _cmake_command_bodies(content: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    command_pattern = re.compile(r"\b(?P<name>add_definitions|add_compile_definitions|target_compile_definitions)\s*\(", re.IGNORECASE)
    for match in command_pattern.finditer(content):
        opening = content.find("(", match.start())
        closing = _matching_text_parenthesis(content, opening)
        if closing is None:
            continue
        result.append((match.group("name"), content[opening + 1 : closing]))
    return result


def _matching_text_parenthesis(content: str, opening: int) -> int | None:
    depth = 0
    in_quote = False
    escaped = False
    for index in range(opening, len(content)):
        char = content[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _cmake_tokens(body: str) -> list[str]:
    normalized = body.replace(";", " ")
    try:
        return shlex.split(normalized)
    except ValueError:
        return normalized.split()


def _definition_tokens(tokens: list[str], *, require_prefix: bool) -> dict[str, str]:
    definitions: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        value = ""
        if token in {"-D", "/D"} and index + 1 < len(tokens):
            value = tokens[index + 1]
            index += 2
        else:
            value = token
            index += 1
        parsed = _definition_token(value, require_prefix=require_prefix)
        if parsed is not None:
            name, definition_value = parsed
            definitions[name] = definition_value
    return definitions


def _compile_definitions_for_file(file_name: str, contexts: list[dict[str, Any]]) -> dict[str, str]:
    normalized = file_name.replace("\\", "/").strip()
    matches: list[dict[str, Any]] = []
    for context in contexts:
        candidate = str(context.get("file_name") or "").replace("\\", "/").strip()
        if (
            normalized == candidate
            or candidate.endswith("/" + normalized)
            or normalized.endswith("/" + candidate)
        ):
            matches.append(context)
    if not matches:
        return {}
    best = max(matches, key=lambda item: len(str(item.get("file_name") or "")))
    return dict(best.get("definitions") or {})


def _compile_command_definitions(entry: dict[str, Any]) -> dict[str, str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        tokens = [str(item) for item in arguments]
    else:
        command = str(entry.get("command") or "")
        if not command:
            return {}
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
    definitions: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        value = ""
        if token in {"-D", "/D"} and index + 1 < len(tokens):
            value = tokens[index + 1]
            index += 2
        elif token.startswith("-D") and len(token) > 2:
            value = token[2:]
            index += 1
        elif token.startswith("/D") and len(token) > 2:
            value = token[2:]
            index += 1
        else:
            index += 1
        if value:
            parsed = _definition_token(value, require_prefix=False)
            if parsed is not None:
                name, definition_value = parsed
                definitions[name] = definition_value
    return definitions


def _definition_token(value: str, *, require_prefix: bool) -> tuple[str, str] | None:
    token = value.strip().strip('"').strip("'")
    if token.startswith("-D") or token.startswith("/D"):
        token = token[2:]
    elif require_prefix:
        return None
    if not token or token.startswith(("$", "<", "${")):
        return None
    name, _, definition_value = token.partition("=")
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return None
    return name, definition_value


def _bundled_semgrep_path() -> Path | None:
    candidates: list[Path] = []
    raw_executable = Path(sys.executable)
    candidates.extend(
        [
            raw_executable.parent / "semgrep",
            raw_executable.parent / "semgrep.exe",
        ]
    )
    executable = raw_executable.resolve()
    executable_parent = executable.parent
    candidates.extend(
        [
            executable_parent / "semgrep",
            executable_parent / "semgrep" / "semgrep",
            executable_parent / "semgrep" / "secflow-semgrep",
            executable_parent / "semgrep" / "semgrep.exe",
            executable_parent / "semgrep" / "secflow-semgrep.exe",
            executable_parent.parent / "semgrep" / "semgrep",
            executable_parent.parent / "semgrep" / "secflow-semgrep",
            executable_parent.parent / "semgrep" / "semgrep.exe",
            executable_parent.parent / "semgrep" / "secflow-semgrep.exe",
            executable_parent.parent.parent / "semgrep" / "semgrep",
            executable_parent.parent.parent / "semgrep" / "secflow-semgrep",
            executable_parent.parent.parent / "semgrep" / "semgrep.exe",
            executable_parent.parent.parent / "semgrep" / "secflow-semgrep.exe",
            executable_parent.parent / "Resources" / "semgrep" / "semgrep",
            executable_parent.parent / "Resources" / "semgrep" / "secflow-semgrep",
            executable_parent.parent.parent / "Resources" / "semgrep" / "semgrep",
            executable_parent.parent.parent / "Resources" / "semgrep" / "secflow-semgrep",
        ]
    )
    try:
        source_root = Path(__file__).resolve().parents[1]
        candidates.extend(
            [
                source_root / "vendor" / "semgrep" / "semgrep",
                source_root / "tools" / "semgrep" / "semgrep",
            ]
        )
    except IndexError:
        pass
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _semgrep_rules_path() -> Path | None:
    explicit = os.getenv("SECFLOW_SEMGREP_RULES", "").strip()
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.is_file() or path.is_dir() else None

    executable_parent = Path(sys.executable).resolve().parent
    candidates = [
        executable_parent / "semgrep-rules",
        executable_parent.parent / "semgrep-rules",
        executable_parent.parent.parent / "semgrep-rules",
    ]
    try:
        source_root = Path(__file__).resolve().parents[1]
        candidates.append(source_root / DEFAULT_SEMGREP_RULES)
    except IndexError:
        pass
    return next((path for path in candidates if path.is_file() or path.is_dir()), None)


def _select_scenarios(
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    code_files: list[dict[str, str]],
) -> list[dict[str, Any]]:
    text_parts: list[str] = []
    for dependency in dependency_scan.get("dependencies") or []:
        text_parts.append(str(dependency.get("name") or ""))
    for record in records:
        text_parts.extend(
            [
                str(record.get("id") or ""),
                str(record.get("title") or ""),
                str(record.get("summary") or ""),
                " ".join(str(item) for item in record.get("cwes") or []),
            ]
        )
    for code_file in code_files:
        text_parts.append(code_file["content"][:4000])
    haystack = "\n".join(text_parts).lower()
    selected_ids: set[str] = set()
    for token, scenario_id in COMPONENT_SCENARIO_HINTS:
        if token in haystack:
            selected_ids.add(scenario_id)
    if re.search(r"runtime\.getruntime|processbuilder|命令执行|command", haystack):
        selected_ids.add("command_execution")
    if re.search(r"statement|executequery|sql|注入|cwe-89", haystack):
        selected_ids.add("sql_injection")
    if re.search(r"readobject|objectmapper|yaml|反序列化|cwe-502", haystack):
        selected_ids.add("deserialization")
    if re.search(r"logger\.|logmanager|日志|lookup|jndi", haystack):
        selected_ids.add("log_injection_lookup")
    if re.search(r"\bfile\b|paths?\.|文件|路径|cwe-22", haystack):
        selected_ids.add("path_traversal")
    if re.search(r"httpservletresponse|printwriter|xss|跨站|cwe-79", haystack):
        selected_ids.add("cross_site_scripting")
    if re.search(r"httpclient|resttemplate|openconnection|ssrf|cwe-918", haystack):
        selected_ids.add("ssrf")
    if re.search(r"documentbuilder|saxparser|xml|xxe|cwe-611", haystack):
        selected_ids.add("xml_external_entity")
    if re.search(r"payment|refund|transfer|withdraw|deposit|recharge|settle|checkout|trade|幂等|扣款|入账|退款|提现", haystack):
        selected_ids.update({"idempotency_missing", "funds_transaction_boundary"})
    if re.search(r"bigdecimal|amount|money|balance|price|fee|total|资金|金额|余额|手续费", haystack):
        selected_ids.add("funds_precision")
    if not selected_ids:
        selected_ids.add("generic_reachability")
    return [dict(item) for item in SCENARIO_DEFINITIONS if item["id"] in selected_ids]


def _heuristic_findings(
    code_files: list[dict[str, str]],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    scenario_ids = {item["id"] for item in scenarios}
    findings: list[dict[str, Any]] = []
    for code_file in code_files:
        file_name = code_file["file_name"]
        lines = [CodeLine(file_name, index, text.rstrip()) for index, text in enumerate(code_file["content"].splitlines(), start=1)]
        sources = _matching_lines(lines, SOURCE_PATTERNS)
        sinks = _matching_sinks(lines)
        snippet_hits = _record_snippet_hits(lines, records)
        ast = _ast_summary(file_name, code_file["content"], language_hint=code_file.get("language_hint"))
        findings.extend(
            _finance_fallback_findings(
                lines,
                code_file["content"],
                scenario_ids,
                ast,
                dependency_scan,
                records,
                len(findings),
            )
        )
        for sink in sinks:
            scenario_id = sink["scenario"]
            if scenario_id not in scenario_ids and "generic_reachability" not in scenario_ids:
                continue
            source = _nearest_source_before(sources, sink["line"])
            if not source:
                continue
            if scenario_id == "log_injection_lookup" and not _source_symbol_in_sink(source, sink):
                continue
            path = _build_path(source, sink, lines)
            record = _best_record_for_scenario(records, dependency_scan, scenario_id, str(sink.get("snippet") or ""))
            findings.append(
                {
                    "id": f"heuristic-{len(findings) + 1}",
                    "engine": "static-path-analysis",
                    "scenario": scenario_id,
                    "title": _scenario_label(scenario_id),
                    "record_id": str(record.get("id") or ""),
                    "component": _component_label(record, dependency_scan),
                    "severity": str(record.get("severity") or "UNKNOWN").upper(),
                    "confidence": "high" if source else "medium",
                    "source": source or {},
                    "sink": sink,
                    "path": path,
                    "ast": ast,
                    "cfg": _cfg_summary(path),
                    "dfg": _dfg_summary(path),
                    "evidence": _snippet_evidence(snippet_hits, sink),
                }
            )
        for hit in snippet_hits:
            if any(item.get("sink", {}).get("line") == hit["line"] for item in findings):
                continue
            record = _record_by_id(records, hit.get("record_id", ""))
            findings.append(
                {
                    "id": f"snippet-{len(findings) + 1}",
                    "engine": "static-pattern-analysis",
                    "scenario": "generic_reachability",
                    "title": "漏洞代码片段命中",
                    "record_id": hit.get("record_id", ""),
                    "component": _component_label(record, dependency_scan),
                    "severity": str(record.get("severity") or "UNKNOWN").upper(),
                    "confidence": "medium",
                    "source": {},
                    "sink": {"file": file_name, "line": hit["line"], "kind": "snippet_match", "snippet": hit["snippet"]},
                    "path": [{"kind": "snippet_match", "file": file_name, "line": hit["line"], "label": "命中漏洞记录中的代码模式", "snippet": hit["snippet"]}],
                    "ast": ast,
                    "cfg": "已在上传代码中发现与漏洞记录一致的调用片段；需要结合业务入口确认可达性。",
                    "dfg": "未确认完整 source→sink 数据流；该发现作为组件可达性证据。",
                    "evidence": hit["snippet"],
                }
            )
    return _prioritize_static_findings(findings)[:_max_findings()]


def _finance_fallback_findings(
    lines: list[CodeLine],
    content: str,
    scenario_ids: set[str],
    ast: dict[str, Any],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    finding_offset: int,
) -> list[dict[str, Any]]:
    """Internal AST/CFG/DFG fallback for business-finance risks when the bundled CLI is unavailable."""
    selected = scenario_ids | ({"funds_precision", "idempotency_missing", "funds_transaction_boundary"} if "generic_reachability" in scenario_ids else set())
    result: list[dict[str, Any]] = []
    spans = _java_method_spans(content)
    if "idempotency_missing" in selected:
        result.extend(
            _finance_idempotency_findings(
                lines,
                spans,
                ast,
                dependency_scan,
                records,
                finding_offset + len(result),
            )
        )
    if "funds_precision" in selected:
        result.extend(
            _finance_precision_findings(
                lines,
                ast,
                dependency_scan,
                records,
                finding_offset + len(result),
            )
        )
    if not spans:
        return result
    if "funds_transaction_boundary" in selected:
        result.extend(
            _finance_transaction_findings(
                lines,
                spans,
                ast,
                dependency_scan,
                records,
                finding_offset + len(result),
            )
        )
    return result


def _finance_precision_findings(
    lines: list[CodeLine],
    ast: dict[str, Any],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    finding_offset: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in lines:
        declaration = FINANCE_FLOAT_DECLARATION_RE.search(item.text)
        big_decimal_from_float = re.search(r"new\s+(?:java\.math\.)?BigDecimal\s*\([^)]*(?:\d+\.\d+|double|float|Double|Float)", item.text)
        if declaration and not FINANCE_AMOUNT_RE.search(declaration.group("name")):
            continue
        if declaration and _looks_like_method_signature_parameter(item.text):
            continue
        if not declaration and not big_decimal_from_float:
            continue
        record = _best_record_for_scenario(records, dependency_scan, "funds_precision", item.text)
        sink = {
            "file": item.file_name,
            "line": item.line,
            "kind": "finance_precision",
            "scenario": "funds_precision",
            "snippet": item.text.strip(),
        }
        findings.append(
            _finance_finding(
                finding_id=f"finance-precision-{finding_offset + len(findings) + 1}",
                scenario="funds_precision",
                title="资金金额精度风险",
                record=record,
                dependency_scan=dependency_scan,
                sink=sink,
                path=[{"kind": "sink", "file": item.file_name, "line": item.line, "label": "资金金额浮点类型 sink", "snippet": item.text.strip()}],
                ast=ast,
                cfg="AST 发现资金金额、余额或费用字段使用 float/double，后续金额计算可能产生精度偏差。",
                dfg="金额字段 → 浮点表示 → 资金计算/持久化",
                evidence=item.text.strip(),
                confidence="medium",
            )
        )
    return findings


def _finance_idempotency_findings(
    lines: list[CodeLine],
    spans: list[JavaMethodSpan],
    ast: dict[str, Any],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    finding_offset: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for span in spans:
        header = _java_method_header(lines, span)
        body = _java_span_text(lines, span)
        haystack = f"{header}\n{body}"
        if not FINANCE_MUTATING_HTTP_ANNOTATION_RE.search(header):
            continue
        if IDEMPOTENCY_GUARD_RE.search(haystack):
            continue
        if not _finance_method_or_body(span.name, haystack):
            continue
        sink_line = _first_finance_service_call(lines, span, header)
        if not sink_line:
            continue
        source = {
            "file": sink_line.file_name,
            "line": span.start,
            "kind": "method_parameter",
            "symbol": "",
            "snippet": _line_text(lines, span.start),
        }
        sink = {
            "file": sink_line.file_name,
            "line": sink_line.line,
            "kind": "finance_endpoint_call",
            "scenario": "idempotency_missing",
            "snippet": sink_line.text.strip(),
        }
        path = _build_path(source, sink, lines)
        record = _best_record_for_scenario(records, dependency_scan, "idempotency_missing", sink_line.text)
        findings.append(
            _finance_finding(
                finding_id=f"finance-idempotency-{finding_offset + len(findings) + 1}",
                scenario="idempotency_missing",
                title="资金接口缺少幂等键",
                record=record,
                dependency_scan=dependency_scan,
                sink=sink,
                path=path,
                ast=ast,
                cfg="Controller 资金入口可重复触发服务调用，未看到 Idempotency-Key 或业务流水去重校验。",
                dfg=f"HTTP 请求参数 → {span.name}() → {sink_line.text.strip()}",
                evidence=sink_line.text.strip(),
                confidence="medium",
                source=source,
            )
        )
    return findings


def _finance_transaction_findings(
    lines: list[CodeLine],
    spans: list[JavaMethodSpan],
    ast: dict[str, Any],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
    finding_offset: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for span in spans:
        header = _java_method_header(lines, span)
        body = _java_span_text(lines, span)
        if TRANSACTION_GUARD_RE.search(f"{header}\n{body}"):
            continue
        if not FINANCE_ACTION_RE.search(span.name):
            continue
        mutation_lines = [item for item in _span_lines(lines, span) if FINANCE_STATE_MUTATION_RE.search(item.text)]
        if not mutation_lines:
            continue
        for item in mutation_lines:
            sink = {
                "file": item.file_name,
                "line": item.line,
                "kind": "finance_state_mutation",
                "scenario": "funds_transaction_boundary",
                "snippet": item.text.strip(),
            }
            record = _best_record_for_scenario(records, dependency_scan, "funds_transaction_boundary", item.text)
            findings.append(
                _finance_finding(
                    finding_id=f"finance-transaction-{finding_offset + len(findings) + 1}",
                    scenario="funds_transaction_boundary",
                    title="资金更新缺少事务边界",
                    record=record,
                    dependency_scan=dependency_scan,
                    sink=sink,
                    path=[
                        {
                            "kind": "method",
                            "file": item.file_name,
                            "line": span.start,
                            "label": "资金业务方法",
                            "snippet": _line_text(lines, span.start),
                        },
                        {
                            "kind": "sink",
                            "file": item.file_name,
                            "line": item.line,
                            "label": "资金状态更新/持久化 sink",
                            "snippet": item.text.strip(),
                        },
                    ],
                    ast=ast,
                    cfg=f"{span.name}() 内发现资金状态更新，但方法或代码块上未看到事务边界。",
                    dfg=f"{span.name}() → 第 {item.line} 行资金状态更新/持久化",
                    evidence=item.text.strip(),
                    confidence="medium",
                )
            )
    return findings


def _finance_finding(
    *,
    finding_id: str,
    scenario: str,
    title: str,
    record: dict[str, Any],
    dependency_scan: dict[str, Any],
    sink: dict[str, Any],
    path: list[dict[str, Any]],
    ast: dict[str, Any],
    cfg: str,
    dfg: str,
    evidence: str,
    confidence: str,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "engine": "static-business-flow-analysis",
        "scenario": scenario,
        "title": title,
        "rule_id": f"secflow.java.finance.{scenario}",
        "record_id": str(record.get("id") or "") if record else "",
        "component": _component_label(record, dependency_scan) if record else "",
        "severity": str(record.get("severity") or "MEDIUM").upper() if record else "MEDIUM",
        "confidence": confidence,
        "source": source or {},
        "sink": sink,
        "path": path,
        "ast": ast,
        "cfg": cfg,
        "dfg": dfg,
        "evidence": evidence,
    }


def _matching_lines(lines: list[CodeLine], patterns: tuple[tuple[str, str], ...]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in lines:
        if item.text.lstrip().startswith("import "):
            continue
        for kind, pattern in patterns:
            if re.search(pattern, item.text):
                symbol = _method_parameter_symbol(item.text) if kind == "method_parameter" else ""
                symbol = symbol or _assigned_symbol(item.text) or _first_identifier(item.text)
                matches.append({"file": item.file_name, "line": item.line, "kind": kind, "symbol": symbol, "snippet": item.text.strip()})
                break
    return matches


def _matching_sinks(lines: list[CodeLine]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in lines:
        for kind, pattern, scenario in SINK_PATTERNS:
            if re.search(pattern, item.text, flags=re.IGNORECASE):
                matches.append({"file": item.file_name, "line": item.line, "kind": kind, "scenario": scenario, "snippet": item.text.strip()})
                break
    return matches


def _nearest_source_before(sources: list[dict[str, Any]], line: int) -> dict[str, Any] | None:
    candidates = [item for item in sources if int(item.get("line") or 0) <= line]
    return max(candidates, key=lambda item: int(item.get("line") or 0)) if candidates else None


def _source_symbol_in_sink(source: dict[str, Any], sink: dict[str, Any]) -> bool:
    symbol = str(source.get("symbol") or "").strip()
    snippet = str(sink.get("snippet") or "")
    return bool(symbol and re.search(rf"\b{re.escape(symbol)}\b", snippet))


def _build_path(source: dict[str, Any] | None, sink: dict[str, Any], lines: list[CodeLine]) -> list[dict[str, Any]]:
    path: list[dict[str, Any]] = []
    if source:
        path.append({"kind": "source", "file": source["file"], "line": source["line"], "label": _source_label(source), "snippet": source["snippet"]})
        for condition in _conditions_between(lines, int(source["line"]), int(sink["line"])):
            path.append(condition)
    path.append({"kind": "sink", "file": sink["file"], "line": sink["line"], "label": _sink_label(sink), "snippet": sink["snippet"]})
    return path


def _conditions_between(lines: list[CodeLine], start: int, end: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in lines:
        if start <= item.line <= end and re.search(r"^\s*(if|for|while|try|catch|switch)\b", item.text):
            result.append({"kind": "cfg_condition", "file": item.file_name, "line": item.line, "label": "控制流条件", "snippet": item.text.strip()})
            if len(result) >= 4:
                break
    return result


def _ast_summary(file_name: str, content: str, *, language_hint: str | None = None) -> dict[str, Any]:
    analysis = analyze_source_structure(file_name, content, language_hint=language_hint)
    # Preserve the legacy keys consumed by existing Java reports.
    analysis["classes"] = list(analysis.get("types") or [])
    analysis["methods"] = list(analysis.get("functions") or [])
    return analysis


def _cfg_summary(path: list[dict[str, Any]]) -> str:
    conditions = [item for item in path if item.get("kind") == "cfg_condition"]
    if conditions:
        return "source 到 sink 之间经过控制条件：" + "；".join(f"{item.get('file')}:{item.get('line')}" for item in conditions)
    if any(item.get("kind") == "source" for item in path):
        return "source 与 sink 位于同一顺序执行路径，未发现显式分支条件。"
    return "未确认 source，仅确认 sink 或漏洞代码片段在上传代码中出现。"


def _dfg_summary(path: list[dict[str, Any]]) -> str:
    labels = [str(item.get("label") or item.get("kind") or "") for item in path]
    return " → ".join(label for label in labels if label)


def _record_snippet_hits(lines: list[CodeLine], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for record in records:
        for snippet in record.get("code_snippets") or []:
            needle = _normalize_code(str(snippet))
            if not needle:
                continue
            for item in lines:
                if _normalize_code(item.text) and (_normalize_code(item.text) in needle or needle in _normalize_code(item.text)):
                    hits.append({"record_id": str(record.get("id") or ""), "line": item.line, "snippet": item.text.strip()})
                    break
    return hits[:10]


def _snippet_evidence(snippet_hits: list[dict[str, Any]], sink: dict[str, Any]) -> str:
    for hit in snippet_hits:
        if hit.get("line") == sink.get("line"):
            return str(hit.get("snippet") or "")
    return str(sink.get("snippet") or "")


def _normalize_code(value: str) -> str:
    return re.sub(r"\s+", "", value.strip().lower())


def _assigned_symbol(text: str) -> str:
    match = re.search(r"\b([A-Za-z_]\w*)\s*(?::=|=)", text)
    return match.group(1) if match else ""


def _first_identifier(text: str) -> str:
    match = re.search(r"\b([A-Za-z_]\w*)\b", text)
    return match.group(1) if match else ""


def _source_label(source: dict[str, Any]) -> str:
    return {
        "http_parameter": "外部 HTTP 参数 source",
        "http_request": "HTTP 请求对象 source",
        "cli_argument": "命令行/环境变量 source",
        "stream_reader": "流式输入 source",
        "file_upload": "文件上传 source",
        "method_parameter": "方法输入参数 source",
    }.get(str(source.get("kind") or ""), "外部输入 source")


def _sink_label(sink: dict[str, Any]) -> str:
    return {
        "logger_sink": "日志输出 sink",
        "jndi_lookup": "JNDI lookup sink",
        "deserialization_sink": "反序列化 sink",
        "command_sink": "命令执行 sink",
        "sql_sink": "SQL 执行 sink",
        "script_sink": "脚本执行 sink",
    }.get(str(sink.get("kind") or ""), "危险调用 sink")


def _scenario_label(scenario_id: str) -> str:
    for item in SCENARIO_DEFINITIONS:
        if item["id"] == scenario_id:
            return str(item["label"])
    return "组件可达性路径"


def _best_record_for_scenario(
    records: list[dict[str, Any]],
    dependency_scan: dict[str, Any],
    scenario_id: str,
    code_hint: str = "",
) -> dict[str, Any]:
    if not records:
        return {}
    lowered_hint = code_hint.lower()
    component_hints: list[str] = []
    if "yaml" in lowered_hint:
        component_hints.append("snakeyaml")
    if "objectmapper" in lowered_hint or "readvalue" in lowered_hint:
        component_hints.append("jackson")
    if re.search(r"\b(?:logger|log)\w*\.", lowered_hint):
        component_hints.append("log4j")
    for component_hint in component_hints:
        for record in records:
            if component_hint in json.dumps(record, ensure_ascii=False).lower():
                return record
    scenario_text = scenario_id.replace("_", " ")
    for record in records:
        blob = " ".join(
            [
                str(record.get("title") or ""),
                str(record.get("summary") or ""),
                " ".join(str(item) for item in record.get("cwes") or []),
                json.dumps(record.get("components") or [], ensure_ascii=False),
            ]
        ).lower()
        if any(token in blob for token in scenario_text.split()):
            return record
    dependencies = json.dumps(dependency_scan.get("dependencies") or [], ensure_ascii=False).lower()
    if "log4j" in dependencies:
        for record in records:
            if "log4j" in json.dumps(record, ensure_ascii=False).lower():
                return record
    return {}


def _method_parameter_symbol(text: str) -> str:
    match = re.search(r"\(([^)]*)\)", text)
    if not match:
        return ""
    parameters = [item.strip() for item in match.group(1).split(",") if item.strip()]
    if not parameters:
        return ""
    tokens = re.findall(r"[A-Za-z_]\w*", parameters[-1])
    return tokens[-1] if tokens else ""


def _record_by_id(records: list[dict[str, Any]], record_id: str) -> dict[str, Any]:
    for record in records:
        if str(record.get("id") or "") == record_id:
            return record
    return records[0] if records else {}


def _span_lines(lines: list[CodeLine], span: JavaMethodSpan) -> list[CodeLine]:
    return [item for item in lines if span.start <= item.line <= span.end]


def _java_span_text(lines: list[CodeLine], span: JavaMethodSpan) -> str:
    return "\n".join(item.text for item in _span_lines(lines, span))


def _java_method_header(lines: list[CodeLine], span: JavaMethodSpan) -> str:
    by_line = {item.line: item.text for item in lines}
    start = max(1, span.start - 8)
    header_lines: list[str] = []
    for line_number in range(start, span.start + 1):
        text = by_line.get(line_number, "")
        stripped = text.strip()
        if not stripped and header_lines:
            header_lines = []
            continue
        if stripped.startswith("@") or line_number == span.start:
            header_lines.append(text)
    return "\n".join(header_lines)


def _line_text(lines: list[CodeLine], line: int) -> str:
    for item in lines:
        if item.line == line:
            return item.text.strip()
    return ""


def _finance_method_or_body(method_name: str, body: str) -> bool:
    if FINANCE_NON_FUNDS_METHOD_RE.search(method_name):
        return False
    if _finance_context_is_non_funds_idempotency(method_name, body):
        return False
    if re.search(r"^(?:reject|decline)\w*$", method_name, flags=re.IGNORECASE) and re.search(
        r"chargeback", body, flags=re.IGNORECASE
    ) and not re.search(r"refund|credit|addFunds|amount", body, flags=re.IGNORECASE):
        return False
    if re.search(r"chargeback", body, flags=re.IGNORECASE) and re.search(
        r"\b(?:approve|request|create|add|credit|refund)\b", f"{method_name}\n{body}", flags=re.IGNORECASE
    ):
        return True
    if re.search(r"disbursement|disburse", f"{method_name}\n{body}", flags=re.IGNORECASE):
        return True
    if re.search(r"repay|repayment|makeRepayment", f"{method_name}\n{body}", flags=re.IGNORECASE):
        return True
    if re.search(r"captureOrder|capture[-_]?order", f"{method_name}\n{body}", flags=re.IGNORECASE):
        return True
    if FINANCE_ACTION_RE.search(method_name):
        return True
    if FINANCE_ACTION_RE.search(body) and FINANCE_AMOUNT_RE.search(body):
        return True
    return bool(re.search(r"\b(?:wallet|account|balance|bill|transaction)\b", body, flags=re.IGNORECASE) and FINANCE_AMOUNT_RE.search(body))


def _looks_like_method_signature_parameter(text: str) -> bool:
    stripped = text.strip()
    if "(" not in stripped:
        return False
    if "=" in stripped:
        return False
    if re.search(r"\b(?:public|private|protected)\s+[A-Za-z_$][\w$]*\s*\(", stripped):
        return True
    return bool(re.search(r"\)\s*(?:throws\b[^{;]*)?[{;]?\s*$", stripped))


def _first_finance_service_call(lines: list[CodeLine], span: JavaMethodSpan, extra_context: str = "") -> CodeLine | None:
    span_text = f"{extra_context}\n{_java_span_text(lines, span)}"
    for item in _span_lines(lines, span):
        for match in FINANCE_SERVICE_CALL_RE.finditer(item.text):
            called = match.group("call")
            if _is_finance_mutating_call(called, item.text, span.name, span_text):
                return item
    return None


def _is_finance_mutating_call(called: str, text: str, method_name: str = "", method_body: str = "") -> bool:
    if FINANCE_NON_FUNDS_METHOD_RE.search(called):
        return False
    if FINANCE_UTILITY_CALL_RE.search(called):
        return False
    if _finance_context_is_non_funds_idempotency(method_name, method_body):
        return False
    if re.search(r"^(?:un)?freezeAccount$", called, flags=re.IGNORECASE) and not re.search(
        r"amount|balance|wallet|minor", text, flags=re.IGNORECASE
    ):
        return False
    if FINANCE_READ_ONLY_CALL_RE.search(called):
        return False
    if FINANCE_PROFILE_CALL_RE.search(called) and not FINANCE_STRONG_MUTATION_RE.search(text):
        return False
    finance_context = f"{text}\n{method_name}\n{method_body}"
    if re.search(r"^(?:reject|decline)\w*$", called, flags=re.IGNORECASE) and re.search(
        r"chargeback", finance_context, flags=re.IGNORECASE
    ) and not re.search(r"refund|credit|addFunds|amount", finance_context, flags=re.IGNORECASE):
        return False
    if re.search(r"^(?:process|proceed)\w*$", called, flags=re.IGNORECASE) and re.search(
        r"BankPayment|PaymentRequest|PaymentResponse|payment|charge|checkout", finance_context, flags=re.IGNORECASE
    ):
        return True
    if re.search(r"chargeback", finance_context, flags=re.IGNORECASE) and re.search(
        r"^(?:approve|request|add|create|save|credit|refund)$", called, flags=re.IGNORECASE
    ):
        return True
    if re.search(r"disbursement|disburse", finance_context, flags=re.IGNORECASE) and re.search(
        r"^(?:add|create|save|insert|submit|process|approve)$", called, flags=re.IGNORECASE
    ):
        return True
    if re.search(r"repay|repayment|makeRepayment", finance_context, flags=re.IGNORECASE) and re.search(
        r"^(?:repay|makeRepayment|pay|save|update|process)$", called, flags=re.IGNORECASE
    ):
        return True
    if re.search(r"captureOrder|capture[-_]?order", finance_context, flags=re.IGNORECASE) and re.search(
        r"^(?:capture|captureOrder|process)$", called, flags=re.IGNORECASE
    ):
        return True
    if FINANCE_PERSISTENCE_CALL_RE.search(called) and FINANCE_STRONG_MUTATION_RE.search(text):
        return True
    if FINANCE_ACTION_RE.search(called):
        return True
    if FINANCE_AMOUNT_RE.search(text) and FINANCE_REAL_MONEY_CONTEXT_RE.search(f"{text}\n{method_body}"):
        return True
    return False


def _finance_context_is_non_funds_idempotency(method_name: str, body: str) -> bool:
    haystack = f"{method_name}\n{body}"
    if FINANCE_WALLET_LOCK_METHOD_RE.search(method_name):
        return True
    if FINANCE_CANCEL_STATE_METHOD_RE.search(method_name) and not re.search(
        r"amount|balance|wallet|minor|refund|credit|debit|releaseReservedBalance|forceCancel",
        haystack,
        flags=re.IGNORECASE,
    ):
        return True
    if FINANCE_WALLET_CRUD_CONTEXT_RE.search(haystack) and not re.search(
        r"amount|transaction|transfer|withdraw|deposit|topup|topUp|pay|charge|debit|credit|refund|addMoney|fund",
        haystack,
        flags=re.IGNORECASE,
    ):
        return True
    if FINANCE_WALLET_CREATION_CONTEXT_RE.search(haystack) and not re.search(
        r"amount|balance|transaction|transfer|withdraw|deposit|topup|topUp|pay|charge|debit|credit|refund",
        haystack,
        flags=re.IGNORECASE,
    ):
        return True
    if FINANCE_ACCOUNT_CREATION_WITH_BUSINESS_KEY_RE.search(haystack) and re.search(
        r"\baccountId\b|account[_-]?id",
        haystack,
        flags=re.IGNORECASE,
    ) and not re.search(
        r"\b(?:credit|debit|transfer|withdraw|deposit|topup|topUp|pay|refund|settle|trade|charge)\b",
        haystack,
        flags=re.IGNORECASE,
    ):
        return True
    if FINANCE_AUDIT_ONLY_METHOD_RE.search(method_name) and not re.search(
        r"setBalance|setFrozenBalance|memberWalletService\s*\.\s*save|memberTransactionService\s*\.\s*save|"
        r"\btransactionNumber\b|\bremittance\b",
        body,
        flags=re.IGNORECASE,
    ):
        return True
    if not FINANCE_NON_FUNDS_CONTEXT_RE.search(haystack):
        return False
    return not FINANCE_REAL_MONEY_CONTEXT_RE.search(haystack)


def _component_label(record: dict[str, Any], dependency_scan: dict[str, Any]) -> str:
    dependencies = record.get("matched_dependencies") if isinstance(record, dict) else []
    if isinstance(dependencies, list) and dependencies:
        dependency = dependencies[0]
        return f"{dependency.get('ecosystem') or ''}/{dependency.get('name') or ''} {dependency.get('version') or ''}".strip()
    scan_dependencies = dependency_scan.get("dependencies") or []
    if scan_dependencies:
        dependency = scan_dependencies[0]
        return f"{dependency.get('ecosystem') or ''}/{dependency.get('name') or ''} {dependency.get('version') or ''}".strip()
    components = record.get("components") if isinstance(record, dict) else []
    if isinstance(components, list) and components:
        component = components[0]
        return f"{component.get('ecosystem') or ''}/{component.get('name') or ''}".strip()
    return ""


def _merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        sink = finding.get("sink") or {}
        identity = finding.get("rule_id") or finding.get("title")
        key = f"{identity}|{sink.get('file')}|{sink.get('line')}|{finding.get('record_id')}"
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
        if len(result) >= _max_findings():
            break
    return result


def _merge_cross_engine_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate equivalent sink locations while preserving distinct scenarios."""
    result: list[dict[str, Any]] = []
    indexes: dict[tuple[str, str, int], int] = {}
    for finding in findings:
        sink = finding.get("sink") or {}
        key = (
            str(finding.get("scenario") or finding.get("rule_id") or finding.get("title") or ""),
            str(sink.get("file") or ""),
            int(sink.get("line") or 0),
        )
        if key in indexes:
            index = indexes[key]
            if _finding_evidence_score(finding) > _finding_evidence_score(result[index]):
                result[index] = finding
            continue
        indexes[key] = len(result)
        result.append(finding)
    return _prioritize_static_findings(result)[:_max_findings()]


def _finding_evidence_score(finding: dict[str, Any]) -> tuple[int, int, int, int, int]:
    path = finding.get("path") or []
    kinds = {str(item.get("kind") or "") for item in path if isinstance(item, dict)}
    rule_id = str(finding.get("rule_id") or "").lower()
    is_recall_rule = str(finding.get("rule_profile") or "").lower() == "recall" or ".recall-" in rule_id
    return (
        int(finding.get("analysis_depth") or 0),
        int(not is_recall_rule),
        int("call" in kinds),
        int("source" in kinds and "sink" in kinds),
        len(path),
    )


def _prioritize_static_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority = {
        "funds_request_chain": 0,
        "idempotency_missing": 1,
        "funds_transaction_boundary": 2,
        "funds_state_transition_race": 2,
        "command_execution": 3,
        "sql_injection": 3,
        "deserialization": 3,
        "ssrf": 3,
        "path_traversal": 3,
        "xml_external_entity": 3,
        "cross_site_scripting": 3,
        "funds_precision": 5,
        "generic_reachability": 6,
    }
    severity = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return sorted(
        findings,
        key=lambda item: (
            priority.get(str(item.get("scenario") or ""), 4),
            severity.get(str(item.get("severity") or "UNKNOWN").upper(), 4),
            str(item.get("file") or (item.get("sink") or {}).get("file") or ""),
            int(item.get("risk_line") or (item.get("sink") or {}).get("line") or 0),
        ),
    )


def _correlate_interprocedural_findings(
    findings: list[dict[str, Any]],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        sink = item.get("sink") or {}
        record = _best_record_for_scenario(
            records,
            dependency_scan,
            str(item.get("scenario") or ""),
            str(sink.get("snippet") or ""),
        )
        if record:
            item["record_id"] = str(record.get("id") or "")
            item["component"] = _component_label(record, dependency_scan)
        result.append(item)
    return result


def _max_findings() -> int:
    try:
        configured = int(os.getenv("SECFLOW_STATIC_MAX_FINDINGS", "500"))
    except ValueError:
        configured = 500
    return max(1, min(configured, 5000))


def _is_review_finding(finding: dict[str, Any]) -> bool:
    profile = str(finding.get("rule_profile") or "standard").lower()
    confidence = str(finding.get("confidence") or "medium").lower()
    return profile == "review" or (confidence == "low" and profile != "recall")


def _enrich_code_findings(findings: list[dict[str, Any]], code_files: list[dict[str, str]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        sink = item.get("sink") or {}
        file_name = str(sink.get("file") or "")
        risk_line = max(1, int(sink.get("line") or 1))
        line_start, line_end, context = _code_context(code_files, file_name, risk_line)
        vulnerable_snippet = context or str(sink.get("snippet") or item.get("evidence") or "").strip()
        item.update(
            {
                "file": file_name,
                "risk_line": risk_line,
                "line_start": line_start or risk_line,
                "line_end": line_end or risk_line,
                "vulnerable_snippet": vulnerable_snippet,
                "remediation": str(item.get("remediation") or "")
                or _remediation_for_scenario(str(item.get("scenario") or "generic_reachability")),
                "fixed_snippet": str(item.get("fixed_snippet") or "")
                or _fixed_code_for_finding(item, str(sink.get("snippet") or "")),
            }
        )
        _apply_contextual_triage(item)
        if _should_suppress_contextual_finding(item, code_files):
            continue
        enriched.append(item)
    idempotency_aggregated = _aggregate_idempotency_method_findings(enriched, code_files)
    method_aggregated = _aggregate_finance_method_findings(idempotency_aggregated, code_files)
    return _prioritize_static_findings(_aggregate_finance_request_chains(method_aggregated, code_files))


def _aggregate_idempotency_method_findings(
    findings: list[dict[str, Any]],
    code_files: list[dict[str, str]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, int, int], list[int]] = {}
    spans_by_key: dict[tuple[str, str, int, int], JavaMethodSpan] = {}
    method_cache: dict[str, list[JavaMethodSpan]] = {}
    for index, finding in enumerate(findings):
        if str(finding.get("scenario") or "") != "idempotency_missing":
            continue
        file_name = str(finding.get("file") or (finding.get("sink") or {}).get("file") or "")
        if Path(file_name).suffix.lower() != ".java":
            continue
        content = _source_content(code_files, file_name)
        if not content:
            continue
        spans = method_cache.setdefault(file_name, _java_method_spans(content))
        risk_line = max(1, int(finding.get("risk_line") or (finding.get("sink") or {}).get("line") or 1))
        span = _java_method_span_for_line(spans, risk_line)
        if not span:
            continue
        key = (file_name, span.name, span.start, span.end)
        groups.setdefault(key, []).append(index)
        spans_by_key[key] = span

    consumed: set[int] = set()
    result: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if index in consumed:
            continue
        key = next((group_key for group_key, indexes in groups.items() if index in indexes), None)
        if not key:
            result.append(finding)
            continue
        indexes = groups.get(key) or [index]
        consumed.update(indexes)
        members = [findings[item_index] for item_index in indexes]
        if len(members) == 1:
            result.append(finding)
            continue
        result.append(_aggregate_idempotency_method_group(members, spans_by_key[key], code_files))
    return result


def _aggregate_idempotency_method_group(
    members: list[dict[str, Any]],
    span: JavaMethodSpan,
    code_files: list[dict[str, str]],
) -> dict[str, Any]:
    ordered = sorted(members, key=lambda item: _finding_evidence_score(item), reverse=True)
    primary = dict(ordered[0])
    file_name = str(primary.get("file") or (primary.get("sink") or {}).get("file") or "")
    sink_rows = _unique_aggregate_sinks(ordered)
    primary.update(
        {
            "id": f"{primary.get('id') or 'finance-idempotency'}-method-grouped",
            "risk_line": int(primary.get("risk_line") or (primary.get("sink") or {}).get("line") or span.start),
            "line_start": span.start,
            "line_end": span.end,
            "vulnerable_snippet": _source_range_or_compact_windows(
                code_files,
                file_name,
                span.start,
                span.end,
                [int(item["line"]) for item in sink_rows if int(item.get("line") or 0) > 0],
            ),
            "aggregation": {
                "kind": "idempotency_method",
                "method": span.name,
                "merged_finding_count": len(ordered),
            },
            "aggregated_sinks": sink_rows,
            "related_findings": [_finding_summary(item) for item in ordered],
        }
    )
    return primary


def _aggregate_finance_request_chains(
    findings: list[dict[str, Any]],
    code_files: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Join money endpoint idempotency and service transaction findings into one request-chain card."""
    transaction_by_method = {
        str((finding.get("aggregation") or {}).get("method") or ""): index
        for index, finding in enumerate(findings)
        if str(finding.get("scenario") or "") == "funds_transaction_boundary"
        and isinstance(finding.get("aggregation"), dict)
        and (finding.get("aggregation") or {}).get("method")
    }
    if not transaction_by_method:
        return findings

    result: list[dict[str, Any]] = []
    consumed: set[int] = set()
    for index, finding in enumerate(findings):
        if index in consumed:
            continue
        if str(finding.get("scenario") or "") != "idempotency_missing":
            result.append(finding)
            continue
        called_methods = _called_method_names(str((finding.get("sink") or {}).get("snippet") or finding.get("evidence") or ""))
        transaction_index = next(
            (transaction_by_method[method] for method in called_methods if method in transaction_by_method and transaction_by_method[method] not in consumed),
            None,
        )
        if transaction_index is None:
            result.append(finding)
            continue
        consumed.add(index)
        consumed.add(transaction_index)
        result.append(_aggregate_finance_request_chain(finding, findings[transaction_index], code_files))

    for index, finding in enumerate(findings):
        if index not in consumed and finding not in result:
            result.append(finding)
    return result


def _aggregate_finance_request_chain(
    endpoint_finding: dict[str, Any],
    transaction_finding: dict[str, Any],
    code_files: list[dict[str, str]],
) -> dict[str, Any]:
    endpoint = dict(endpoint_finding)
    fallback_methods = _called_method_names(str((endpoint.get("sink") or {}).get("snippet") or ""))
    method = str((transaction_finding.get("aggregation") or {}).get("method") or (fallback_methods[0] if fallback_methods else "moneyOperation"))
    controller_file = str(endpoint.get("file") or (endpoint.get("sink") or {}).get("file") or "")
    controller_line = int(endpoint.get("risk_line") or (endpoint.get("sink") or {}).get("line") or 0)
    service_file = str(transaction_finding.get("file") or (transaction_finding.get("sink") or {}).get("file") or "")
    service_line = int(transaction_finding.get("risk_line") or (transaction_finding.get("sink") or {}).get("line") or 0)
    endpoint_snippet = str(endpoint.get("vulnerable_snippet") or (endpoint.get("sink") or {}).get("snippet") or "").strip()
    transaction_snippet = str(transaction_finding.get("vulnerable_snippet") or (transaction_finding.get("sink") or {}).get("snippet") or "").strip()
    endpoint.update(
        {
            "id": f"{endpoint.get('id') or 'finance-request'}-chain",
            "scenario": "funds_request_chain",
            "title": f"资金请求链路风险：{method}() 缺少幂等与事务边界",
            "severity": _max_severity([str(endpoint.get("severity") or ""), str(transaction_finding.get("severity") or "")]),
            "confidence": _max_confidence([str(endpoint.get("confidence") or ""), str(transaction_finding.get("confidence") or "")]),
            "risk_line": controller_line,
            "line_start": int(endpoint.get("line_start") or controller_line or 1),
            "line_end": int(endpoint.get("line_end") or controller_line or 1),
            "vulnerable_snippet": (
                "请求入口缺少幂等校验：\n"
                f"{endpoint_snippet or _source_line(code_files, controller_file, controller_line)}\n\n"
                "资金状态更新缺少事务边界：\n"
                f"{transaction_snippet or _source_line(code_files, service_file, service_line)}"
            ).strip(),
            "remediation": (
                "在请求入口校验 Idempotency-Key 或业务流水号，并把幂等记录、扣款、入账、订单/流水状态更新放入同一事务；"
                "数据库侧增加业务流水唯一约束，重复请求返回已完成结果。"
            ),
            "fixed_snippet": _fixed_code_for_finding({"scenario": "idempotency_missing"}, ""),
            "cfg": (
                f"Controller 入口 {controller_file}:{controller_line} 调用 {method}()，"
                f"下游 {service_file}:{service_line} 存在资金更新链路但未看到事务边界。"
            ),
            "dfg": (
                "资金请求链路：HTTP 请求/业务流水 → Controller 调用 "
                f"{method}() → " + str(transaction_finding.get("dfg") or "资金状态更新/持久化")
            ),
            "path": _request_chain_path(endpoint, transaction_finding, method),
            "aggregation": {
                "kind": "finance_request_chain",
                "method": method,
                "merged_finding_count": 2 + int((transaction_finding.get("aggregation") or {}).get("merged_finding_count") or 1) - 1,
            },
            "related_findings": [
                _finding_summary(endpoint_finding),
                _finding_summary(transaction_finding),
            ],
            "aggregated_sinks": transaction_finding.get("aggregated_sinks") or [],
        }
    )
    return endpoint


def _request_chain_path(
    endpoint_finding: dict[str, Any],
    transaction_finding: dict[str, Any],
    method: str,
) -> list[dict[str, Any]]:
    endpoint_sink = endpoint_finding.get("sink") or {}
    path: list[dict[str, Any]] = [
        {
            "kind": "source",
            "file": endpoint_finding.get("file") or endpoint_sink.get("file") or "",
            "line": endpoint_finding.get("risk_line") or endpoint_sink.get("line") or 0,
            "label": "资金请求入口（需幂等键/业务流水号）",
            "snippet": endpoint_sink.get("snippet") or endpoint_finding.get("evidence") or "",
        },
        {
            "kind": "call",
            "file": endpoint_finding.get("file") or endpoint_sink.get("file") or "",
            "line": endpoint_finding.get("risk_line") or endpoint_sink.get("line") or 0,
            "label": f"调用资金业务方法 {method}()",
            "snippet": endpoint_sink.get("snippet") or "",
        },
    ]
    for item in transaction_finding.get("path") or []:
        if isinstance(item, dict):
            path.append(item)
    return path


def _finding_summary(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": str(finding.get("title") or ""),
        "scenario": str(finding.get("scenario") or ""),
        "file": str(finding.get("file") or (finding.get("sink") or {}).get("file") or ""),
        "line": int(finding.get("risk_line") or (finding.get("sink") or {}).get("line") or 0),
        "aggregation": finding.get("aggregation") or {},
    }


def _called_method_names(snippet: str) -> list[str]:
    names = re.findall(r"\.\s*([A-Za-z_$][\w$]*)\s*\(", snippet)
    return [name for name in names if name not in {"save", "update", "insert", "delete", "setBalance", "setAmount"}]


def _called_service_method_has_explicit_idempotency_guard(
    called_methods: list[str],
    code_files: list[dict[str, str]],
) -> bool:
    method_names = {name for name in called_methods if name}
    if not method_names:
        return False
    for file in code_files:
        file_name = str(file.get("file_name") or "")
        if Path(file_name).suffix.lower() != ".java":
            continue
        content = str(file.get("content") or "")
        if not content:
            continue
        lines = [CodeLine(file_name, index, text.rstrip()) for index, text in enumerate(content.splitlines(), start=1)]
        for span in _java_method_spans(content):
            if span.name not in method_names:
                continue
            method_text = f"{_java_method_header(lines, span)}\n{_java_span_text(lines, span)}"
            if EXPLICIT_IDEMPOTENCY_GUARD_RE.search(method_text):
                return True
    return False


def _called_service_method_has_state_transition_guard(
    called_methods: list[str],
    code_files: list[dict[str, str]],
) -> bool:
    method_names = {name for name in called_methods if name}
    if not method_names:
        return False
    guarded_state_re = re.compile(
        r"\bcanCancel\s*\(|\bgetStatus\s*\(\s*\)|\bsetStatus\s*\(|\bOrderStatus\b|"
        r"\bWithdrawStatus\b|\bPROCESSING\b|\bWAITING\b|\bSUCCESS\b|\bFAIL\b|"
        r"\bisTrue\s*\([^;]*(?:status|getStatus|Status)\b|不是审核状态|cannot be cancelled|already",
        flags=re.IGNORECASE,
    )
    for file in code_files:
        file_name = str(file.get("file_name") or "")
        if Path(file_name).suffix.lower() != ".java":
            continue
        content = str(file.get("content") or "")
        if not content:
            continue
        lines = [CodeLine(file_name, index, text.rstrip()) for index, text in enumerate(content.splitlines(), start=1)]
        for span in _java_method_spans(content):
            if span.name not in method_names:
                continue
            method_text = f"{_java_method_header(lines, span)}\n{_java_span_text(lines, span)}"
            if guarded_state_re.search(method_text):
                return True
    return False


def _max_severity(values: list[str]) -> str:
    order = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    normalized = [value.upper() for value in values if value]
    return max(normalized or ["UNKNOWN"], key=lambda item: order.get(item, 0))


def _max_confidence(values: list[str]) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    normalized = [value.lower() for value in values if value]
    return max(normalized or ["medium"], key=lambda item: order.get(item, 2))


def _aggregate_finance_method_findings(
    findings: list[dict[str, Any]],
    code_files: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Group multiple money-update sinks in the same Java method into one audit card."""
    groups: dict[tuple[str, str, str, int, int], list[dict[str, Any]]] = {}
    group_key_by_index: dict[int, tuple[str, str, str, int, int]] = {}
    span_by_key: dict[tuple[str, str, str, int, int], JavaMethodSpan] = {}
    method_cache: dict[str, list[JavaMethodSpan]] = {}

    for index, finding in enumerate(findings):
        if str(finding.get("scenario") or "") != "funds_transaction_boundary":
            continue
        file_name = str(finding.get("file") or "")
        if Path(file_name).suffix.lower() != ".java":
            continue
        content = _source_content(code_files, file_name)
        if not content:
            continue
        spans = method_cache.setdefault(file_name, _java_method_spans(content))
        risk_line = max(1, int(finding.get("risk_line") or (finding.get("sink") or {}).get("line") or 1))
        span = _java_method_span_for_line(spans, risk_line)
        if not span:
            continue
        key = ("funds_transaction_boundary", file_name, span.name, span.start, span.end)
        groups.setdefault(key, []).append(finding)
        group_key_by_index[index] = key
        span_by_key[key] = span

    result: list[dict[str, Any]] = []
    emitted: set[tuple[str, str, str, int, int]] = set()
    for index, finding in enumerate(findings):
        key = group_key_by_index.get(index)
        if not key:
            result.append(finding)
            continue
        if key in emitted:
            continue
        emitted.add(key)
        members = groups.get(key) or [finding]
        if len(members) <= 1:
            result.append(finding)
            continue
        result.append(_aggregate_finance_method_group(members, span_by_key[key], code_files))
    return result


def _aggregate_finance_method_group(
    members: list[dict[str, Any]],
    span: JavaMethodSpan,
    code_files: list[dict[str, str]],
) -> dict[str, Any]:
    ordered = sorted(members, key=lambda item: int(item.get("risk_line") or 0))
    primary = dict(ordered[0])
    file_name = str(primary.get("file") or "")
    sink_rows = _unique_aggregate_sinks(ordered)
    line_start = min(int(item.get("line_start") or item.get("risk_line") or 1) for item in ordered)
    line_end = max(int(item.get("line_end") or item.get("risk_line") or 1) for item in ordered)
    vulnerable_snippet = _source_range_or_compact_windows(
        code_files,
        file_name,
        line_start,
        line_end,
        [int(item["line"]) for item in sink_rows if int(item.get("line") or 0) > 0],
    )
    sink_count = len(sink_rows)
    primary.update(
        {
            "id": f"{primary.get('id') or 'finance-method'}-grouped",
            "title": f"资金操作缺少事务边界：{span.name}() 中 {sink_count} 个更新点",
            "risk_line": int(sink_rows[0].get("line") or primary.get("risk_line") or span.start),
            "line_start": line_start,
            "line_end": line_end,
            "vulnerable_snippet": vulnerable_snippet or str(primary.get("vulnerable_snippet") or ""),
            "evidence": "\n".join(f"{item.get('line')}: {item.get('snippet')}" for item in sink_rows),
            "cfg": (
                f"同一业务方法 {span.name}() 内存在 {sink_count} 个资金状态更新或持久化操作，"
                "未看到 @Transactional 事务边界。"
            ),
            "dfg": "资金状态更新链路：" + " → ".join(
                f"第 {item.get('line')} 行 {item.get('snippet')}" for item in sink_rows
            ),
            "path": _aggregate_path(primary, sink_rows, file_name),
            "aggregation": {
                "kind": "finance_method",
                "method": span.name,
                "method_start": span.start,
                "method_end": span.end,
                "merged_finding_count": len(ordered),
                "sink_count": sink_count,
            },
            "aggregated_sinks": sink_rows,
        }
    )
    return primary


def _unique_aggregate_sinks(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for finding in findings:
        sink = finding.get("sink") or {}
        file_name = str(finding.get("file") or sink.get("file") or "")
        line = int(finding.get("risk_line") or sink.get("line") or 0)
        snippet = str(sink.get("snippet") or finding.get("evidence") or "").strip()
        key = (file_name, line, snippet)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "file": file_name,
                "line": line,
                "snippet": snippet,
                "rule_id": str(finding.get("rule_id") or ""),
                "title": str(finding.get("title") or ""),
            }
        )
    return rows


def _aggregate_path(primary: dict[str, Any], sink_rows: list[dict[str, Any]], file_name: str) -> list[dict[str, Any]]:
    path = [
        item
        for item in primary.get("path") or []
        if isinstance(item, dict) and str(item.get("kind") or "") != "sink"
    ]
    for item in sink_rows:
        path.append(
            {
                "kind": "sink",
                "file": item.get("file") or file_name,
                "line": item.get("line") or 0,
                "label": "同一资金方法内的状态更新/持久化 sink",
                "snippet": item.get("snippet") or "",
            }
        )
    return path


def _source_range_or_compact_windows(
    code_files: list[dict[str, str]],
    file_name: str,
    line_start: int,
    line_end: int,
    risk_lines: list[int],
) -> str:
    lines = _source_content(code_files, file_name).splitlines()
    if not lines:
        return ""
    line_start = max(1, min(line_start, len(lines)))
    line_end = max(line_start, min(line_end, len(lines)))
    if line_end - line_start <= 80:
        return "\n".join(lines[line_start - 1 : line_end]).strip("\n")
    windows: list[tuple[int, int]] = []
    for line in sorted(set(risk_lines)):
        if line <= 0:
            continue
        windows.append((max(1, line - 2), min(len(lines), line + 2)))
    merged = _merge_line_windows(windows)
    chunks: list[str] = []
    for start, end in merged:
        chunks.append("\n".join(lines[start - 1 : end]).strip("\n"))
    return "\n...\n".join(chunk for chunk in chunks if chunk)


def _merge_line_windows(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if not result or start > result[-1][1] + 1:
            result.append((start, end))
            continue
        result[-1] = (result[-1][0], max(result[-1][1], end))
    return result


def _java_method_span_for_line(spans: list[JavaMethodSpan], line: int) -> JavaMethodSpan | None:
    matches = [span for span in spans if span.start <= line <= span.end]
    if not matches:
        return None
    return min(matches, key=lambda item: item.end - item.start)


_JAVA_METHOD_SIGNATURE_RE = re.compile(
    r"^\s*"
    r"(?!(?:if|for|while|switch|catch|try|else|do|return|new)\b)"
    r"(?:[\w$<>\[\],.?&]+\s+)+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*"
    r"(?:throws\s+[^{;]+)?\{",
    flags=re.DOTALL,
)


def _java_method_spans(content: str) -> list[JavaMethodSpan]:
    lines = _strip_java_comments_preserve_lines(content).splitlines()
    spans: list[JavaMethodSpan] = []
    pending_start: int | None = None
    pending_text = ""
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if pending_start is None:
            if stripped.startswith("@"):
                continue
            if "(" not in stripped or ";" in stripped.split("{", 1)[0] or _is_java_control_line(stripped):
                continue
            pending_start = index
            pending_text = stripped
        else:
            pending_text += " " + stripped
        if "{" not in pending_text:
            if ";" in stripped:
                pending_start = None
                pending_text = ""
            continue
        match = _JAVA_METHOD_SIGNATURE_RE.search(pending_text)
        if match:
            spans.append(
                JavaMethodSpan(
                    name=match.group("name"),
                    start=pending_start + 1,
                    end=_java_matching_brace_line(lines, pending_start),
                )
            )
        pending_start = None
        pending_text = ""
    return spans


def _strip_java_comments_preserve_lines(content: str) -> str:
    result: list[str] = []
    index = 0
    in_block = False
    while index < len(content):
        if in_block:
            if content.startswith("*/", index):
                in_block = False
                result.append("  ")
                index += 2
                continue
            result.append("\n" if content[index] == "\n" else " ")
            index += 1
            continue
        if content.startswith("/*", index):
            in_block = True
            result.append("  ")
            index += 2
            continue
        if content.startswith("//", index):
            while index < len(content) and content[index] != "\n":
                result.append(" ")
                index += 1
            continue
        result.append(content[index])
        index += 1
    return "".join(result)


def _is_java_control_line(value: str) -> bool:
    return bool(re.match(r"^(?:if|for|while|switch|catch|try|else|do|return|new)\b", value))


def _java_matching_brace_line(lines: list[str], start_index: int) -> int:
    depth = 0
    opened = False
    for index in range(start_index, len(lines)):
        for character in lines[index]:
            if character == "{":
                depth += 1
                opened = True
            elif character == "}":
                depth -= 1
                if opened and depth <= 0:
                    return index + 1
    return len(lines)


def _should_suppress_contextual_finding(finding: dict[str, Any], code_files: list[dict[str, str]]) -> bool:
    scenario = str(finding.get("scenario") or "")
    if scenario not in {"idempotency_missing", "funds_request_chain"}:
        return False
    if str(finding.get("engine") or "") == "java-native-finance" and finding.get("semantic_proof"):
        return False
    file_name = str(finding.get("file") or (finding.get("sink") or {}).get("file") or "")
    if Path(file_name).suffix.lower() != ".java":
        return False
    content = _source_content(code_files, file_name)
    if not content:
        return False
    risk_line = int(finding.get("risk_line") or (finding.get("sink") or {}).get("line") or 1)
    span = _java_method_span_for_line(_java_method_spans(content), risk_line)
    if not span:
        return False
    lines = [CodeLine(file_name, index, text.rstrip()) for index, text in enumerate(content.splitlines(), start=1)]
    header = _java_method_header(lines, span)
    body = _java_span_text(lines, span)
    haystack = f"{file_name}\n{header}\n{body}\n{finding.get('dfg') or ''}\n{finding.get('evidence') or ''}"
    if _source_line_is_comment(code_files, file_name, risk_line):
        finding["suppressed"] = True
        finding["triage_note"] = "风险位置位于 Java 注释中，不作为可执行代码漏洞展示。"
        return True
    if _finance_context_is_non_funds_idempotency(span.name, haystack):
        finding["suppressed"] = True
        finding["triage_note"] = "该命中属于统计、配置、机器人参数、奖励/地址配置或纯 setter 型后台管理操作，不按资金幂等漏洞展示。"
        return True
    called_methods = _called_method_names(
        f"{body}\n{(finding.get('sink') or {}).get('snippet') or ''}\n{finding.get('evidence') or ''}"
    )
    if _called_service_method_has_explicit_idempotency_guard(called_methods, code_files):
        finding["suppressed"] = True
        finding["triage_note"] = "下游服务方法已看到显式幂等键、客户端订单号、唯一性/重复检查或锁保护，暂不归类为幂等缺失。"
        return True
    if (
        FINANCE_CANCEL_STATE_METHOD_RE.search(span.name) or FINANCE_AUDIT_ONLY_METHOD_RE.search(span.name)
    ) and _called_service_method_has_state_transition_guard(called_methods, code_files):
        finding["suppressed"] = True
        finding["triage_note"] = "该状态流转动作下游已有状态前置校验，重复请求不会按资金幂等缺失展示。"
        return True
    if IDEMPOTENCY_GUARD_RE.search(f"{header}\n{body}"):
        finding["suppressed"] = True
        finding["triage_note"] = "该资金动作已看到 Idempotency-Key、业务流水、唯一性/重复检查或交易标识线索，暂不归类为幂等缺失。"
        return True
    return False


def _source_line_is_comment(code_files: list[dict[str, str]], file_name: str, line_number: int) -> bool:
    content = _source_content(code_files, file_name)
    if not content or line_number <= 0:
        return False
    lines = content.splitlines()
    if line_number > len(lines):
        return False
    stripped = lines[line_number - 1].strip()
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def _apply_contextual_triage(finding: dict[str, Any]) -> None:
    if str(finding.get("scenario") or "") != "weak_random":
        return
    haystack = "\n".join(
        [
            str(finding.get("file") or ""),
            str(finding.get("vulnerable_snippet") or ""),
            str(finding.get("evidence") or ""),
            str(finding.get("dfg") or ""),
        ]
    ).lower()
    if _has_strong_security_sensitive_random_context(haystack):
        finding["priority"] = "high"
        finding["security_context"] = "安全敏感随机：该随机值疑似用于令牌、会话、密钥、认证或签名上下文。"
        finding["triage_note"] = "应使用 SecureRandom，并确认随机值生命周期和暴露面。"
        finding["confidence"] = str(finding.get("confidence") or "high").lower()
        return
    if _has_non_security_random_context(haystack):
        finding["priority"] = "low"
        finding["security_context"] = "普通随机：当前上下文更像采样、退避、抖动、填充或测试辅助逻辑。"
        finding["triage_note"] = "保留为低优先级审计线索；若该值实际用于安全令牌或密钥，应改用 SecureRandom。"
        finding["confidence"] = "low"
        finding["severity"] = "LOW"
        return
    if _has_security_sensitive_random_context(haystack):
        finding["priority"] = "high"
        finding["security_context"] = "安全敏感随机：该随机值疑似用于令牌、会话、密钥、认证或签名上下文。"
        finding["triage_note"] = "应使用 SecureRandom，并确认随机值生命周期和暴露面。"
        finding["confidence"] = str(finding.get("confidence") or "high").lower()
        return
    finding["priority"] = "medium"
    finding["security_context"] = "未确认安全敏感用途：需要结合调用方确认随机值是否进入令牌、会话、密钥或认证流程。"
    finding["triage_note"] = "若用于安全敏感值，应使用 SecureRandom；若仅用于普通采样或调度，可作为低优先级治理项。"


def _has_security_sensitive_random_context(text: str) -> bool:
    return _has_strong_security_sensitive_random_context(text) or bool(
        re.search(
            r"(?i)(token|api[_-]?key|access[_-]?key|secret[_-]?key|randomsalt|passwordsalt|"
            r"\bnonce\b|nonce[_-]|[_-]nonce|randomnonce|\bkey\b|\biv\b)",
            text,
        )
    )


def _has_strong_security_sensitive_random_context(text: str) -> bool:
    return bool(
        re.search(
            r"(?i)("
            r"session|secret|credential|password|passwd|pwd|csrf|xsrf|jwt|cookie|"
            r"authorize|authentication|signature|signing|signed|crypto|cipher|otp|verification|reset|rememberme|"
            r"\bauth\b"
            r")",
            text,
        )
    )


def _has_non_security_random_context(text: str) -> bool:
    return bool(
        re.search(
            r"(?i)\b("
            r"sample|sampling|sampler|estimate|estimator|backoff|jitter|padding|pad|retry|delay|"
            r"shuffle|partition|bucket|load|balance|balancer|probability|probabilistic|randomization|"
            r"synthetic|test|testing|fixture|benchmark|demo|example|tutorial|visiblefortesting|mock|stub|simulation"
            r")\b",
            text,
        )
    )


def _code_context(code_files: list[dict[str, str]], file_name: str, line: int, radius: int = 2) -> tuple[int, int, str]:
    for code_file in code_files:
        candidate = str(code_file.get("file_name") or "")
        if candidate != file_name and Path(candidate).name != Path(file_name).name and not candidate.endswith(file_name):
            continue
        lines = str(code_file.get("content") or "").splitlines()
        if not lines:
            return line, line, ""
        start = max(1, line - radius)
        end = min(len(lines), line + radius)
        return start, end, "\n".join(lines[start - 1 : end]).strip("\n")
    return line, line, ""


def _remediation_for_scenario(scenario: str) -> str:
    return {
        "log_injection_lookup": "升级日志组件到已确认的安全版本，并在写入日志前规范化换行符和表达式标记。",
        "deserialization": "限制反序列化目标类型，使用安全构造器和资源限制，禁止把不可信输入绑定为任意对象。",
        "command_execution": "使用固定可执行文件和参数白名单，禁止将用户输入拼接为 shell 命令。",
        "sql_injection": "改用参数化查询并绑定参数，禁止拼接来自请求的 SQL 片段。",
        "path_traversal": "只接受文件名，解析规范路径后确认路径仍位于允许的根目录。",
        "cross_site_scripting": "根据 HTML、属性、JavaScript 或 URL 上下文执行输出编码。",
        "ldap_injection": "使用参数化目录查询或按 RFC 4515 转义 LDAP 过滤器元字符。",
        "xpath_injection": "固定 XPath 结构并通过 XPathVariableResolver 绑定变量。",
        "ssrf": "使用协议、主机、端口白名单，并阻断环回、链路本地和内网地址。",
        "response_splitting": "拒绝响应头值中的 CR/LF 字符，并对白名单字段赋值。",
        "xml_external_entity": "关闭 DOCTYPE、外部实体和外部 DTD/Schema 访问。",
        "weak_cryptography": "迁移到 AES-GCM、SHA-256 以上哈希以及当前安全 TLS 配置。",
        "weak_random": "安全令牌、密钥和会话标识应由 SecureRandom 生成。",
        "trust_boundary": "写入会话等信任域前进行类型、长度和业务授权校验。",
        "insecure_cookie": "对敏感 Cookie 启用 Secure、HttpOnly 和合适的 SameSite 策略。",
        "idempotency_missing": "为资金接口引入 Idempotency-Key、业务流水号唯一索引或支付网关交易号去重，并把幂等记录与资金状态更新放在同一事务内。",
        "funds_state_transition_race": "使用数据库条件更新、版本号或 compare-and-set 原子推进资金状态，避免先读状态再写入造成并发重复处理。",
        "funds_precision": "金额、余额、手续费等资金字段使用 BigDecimal 或最小货币单位 long，禁止使用 float/double 参与资金计算。",
        "funds_transaction_boundary": "把扣款、入账、订单状态变更、流水写入放入同一事务边界，失败时整体回滚并使用唯一约束防重。",
        "generic_reachability": "在调用组件 API 前校验输入，并升级关联依赖到已确认的安全版本。",
    }.get(scenario, "校验外部输入、收敛危险调用，并升级关联组件到已确认的安全版本。")


def _fixed_code_for_finding(finding: dict[str, Any], sink_snippet: str) -> str:
    scenario = str(finding.get("scenario") or "")
    snippet = sink_snippet.strip()
    indent = re.match(r"\s*", sink_snippet).group(0) if sink_snippet else ""
    if scenario == "log_injection_lookup":
        variable = _last_call_argument(snippet)
        if re.fullmatch(r"[A-Za-z_]\w*", variable):
            fixed_call = re.sub(rf"\b{re.escape(variable)}(\s*\)\s*;?)$", r"safeLogValue\1", snippet)
            return (
                f'{indent}String safeLogValue = String.valueOf({variable})\n'
                f'{indent}    .replace("\\r", "\\\\r")\n'
                f'{indent}    .replace("\\n", "\\\\n")\n'
                f'{indent}    .replace("${{", "$ {{");\n'
                f"{indent}{fixed_call}"
            )
        return f'{indent}LOGGER.info("event={{}}", sanitizeForLog(untrustedValue));'
    if scenario == "deserialization":
        if re.search(r"\bnew\s+Yaml\s*\(", snippet):
            return (
                f"{indent}private final Yaml yaml = new Yaml(\n"
                f"{indent}    new org.yaml.snakeyaml.constructor.SafeConstructor(\n"
                f"{indent}        new org.yaml.snakeyaml.LoaderOptions()\n"
                f"{indent}    )\n"
                f"{indent});"
            )
        if re.search(r"\.load\s*\(", snippet):
            argument = _last_call_argument(snippet) or "yamlText"
            return (
                f"{indent}org.yaml.snakeyaml.LoaderOptions options = new org.yaml.snakeyaml.LoaderOptions();\n"
                f"{indent}options.setMaxAliasesForCollections(50);\n"
                f"{indent}Yaml safeYaml = new Yaml(\n"
                f"{indent}    new org.yaml.snakeyaml.constructor.SafeConstructor(options)\n"
                f"{indent});\n"
                f"{indent}Object parsed = safeYaml.load({argument});"
            )
        if "readValue" in snippet:
            return re.sub(r"Object\.class", "java.util.Map.class", snippet) if "Object.class" in snippet else (
                f"{indent}return objectMapper.readerFor(ExpectedType.class).readValue(jsonText);"
            )
        return f"{indent}objectInputStream.setObjectInputFilter(allowListedFilter);"
    if scenario == "sql_injection":
        return (
            f'{indent}try (PreparedStatement statement = connection.prepareStatement("SELECT * FROM target WHERE id = ?")) {{\n'
            f"{indent}    statement.setString(1, validatedId);\n"
            f"{indent}    return statement.executeQuery();\n"
            f"{indent}}}"
        )
    if scenario == "command_execution":
        file_name = str(
            finding.get("file")
            or (finding.get("sink") or {}).get("file")
            or (finding.get("source") or {}).get("file")
            or ""
        )
        suffix = Path(file_name).suffix.casefold()
        argument = _last_call_argument(snippet) or "command"
        if suffix == ".py":
            return (
                f'{indent}allowed_commands = {{"status": ["/usr/bin/fixed-tool", "--status"]}}\n'
                f"{indent}arguments = allowed_commands.get({argument})\n"
                f"{indent}if arguments is None:\n"
                f'{indent}    raise ValueError("unsupported command")\n'
                f"{indent}subprocess.run(arguments, check=True, shell=False)"
            )
        return (
            f"{indent}if (!ALLOWED_ARGUMENTS.contains(validatedArgument)) {{\n"
            f'{indent}    throw new IllegalArgumentException("unsupported argument");\n'
            f"{indent}}}\n"
            f'{indent}new ProcessBuilder("/usr/bin/fixed-tool", validatedArgument).start();'
        )
    if scenario == "path_traversal":
        return (
            f"{indent}Path root = allowedRoot.toAbsolutePath().normalize();\n"
            f"{indent}Path target = root.resolve(Paths.get(untrustedName).getFileName()).normalize();\n"
            f"{indent}if (!target.startsWith(root)) throw new SecurityException(\"invalid path\");"
        )
    if scenario == "cross_site_scripting":
        return f"{indent}response.getWriter().write(org.owasp.encoder.Encode.forHtml(untrustedValue));"
    if scenario == "ssrf":
        return (
            f"{indent}URI target = URI.create(untrustedUrl);\n"
            f"{indent}if (!ALLOWED_HOSTS.contains(target.getHost())) throw new SecurityException(\"blocked host\");\n"
            f"{indent}httpClient.execute(new HttpGet(target));"
        )
    if scenario == "response_splitting":
        return f'{indent}response.setHeader("X-Allowed", rejectCrlf(untrustedValue));'
    if scenario == "xml_external_entity":
        return (
            f"{indent}DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n"
            f'{indent}factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            f'{indent}factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n'
            f'{indent}factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");'
        )
    if scenario == "weak_cryptography":
        return f'{indent}Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");'
    if scenario == "weak_random":
        return f"{indent}SecureRandom secureRandom = new SecureRandom();"
    if scenario == "trust_boundary":
        return f"{indent}session.setAttribute(allowedKey, validateTrustedState(untrustedValue));"
    if scenario == "insecure_cookie":
        return (
            f"{indent}cookie.setSecure(true);\n"
            f"{indent}cookie.setHttpOnly(true);\n"
            f'{indent}response.addHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; SameSite=Lax");'
        )
    if scenario == "idempotency_missing":
        return (
            f'{indent}String idempotencyKey = request.getHeader("Idempotency-Key");\n'
            f"{indent}if (!idempotencyService.tryBegin(idempotencyKey, orderNo)) {{\n"
            f"{indent}    return idempotencyService.previousResult(idempotencyKey, orderNo);\n"
            f"{indent}}}\n"
            f"{indent}return paymentService.payWithIdempotency(orderNo, amount, idempotencyKey);"
        )
    if scenario == "funds_precision":
        return (
            f'{indent}BigDecimal amount = new BigDecimal(amountText).setScale(2, RoundingMode.HALF_UP);\n'
            f"{indent}long amountInCents = amount.movePointRight(2).longValueExact();"
        )
    if scenario == "funds_transaction_boundary":
        return (
            f"{indent}@Transactional\n"
            f"{indent}public PaymentResult transfer(TransferCommand command) {{\n"
            f"{indent}    idempotencyRepository.insertUnique(command.requestNo());\n"
            f"{indent}    accountRepository.debit(command.fromAccount(), command.amount());\n"
            f"{indent}    accountRepository.credit(command.toAccount(), command.amount());\n"
            f"{indent}    return paymentRepository.markSuccess(command.requestNo());\n"
            f"{indent}}}"
        )
    return f"{indent}validateInput(untrustedValue);\n{indent}{snippet or 'safeComponentCall(validatedValue);'}"


def _last_call_argument(snippet: str) -> str:
    match = re.search(r"\((.*)\)\s*;?\s*$", snippet)
    if not match:
        return ""
    return match.group(1).rsplit(",", 1)[-1].strip()


def _parse_semgrep_json(
    result_path: Path,
    code_files: list[dict[str, str]],
    dependency_scan: dict[str, Any],
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return [], ["静态分析 JSON 无法解析。"]

    diagnostics = [_semgrep_error_message(item) for item in payload.get("errors") or []]
    diagnostics = [item for item in diagnostics if item]
    findings: list[dict[str, Any]] = []
    for result in payload.get("results") or []:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = _normalize_rule_id(str(result.get("check_id") or ""))
        file_name = _normalize_semgrep_path(str(result.get("path") or ""), code_files)
        line = max(1, int((result.get("start") or {}).get("line") or 1))
        if _semgrep_finding_is_suppressed(code_files, file_name, line):
            continue
        snippet = _source_line(code_files, file_name, line)
        sink = {
            "file": file_name,
            "line": line,
            "kind": "sink",
            "snippet": snippet,
        }
        dataflow_path = _semgrep_dataflow_path(extra.get("dataflow_trace") or {}, code_files)
        if not dataflow_path:
            file_content = _source_content(code_files, file_name)
            lines = [CodeLine(file_name, index, text.rstrip()) for index, text in enumerate(file_content.splitlines(), start=1)]
            source = _nearest_source_before(_matching_lines(lines, SOURCE_PATTERNS), line)
            dataflow_path = _build_path(source, sink, lines)
        dataflow_path = _add_tree_sitter_controls(dataflow_path, code_files)
        source = next((item for item in dataflow_path if item.get("kind") == "source"), {})
        scenario = str(metadata.get("scenario") or _scenario_from_rule(rule_id))
        record = _best_record_for_scenario(records, dependency_scan, scenario, snippet)
        ast = _ast_summary(
            file_name,
            _source_content(code_files, file_name),
            language_hint=_source_language_hint(code_files, file_name),
        )
        ast["rule"] = rule_id
        ast["metavariables"] = _semgrep_metavariables(extra.get("metavars") or {})
        findings.append(
            {
                "id": f"semgrep-{len(findings) + 1}",
                "engine": "static-path-analysis",
                "rule_id": rule_id,
                "scenario": scenario,
                "title": str(extra.get("message") or rule_id or "静态分析发现"),
                "record_id": str(record.get("id") or ""),
                "component": _component_label(record, dependency_scan),
                "severity": _semgrep_severity(extra.get("severity"), metadata),
                "cwes": _metadata_cwes(metadata),
                "confidence": str(metadata.get("confidence") or "MEDIUM").lower(),
                "rule_profile": str(metadata.get("profile") or "standard").lower(),
                "source": source,
                "sink": sink,
                "path": dataflow_path,
                "ast": ast,
                "cfg": _cfg_summary(dataflow_path),
                "dfg": _dfg_summary(dataflow_path),
                "evidence": snippet or str(extra.get("message") or ""),
                "remediation": str(metadata.get("remediation") or ""),
                "fixed_snippet": str(extra.get("fix") or ""),
            }
        )
    return _prioritize_static_findings(findings)[:_max_findings()], diagnostics


def _semgrep_finding_is_suppressed(
    code_files: list[dict[str, str]],
    file_name: str,
    line: int,
) -> bool:
    lines = _source_content(code_files, file_name).splitlines()
    context = "\n".join(lines[max(0, line - 3) : min(len(lines), line + 1)])
    return bool(re.search(r"#\s*nosec\b|nolint(?::[^\s]+)?", context, flags=re.IGNORECASE))


def _semgrep_error_message(error: Any) -> str:
    if not isinstance(error, dict):
        return str(error or "")
    message = str(error.get("message") or error.get("type") or "").strip()
    path = str(error.get("path") or "").strip()
    return f"{path}: {message}" if path and message else message


def _normalize_rule_id(value: str) -> str:
    marker = "secflow."
    return marker + value.split(marker, 1)[1] if marker in value else value


def _normalize_semgrep_path(value: str, code_files: list[dict[str, str]]) -> str:
    normalized = value.removeprefix("file://").removeprefix("./")
    for code_file in code_files:
        candidate = str(code_file.get("file_name") or "")
        if normalized == candidate or normalized.endswith("/" + candidate) or candidate.endswith("/" + normalized):
            return candidate
    name = Path(normalized).name
    matches = [str(item.get("file_name") or "") for item in code_files if Path(str(item.get("file_name") or "")).name == name]
    return matches[0] if len(matches) == 1 else normalized


def _source_content(code_files: list[dict[str, str]], file_name: str) -> str:
    for code_file in code_files:
        candidate = str(code_file.get("file_name") or "")
        if candidate == file_name or candidate.endswith(file_name) or file_name.endswith(candidate):
            return str(code_file.get("content") or "")
    return ""


def _source_language_hint(code_files: list[dict[str, str]], file_name: str) -> str | None:
    for code_file in code_files:
        candidate = str(code_file.get("file_name") or "")
        if candidate == file_name or candidate.endswith(file_name) or file_name.endswith(candidate):
            return str(code_file.get("language_hint") or "") or None
    return None


def _source_line(code_files: list[dict[str, str]], file_name: str, line: int) -> str:
    lines = _source_content(code_files, file_name).splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def _semgrep_dataflow_path(trace: dict[str, Any], code_files: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not isinstance(trace, dict) or not trace:
        return []
    path: list[dict[str, Any]] = []
    source = _semgrep_trace_location(trace.get("taint_source"), "source", code_files)
    if source:
        path.append(source)
    for item in trace.get("intermediate_vars") or []:
        location = _semgrep_trace_location(item, "dataflow_step", code_files)
        if location:
            path.append(location)
    sink = _semgrep_trace_location(trace.get("taint_sink"), "sink", code_files)
    if sink:
        path.append(sink)
    return path


def _add_tree_sitter_controls(
    path: list[dict[str, Any]],
    code_files: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if any(item.get("kind") == "cfg_condition" for item in path):
        return path
    source = next((item for item in path if item.get("kind") == "source"), None)
    sink = next((item for item in reversed(path) if item.get("kind") == "sink"), None)
    if not source or not sink or source.get("file") != sink.get("file"):
        return path
    file_name = str(source.get("file") or "")
    controls = control_flow_steps(
        file_name,
        _source_content(code_files, file_name),
        int(source.get("line") or 0),
        int(sink.get("line") or 0),
        language_hint=_source_language_hint(code_files, file_name),
    )
    if not controls:
        return path
    sink_index = next((index for index, item in enumerate(path) if item is sink), len(path))
    return [*path[:sink_index], *controls, *path[sink_index:]]


def _semgrep_trace_location(value: Any, kind: str, code_files: list[dict[str, str]]) -> dict[str, Any]:
    if isinstance(value, list) and value:
        value = value[0]
    if not isinstance(value, dict):
        return {}
    location = value.get("location") if isinstance(value.get("location"), dict) else value
    file_name = _normalize_semgrep_path(str(location.get("path") or ""), code_files)
    line = max(1, int((location.get("start") or {}).get("line") or 1))
    snippet = str(value.get("content") or _source_line(code_files, file_name, line))
    return {
        "kind": kind,
        "file": file_name,
        "line": line,
        "label": {"source": "静态数据流 source", "sink": "静态数据流 sink"}.get(kind, "数据传播变量"),
        "snippet": snippet,
    }


def _semgrep_metavariables(metavars: dict[str, Any]) -> dict[str, str]:
    if not isinstance(metavars, dict):
        return {}
    return {
        str(key): str(value.get("abstract_content") or "")
        for key, value in metavars.items()
        if isinstance(value, dict) and value.get("abstract_content")
    }


def _scenario_from_rule(rule_id: str) -> str:
    lowered = rule_id.lower()
    mappings = (
        ("idempotency", "idempotency_missing"),
        ("finance.money-float", "funds_precision"),
        ("bigdecimal", "funds_precision"),
        ("money-operation", "funds_transaction_boundary"),
        ("sql", "sql_injection"),
        ("command", "command_execution"),
        ("path", "path_traversal"),
        ("xss", "cross_site_scripting"),
        ("ldap", "ldap_injection"),
        ("xpath", "xpath_injection"),
        ("ssrf", "ssrf"),
        ("log", "log_injection_lookup"),
        ("deserial", "deserialization"),
        ("response", "response_splitting"),
        ("xxe", "xml_external_entity"),
        ("crypto", "weak_cryptography"),
        ("random", "weak_random"),
    )
    return next((scenario for token, scenario in mappings if token in lowered), "generic_reachability")


def _semgrep_severity(value: Any, metadata: dict[str, Any]) -> str:
    score = metadata.get("security-severity") or metadata.get("security_severity")
    if score is not None:
        normalized = _severity_from_security_score(score)
        if normalized != "UNKNOWN":
            return normalized
    return {
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }.get(str(value or "").upper(), "UNKNOWN")


def _metadata_cwes(metadata: dict[str, Any]) -> list[str]:
    values = metadata.get("cwe") or metadata.get("cwes") or []
    if isinstance(values, str):
        values = [values]
    result: list[str] = []
    for value in values:
        for number in re.findall(r"CWE[-_ ]?(\d+)", str(value), flags=re.IGNORECASE):
            result.append(f"CWE-{int(number)}")
    return list(dict.fromkeys(result))


def _severity_from_security_score(value: Any) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def _rule_cwes(properties: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for tag in properties.get("tags") or []:
        match = re.search(r"cwe-(\d+)", str(tag), flags=re.IGNORECASE)
        if match:
            result.append(f"CWE-{int(match.group(1))}")
    return list(dict.fromkeys(result))


def _scenario_nodes(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": item["id"], "label": item["label"], "condition": item["condition"], "ast": item["ast"], "cfg": item["cfg"], "dfg": item["dfg"]} for item in scenarios]


def _scenario_edges(scenarios: list[dict[str, Any]], has_code: bool) -> list[dict[str, str]]:
    edges = [
        {"source": "scan_attachments", "target": "query_component_intelligence", "condition": "识别到 pom 或代码依赖"},
        {"source": "query_component_intelligence", "target": "select_static_scenarios", "condition": "命中漏洞组件或代码 API"},
    ]
    if has_code:
        edges.extend(
            [
                {"source": "select_static_scenarios", "target": "run_static_analysis", "condition": "存在代码附件"},
                {"source": "run_static_analysis", "target": "correlate_source_sink_paths", "condition": "返回静态路径或降级 AST/CFG/DFG 结果"},
            ]
        )
    else:
        edges.append({"source": "select_static_scenarios", "target": "generate_markdown_report", "condition": "仅有 pom/依赖信息"})
    for item in scenarios:
        edges.append({"source": "select_static_scenarios", "target": item["id"], "condition": str(item["condition"])})
    return edges


def _write_code_files(source_root: Path, code_files: list[dict[str, str]]) -> None:
    source_root.mkdir(parents=True, exist_ok=True)
    for code_file in code_files:
        relative = _safe_relative_path(code_file["file_name"])
        target = source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code_file["content"], encoding="utf-8")


def _safe_relative_path(file_name: str) -> Path:
    parts = [part for part in Path(file_name).parts if part not in {"", ".", ".."}]
    if not parts:
        return Path("Uploaded.java")
    return Path(*parts)


def _language_for_file(file_name: str) -> str:
    return language_for_file(file_name)


semgrep_tool = SemgrepTool()
