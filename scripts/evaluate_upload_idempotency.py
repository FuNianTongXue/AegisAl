from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

ALLOWED_EXTENSIONS = {
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".cs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".swift",
    ".m",
    ".mm",
}
SKIPPED_DIRS = {
    ".git",
    ".gradle",
    ".idea",
    ".mvn",
    ".svn",
    ".hg",
    "build",
    "target",
    "dist",
    "out",
    "generated",
    "node_modules",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "coverage",
    ".nyc_output",
}
MAX_ATTACHMENTS = 300
MAX_ATTACHMENT_CHARS = 120_000
MAX_TOTAL_CHARS = 6_000_000

FINANCE_RE = re.compile(
    r"pay|payment|payout|billing|bill|refund|transfer|fund|money|withdraw|deposit|recharge|settle|checkout|charge|"
    r"topup|topUp|order|trade|batch|credit|debit|freeze|thaw|remit|remittance|transafer|wallet|balance|ledger|stock|securities|broker|"
    r"exchange|portfolio|dividend|repay|repayment|disburse|disbursement|chargeback|capture",
    re.IGNORECASE,
)
STRONG_FINANCE_RE = re.compile(
    r"amount|money|upi|balance|wallet|order|withdraw|deposit|transfer|credit|debit|refund|charge|settle|payout|bill|trade|"
    r"billing|batch|freeze|thaw|increase|decrease|transaction|dividend|totalMinor|amountMinor|currency|"
    r"payment[_-]?id|order[_-]?id|repay|repayment|loan|disburse|disbursement|chargeback|capture",
    re.IGNORECASE,
)
PAYMENT_PROFILE_RE = re.compile(
    r"payment\s*details|paymentdetails|accountnumber|account_holder|accountholder|ifsc|bankname|bank_name|"
    r"\b(?:add|create|update|delete)?(?:payment)?details?\b|\b(?:create|update|delete)Plan\b",
    re.IGNORECASE,
)
NON_FUNDS_METHOD_RE = re.compile(
    r"^(?:get|find|query|list|search|show|load|fetch|read|page|count|exists|check|validate|verify).*$|"
    r".*(?:List|Status|Details?|Profile|Config|Settings?|Statistics|Chart|Password|Login|Customer|User|Auth)$|"
    r".*(?:RobotConfig|InitPlate|Limit)$|"
    r"^(?:add|create|update|delete)?(?:payment)?details?$|^(?:create|update|delete)Plan$|"
    r"^(?:createExchange|addStock|addNewStock|changeStockStatus|transferPrimaryContact|assignRepresentative|revokeRepresentative|createInstruction|declineTrade|submitIpoOffer|createPortfolio)$|"
    r"^(?:create|update)(?:Wallet)?$|^(?:add|create|update|delete)Acc?ou?n?t(?:Handler)?$|^addAccounthandler$|^createAcoountHandler$|"
    r"^(?:lock|unlock)Wallet$|^startGame$|"
    r"^alterActivity(?:FreezeAmount|TradedAmount)$|^createRobotConfig.*$|^audit(?:Pass|NoPass|Reject|Approve)?$",
    re.IGNORECASE,
)
ACCOUNT_STATUS_METHOD_RE = re.compile(r"^(?:un)?freezeAccount$", re.IGNORECASE)
STATE_GUARDED_METHOD_RE = re.compile(r"^cancel(?:Order|Trade|Request)?$|^audit(?:Pass|NoPass|Reject|Approve)?$", re.IGNORECASE)
IDEMPOTENCY_RE = re.compile(
    r"idempot|Idempotency-Key|X-Idempotency-Key|clientOrderId|client[_-]?order[_-]?id|requestNo|requestId|paymentId|payment[_-]?id|bizNo|businessNo|serialNo|nonce|"
    r"dedup|duplicate|unique(?:Key|Request|Constraint|Index)|existsBy|setIfAbsent|"
    r"tryLock|lockKey|orderNo|tradeNo|transactionId|eventId|stripeEventId|checkoutSessionId|matchRecord|time\s+Repeat",
    re.IGNORECASE,
)
EXPLICIT_IDEMPOTENCY_RE = re.compile(
    r"idempot|Idempotency-Key|X-Idempotency-Key|clientOrderId|client[_-]?order[_-]?id|dedup|duplicate|nonce|"
    r"unique(?:Key|Request|Constraint|Index)|"
    r"(?:existsBy|findBy)[A-Za-z0-9_$]*(?:Idempot|ClientOrder|Request|Event|Stripe)[A-Za-z0-9_$]*|"
    r"setIfAbsent|tryLock|lockKey|matchRecord|already processed|业务流水|幂等",
    re.IGNORECASE,
)
MAPPING_RE = re.compile(r"@(PostMapping|PutMapping|PatchMapping|RequestMapping)\b")
UNSAFE_METHOD_RE = re.compile(r"RequestMethod\.(POST|PUT|PATCH)|@(PostMapping|PutMapping|PatchMapping)\b")
METHOD_START_RE = re.compile(
    r"^\s*(?!(?:if|for|while|switch|catch|try|else|do|return|new|throw)\b)"
    r"(?:public|protected|private|static|final|synchronized|abstract|native|default|\s)*"
    r"[\w$<>\[\],.?&\s]+\s+[A-Za-z_$][\w$]*\s*\(",
)
METHOD_SIGNATURE_RE = re.compile(
    r"^\s*(?!(?:if|for|while|switch|catch|try|else|do|return|new)\b)"
    r"(?:public|protected|private)?\s*(?:static\s+)?"
    r"[\w$<>\[\],.?&\s]+\s+(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*"
    r"(?:throws\s+[^{;]+)?\{",
)
SINK_RE = re.compile(
    r"\.(save|insert|update|submit\w*|add(?!Attribute\b)\w*|add|create\w*|pay\w*|refund\w*|\w*transfer\w*|\w*withdraw\w*|deposit\w*|"
    r"charge\w*|settle\w*|credit\w*|debit\w*|freeze\w*|thaw\w*|increase\w*|decrease\w*|process\w*|proceed\w*|proced\w*|"
    r"run\w*|place\w*|cancel\w*|\w*pass\w*|remit\w*|topup\w*|\w*transafer\w*|\w*trade\w*|"
    r"approve\w*|reject\w*|accept\w*|request\w*|\w*repay\w*|\w*repayment\w*|capture\w*|disburse\w*)\s*\(",
    re.IGNORECASE,
)
NON_FUNDS_CONTEXT_RE = re.compile(
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
    r"CreateExchangeRequest|createExchange|ExchangeMarketClock|CreateStockRequest|addStock|addNewStock|changeStockStatus|"
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
    r"alterActivity(?:FreezeAmount|TradedAmount)|modify-freezeamount|modify-tradedamount|"
    r"活动冻结总资产|活动成交总数",
    re.IGNORECASE,
)
REAL_MONEY_CONTEXT_RE = re.compile(
    r"memberWallet|walletService|memberTransaction|hotTransferRecord|exchangeOrder|forceCancelOrder|"
    r"thawBalance|increaseBalance|decreaseBalance|setFrozenBalance|setBalance|updateByMemberIdAndCoinId|"
    r"rpc/transfer|startDividend|chargeback|Chargeback|disbursement|Disbursement|repayment|makeRepayment|"
    r"accountFundsService|addFunds|DepositDTO|提现|打款|充值|退回保证金|扣除保证金|分发活动币",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SilverCandidate:
    file: str
    line: int
    end_line: int
    method: str
    reason: str


@dataclass(frozen=True)
class EngineFinding:
    title: str
    file: str
    line: int
    scenario: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate idempotency findings through the normal /api/assistant/questions upload path."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "config/evaluation/github-finance-trading-java-200-2026-07-18.json",
    )
    parser.add_argument("--server-url", default="http://127.0.0.1:18781")
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/secflow-finance-upload-eval"))
    parser.add_argument("--repositories-dir", type=Path)
    parser.add_argument("--reports-dir", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/github-finance-trading-java-200-idempotency-results.json")
    parser.add_argument("--markdown", type=Path, default=ROOT / "docs/github-finance-trading-java-200-idempotency-2026-07-18.md")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--request-timeout", type=int, default=900)
    parser.add_argument("--clone-timeout", type=int, default=900)
    parser.add_argument("--sleep", type=float, default=0.2)
    parser.add_argument("--run-label", default="native-cfg-dfg-v1")
    return parser.parse_args()


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


def manifest_projects(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    return list(payload.get("projects") or [])


def ensure_checkout(spec: dict[str, Any], repositories: Path, clone_timeout: int) -> tuple[Path, str]:
    slug = str(spec["slug"])
    target = repositories / slug.replace("/", "__")
    if not (target / ".git").is_dir():
        target.parent.mkdir(parents=True, exist_ok=True)
        cloned = run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", str(spec["url"]), str(target)],
            timeout=clone_timeout,
        )
        if cloned.returncode != 0:
            raise RuntimeError((cloned.stderr or cloned.stdout).strip())
    ref = str(spec.get("ref") or "").strip()
    if ref:
        current = run(["git", "rev-parse", "HEAD"], cwd=target)
        if current.stdout.strip() != ref:
            fetched = run(["git", "fetch", "--depth", "1", "origin", ref], cwd=target, timeout=clone_timeout)
            if fetched.returncode != 0:
                raise RuntimeError((fetched.stderr or fetched.stdout).strip())
            checked = run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=target)
            if checked.returncode != 0:
                raise RuntimeError((checked.stderr or checked.stdout).strip())
    commit = run(["git", "rev-parse", "HEAD"], cwd=target)
    if commit.returncode != 0:
        raise RuntimeError((commit.stderr or commit.stdout).strip())
    return target, commit.stdout.strip()


def should_skip_dir(path: Path) -> bool:
    return path.name.lower() in SKIPPED_DIRS


def is_allowed(path: Path) -> bool:
    return path.name.lower() == "pom.xml" or path.suffix.lower() in ALLOWED_EXTENSIONS


def priority(path: Path) -> tuple[int, str]:
    if path.name.lower() == "pom.xml":
        return (0, str(path))
    if path.suffix.lower() == ".java":
        return (1, str(path))
    return (2, str(path))


def iter_project_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for path in root.rglob("*"):
        if any(should_skip_dir(parent) for parent in path.relative_to(root).parents if str(parent) != "."):
            continue
        if path.is_dir():
            continue
        if path.is_file() and is_allowed(path):
            result.append(path)
    return sorted(result, key=priority)


def load_attachments(root: Path) -> tuple[list[dict[str, str | None]], dict[str, int]]:
    attachments: list[dict[str, str | None]] = []
    total_chars = 0
    skipped_large = 0
    skipped_decode = 0
    skipped_empty = 0
    skipped_limit = 0
    candidates = iter_project_files(root)
    for index, path in enumerate(candidates):
        if len(attachments) >= MAX_ATTACHMENTS:
            skipped_limit += len(candidates) - index
            break
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skipped_decode += 1
            continue
        content = content[:MAX_ATTACHMENT_CHARS]
        if not content.strip():
            skipped_empty += 1
            continue
        if total_chars + len(content) > MAX_TOTAL_CHARS:
            skipped_large += 1
            continue
        relative = f"{root.name}/{path.relative_to(root)}".replace("\\", "/")
        attachments.append({"file_name": relative, "content": content, "mime_type": None})
        total_chars += len(content)
    return attachments, {
        "candidate_files": len(candidates),
        "uploaded_files": len(attachments),
        "uploaded_chars": total_chars,
        "skipped_large": skipped_large,
        "skipped_decode": skipped_decode,
        "skipped_empty": skipped_empty,
        "skipped_limit": skipped_limit,
    }


def source_counts(root: Path) -> dict[str, int]:
    java = 0
    pom = 0
    for path in iter_project_files(root):
        if path.suffix.lower() == ".java":
            java += 1
        elif path.name.lower() == "pom.xml":
            pom += 1
    return {"java": java, "pom": pom}


def method_body(lines: list[str], signature_index: int) -> tuple[str, int]:
    body_lines: list[str] = []
    depth = 0
    started = False
    for index in range(signature_index, min(len(lines), signature_index + 260)):
        line = lines[index]
        body_lines.append(line)
        depth += line.count("{")
        if "{" in line:
            started = True
        depth -= line.count("}")
        if started and depth <= 0:
            return "\n".join(body_lines), index + 1
    return "\n".join(body_lines), min(len(lines), signature_index + 260)


def strip_java_comments_preserve_lines(content: str) -> str:
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


def looks_non_funds_candidate(method: str, joined: str) -> bool:
    if re.search(r'\balready processed\b|"PENDING"\.equals\([^)]*\.getStatus\s*\(', joined, flags=re.IGNORECASE):
        return True
    if re.search(r"^pass$", method, flags=re.IGNORECASE) and not REAL_MONEY_CONTEXT_RE.search(joined):
        return True
    if re.search(r"^(?:reject|decline)\w*$", method, flags=re.IGNORECASE) and re.search(
        r"chargeback", joined, flags=re.IGNORECASE
    ) and not re.search(r"refund|credit|addFunds|amount", joined, flags=re.IGNORECASE):
        return True
    if re.search(r"^(?:noPass|reject\w*)$", method, flags=re.IGNORECASE) and not REAL_MONEY_CONTEXT_RE.search(joined):
        return True
    if re.search(r"^audit(?:Pass|NoPass|Reject|Approve)?$", method, flags=re.IGNORECASE) and not REAL_MONEY_CONTEXT_RE.search(joined):
        return True
    if not NON_FUNDS_CONTEXT_RE.search(joined):
        return False
    return not REAL_MONEY_CONTEXT_RE.search(joined)


def find_method_signature(lines: list[str], annotation_index: int) -> tuple[int, str]:
    signature_lines: list[str] = []
    signature_index = -1
    for current in range(annotation_index, min(len(lines), annotation_index + 60)):
        stripped = lines[current].strip()
        if not stripped:
            continue
        if signature_index < 0 and stripped.startswith("@"):
            continue
        if signature_index < 0 and not METHOD_START_RE.search(stripped):
            # Skip multi-line annotation arguments such as Swagger @Operation/@ApiResponses.
            continue
        if signature_index < 0:
            signature_index = current
        signature_lines.append(stripped)
        signature = " ".join(signature_lines)
        if ";" in signature.split("{", 1)[0]:
            return -1, ""
        if "{" not in signature:
            continue
        match = METHOD_SIGNATURE_RE.search(signature)
        return (signature_index, match.group("name")) if match else (-1, "")
    return -1, ""


def called_method_names(body: str) -> list[str]:
    names = re.findall(r"\.\s*([A-Za-z_$][\w$]*)\s*\(", body)
    return [name for name in names if name not in {"save", "update", "insert", "delete", "setBalance", "setAmount"}]


def project_method_has_explicit_idempotency_guard(method: str, project_text: str) -> bool:
    if not method:
        return False
    lines = project_text.splitlines()
    for line_index, line in enumerate(lines):
        stripped = line.strip()
        if method not in stripped or not METHOD_START_RE.search(stripped):
            continue
        signature_parts = [stripped]
        for next_index in range(line_index + 1, min(len(lines), line_index + 20)):
            signature = " ".join(signature_parts)
            if "{" in signature or ";" in signature.split("{", 1)[0]:
                break
            signature_parts.append(lines[next_index].strip())
        signature = " ".join(signature_parts)
        match = METHOD_SIGNATURE_RE.search(signature)
        if not match or match.group("name") != method:
            continue
        body, _ = method_body(lines, line_index)
        if EXPLICIT_IDEMPOTENCY_RE.search(body):
            return True
    return False


def project_method_has_state_transition_guard(method: str, project_text: str) -> bool:
    if not method:
        return False
    guarded_state_re = re.compile(
        r"\bcanCancel\s*\(|\bgetStatus\s*\(\s*\)|\bsetStatus\s*\(|\bOrderStatus\b|"
        r"\bWithdrawStatus\b|\bPROCESSING\b|\bWAITING\b|\bSUCCESS\b|\bFAIL\b|"
        r"\bisTrue\s*\([^;]*(?:status|getStatus|Status)\b|不是审核状态|cannot be cancelled|already",
        flags=re.IGNORECASE,
    )
    lines = project_text.splitlines()
    for line_index, line in enumerate(lines):
        stripped = line.strip()
        if method not in stripped or not METHOD_START_RE.search(stripped):
            continue
        signature_parts = [stripped]
        for next_index in range(line_index + 1, min(len(lines), line_index + 20)):
            signature = " ".join(signature_parts)
            if "{" in signature or ";" in signature.split("{", 1)[0]:
                break
            signature_parts.append(lines[next_index].strip())
        signature = " ".join(signature_parts)
        match = METHOD_SIGNATURE_RE.search(signature)
        if not match or match.group("name") != method:
            continue
        body, _ = method_body(lines, line_index)
        if guarded_state_re.search(body):
            return True
    return False


def request_body_type_has_business_key(joined: str, dto_sources: dict[str, str]) -> bool:
    # A business object id such as paymentId/orderId/transactionId is not sufficient
    # evidence of idempotency. Only explicit idempotency/dedup request fields suppress
    # silver candidates at DTO level.
    dto_idempotency_re = re.compile(r"idempot|Idempotency-Key|X-Idempotency-Key|dedup|duplicate|nonce", re.IGNORECASE)
    request_body_type_re = re.compile(
        r"(?:@Valid\s+)?@RequestBody\s+(?:@Valid\s+)?(?P<type>[A-Za-z_$][\w$]*)\s+[A-Za-z_$][\w$]*|"
        r"@Valid\s+@RequestBody\s+(?P<type2>[A-Za-z_$][\w$]*)\s+[A-Za-z_$][\w$]*"
    )
    for match in request_body_type_re.finditer(joined):
        type_name = match.group("type") or match.group("type2")
        if not type_name:
            continue
        dto = dto_sources.get(type_name)
        if dto and dto_idempotency_re.search(dto):
            return True
    return False


def project_has_webhook_dedup(project_text: str) -> bool:
    return bool(
        re.search(r"\bevent\.getId\s*\(|\beventId\b|\bstripeEventId\b|findByStripeEventId|createProcessingIfNotExists", project_text)
        and re.search(r"webhook|Stripe-Signature|constructEvent", project_text, flags=re.IGNORECASE)
    )


def silver_candidates(attachments: list[dict[str, str | None]]) -> list[SilverCandidate]:
    candidates: list[SilverCandidate] = []
    dto_sources: dict[str, str] = {}
    project_text_parts: list[str] = []
    for attachment in attachments:
        file_name = str(attachment.get("file_name") or "")
        content = strip_java_comments_preserve_lines(str(attachment.get("content") or ""))
        if content:
            project_text_parts.append(content)
        class_match = re.search(r"\b(?:class|record)\s+([A-Za-z_$][\w$]*)\b", content)
        if class_match:
            dto_sources[class_match.group(1)] = content
    project_text = "\n".join(project_text_parts)
    for attachment in attachments:
        file_name = str(attachment.get("file_name") or "")
        if not file_name.endswith(".java"):
            continue
        normalized_file = file_name.replace("\\", "/").lower()
        content = strip_java_comments_preserve_lines(str(attachment.get("content") or ""))
        lines = content.splitlines()
        for index, line in enumerate(lines):
            if not MAPPING_RE.search(line):
                continue
            annotation_window = "\n".join(lines[index : min(len(lines), index + 6)])
            if not UNSAFE_METHOD_RE.search(annotation_window):
                continue
            signature_index, method = find_method_signature(lines, index)
            if signature_index < 0:
                continue
            if NON_FUNDS_METHOD_RE.search(method):
                continue
            body, end_line = method_body(lines, signature_index)
            if ACCOUNT_STATUS_METHOD_RE.search(method) and not re.search(r"amount|balance|wallet|minor", body, flags=re.IGNORECASE):
                continue
            joined = f"{annotation_window}\n{method}\n{body}"
            if looks_non_funds_candidate(method, joined):
                continue
            if "webhook" in joined.lower() and project_has_webhook_dedup(project_text):
                continue
            called_methods = called_method_names(body)
            if any(project_method_has_explicit_idempotency_guard(name, project_text) for name in called_methods):
                continue
            if STATE_GUARDED_METHOD_RE.search(method) and any(
                project_method_has_state_transition_guard(name, project_text) for name in called_methods
            ):
                continue
            if PAYMENT_PROFILE_RE.search(joined) and not STRONG_FINANCE_RE.search(joined):
                continue
            if not FINANCE_RE.search(joined):
                continue
            if not SINK_RE.search(body):
                continue
            if IDEMPOTENCY_RE.search(body):
                continue
            candidates.append(
                SilverCandidate(
                    file=file_name,
                    line=signature_index + 1,
                    end_line=end_line,
                    method=method,
                    reason="unsafe finance REST method with state-changing call and no visible idempotency token",
                )
            )
    return candidates


def post_json(url: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def ask_project(
    server_url: str,
    slug: str,
    attachments: list[dict[str, str | None]],
    timeout: int,
    run_label: str,
) -> dict[str, Any]:
    payload = {
        "question": f"请按照用户上传项目的正常流程进行本地代码审计，重点检测资金/交易接口幂等性漏洞，生成完整 Markdown 报告。评测批次：{run_label}",
        "top_k": 3,
        "user_id": "secflow-batch-evaluator",
        "session_id": f"finance-idempotency-{re.sub(r'[^A-Za-z0-9_.-]', '-', run_label)[:32]}-{re.sub(r'[^A-Za-z0-9_.-]', '-', slug)[:60]}",
        "response_language": "zh-Hans",
        "attachments": attachments,
    }
    envelope = post_json(f"{server_url.rstrip('/')}/api/assistant/questions", payload, timeout)
    if envelope.get("status") != "success":
        raise RuntimeError(str(envelope))
    return envelope.get("data") or {}


def load_report(server_url: str, report_id: str, timeout: int) -> str:
    envelope = get_json(f"{server_url.rstrip('/')}/api/reports/{report_id}", timeout)
    if envelope.get("status") != "success":
        raise RuntimeError(str(envelope))
    return str((envelope.get("data") or {}).get("content") or "")


def report_id(answer: dict[str, Any]) -> str:
    report = answer.get("report") if isinstance(answer.get("report"), dict) else {}
    return str(report.get("id") or "")


def parse_engine_idempotency_findings(content: str) -> list[EngineFinding]:
    findings: list[EngineFinding] = []
    sections = re.split(r"(?m)^###\s+\d+\.\s+", content)
    for section in sections[1:]:
        title = section.splitlines()[0].strip() if section.splitlines() else ""
        title_is_idempotency = "幂等" in title or "idempot" in title.lower()
        scenario_is_idempotency = bool(
            re.search(r"(?:风险场景|Risk scenario|シナリオ|위험 시나리오)[：:].*(?:幂等|idempot)", section, re.IGNORECASE)
            or re.search(r"(?:规则|Rule)[：:].*(?:idempotency|幂等)", section, re.IGNORECASE)
        )
        if not title_is_idempotency and not scenario_is_idempotency:
            continue
        location_match = re.search(r"(?:风险位置|Risk location|リスク位置|위험 위치)[：:]\s*(.+?):(\d+)", section)
        if not location_match:
            location_match = re.search(r"([\w./@+ -]+\.java):(\d+)", section)
        if not location_match:
            continue
        findings.append(
            EngineFinding(
                title=title,
                file=location_match.group(1).strip(),
                line=int(location_match.group(2)),
                scenario="idempotency_missing",
            )
        )
    return findings


def parse_engine_finance_findings(content: str) -> list[EngineFinding]:
    findings: list[EngineFinding] = []
    sections = re.split(r"(?m)^###\s+\d+\.\s+", content)
    for section in sections[1:]:
        lines = section.splitlines()
        title = lines[0].strip() if lines else ""
        scenario_match = re.search(
            r"(?:风险场景|Risk scenario|シナリオ|위험 시나리오)[：:]\s*([^\n]+)",
            section,
            re.IGNORECASE,
        )
        rule_match = re.search(r"(?:规则|Rule)[：:]\s*([^\n]+)", section, re.IGNORECASE)
        semantic_text = " ".join(
            [title, scenario_match.group(1) if scenario_match else "", rule_match.group(1) if rule_match else ""]
        )
        if not re.search(
            r"幂等|资金|金额精度|事务边界|状态迁移|idempot|funds?|finance|transaction|state.transition",
            semantic_text,
            re.IGNORECASE,
        ):
            continue
        location_match = re.search(r"(?:风险位置|Risk location|リスク位置|위험 위치)[：:]\s*(.+?):(\d+)", section)
        if not location_match:
            location_match = re.search(r"([\w./@+ -]+\.java):(\d+)", section)
        if not location_match:
            continue
        scenario = scenario_match.group(1).strip() if scenario_match else (rule_match.group(1).strip() if rule_match else "finance")
        findings.append(
            EngineFinding(
                title=title,
                file=location_match.group(1).strip(),
                line=int(location_match.group(2)),
                scenario=scenario,
            )
        )
    return findings


def match_findings(candidates: list[SilverCandidate], findings: list[EngineFinding]) -> dict[str, Any]:
    matched_candidates: set[int] = set()
    matched_findings: set[int] = set()
    for finding_index, finding in enumerate(findings):
        same_file = [
            (candidate_index, candidate)
            for candidate_index, candidate in enumerate(candidates)
            if candidate_index not in matched_candidates and finding.file == candidate.file
        ]
        exact = [
            (candidate_index, candidate)
            for candidate_index, candidate in same_file
            if candidate.line <= finding.line <= candidate.end_line
        ]
        tolerant = [
            (candidate_index, candidate)
            for candidate_index, candidate in same_file
            if candidate.line - 8 <= finding.line <= candidate.end_line + 8
        ]
        selected = exact or sorted(
            tolerant,
            key=lambda item: min(abs(finding.line - item[1].line), abs(finding.line - item[1].end_line)),
        )
        if selected:
            candidate_index, _ = selected[0]
            matched_candidates.add(candidate_index)
            matched_findings.add(finding_index)
    matched = len(matched_findings)
    engine_only = len(findings) - matched
    heuristic_only = len(candidates) - len(matched_candidates)
    return {
        "matched_engine_findings": matched,
        "engine_only_findings": engine_only,
        "heuristic_only_candidates": heuristic_only,
        "engine_candidate_agreement": matched / len(findings) if findings else None,
        "heuristic_candidate_coverage": matched / len(candidates) if candidates else None,
        "ground_truth_available": False,
        "matched_candidate_indexes": sorted(matched_candidates),
        "unmatched_findings": [asdict(findings[index]) for index in range(len(findings)) if index not in matched_findings],
        "unmatched_candidates": [asdict(candidates[index]) for index in range(len(candidates)) if index not in matched_candidates],
    }


def write_markdown(report: dict[str, Any], markdown: Path) -> None:
    summary = report.get("summary") or {}
    lines = [
        "# GitHub 金融/证券/交易 Java 项目幂等性扫描评估",
        "",
        f"- 生成时间：{report.get('generated_at')}",
        f"- 项目数：{summary.get('requested_projects')} 请求 / {summary.get('completed_projects')} 完成",
        f"- 上传路径：`POST /api/assistant/questions`，按 mac 客户端目录拖入规则限制 300 文件、单文件 120k 字符、总 600 万字符",
        f"- 启发式复核候选：{summary.get('heuristic_candidates')}",
        f"- 引擎幂等性命中：{summary.get('engine_idempotency_findings')}",
        f"- 引擎资金逻辑总命中：{summary.get('engine_finance_findings')}",
        f"- 引擎与候选同位置匹配：{summary.get('matched_engine_findings')}",
        f"- 仅引擎命中 / 仅候选：{summary.get('engine_only_findings')} / {summary.get('heuristic_only_candidates')}",
        "",
        "说明：真实 GitHub 项目没有维护方提供的逐行标准答案，因此本报告不计算或声称 Precision、Recall、FPR、FNR。候选一致性仅用于抽样复核，不是准确率。",
        "",
        "## 项目明细 Top 50",
        "",
        "| 项目 | 状态 | Java | 上传文件 | 复核候选 | 引擎命中 | 同位置 | 仅引擎 | 仅候选 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in (report.get("projects") or [])[:50]:
        counts = item.get("source_files") or {}
        upload = item.get("upload") or {}
        metrics = item.get("candidate_agreement") or {}
        lines.append(
            f"| {item.get('slug')} | {item.get('status')} | {counts.get('java', 0)} | "
            f"{upload.get('uploaded_files', 0)} | {item.get('heuristic_candidate_count', item.get('silver_candidate_count', 0))} | "
            f"{item.get('engine_idempotency_count', 0)} | {metrics.get('matched_engine_findings', 0)} | "
            f"{metrics.get('engine_only_findings', 0)} | {metrics.get('heuristic_only_candidates', 0)} |"
        )
    markdown.parent.mkdir(parents=True, exist_ok=True)
    markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")


def summarize(report: dict[str, Any], requested: int) -> None:
    completed = [item for item in report["projects"] if item.get("status") in {"completed", "warning"}]
    matched = sum(int((item.get("candidate_agreement") or {}).get("matched_engine_findings") or 0) for item in completed)
    engine_only = sum(int((item.get("candidate_agreement") or {}).get("engine_only_findings") or 0) for item in completed)
    heuristic_only = sum(int((item.get("candidate_agreement") or {}).get("heuristic_only_candidates") or 0) for item in completed)
    findings = sum(int(item.get("engine_idempotency_count") or 0) for item in completed)
    finance_findings = sum(int(item.get("engine_finance_count") or 0) for item in completed)
    candidates = sum(int(item.get("heuristic_candidate_count") or item.get("silver_candidate_count") or 0) for item in completed)
    report["summary"] = {
        "requested_projects": requested,
        "completed_projects": len(completed),
        "failed_projects": len(report["projects"]) - len(completed),
        "total_java_files": sum(int((item.get("source_files") or {}).get("java") or 0) for item in completed),
        "total_uploaded_files": sum(int((item.get("upload") or {}).get("uploaded_files") or 0) for item in completed),
        "heuristic_candidates": candidates,
        "engine_idempotency_findings": findings,
        "engine_finance_findings": finance_findings,
        "matched_engine_findings": matched,
        "engine_only_findings": engine_only,
        "heuristic_only_candidates": heuristic_only,
        "ground_truth_available": False,
        "accuracy_metrics_claimed": False,
        "total_elapsed_seconds": round(sum(float(item.get("elapsed_seconds") or 0) for item in completed), 2),
    }


def main() -> int:
    args = parse_args()
    projects = manifest_projects(args.manifest)
    if args.limit > 0:
        projects = projects[: args.limit]
    repositories = args.repositories_dir or (args.workspace / "repositories")
    reports_dir = args.reports_dir or (args.workspace / "reports")
    previous_by_slug: dict[str, dict[str, Any]] = {}
    if args.resume and args.output.is_file():
        previous = json.loads(args.output.read_text(encoding="utf-8"))
        previous_by_slug = {
            str(item.get("slug") or ""): item
            for item in previous.get("projects") or []
            if item.get("status") in {"completed", "warning"}
        }
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "manifest": str(args.manifest),
        "server_url": args.server_url,
        "run_label": args.run_label,
        "evaluation_policy": {
            "upload_path": "POST /api/assistant/questions",
            "ground_truth": "none for unlabeled GitHub projects; candidate agreement is not an accuracy metric",
            "focus": "finance idempotency missing on unsafe REST money/trading endpoints",
        },
        "projects": [],
    }
    for index, spec in enumerate(projects, start=1):
        slug = str(spec["slug"])
        print(f"[{index}/{len(projects)}] {slug}", flush=True)
        if slug in previous_by_slug:
            report["projects"].append(previous_by_slug[slug])
            print("  reused completed result", flush=True)
            continue
        started = time.monotonic()
        item: dict[str, Any] = {
            "slug": slug,
            "url": spec.get("url"),
            "ref": spec.get("ref"),
            "stars": spec.get("stars"),
        }
        try:
            checkout, commit = ensure_checkout(spec, repositories, args.clone_timeout)
            item["commit"] = commit
            item["source_files"] = source_counts(checkout)
            attachments, upload_stats = load_attachments(checkout)
            item["upload"] = upload_stats
            candidates = silver_candidates(attachments)
            item["heuristic_candidate_count"] = len(candidates)
            item["heuristic_candidates_sample"] = [asdict(candidate) for candidate in candidates[:20]]
            if not attachments:
                item.update({"status": "skipped", "error": "no uploadable attachments"})
            else:
                answer = ask_project(args.server_url, slug, attachments, args.request_timeout, args.run_label)
                item["answer_mode"] = answer.get("mode")
                item["trace"] = answer.get("trace") or []
                item["report"] = answer.get("report") or {}
                rid = report_id(answer)
                content = load_report(args.server_url, rid, args.request_timeout) if rid else ""
                if rid and content:
                    reports_dir.mkdir(parents=True, exist_ok=True)
                    (reports_dir / f"{slug.replace('/', '__')}.md").write_text(content, encoding="utf-8")
                findings = parse_engine_idempotency_findings(content)
                finance_findings = parse_engine_finance_findings(content)
                item["engine_idempotency_count"] = len(findings)
                item["engine_idempotency_findings"] = [asdict(finding) for finding in findings[:30]]
                item["engine_finance_count"] = len(finance_findings)
                item["engine_finance_findings"] = [asdict(finding) for finding in finance_findings[:50]]
                item["candidate_agreement"] = match_findings(candidates, findings)
                item["status"] = "completed"
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            item.update({"status": "failed", "error": f"HTTP {exc.code}: {body[:1000]}"})
        except Exception as exc:  # noqa: BLE001
            item.update({"status": "failed", "error": str(exc)})
        item["elapsed_seconds"] = round(time.monotonic() - started, 2)
        report["projects"].append(item)
        summarize(report, len(projects))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        write_markdown(report, args.markdown)
        time.sleep(args.sleep)
    summarize(report, len(projects))
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_markdown(report, args.markdown)
    return 0 if report["summary"]["completed_projects"] == len(projects) else 1


if __name__ == "__main__":
    raise SystemExit(main())
