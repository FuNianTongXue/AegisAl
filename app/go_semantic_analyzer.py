from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from tree_sitter import Language, Node, Parser
    import tree_sitter_go
except Exception:  # pragma: no cover - optional runtime dependency
    Language = None
    Node = Any
    Parser = None
    tree_sitter_go = None


_CONTEXT_RE = re.compile(
    r"(?P<context>[A-Za-z_]\w*)\s*,\s*(?P<cancel>[A-Za-z_]\w*|_)\s*(?P<operator>:=|=)\s*"
    r"context\.(?P<kind>WithCancel(?:Cause)?|WithTimeout(?:Cause)?|WithDeadline(?:Cause)?)\s*\("
)
_CONTEXT_PARAM_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s+context\.Context\b")
_HTTP_RESPONSE_PARAM_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s+http\.ResponseWriter\b")
_HTTP_REQUEST_PARAM_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s+\*http\.Request\b")
_UNBOUNDED_LOOP_RE = re.compile(r"\bfor\s*(?:;\s*;\s*)?\{")
_STRUCT_RE = re.compile(
    r"(?ms)^\s*type\s+(?P<name>[A-Za-z_]\w*)\s+struct\s*\{(?P<body>.*?)^\s*\}"
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|credential|token|api_?key|access_?key|private_?key|client_?secret|auth_?key|jwt_?key)"
)
_SERIALIZER_RE = re.compile(
    r"\b(?:json|yaml|xml)\.(?:Marshal|MarshalIndent)\s*\(|"
    r"\b(?:json|yaml|xml|toml)\.NewEncoder\s*\([^\n]*\)\.Encode\s*\(|"
    r"\btoml\.NewEncoder\s*\("
)
_DECLARED_INTEGER_RE = re.compile(
    r"\bvar\s+(?P<name>[A-Za-z_]\w*)\s+(?P<type>u?int(?:8|16|32|64)?|byte|rune)\s*=\s*(?P<value>[^\n;]+)"
)
_ASSIGNED_INTEGER_RE = re.compile(
    r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<value>"
    r"[-+]?(?:0[xX][0-9A-Fa-f]+|\d+)|math\.(?:Max|Min)(?:Int|Uint)(?:8|16|32|64)?)\s*(?:$|;|//)"
)
_CONVERSION_RE = re.compile(
    r"\b(?P<target>u?int(?:8|16|32|64)|byte|rune)\s*\(\s*(?P<value>"
    r"[A-Za-z_]\w*|[-+]?(?:0[xX][0-9A-Fa-f]+|\d+)|math\.(?:Max|Min)(?:Int|Uint)(?:8|16|32|64)?)\s*\)"
)
_INTEGER_PARAMETER_RE = re.compile(
    r"\b(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+"
    r"(?P<slice>\[\])?(?P<type>u?int(?:8|16|32|64)?|byte|rune)\b"
)
_TYPED_INTEGER_ASSIGN_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<type>u?int(?:8|16|32|64)|byte|rune)"
    r"\s*\(\s*(?P<value>[-+]?(?:0[xX][0-9A-Fa-f]+|\d+))\s*\)"
)
_PARSED_INTEGER_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*,\s*(?:[A-Za-z_]\w*|_)\s*(?::=|=)\s*"
    r"strconv\.Parse(?P<kind>Int|Uint)"
    r"\s*\([^\n,]+,\s*[^\n,]+,\s*(?P<bits>8|16|32|64)\s*\)"
)
_ATOI_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*,\s*[A-Za-z_]\w*\s*:=\s*strconv\.Atoi\s*\("
)
_RANDOM_INTEGER_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:math/)?rand\.(?P<kind>Int|Int31|Int63)\s*\(\s*\)"
)
_INTEGER_EXPRESSION_ASSIGN_RE = re.compile(
    r"(?m)^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<value>[^,;\n]+)"
)
_RANGE_VALUE_RE = re.compile(
    r"\bfor\s+_\s*,\s*(?P<value>[A-Za-z_]\w*)\s*:=\s*range\s+(?P<sequence>[A-Za-z_]\w*)"
)
_FIXED_BYTES_RE = re.compile(
    r"(?m)^\s*(?:var\s+|const\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?:\[\]byte\s*\([^\n]+\)|\[\]byte\s*\{[^\n]*\}|make\s*\(\s*\[\]byte\s*,\s*\d+\s*\)|\"[^\n]+\")"
)
_CRYPTO_NONCE_SINK_RE = re.compile(
    r"(?:cipher\.(?:NewCBCEncrypter|NewCFBEncrypter|NewCTR|NewOFB)\s*\([^,]+,\s*"
    r"(?P<stream>\[\]byte\s*\([^)]*\)|[A-Za-z_]\w*(?:\[[^\]]+\])?)|"
    r"[A-Za-z_]\w*\.Seal\s*\([^,]+,\s*(?P<aead>\[\]byte\s*\([^)]*\)|[A-Za-z_]\w*(?:\[[^\]]+\])?))"
)
_FUNCTION_RE = re.compile(
    r"(?ms)\bfunc\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)[^{]*\{(?P<body>.*?)^\}"
)
_MAKE_SLICE_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*make\s*\(\s*\[\][^,]+,\s*"
    r"(?P<length>\d+)\s*(?:,\s*(?P<capacity>\d+)\s*)?\)"
)
_ARRAY_RE = re.compile(r"\bvar\s+(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<length>\d+)\s*\][^\n]+")
_NIL_SLICE_RE = re.compile(r"\bvar\s+(?P<name>[A-Za-z_]\w*)\s+\[\][^=\n]+(?:$|//)")
_SLICE_ALIAS_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<source>[A-Za-z_]\w*)"
    r"\s*\[\s*(?P<low>[^:\]]*)\s*:\s*(?P<high>[^:\]]*)"
    r"(?:\s*:\s*(?P<maximum>[^\]]+))?\s*\]"
)
_FOR_RANGE_RE = re.compile(
    r"\bfor\s+(?P<name>[A-Za-z_]\w*)\s*:=\s*(?P<start>-?\d+)\s*;\s*"
    r"(?P=name)\s*(?P<operator><=?|>=?)\s*"
    r"(?P<end>len\s*\(\s*[A-Za-z_]\w*\s*\)|[A-Za-z_]\w*|-?\d+)\s*;"
)
_RANGE_INDEX_RE = re.compile(
    r"\bfor\s+(?P<name>[A-Za-z_]\w*)\s*(?:,\s*_)?\s*:=\s*range\s+(?P<sequence>[A-Za-z_]\w*)"
)
_NOSEC_RE = re.compile(r"#\s*nosec\b|nolint(?::[^\s]+)?", flags=re.IGNORECASE)
_SQL_SOURCE_CALL_RE = re.compile(
    r"(?:\b[A-Za-z_]\w*\.(?:FormValue|PostFormValue)\s*\(|"
    r"\b[A-Za-z_]\w*\.URL\.Query\s*\(\s*\)\.Get\s*\(|"
    r"\bos\.Args(?:\s*\[|\b)|\bflag\.Arg\s*\()"
)
_SQL_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|=)\s*(?P<value>[^\n;]+)"
)
_SQL_KEYWORD_RE = re.compile(r"(?i)\b(?:select|delete|insert|create|update|alter|drop|with)\b")
_SQL_SINK_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\."
    r"(?P<method>Query|QueryContext|QueryRow|QueryRowContext|QueryOne|QueryEx|Exec|ExecContext|ExecEx)"
    r"\s*\((?P<arguments>[^\n;]*)"
)
_SQL_SANITIZER_RE = re.compile(
    r"\b(?:strconv\.(?:Atoi|ParseInt|ParseUint)|pq\.QuoteIdentifier)\s*\("
)
_COMMAND_SOURCE_CALL_RE = re.compile(
    r"(?:\b[A-Za-z_]\w*\.(?:FormValue|PostFormValue)\s*\(|"
    r"\b[A-Za-z_]\w*\.Form\.Get\s*\(|"
    r"\b[A-Za-z_]\w*\.URL\.Query\s*\(\s*\)\.Get\s*\(|"
    r"\bos\.Args(?:\s*\[|\b)|\bos\.Getenv\s*\(|\bflag\.Arg\s*\()"
)
_COMMAND_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|=)\s*(?P<value>[^\n;]+)"
)
_HTML_SANITIZER_RE = re.compile(r"\b(?:html\.EscapeString|template\.HTMLEscapeString)\s*\(")
_XSS_SANITIZER_RE = re.compile(
    r"\b(?:html\.EscapeString|template\.HTMLEscapeString|"
    r"json\.Marshal(?:Indent)?|"
    r"strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool|Itoa|FormatInt|FormatUint|FormatFloat|Quote))\s*\("
)
_SMTP_ADDRESS_SANITIZER_RE = re.compile(r"\bmail\.ParseAddress(?:List)?\s*\(")
_GO_IMPORT_RE = re.compile(
    r"(?m)^\s*(?:import\s+)?(?:(?P<alias>[A-Za-z_]\w*|[._])\s+)?"
    r"(?P<quote>[\"`])(?P<path>[^\"`]+)(?P=quote)"
)
_MATH_RAND_PATH_RE = re.compile(r"^math/rand(?:/v\d+)?$")
_WEAK_MATH_RAND_METHODS = {
    "ExpFloat64",
    "Float32",
    "Float64",
    "Int",
    "Int31",
    "Int31n",
    "Int32",
    "Int32N",
    "Int63",
    "Int63n",
    "Int64",
    "Int64N",
    "IntN",
    "Intn",
    "N",
    "New",
    "NewChaCha8",
    "NewPCG",
    "NewSource",
    "NormFloat64",
    "Perm",
    "Read",
    "Shuffle",
    "Uint",
    "Uint32",
    "Uint64",
}
_WEAK_MATH_RAND_METHOD_RE = "|".join(sorted(_WEAK_MATH_RAND_METHODS, key=len, reverse=True))
_TLS_VERSION_VALUES = {
    "VersionSSL30": 0x0300,
    "VersionTLS10": 0x0301,
    "VersionTLS11": 0x0302,
    "VersionTLS12": 0x0303,
    "VersionTLS13": 0x0304,
}
_TLS_CONFIG_FIELD_RE = re.compile(
    r"\b(?P<field>InsecureSkipVerify|PreferServerCipherSuites|MinVersion|MaxVersion)\s*:\s*(?P<expr>[^,\n}]+)"
)
_TLS_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?:const|var)?\s*(?P<name>[A-Za-z_]\w*)\s*(?:[A-Za-z_]\w*)?\s*=\s*(?P<expr>[^\n;]+)"
)
_TLS_FIELD_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\.(?P<field>InsecureSkipVerify|PreferServerCipherSuites|MinVersion|MaxVersion)"
    r"\s*=\s*(?P<expr>[^\n;]+)"
)
_PLAINTEXT_URL_VALUE_RE = re.compile(
    r'^[\"`]ftp://[^\"`\s]+[\"`]$|^[\"`]http://(?!127\.0\.0\.1(?:[:/]|$)|localhost(?:[:/]|$))[^\"`\s]+[\"`]$',
    re.IGNORECASE,
)
_PLAINTEXT_URL_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?:const\s+|var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<value>[\"`][^\"`\s]+[\"`])"
)


@dataclass(frozen=True)
class _SequenceBounds:
    length: int
    capacity: int


@dataclass(frozen=True)
class _IntegerConversion:
    target: str
    value: str
    start: int


def analyze_go_semantics(code_files: list[dict[str, str]]) -> dict[str, Any]:
    parser = _parser()
    if parser is None:
        return {
            "status": "unavailable",
            "findings": [],
            "diagnostics": ["Go 语义分析器缺少 Tree-sitter Go 语法包。"],
        }

    findings: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    for code_file in code_files:
        file_name = str(code_file.get("file_name") or "")
        if Path(file_name).suffix.lower() != ".go":
            continue
        content = str(code_file.get("content") or "")
        source = content.encode("utf-8", errors="replace")
        tree = parser.parse(source)
        if tree.root_node.has_error:
            diagnostics.append(f"{file_name}: Go 语义分析遇到语法错误，结果可能不完整。")
        functions = [
            node
            for node in _walk(tree.root_node)
            if node.type in {"function_declaration", "method_declaration", "func_literal"}
        ]
        background_context_helpers = _background_context_helper_lines(content)
        for function in functions:
            body = function.child_by_field_name("body") or function
            function_text = source[body.start_byte : body.end_byte].decode("utf-8", errors="replace")
            signature_text = source[function.start_byte : body.start_byte].decode("utf-8", errors="replace")
            base_line = body.start_point.row + 1
            findings.extend(
                _context_findings(file_name, content, function_text, base_line, signature_text)
            )
            findings.extend(
                _detached_background_context_findings(
                    file_name,
                    content,
                    function_text,
                    base_line,
                    signature_text,
                    background_context_helpers,
                )
            )
            findings.extend(
                _integer_findings(file_name, content, function_text, base_line, signature_text)
            )
            findings.extend(_bounds_findings(file_name, content, function_text, base_line))
            findings.extend(
                _command_execution_findings(file_name, content, function_text, base_line, signature_text)
            )
            findings.extend(
                _text_template_execution_findings(file_name, content, function_text, base_line, signature_text)
            )
            findings.extend(_plaintext_transport_findings(file_name, content, function_text, base_line))
            findings.extend(_md5_password_hash_findings(file_name, content, function_text, base_line))
            findings.extend(_directory_listing_findings(file_name, content, function_text, base_line))
            findings.extend(
                _unsafe_deserialization_findings(file_name, content, function_text, base_line, signature_text)
            )
            findings.extend(_range_variable_address_findings(file_name, content, function_text, base_line))
            findings.extend(_log_injection_findings(file_name, content, function_text, base_line))
            findings.extend(_ssrf_findings(file_name, content, function_text, base_line))
            findings.extend(_open_redirect_findings(file_name, content, function_text, base_line, signature_text))
            findings.extend(_ssti_findings(file_name, content, function_text, base_line, signature_text))
            findings.extend(_formatted_template_xss_findings(file_name, content, function_text, base_line, signature_text))
            findings.extend(_http_responsewriter_xss_findings(file_name, content, function_text, base_line, signature_text))
            findings.extend(_formatted_sql_findings(file_name, content, function_text, base_line, signature_text))
        findings.extend(_weak_math_random_findings(file_name, content))
        findings.extend(_weak_hash_findings(file_name, content))
        findings.extend(_tls_config_findings(file_name, content))
        findings.extend(_jwt_none_algorithm_findings(file_name, content))
        findings.extend(_jwt_parse_unverified_findings(file_name, content))
        findings.extend(_cgi_serve_findings(file_name, content))
        findings.extend(_trusted_template_type_findings(file_name, content))
        findings.extend(_weak_rsa_key_findings(file_name, content))
        findings.extend(_pprof_debug_exposure_findings(file_name, content))
        findings.extend(_xxe_external_entity_findings(file_name, content))
        findings.extend(_gorilla_websocket_origin_findings(file_name, content))
        findings.extend(_gorilla_session_identity_overwrite_findings(file_name, content))
        findings.extend(_http_smuggling_header_findings(file_name, content))
        findings.extend(_cross_origin_protection_bypass_findings(file_name, content))
        findings.extend(_unbounded_http_serve_findings(file_name, content))
        findings.extend(_zip_unbounded_copy_findings(file_name, content))
        findings.extend(_reverse_proxy_director_findings(file_name, content))
        findings.extend(_shared_url_mutation_findings(file_name, content))
        findings.extend(_reflect_dynamic_access_findings(file_name, content))
        findings.extend(_http_external_url_audit_findings(file_name, content))
        findings.extend(_syscall_start_process_findings(file_name, content))
        findings.extend(_smtp_header_injection_findings(file_name, content))
        findings.extend(_unsafe_pointer_string_findings(file_name, content))
        findings.extend(_bind_all_interfaces_findings(file_name, content))
        findings.extend(_redirect_sensitive_header_findings(file_name, content))
        findings.extend(_hardcoded_secret_comparison_findings(file_name, content))
        findings.extend(_ssh_public_key_callback_findings(file_name, content))
        findings.extend(_insecure_write_file_permission_findings(file_name, content))
        findings.extend(_gorilla_session_cookie_findings(file_name, content))
        findings.extend(_grpc_insecure_server_findings(file_name, content))
        findings.extend(_interprocedural_sql_findings(file_name, content, source, functions))
        findings.extend(_sensitive_serialization_findings(file_name, content))
        findings.extend(_fixed_nonce_findings(file_name, content))
        findings.extend(_interprocedural_slice_bounds_findings(file_name, content))

    findings.extend(_project_sql_global_findings(code_files))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        sink = finding.get("sink") or {}
        key = (str(finding.get("rule_id") or ""), str(sink.get("file") or ""), int(sink.get("line") or 0))
        if key in seen:
            continue
        seen.add(key)
        finding["id"] = f"go-semantic-{len(deduped) + 1}"
        deduped.append(finding)
    return {
        "status": "completed",
        "findings": deduped,
        "diagnostics": diagnostics,
    }


def _context_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str = "",
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in _CONTEXT_RE.finditer(text):
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        cancel = match.group("cancel")
        if (
            cancel != "_"
            and match.group("operator") == "="
            and _package_cancel_is_released(content, cancel)
        ):
            continue
        if cancel != "_" and _cancel_is_released_or_transferred(text, match.end(), cancel, content):
            continue
        snippet = _line(content, line)
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.context-cancel-leak",
                scenario="resource_exhaustion",
                title="context cancel 函数未调用",
                cwes=["CWE-400"],
                severity="medium",
                confidence="high" if cancel == "_" else "medium",
                file_name=file_name,
                line=line,
                snippet=snippet,
                dfg=f"context.{match.group('kind')} -> {cancel} -> 未调用/未返回",
                remediation="创建 context 后立即 defer cancel()，或把 cancel 返回给明确负责释放的调用方。",
            )
        )

    loop = _UNBOUNDED_LOOP_RE.search(text)
    if loop is None:
        return findings
    loop_tail = text[loop.end() :]
    if re.search(r"\bbreak\b", loop_tail):
        return findings
    if re.search(r"\bselect\s*\{", loop_tail) and not re.search(r"\bdefault\s*:", loop_tail):
        return findings
    loop_line = base_line + text.count("\n", 0, loop.start())
    if _is_suppressed(content, loop_line):
        return findings
    for context_match in _CONTEXT_PARAM_RE.finditer(signature_text):
        context_name = context_match.group("name")
        if _context_cancellation_is_observed(text, context_name):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.context-cancel-leak",
                scenario="resource_exhaustion",
                title="无界循环未观察 context 取消信号",
                cwes=["CWE-400"],
                severity="medium",
                confidence="medium",
                file_name=file_name,
                line=loop_line,
                snippet=_line(content, loop_line),
                dfg=f"{context_name}(context.Context) -> 无界循环 -> 未读取 Done/Err/Cause",
                remediation="在循环中 select 监听 ctx.Done()，或检查 ctx.Err()/context.Cause(ctx) 并退出。",
            )
        )
        break
    return findings


def _detached_background_context_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
    background_context_helpers: dict[str, int],
) -> list[dict[str, Any]]:
    has_context_source = bool(_CONTEXT_PARAM_RE.search(signature_text)) or _request_context_is_bound(
        signature_text,
        text,
    )
    if not has_context_source or not re.search(r"\bgo\b", text):
        return []

    background_vars: dict[str, int] = {}
    for match in re.finditer(
        r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*context\.(?:Background|TODO)\s*\(",
        text,
    ):
        background_vars[match.group("name")] = base_line + text.count("\n", 0, match.start())

    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\bgo\s+", text):
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        statement = _go_statement_text(text, match.end())
        source_line = line
        reason = ""
        if re.search(r"\bcontext\.(?:Background|TODO)\s*\(", statement):
            reason = "goroutine 内创建 context.Background/TODO"
        else:
            source_name = next(
                (
                    name
                    for name in background_vars
                    if re.search(rf"\b{re.escape(name)}\b", statement)
                ),
                "",
            )
            if source_name:
                source_line = background_vars[source_name]
                reason = f"goroutine 使用脱离父 ctx 的 {source_name}"
            else:
                helper = re.match(r"\s*(?P<name>[A-Za-z_]\w*)\s*\(", statement)
                if helper and helper.group("name") in background_context_helpers:
                    source_line = background_context_helpers[helper.group("name")]
                    reason = f"goroutine 调用创建 context.Background/TODO 的 {helper.group('name')}"
        if not reason:
            continue
        finding = _finding(
            rule_id="secflow.go.semantic.detached-background-context",
            scenario="resource_exhaustion",
            title="goroutine 脱离父 context 运行",
            cwes=["CWE-400"],
            severity="medium",
            confidence="medium",
            file_name=file_name,
            line=line,
            snippet=_line(content, line),
            dfg=f"context.Context 参数 -> go statement -> {reason}",
            remediation="把父 ctx 传入 goroutine/worker，并在循环或阻塞调用中监听 ctx.Done()。",
        )
        finding["source"]["line"] = source_line
        finding["source"]["snippet"] = _line(content, source_line)
        finding["path"][0] = finding["source"]
        findings.append(finding)
    return findings


def _go_statement_text(text: str, offset: int) -> str:
    tail = text[offset:]
    stripped = tail.lstrip()
    leading = len(tail) - len(stripped)
    statement_offset = offset + leading
    if stripped.startswith("func"):
        brace_index = text.find("{", statement_offset)
        if brace_index >= 0:
            _, end = _balanced_body(text, brace_index, "{", "}")
            if end > brace_index:
                return text[statement_offset : min(len(text), end + 120)]
    return stripped.splitlines()[0] if stripped else ""


def _background_context_helper_lines(content: str) -> dict[str, int]:
    helpers: dict[str, int] = {}
    for match in _FUNCTION_RE.finditer(content):
        body = match.group("body")
        if re.search(r"\bcontext\.(?:Background|TODO)\s*\(", body):
            helpers[match.group("name")] = content.count("\n", 0, match.start()) + 1
    return helpers


def _request_context_is_bound(signature_text: str, text: str) -> bool:
    request_names = {match.group("name") for match in _HTTP_REQUEST_PARAM_RE.finditer(signature_text)}
    return any(
        re.search(
            rf"(?m)^\s*[A-Za-z][A-Za-z0-9_]*\s*(?::=|=)\s*{re.escape(request_name)}\.Context\s*\(",
            text,
        )
        for request_name in request_names
    )


def _weak_math_random_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _math_rand_import_aliases(content)
    if not aliases:
        return []
    findings: list[dict[str, Any]] = []
    masked = _mask_go_comments(content)
    for alias, import_line in aliases.items():
        if alias == ".":
            selector_pattern = rf"(?<!\.)\b(?P<method>{_WEAK_MATH_RAND_METHOD_RE})\s*\("
        else:
            selector_pattern = rf"\b{re.escape(alias)}\s*\.\s*(?P<method>{_WEAK_MATH_RAND_METHOD_RE})\s*\("
        for match in re.finditer(selector_pattern, masked):
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            method = match.group("method")
            finding = _finding(
                rule_id="secflow.go.semantic.weak-math-random",
                scenario="weak_random",
                title="math/rand 生成可预测随机值",
                cwes=["CWE-338"],
                severity="medium",
                confidence="medium",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f'math/rand import(line {import_line}) -> {alias}.{method}() -> 安全敏感随机值可能可预测',
                remediation="安全敏感随机数使用 crypto/rand；仅测试、模拟或非安全用途应加明确 suppression。",
            )
            finding["source"]["line"] = import_line
            finding["source"]["snippet"] = _line(content, import_line)
            finding["source"]["label"] = "math/rand 导入"
            finding["path"][0] = finding["source"]
            findings.append(finding)
    return findings


def _math_rand_import_aliases(content: str) -> dict[str, int]:
    masked = _mask_go_comments(content)
    aliases: dict[str, tuple[str, int]] = {}
    conflicted: set[str] = set()
    for match in _GO_IMPORT_RE.finditer(masked):
        path = match.group("path")
        explicit_alias = match.group("alias")
        alias = explicit_alias or ("rand" if path.startswith("math/rand") else path.rsplit("/", 1)[-1])
        if alias == "_":
            continue
        line = content.count("\n", 0, match.start()) + 1
        existing = aliases.get(alias)
        if existing is not None and existing[0] != path:
            conflicted.add(alias)
        aliases[alias] = (path, line)
    return {
        alias: line
        for alias, (path, line) in aliases.items()
        if alias not in conflicted and _MATH_RAND_PATH_RE.fullmatch(path)
    }


def _weak_hash_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    packages = [
        ("golang.org/x/crypto/md4", "md4", {"New"}),
        ("golang.org/x/crypto/ripemd160", "ripemd160", {"New"}),
        ("golang.org/x/crypto/sha3", "sha3", {"New224", "Sum224"}),
    ]
    findings: list[dict[str, Any]] = []
    for package_path, default_alias, methods in packages:
        aliases = _package_import_aliases(content, package_path, default_alias)
        for alias, import_line in aliases.items():
            method_pattern = "|".join(re.escape(method) for method in sorted(methods, key=len, reverse=True))
            for match in re.finditer(rf"\b{re.escape(alias)}\.(?P<method>{method_pattern})\s*\(", _mask_go_comments(content)):
                line = content.count("\n", 0, match.start()) + 1
                if _is_suppressed(content, line):
                    continue
                method = match.group("method")
                finding = _finding(
                    rule_id="secflow.go.semantic.weak-hash",
                    scenario="weak_cryptography",
                    title="代码使用弱哈希算法",
                    cwes=["CWE-327", "CWE-328"],
                    severity="medium",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"{package_path} import(line {import_line}) -> {alias}.{method}()",
                    remediation="安全用途使用 SHA-256/SHA-512、BLAKE2/3 或 HMAC；密码存储使用 Argon2id、scrypt 或 bcrypt。",
                )
                finding["source"]["line"] = import_line
                finding["source"]["snippet"] = _line(content, import_line)
                finding["source"]["label"] = "弱哈希包导入"
                finding["path"][0] = finding["source"]
                findings.append(finding)
    return findings


def _tls_config_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "crypto/tls", "tls")
    if not aliases:
        return []
    bool_values, version_values = _literal_assignments(content, aliases)
    findings: list[dict[str, Any]] = []

    for match in _TLS_CONFIG_FIELD_RE.finditer(content):
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        field = match.group("field")
        expr = match.group("expr").strip()
        issue = _tls_config_issue(field, expr, bool_values, version_values, aliases)
        if issue is None:
            continue
        findings.append(_tls_finding(file_name, content, line, line, field, expr, issue))

    config_lines = _tls_config_variable_lines(content, aliases)
    for match in _TLS_FIELD_ASSIGNMENT_RE.finditer(content):
        name = match.group("name")
        field = match.group("field")
        expr = match.group("expr").strip()
        issue = _tls_config_issue(field, expr, bool_values, version_values, aliases)
        if issue is None:
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _tls_finding(file_name, content, _nearest_tls_config_line(config_lines, name, match.start(), line), line, field, expr, issue)
        )

    for match in re.finditer(r"\bCipherSuites\s*:\s*\[\]uint16\s*\{(?P<body>[^}]*)\}", content, flags=re.DOTALL):
        body = match.group("body")
        if not any(re.search(rf"\b{re.escape(alias)}\.TLS_RSA_WITH_[A-Z0-9_]+\b", body) for alias in aliases):
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.insecure-tls-config",
                scenario="insecure_transport",
                title="TLS 配置包含 RSA 密钥交换 cipher suite",
                cwes=["CWE-295", "CWE-327"],
                severity="medium",
                confidence="medium",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="crypto/tls.Config.CipherSuites -> TLS_RSA_WITH_* -> 缺少前向保密",
                remediation="优先使用 TLS 1.3，或仅保留 ECDHE/AEAD cipher suite，并让 Go 使用安全默认值。",
            )
        )

    for alias in aliases:
        for match in re.finditer(rf"&?{re.escape(alias)}\.Config\s*\{{", content):
            body = _balanced_brace_body(content, content.find("{", match.start()))
            if body is None:
                continue
            line = content.count("\n", 0, match.start()) + 1
            source_line = _line(content, line)
            if not re.search(rf"\.[Tt]LS\s*=\s*&?{re.escape(alias)}\.Config\b", source_line):
                continue
            rand_match = re.search(r"\bRand\s*:\s*(?P<expr>[^,\n}]+)", body)
            if rand_match is None:
                continue
            expr = rand_match.group("expr").strip()
            if re.fullmatch(r"(?:crypto/)?rand\.Reader", expr):
                continue
            field_line = line + body.count("\n", 0, rand_match.start())
            if _is_suppressed(content, field_line):
                continue
            finding = _finding(
                rule_id="secflow.go.semantic.insecure-tls-config",
                scenario="weak_cryptography",
                title="TLS 配置使用非安全随机源",
                cwes=["CWE-327", "CWE-338"],
                severity="high",
                confidence="medium",
                file_name=file_name,
                line=field_line,
                snippet=_line(content, field_line),
                dfg=f"crypto/tls.Config.Rand={expr} -> TLS 握手随机数可预测",
                remediation="不要覆盖 tls.Config.Rand；如必须提供随机源，使用 crypto/rand.Reader。",
            )
            finding["source"]["line"] = line
            finding["source"]["snippet"] = _line(content, line)
            finding["path"][0] = finding["source"]
            findings.append(finding)
    return findings


def _tls_config_issue(
    field: str,
    expr: str,
    bool_values: dict[str, bool],
    version_values: dict[str, int],
    aliases: dict[str, int],
) -> tuple[str, list[str]] | None:
    if field == "InsecureSkipVerify" and _resolved_bool(expr, bool_values) is True:
        return "证书和主机名验证被关闭", ["CWE-295", "CWE-319"]
    if field == "PreferServerCipherSuites" and _resolved_bool(expr, bool_values) is False:
        return "服务端未优先选择自身安全 cipher suite 顺序", ["CWE-295", "CWE-327"]
    if field in {"MinVersion", "MaxVersion"}:
        version = _resolved_tls_version(expr, version_values, aliases)
        if version is not None and 0 < version < _TLS_VERSION_VALUES["VersionTLS12"]:
            reason = "最低 TLS 版本低于 TLS 1.2" if field == "MinVersion" else "最高 TLS 版本被限制在 TLS 1.0/1.1"
            return reason, ["CWE-295", "CWE-319", "CWE-327"]
    return None


def _tls_finding(
    file_name: str,
    content: str,
    source_line: int,
    sink_line: int,
    field: str,
    expr: str,
    issue: tuple[str, list[str]],
) -> dict[str, Any]:
    reason, cwes = issue
    finding = _finding(
        rule_id="secflow.go.semantic.insecure-tls-config",
        scenario="insecure_transport",
        title="TLS 配置降低连接安全性",
        cwes=cwes,
        severity="high",
        confidence="high",
        file_name=file_name,
        line=sink_line,
        snippet=_line(content, sink_line),
        dfg=f"crypto/tls.Config.{field}={expr} -> {reason}",
        remediation="启用证书验证，使用 TLS 1.2 以上版本，并移除弱 cipher suite 或过低版本上限。",
    )
    finding["source"]["line"] = source_line
    finding["source"]["snippet"] = _line(content, source_line)
    finding["path"][0] = finding["source"]
    return finding


def _tls_config_variable_lines(content: str, aliases: dict[str, int]) -> dict[str, list[tuple[int, int]]]:
    result: dict[str, list[tuple[int, int]]] = {}
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    if not alias_pattern:
        return result
    for match in re.finditer(
        rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*&?(?:{alias_pattern})\.Config\s*\{{",
        content,
    ):
        result.setdefault(match.group("name"), []).append((match.start(), content.count("\n", 0, match.start()) + 1))
    return result


def _nearest_tls_config_line(
    config_lines: dict[str, list[tuple[int, int]]],
    name: str,
    offset: int,
    fallback: int,
) -> int:
    candidates = [line for start, line in config_lines.get(name, []) if start < offset]
    return candidates[-1] if candidates else fallback


def _plaintext_transport_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    urls: dict[str, tuple[str, int]] = {}
    for match in _PLAINTEXT_URL_ASSIGNMENT_RE.finditer(text):
        value = match.group("value")
        if not _PLAINTEXT_URL_VALUE_RE.fullmatch(value):
            continue
        urls[match.group("name")] = (value.strip("\"`"), base_line + text.count("\n", 0, match.start()))

    findings: list[dict[str, Any]] = []
    call_patterns = [
        re.compile(r"\bftp\.(?:Dial|DialTimeout|Connect)\s*\("),
        re.compile(r"\.[A-Za-z_]*(?:Base|Get|Post|Put|Patch|Delete)\s*\("),
    ]
    for call_re in call_patterns:
        for match in call_re.finditer(text):
            arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if not arguments:
                continue
            source_line = 0
            url_value = ""
            first = arguments[0].strip()
            if _PLAINTEXT_URL_VALUE_RE.fullmatch(first):
                source_line = base_line + text.count("\n", 0, match.start())
                url_value = first.strip("\"`")
            elif first in urls:
                url_value, source_line = urls[first]
            if not url_value:
                continue
            line = base_line + text.count("\n", 0, match.start())
            if _is_suppressed(content, line):
                continue
            finding = _finding(
                rule_id="secflow.go.semantic.plaintext-transport",
                scenario="insecure_transport",
                title="明文协议 URL 进入网络客户端",
                cwes=["CWE-319"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{url_value} -> network client",
                remediation="使用 HTTPS、SFTP/FTPS 或 SSH，并避免把明文协议 URL 作为外部服务端点。",
            )
            finding["source"]["line"] = source_line
            finding["source"]["snippet"] = _line(content, source_line)
            finding["path"][0] = finding["source"]
            findings.append(finding)
    return findings


def _md5_password_hash_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "crypto/md5", "md5")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    if not alias_pattern:
        return []

    hash_vars: dict[str, int] = {}
    for match in re.finditer(
        rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:{alias_pattern})\.New\s*\(\s*\)",
        text,
    ):
        hash_vars[match.group("name")] = base_line + text.count("\n", 0, match.start())
    if not hash_vars:
        return []

    findings: list[dict[str, Any]] = []
    sink_re = re.compile(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.set(?:Password|Passwd)\s*\(")
    for match in sink_re.finditer(text):
        arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        source_name = next(
            (
                name
                for name in hash_vars
                if re.search(rf"\b{re.escape(name)}\.Sum\s*\(", arguments_text)
            ),
            "",
        )
        if not source_name:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        source_line = hash_vars[source_name]
        finding = _finding(
            rule_id="secflow.go.semantic.md5-password-hash",
            scenario="weak_cryptography",
            title="MD5 哈希结果被用作密码存储值",
            cwes=["CWE-327"],
            severity="high",
            confidence="high",
            file_name=file_name,
            line=line,
            snippet=_line(content, line),
            dfg=f"md5.New() -> {source_name}.Sum(...) -> setPassword",
            remediation="密码存储使用 Argon2id、scrypt 或 bcrypt，并使用唯一随机盐和合理成本参数。",
        )
        finding["source"]["line"] = source_line
        finding["source"]["snippet"] = _line(content, source_line)
        finding["path"][0] = finding["source"]
        findings.append(finding)
    return findings


def _jwt_none_algorithm_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases: dict[str, int] = {}
    for package_path in (
        "github.com/dgrijalva/jwt-go",
        "github.com/golang-jwt/jwt",
        "github.com/golang-jwt/jwt/v4",
        "github.com/golang-jwt/jwt/v5",
    ):
        aliases.update(_package_import_aliases(content, package_path, "jwt"))
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    findings: list[dict[str, Any]] = []
    for match in re.finditer(
        rf"\b(?:{alias_pattern})\.(?:SigningMethodNone|UnsafeAllowNoneSignatureType)\b",
        content,
    ):
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.jwt-none-algorithm",
                scenario="authentication_bypass",
                title="JWT 使用 none 算法或允许无签名令牌",
                cwes=["CWE-287", "CWE-327", "CWE-345", "CWE-346"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="jwt.SigningMethodNone/UnsafeAllowNoneSignatureType -> JWT 签名完整性可被绕过",
                remediation="禁用 none 算法，显式限制为预期的 HMAC 或非对称签名算法，并验证签名、签发者和受众。",
            )
        )
    return findings


def _jwt_parse_unverified_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases: dict[str, int] = {}
    for package_path in (
        "github.com/dgrijalva/jwt-go",
        "github.com/golang-jwt/jwt",
        "github.com/golang-jwt/jwt/v4",
        "github.com/golang-jwt/jwt/v5",
    ):
        aliases.update(_package_import_aliases(content, package_path, "jwt"))
    if not aliases:
        return []

    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    parser_variables: set[str] = set()
    for match in re.finditer(
        rf"(?m)^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*"
        rf"(?:new\s*\(\s*(?:{alias_pattern})\.Parser\s*\)|&?(?:{alias_pattern})\.Parser\s*\{{|(?:{alias_pattern})\.NewParser\s*\()",
        content,
    ):
        parser_variables.add(match.group("name"))
    for match in re.finditer(rf"\bvar\s+(?P<name>[A-Za-z_]\w*)\s+(?:{alias_pattern})\.Parser\b", content):
        parser_variables.add(match.group("name"))

    direct_re = re.compile(
        rf"(?:new\s*\(\s*(?:{alias_pattern})\.Parser\s*\)|&?(?:{alias_pattern})\.Parser\s*\{{[^}}]*\}}|"
        rf"(?:{alias_pattern})\.NewParser\s*\([^)]*\))\.ParseUnverified\s*\("
    )
    variable_re = (
        re.compile(rf"\b(?:{'|'.join(re.escape(name) for name in sorted(parser_variables))})\.ParseUnverified\s*\(")
        if parser_variables
        else None
    )
    findings: list[dict[str, Any]] = []
    for match in list(direct_re.finditer(content)) + (list(variable_re.finditer(content)) if variable_re else []):
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.jwt-parse-unverified",
                scenario="authentication_bypass",
                title="JWT ParseUnverified 跳过签名验证",
                cwes=["CWE-345"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="jwt.Parser.ParseUnverified -> claims trusted before signature verification",
                remediation="使用 ParseWithClaims/Parse 并提供 keyFunc，显式限制签名算法、签发者和受众。",
            )
        )
    return findings


def _cgi_serve_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "net/http/cgi", "cgi")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    findings: list[dict[str, Any]] = []
    for match in re.finditer(rf"\b(?:{alias_pattern})\.Serve\s*\(", content):
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.cgi-serve",
                scenario="weak_cryptography",
                title="使用 net/http/cgi 处理请求",
                cwes=["CWE-327"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="net/http/cgi.Serve -> 过时 CGI 请求处理面暴露",
                remediation="避免使用 net/http/cgi；迁移到常规 net/http handler，并在反向代理层配置隔离和超时。",
            )
        )
    return findings


def _directory_listing_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "net/http", "http")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    fs_vars: dict[str, int] = {}
    for match in re.finditer(
        rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:{alias_pattern})\.FileServer\s*\(\s*(?:{alias_pattern})\.Dir\s*\(",
        text,
    ):
        fs_vars[match.group("name")] = base_line + text.count("\n", 0, match.start())
    if not fs_vars:
        return []

    findings: list[dict[str, Any]] = []
    sink_re = re.compile(
        rf"\b(?:(?:{alias_pattern})\.(?:ListenAndServe|ListenAndServeTLS|Handle)|[A-Za-z_]\w*\.Handle)\s*\("
    )
    for match in sink_re.finditer(text):
        arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if not arguments:
            continue
        source_name = next(
            (
                name
                for name in fs_vars
                if any(re.fullmatch(re.escape(name), argument.strip()) for argument in arguments[1:])
            ),
            "",
        )
        if not source_name:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        source_line = fs_vars[source_name]
        finding = _finding(
            rule_id="secflow.go.semantic.directory-listing",
            scenario="information_disclosure",
            title="http.FileServer(http.Dir(...)) 暴露目录列表",
            cwes=["CWE-548"],
            severity="medium",
            confidence="high",
            file_name=file_name,
            line=line,
            snippet=_line(content, line),
            dfg=f"http.FileServer(http.Dir(...)) -> {source_name} -> HTTP handler/server",
            remediation="不要直接暴露可列目录的 http.Dir；使用嵌入资源、显式文件白名单，或包装 FileSystem 禁止目录 listing。",
        )
        finding["source"]["line"] = source_line
        finding["source"]["snippet"] = _line(content, source_line)
        finding["path"][0] = finding["source"]
        findings.append(finding)
    return findings


def _trusted_template_type_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "html/template", "template")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    trusted_types = r"HTML|HTMLAttr|CSS|JS|JSStr|Srcset|URL"
    findings: list[dict[str, Any]] = []

    declaration_re = re.compile(
        rf"(?m)^\s*(?:const|var)\s+[A-Za-z_]\w*\s+(?:{alias_pattern})\.(?P<kind>{trusted_types})\s*=\s*(?P<expr>[^\n]+)"
    )
    for match in declaration_re.finditer(content):
        expr = match.group("expr").strip()
        if not _template_trusted_expr_is_dynamic(expr):
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(_trusted_template_type_finding(file_name, content, line, match.group("kind"), expr))

    conversion_re = re.compile(rf"\b(?:{alias_pattern})\.(?P<kind>{trusted_types})\s*\(")
    for match in conversion_re.finditer(content):
        arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if len(arguments) != 1:
            continue
        expr = arguments[0].strip()
        if not _template_trusted_expr_is_dynamic(expr):
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(_trusted_template_type_finding(file_name, content, line, match.group("kind"), expr))
    return findings


def _trusted_template_type_finding(
    file_name: str,
    content: str,
    line: int,
    kind: str,
    expr: str,
) -> dict[str, Any]:
    return _finding(
        rule_id="secflow.go.semantic.trusted-template-type",
        scenario="cross_site_scripting",
        title="动态值被转换为 html/template 可信类型",
        cwes=["CWE-79"],
        severity="high",
        confidence="high",
        file_name=file_name,
        line=line,
        snippet=_line(content, line),
        dfg=f"{expr} -> template.{kind} -> 跳过 html/template 上下文转义",
        remediation="避免使用 template.HTML/CSS/JS/URL 等可信类型包装动态值；传入普通字符串让 html/template 自动转义。",
    )


def _template_trusted_expr_is_dynamic(expr: str) -> bool:
    normalized = expr.strip().rstrip(";,").strip()
    if not normalized:
        return False
    parts = [part.strip() for part in normalized.split("+")]
    return not parts or not all(_string_literal_value(part) is not None for part in parts)


def _unsafe_deserialization_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    json_aliases = _package_import_aliases(content, "encoding/json", "json")
    xml_aliases = _package_import_aliases(content, "encoding/xml", "xml")
    gob_aliases = _package_import_aliases(content, "encoding/gob", "gob")
    yaml_aliases: dict[str, int] = {}
    for package_path in ("gopkg.in/yaml.v2", "gopkg.in/yaml.v3", "github.com/go-yaml/yaml"):
        yaml_aliases.update(_package_import_aliases(content, package_path, "yaml"))
    findings: list[dict[str, Any]] = []

    unmarshal_aliases = {**json_aliases, **xml_aliases, **yaml_aliases}
    interface_vars: dict[str, int] = {}
    for match in re.finditer(r"(?m)^\s*var\s+(?P<name>[A-Za-z_]\w*)\s+(?:interface\s*\{\s*\}|any)(?:\s|;|$)", text):
        interface_vars[match.group("name")] = base_line + text.count("\n", 0, match.start())
    if unmarshal_aliases and interface_vars:
        alias_pattern = "|".join(re.escape(alias) for alias in unmarshal_aliases)
        for match in re.finditer(rf"\b(?:{alias_pattern})\.Unmarshal\s*\(", text):
            arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if len(arguments) < 2:
                continue
            target = arguments[1].strip()
            source_name = next(
                (name for name in interface_vars if re.fullmatch(rf"&\s*{re.escape(name)}", target)),
                "",
            )
            if not source_name:
                continue
            line = base_line + text.count("\n", 0, match.start())
            if _is_suppressed(content, line):
                continue
            finding = _deserialization_finding(
                file_name,
                content,
                line,
                f"Unmarshal(..., &{source_name})",
                "反序列化目标为 interface{}，攻击者可控制动态结构和值类型",
            )
            finding["source"]["line"] = interface_vars[source_name]
            finding["source"]["snippet"] = _line(content, interface_vars[source_name])
            finding["path"][0] = finding["source"]
            findings.append(finding)

    tainted: set[str] = set()
    masked = _mask_go_comments(text)
    for _ in range(5):
        changed = False
        for match in _COMMAND_ASSIGNMENT_RE.finditer(masked):
            target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
            if not target:
                continue
            expression = match.group("value").strip()
            if (_COMMAND_SOURCE_CALL_RE.search(expression) or _expression_mentions_any(expression, tainted)) and target not in tainted:
                tainted.add(target)
                changed = True
        if not changed:
            break

    if xml_aliases and tainted:
        alias_pattern = "|".join(re.escape(alias) for alias in xml_aliases)
        for match in re.finditer(rf"\b(?:{alias_pattern})\.Unmarshal\s*\(", text):
            arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if not arguments or not _expression_mentions_any(arguments[0], tainted):
                continue
            line = base_line + text.count("\n", 0, match.start())
            if _is_suppressed(content, line):
                continue
            findings.append(
                _deserialization_finding(
                    file_name,
                    content,
                    line,
                    "HTTP input -> xml.Unmarshal",
                    "HTTP 输入直接进入 XML 反序列化",
                )
            )

    if gob_aliases and tainted:
        alias_pattern = "|".join(re.escape(alias) for alias in gob_aliases)
        decoder_lines: dict[str, int] = {}
        for match in re.finditer(
            rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:{alias_pattern})\.NewDecoder\s*\((?P<expr>[^\n]+)\)",
            text,
        ):
            if _expression_mentions_any(match.group("expr"), tainted):
                decoder_lines[match.group("name")] = base_line + text.count("\n", 0, match.start())
        for name, source_line in decoder_lines.items():
            for match in re.finditer(rf"\b{re.escape(name)}\.Decode\s*\(", text):
                line = base_line + text.count("\n", 0, match.start())
                if _is_suppressed(content, line):
                    continue
                finding = _deserialization_finding(
                    file_name,
                    content,
                    line,
                    f"HTTP input -> gob.NewDecoder -> {name}.Decode",
                    "HTTP 输入直接进入 gob 反序列化",
                )
                finding["source"]["line"] = source_line
                finding["source"]["snippet"] = _line(content, source_line)
                finding["path"][0] = finding["source"]
                findings.append(finding)
    return findings


def _deserialization_finding(
    file_name: str,
    content: str,
    line: int,
    dfg: str,
    reason: str,
) -> dict[str, Any]:
    return _finding(
        rule_id="secflow.go.semantic.unsafe-deserialization",
        scenario="unsafe_deserialization",
        title="不安全反序列化输入流",
        cwes=["CWE-502"],
        severity="high",
        confidence="high",
        file_name=file_name,
        line=line,
        snippet=_line(content, line),
        dfg=f"{dfg} -> {reason}",
        remediation="只反序列化可信来源；优先使用明确 schema/struct，限制 XML/gob 输入来源，并在入口做大小、类型和来源校验。",
    )


def _range_variable_address_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    pointer_slices = {
        match.group("name")
        for match in re.finditer(
            r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*\[\]\s*\*",
            text,
        )
    }
    findings: list[dict[str, Any]] = []
    for match in re.finditer(
        r"\bfor\s+(?:[A-Za-z_]\w*|_)\s*,\s*(?P<value>[A-Za-z_]\w*)\s*:=\s*range\s+(?P<sequence>[A-Za-z_]\w*)\s*\{",
        text,
    ):
        value = match.group("value")
        sequence = match.group("sequence")
        opening = text.find("{", match.start())
        body, _ = _balanced_body(text, opening, "{", "}")
        if body is None:
            continue
        for address in re.finditer(rf"&\s*{re.escape(value)}(?P<field>(?:\.[A-Za-z_]\w*)*)", body):
            field = address.group("field") or ""
            if field and sequence in pointer_slices:
                continue
            line = base_line + text.count("\n", 0, opening + 1 + address.start())
            snippet = _line(content, line)
            if re.search(rf"\]\s*=\s*&\s*{re.escape(value)}\b", snippet):
                continue
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.range-variable-address",
                    scenario="memory_safety",
                    title="range 循环变量地址被取用",
                    cwes=["CWE-118"],
                    severity="medium",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=snippet,
                    dfg=f"range {sequence} -> {value} -> &{value}{field}",
                    remediation="不要取 range 值变量地址；对切片使用索引 `&items[i]`，或在循环体内复制到明确的新变量并理解生命周期。",
                )
            )
    return findings


def _log_injection_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    log_aliases = _package_import_aliases(content, "log", "log")
    slog_aliases = _package_import_aliases(content, "log/slog", "slog")
    if not log_aliases and not slog_aliases:
        return []
    sanitizer_re = re.compile(r"\b(?:json\.Marshal|strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool))\s*\(")
    tainted: set[str] = set()
    masked = _mask_go_comments(text)
    for _ in range(5):
        changed = False
        for match in _COMMAND_ASSIGNMENT_RE.finditer(masked):
            target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
            if not target:
                continue
            expression = match.group("value").strip()
            if sanitizer_re.search(expression):
                tainted.discard(target)
                continue
            if (_COMMAND_SOURCE_CALL_RE.search(expression) or _expression_mentions_any(expression, tainted)) and target not in tainted:
                tainted.add(target)
                changed = True
        if not changed:
            break

    findings: list[dict[str, Any]] = []
    for alias in log_aliases:
        for match in re.finditer(rf"\b{re.escape(alias)}\.(?:Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)\s*\(", text):
            arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if not any(_expression_mentions_any(argument, tainted) for argument in arguments):
                continue
            line = base_line + text.count("\n", 0, match.start())
            if _is_suppressed(content, line):
                continue
            findings.append(_log_injection_finding(file_name, content, line, f"{alias}.* tainted argument"))

    for alias in slog_aliases:
        for match in re.finditer(rf"\b{re.escape(alias)}\.(?:Debug|Info|Warn|Error)\s*\(", text):
            arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if not arguments or not _expression_mentions_any(arguments[0], tainted):
                continue
            line = base_line + text.count("\n", 0, match.start())
            if _is_suppressed(content, line):
                continue
            findings.append(_log_injection_finding(file_name, content, line, f"{alias} tainted message"))
    return findings


def _log_injection_finding(file_name: str, content: str, line: int, dfg: str) -> dict[str, Any]:
    return _finding(
        rule_id="secflow.go.semantic.log-injection",
        scenario="log_injection",
        title="外部输入进入日志消息",
        cwes=["CWE-117"],
        severity="medium",
        confidence="high",
        file_name=file_name,
        line=line,
        snippet=_line(content, line),
        dfg=f"external input -> {dfg}",
        remediation="记录外部输入前进行换行/控制字符编码；结构化日志中把用户输入放入属性值，不要作为消息模板。",
    )


def _ssrf_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    if not _package_import_aliases(content, "net/http", "http"):
        return []
    tainted: set[str] = set()
    for _ in range(6):
        changed = False
        for match in _COMMAND_ASSIGNMENT_RE.finditer(text):
            target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
            if not target:
                continue
            expression = match.group("value").strip()
            source_call = _expression_has_external_source(expression)
            if (source_call or _expression_mentions_any(expression, tainted)) and target not in tainted:
                tainted.add(target)
                changed = True
        if not changed:
            break

    url_assignments: dict[str, list[tuple[int, bool]]] = {}
    for match in _COMMAND_ASSIGNMENT_RE.finditer(text):
        target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
        if not target:
            continue
        expression = match.group("value").strip()
        is_url = _expression_is_external_url(expression, tainted) or _expression_mentions_tainted_url(
            expression,
            url_assignments,
            match.start(),
        )
        url_assignments.setdefault(target, []).append((match.start(), is_url))

    findings: list[dict[str, Any]] = []
    sink_patterns = [
        re.compile(r"\bhttp\.(?:Get|Head|Post|PostForm)\s*\("),
        re.compile(r"\b[A-Za-z_]\w*\.(?:Get|Head|Post|PostForm)\s*\("),
    ]
    for sink_re in sink_patterns:
        for match in sink_re.finditer(text):
            arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if not arguments:
                continue
            url_arg = arguments[0].strip()
            if not (
                _argument_is_tainted_url(url_arg, url_assignments, match.start())
                or _expression_is_external_url(url_arg, tainted)
            ):
                continue
            line = base_line + text.count("\n", 0, match.start())
            if _is_security_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.ssrf",
                    scenario="server_side_request_forgery",
                    title="外部输入控制服务端请求目标",
                    cwes=["CWE-918"],
                    severity="high",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"external input -> {url_arg} -> HTTP client request",
                    remediation="对服务端请求目标使用固定上游或严格 allowlist；解析 URL 后校验 scheme、host、端口并阻断内网/metadata 地址。",
                )
            )
    return findings


def _argument_is_tainted_url(
    expression: str,
    url_assignments: dict[str, list[tuple[int, bool]]],
    offset: int,
) -> bool:
    expr = expression.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", expr):
        return _nearest_url_assignment_is_tainted(expr, url_assignments, offset)
    return _expression_mentions_tainted_url(expr, url_assignments, offset)


def _expression_mentions_tainted_url(
    expression: str,
    url_assignments: dict[str, list[tuple[int, bool]]],
    offset: int,
) -> bool:
    for name in re.findall(r"\b[A-Za-z_]\w*\b", expression):
        if _nearest_url_assignment_is_tainted(name, url_assignments, offset):
            return True
    return False


def _nearest_url_assignment_is_tainted(
    name: str,
    url_assignments: dict[str, list[tuple[int, bool]]],
    offset: int,
) -> bool:
    candidates = [(start, tainted) for start, tainted in url_assignments.get(name, []) if start < offset]
    return candidates[-1][1] if candidates else False


def _expression_has_external_source(expression: str) -> bool:
    return bool(
        _COMMAND_SOURCE_CALL_RE.search(expression)
        or re.search(r"\b[A-Za-z_]\w*\.URL\.Query\s*\(\s*\)\s*\[[^\]]+\]", expression)
    )


def _expression_is_external_url(expression: str, tainted: set[str]) -> bool:
    expr = expression.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", expr):
        return False
    if re.search(
        r'\.(?:FormValue|PostFormValue)\s*\(\s*["`](?:url|uri|target|endpoint)["`]\s*\)|'
        r'\.URL\.Query\s*\(\s*\)\.Get\s*\(\s*["`](?:url|uri|target|endpoint)["`]\s*\)',
        expr,
        flags=re.IGNORECASE,
    ):
        return True
    if not (_expression_has_external_source(expr) or _expression_mentions_any(expr, tainted)):
        return False
    if re.search(r'["`]https?://["`]\s*\+', expr):
        return True
    format_match = re.search(r"\bfmt\.(?:Sprintf|Printf|Fprintf)\s*\(\s*([\"`])(?P<format>.*?)(?:\1)", expr)
    if format_match:
        fmt = format_match.group("format")
        return bool(re.match(r"https?://\s*%[+#0\- 0-9.]*[vqs]", fmt))
    return False


def _is_security_suppressed(content: str, line: int) -> bool:
    if line <= 0:
        return False
    lines = content.splitlines()
    context = "\n".join(lines[max(0, line - 3) : min(len(lines), line + 1)])
    return bool(
        re.search(
            r"#\s*nosec\b|nolint\s*:\s*(?:gosec|secflow|security)\b",
            context,
            flags=re.IGNORECASE,
        )
    )


def _open_redirect_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    if not _package_import_aliases(content, "net/http", "http"):
        return []
    response_writers = {match.group("name") for match in _HTTP_RESPONSE_PARAM_RE.finditer(signature_text)}
    request_names = {match.group("name") for match in _HTTP_REQUEST_PARAM_RE.finditer(signature_text)}
    if not response_writers or not request_names:
        return []

    redirect_vars: dict[str, int] = {}
    for match in _COMMAND_ASSIGNMENT_RE.finditer(text):
        target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
        if not target:
            continue
        expression = match.group("value").strip()
        if (
            _expression_uses_request_host_as_url(expression, request_names)
            or _expression_mentions_any(expression, set(redirect_vars))
        ):
            redirect_vars[target] = base_line + text.count("\n", 0, match.start())

    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\bhttp\.Redirect\s*\(", text):
        arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if len(arguments) < 3:
            continue
        if arguments[0].strip() not in response_writers or arguments[1].strip() not in request_names:
            continue
        target_expr = arguments[2].strip()
        source_line = 0
        if target_expr in redirect_vars:
            source_line = redirect_vars[target_expr]
        elif _expression_uses_request_host_as_url(target_expr, request_names):
            source_line = base_line + text.count("\n", 0, match.start())
        if not source_line:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_security_suppressed(content, line):
            continue
        finding = _finding(
            rule_id="secflow.go.semantic.open-redirect",
            scenario="open_redirect",
            title="重定向目标由请求 Host 控制",
            cwes=["CWE-601"],
            severity="medium",
            confidence="high",
            file_name=file_name,
            line=line,
            snippet=_line(content, line),
            dfg=f"HTTP request Host -> {target_expr} -> http.Redirect",
            remediation="重定向目标使用固定可信域名或严格 allowlist；不要用请求 Host 直接拼接绝对 URL。",
        )
        finding["source"]["line"] = source_line
        finding["source"]["snippet"] = _line(content, source_line)
        finding["path"][0] = finding["source"]
        findings.append(finding)
    return findings


def _expression_uses_request_host_as_url(expression: str, request_names: set[str]) -> bool:
    expr = expression.strip()
    for request_name in request_names:
        host = rf"\b{re.escape(request_name)}\.Host\b"
        if re.search(rf'["`]https?://["`]\s*\+\s*{host}', expr):
            return True
        format_match = re.search(r"\bfmt\.Sprintf\s*\(\s*([\"`])(?P<format>.*?)(?:\1)", expr)
        if format_match and re.match(r"https?://\s*%[+#0\- 0-9.]*[vqs]", format_match.group("format")):
            if re.search(host, expr):
                return True
    return False


def _ssti_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    if not _package_import_aliases(content, "html/template", "template"):
        return []
    if not _HTTP_REQUEST_PARAM_RE.search(signature_text):
        return []

    tainted = _request_tainted_variables(text, sanitizer_re=_XSS_SANITIZER_RE)
    template_vars: dict[str, int] = {}
    for match in re.finditer(
        r"(?m)^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*fmt\.Sprintf\s*\(",
        text,
    ):
        arguments_text, _ = _balanced_call_arguments(text, text.find("(", match.start()))
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if len(arguments) < 2 or not _expression_mentions_any(",".join(arguments[1:]), tainted):
            continue
        line = base_line + text.count("\n", 0, match.start())
        template_vars[match.group("name")] = line

    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\b[A-Za-z_]\w*\.Parse\s*\(", text):
        arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if not arguments:
            continue
        template_var = arguments[0].strip()
        if template_var not in template_vars:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_security_suppressed(content, line):
            continue
        finding = _finding(
            rule_id="secflow.go.semantic.ssti",
            scenario="server_side_template_injection",
            title="请求输入进入模板源码后被 Parse",
            cwes=["CWE-1336"],
            severity="high",
            confidence="high",
            file_name=file_name,
            line=line,
            snippet=_line(content, line),
            dfg=f"HTTP request -> fmt.Sprintf -> {template_var} -> template.Parse",
            remediation="模板源码必须固定；用户输入只能作为 Execute 的 data 值传入，让 html/template 做上下文转义。",
        )
        finding["source"]["line"] = template_vars[template_var]
        finding["source"]["snippet"] = _line(content, template_vars[template_var])
        finding["path"][0] = finding["source"]
        findings.append(finding)
    return findings


def _formatted_template_xss_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    template_aliases = _package_import_aliases(content, "html/template", "template")
    fmt_aliases = _package_import_aliases(content, "fmt", "fmt")
    if not template_aliases or not fmt_aliases or not _HTTP_REQUEST_PARAM_RE.search(signature_text):
        return []

    tainted = _request_tainted_variables(text, sanitizer_re=_XSS_SANITIZER_RE)
    if not tainted:
        return []
    fmt_pattern = "|".join(re.escape(alias) for alias in fmt_aliases)
    findings: list[dict[str, Any]] = []
    for match in re.finditer(
        rf"(?m)^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*)?\s*(?::=|=)\s*"
        rf"(?:{fmt_pattern})\.(?:Printf|Sprintf)\s*\(",
        text,
    ):
        arguments_text, _ = _balanced_call_arguments(text, text.find("(", match.start()))
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if len(arguments) < 2:
            continue
        format_value = _string_literal_value(arguments[0].strip()) or ""
        if "<" not in format_value and "%s" not in format_value:
            continue
        if not _expression_mentions_any(",".join(arguments[1:]), tainted):
            continue
        assigned_name = match.group("name")
        if not re.search(
            rf"\b(?:{'|'.join(re.escape(alias) for alias in template_aliases)})\.(?:HTML|HTMLAttr|JS|JSStr|URL|CSS|Srcset)\s*\(\s*{re.escape(assigned_name)}\s*\)",
            text[match.end() :],
        ):
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.formatted-template-xss",
                scenario="cross_site_scripting",
                title="请求输入进入格式化 HTML 后被标记为可信模板类型",
                cwes=["CWE-79"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"HTTP request -> fmt.* formatted HTML -> {assigned_name} -> template trusted type",
                remediation="不要把请求输入格式化进 template.HTML/JS/CSS 等可信类型；传普通字符串给 html/template 自动转义。",
            )
        )
    return findings


def _http_responsewriter_xss_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    response_writers = {match.group("name") for match in _HTTP_RESPONSE_PARAM_RE.finditer(signature_text)}
    pointer_response_writers = {
        match.group("name")
        for match in re.finditer(r"\b(?P<name>[A-Za-z_]\w*)\s+\*http\.ResponseWriter\b", signature_text)
    }
    if not response_writers and not pointer_response_writers:
        return []

    tainted = _request_tainted_variables(text, sanitizer_re=_XSS_SANITIZER_RE)
    request_names = {match.group("name") for match in _HTTP_REQUEST_PARAM_RE.finditer(signature_text)}
    string_parameter_names = _string_parameter_names(signature_text)
    for name in string_parameter_names:
        if name.lower() in {"body", "html", "content", "message", "error", "response"}:
            tainted.add(name)

    masked = _mask_go_comments(text)
    for _ in range(5):
        changed = False
        for match in _COMMAND_ASSIGNMENT_RE.finditer(masked):
            target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
            if not target:
                continue
            expression = match.group("value").strip()
            if _XSS_SANITIZER_RE.search(expression):
                tainted.discard(target)
                continue
            if (_http_request_source_expression(expression, request_names) or _expression_mentions_any(expression, tainted)) and target not in tainted:
                tainted.add(target)
                changed = True
        if not changed:
            break

    findings: list[dict[str, Any]] = []
    findings.extend(
        _responsewriter_fprintf_xss_findings(file_name, content, text, base_line, response_writers | pointer_response_writers, tainted)
    )
    findings.extend(
        _responsewriter_write_xss_findings(
            file_name,
            content,
            text,
            base_line,
            response_writers,
            pointer_response_writers,
            tainted,
        )
    )
    return findings


def _responsewriter_fprintf_xss_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    response_writers: set[str],
    tainted: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\bfmt\.Fprintf\s*\(", text):
        arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if len(arguments) < 2 or _responsewriter_argument_name(arguments[0]) not in response_writers:
            continue
        format_value = _string_literal_value(arguments[1].strip()) or ""
        dynamic_arguments = arguments[2:]
        tainted_dynamic = any(_xss_expression_mentions_unsanitized(argument, tainted) for argument in dynamic_arguments)
        html_dynamic = bool(
            dynamic_arguments
            and re.search(r"<[A-Za-z/!]", format_value)
            and any(not _xss_argument_is_sanitized_or_literal(argument) for argument in dynamic_arguments)
        )
        if not tainted_dynamic and not html_dynamic:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.responsewriter-xss",
                scenario="cross_site_scripting",
                title="动态值直接格式化写入 HTTP 响应",
                cwes=["CWE-79"],
                severity="high",
                confidence="medium" if html_dynamic and not tainted_dynamic else "high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="dynamic value -> fmt.Fprintf(http.ResponseWriter, HTML/text format)",
                remediation="使用 html/template 自动上下文转义，或对输出值按 HTML/URL/属性上下文编码后再写响应。",
            )
        )
    return findings


def _responsewriter_write_xss_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    response_writers: set[str],
    pointer_response_writers: set[str],
    tainted: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    write_re = re.compile(
        r"(?P<receiver>\(\s*\*\s*(?P<pointer>[A-Za-z_]\w*)\s*\)|(?P<name>[A-Za-z_]\w*))\.Write\s*\("
    )
    for match in write_re.finditer(text):
        writer = match.group("pointer") or match.group("name") or ""
        if writer not in response_writers and writer not in pointer_response_writers:
            continue
        arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if not arguments:
            continue
        expression = _unwrap_byte_conversion(arguments[0])
        tainted_expression = _xss_expression_mentions_unsanitized(expression, tainted)
        formatted_expression = "fmt.Sprintf" in expression and re.search(r"<[A-Za-z/!]", expression)
        if not tainted_expression and not formatted_expression:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.responsewriter-xss",
                scenario="cross_site_scripting",
                title="动态内容直接写入 HTTP 响应",
                cwes=["CWE-79"],
                severity="high",
                confidence="medium" if formatted_expression and not tainted_expression else "high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="dynamic value -> ResponseWriter.Write -> browser-rendered response",
                remediation="使用 html/template 自动上下文转义，或对输出值按 HTML/URL/属性上下文编码后再写响应。",
            )
        )
    return findings


def _responsewriter_argument_name(expression: str) -> str:
    expr = expression.strip()
    pointer_match = re.fullmatch(r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)", expr)
    if pointer_match:
        return pointer_match.group("name")
    return expr


def _unwrap_byte_conversion(expression: str) -> str:
    expr = expression.strip()
    if expr.startswith("[]byte"):
        opening = expr.find("(")
        if opening >= 0:
            arguments_text, _ = _balanced_call_arguments(expr, opening)
            if arguments_text is not None:
                return arguments_text.strip()
    return expr


def _xss_expression_mentions_unsanitized(expression: str, tainted: set[str]) -> bool:
    if not _expression_mentions_any(expression, tainted):
        return False
    if _XSS_SANITIZER_RE.search(expression):
        return False
    return True


def _xss_argument_is_sanitized_or_literal(expression: str) -> bool:
    expr = expression.strip()
    if _string_literal_value(expr) is not None:
        return True
    if _XSS_SANITIZER_RE.search(expr):
        return True
    if re.fullmatch(r"[-+]?(?:0[xX][0-9A-Fa-f]+|0[oO][0-7]+|\d+)", expr):
        return True
    return False


def _string_parameter_names(signature_text: str) -> set[str]:
    params = signature_text.partition("(")[2].rpartition(")")[0]
    result: set[str] = set()
    for match in re.finditer(r"\b(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+string\b", params):
        result.update(name.strip() for name in match.group("names").split(",") if name.strip() != "_")
    return result


def _http_request_source_expression(expression: str, request_names: set[str]) -> bool:
    if _COMMAND_SOURCE_CALL_RE.search(expression):
        return True
    for request_name in request_names:
        req = re.escape(request_name)
        if re.search(
            rf"\b{req}\.(?:RequestURI|Host)\b|"
            rf"\b{req}\.URL\.(?:Path|RawPath|RawQuery|Fragment|EscapedPath)\b|"
            rf"\b{req}\.(?:Header|Trailer)\.Get\s*\(|"
            rf"\b{req}\.(?:Cookie|Cookies|Referer|UserAgent)\s*\(",
            expression,
        ):
            return True
    return False


def _formatted_sql_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    tainted = _request_tainted_variables(text, _SQL_SANITIZER_RE)
    if _HTTP_REQUEST_PARAM_RE.search(signature_text):
        request_names = {match.group("name") for match in _HTTP_REQUEST_PARAM_RE.finditer(signature_text)}
        response_names = {match.group("name") for match in _HTTP_RESPONSE_PARAM_RE.finditer(signature_text)}
        for name in _parameter_names(signature_text.partition("(")[2].rpartition(")")[0]):
            if name not in request_names | response_names:
                tainted.add(name)

    sql_vars: dict[str, int] = {}
    for match in re.finditer(
        r"(?m)^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*fmt\.Sprintf\s*\(",
        text,
    ):
        arguments_text, _ = _balanced_call_arguments(text, text.find("(", match.start()))
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if not arguments:
            continue
        fmt_value = _string_literal_value(arguments[0].strip()) or arguments[0]
        if not _SQL_KEYWORD_RE.search(fmt_value):
            continue
        if len(arguments) < 2 or not _expression_mentions_any(",".join(arguments[1:]), tainted):
            continue
        sql_vars[match.group("name")] = base_line + text.count("\n", 0, match.start())

    findings: list[dict[str, Any]] = []
    for sink in _SQL_SINK_RE.finditer(text):
        arguments = sink.group("arguments")
        source_name = next((name for name in sql_vars if re.search(rf"\b{re.escape(name)}\b", arguments)), "")
        direct = False
        if not source_name and "fmt.Sprintf" in arguments:
            direct = _SQL_KEYWORD_RE.search(arguments) is not None and _expression_mentions_any(arguments, tainted)
        if not source_name and not direct:
            continue
        line = base_line + text.count("\n", 0, sink.start())
        if _is_suppressed(content, line):
            continue
        source_line = sql_vars.get(source_name, line)
        finding = _finding(
            rule_id="secflow.go.semantic.formatted-sql-injection",
            scenario="sql_injection",
            title="格式化 SQL 字符串进入数据库执行",
            cwes=["CWE-89"],
            severity="high",
            confidence="high",
            file_name=file_name,
            line=line,
            snippet=_line(content, line),
            dfg=f"external/handler input -> fmt.Sprintf SQL -> {sink.group('method')}",
            remediation="使用参数化查询和占位符；不要用 fmt.Sprintf 或字符串拼接组装 SQL 语句。",
        )
        finding["source"]["line"] = source_line
        finding["source"]["snippet"] = _line(content, source_line)
        finding["path"][0] = finding["source"]
        findings.append(finding)
    return findings


def _request_tainted_variables(text: str, sanitizer_re: re.Pattern[str] | None = None) -> set[str]:
    tainted: set[str] = set()
    for _ in range(5):
        changed = False
        for match in _COMMAND_ASSIGNMENT_RE.finditer(text):
            target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
            if not target:
                continue
            expression = match.group("value").strip()
            if sanitizer_re is not None and sanitizer_re.search(expression):
                tainted.discard(target)
                continue
            if (_COMMAND_SOURCE_CALL_RE.search(expression) or _expression_mentions_any(expression, tainted)) and target not in tainted:
                tainted.add(target)
                changed = True
        if not changed:
            break
    return tainted


def _interprocedural_slice_bounds_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    requirements: dict[str, list[tuple[int, int, int]]] = {}
    for function in _FUNCTION_RE.finditer(content):
        parameter_positions = _slice_parameter_positions(function.group("params"))
        if not parameter_positions:
            continue
        body = function.group("body")
        for param_name, position in parameter_positions.items():
            for slice_match in re.finditer(rf"\b{re.escape(param_name)}\s*\[\s*:\s*(?P<high>\d+)\s*\]", body):
                high = int(slice_match.group("high"))
                line = content.count("\n", 0, function.start("body") + slice_match.start()) + 1
                requirements.setdefault(function.group("name"), []).append((position, high, line))

    if not requirements:
        return []

    capacities: dict[str, list[tuple[int, int]]] = {}
    for match in re.finditer(
        r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*make\s*\(\s*\[\][^,\n]+,\s*\d+\s*,\s*(?P<capacity>\d+)\s*\)",
        content,
    ):
        capacities.setdefault(match.group("name"), []).append((match.start(), int(match.group("capacity"))))

    findings: list[dict[str, Any]] = []
    for function_name, items in requirements.items():
        for call in re.finditer(rf"\b{re.escape(function_name)}\s*\(", content):
            arguments_text, _ = _balanced_call_arguments(content, call.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            for position, high, sink_line in items:
                if position >= len(arguments):
                    continue
                argument = arguments[position].strip()
                if not re.fullmatch(r"[A-Za-z_]\w*", argument):
                    continue
                candidates = [(start, cap) for start, cap in capacities.get(argument, []) if start < call.start()]
                if not candidates:
                    continue
                _, capacity = candidates[-1]
                if capacity >= high:
                    continue
                call_line = content.count("\n", 0, call.start()) + 1
                if _is_suppressed(content, sink_line):
                    continue
                finding = _finding(
                    rule_id="secflow.go.semantic.interprocedural-slice-out-of-bounds",
                    scenario="memory_safety",
                    title="跨函数切片上界超过调用方容量",
                    cwes=["CWE-118"],
                    severity="high",
                    confidence="high",
                    file_name=file_name,
                    line=sink_line,
                    snippet=_line(content, sink_line),
                    dfg=f"make(..., cap={capacity}) -> {function_name}({argument}) -> slice high {high}",
                    remediation="在 callee 中基于 len/cap 检查上界，或由 caller 传入满足容量约束的切片。",
                )
                finding["source"]["line"] = call_line
                finding["source"]["snippet"] = _line(content, call_line)
                finding["path"][0] = finding["source"]
                findings.append(finding)
    return findings


def _slice_parameter_positions(params: str) -> dict[str, int]:
    positions: dict[str, int] = {}
    position = 0
    for part in _split_go_arguments(params):
        item = part.strip()
        if not item:
            continue
        match = re.fullmatch(r"(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+\[\][^,]+", item)
        if match:
            names = [name.strip() for name in match.group("names").split(",")]
            for name in names:
                positions[name] = position
                position += 1
        else:
            position += max(1, item.count(",") + 1)
    return positions


def _bind_all_interfaces_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "net", "net")
    if not aliases:
        return []
    values = _string_constant_assignments(content)
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    findings: list[dict[str, Any]] = []
    for match in re.finditer(rf"\b(?:{alias_pattern})\.Listen\s*\(", content):
        arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if not arguments:
            continue
        address_expr = ""
        if len(arguments) >= 2:
            address_expr = arguments[1].strip()
        else:
            parse_match = re.fullmatch(r"[A-Za-z_]\w*\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", arguments[0].strip())
            if parse_match:
                address_expr = parse_match.group("arg")
        address_value = _resolved_string_value(address_expr, values)
        if address_value is None or not _binds_all_interfaces(address_value):
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.bind-all-interfaces",
                scenario="information_disclosure",
                title="服务监听所有网络接口",
                cwes=["CWE-200"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"net.Listen address={address_value!r} -> 0.0.0.0/all interfaces",
                remediation="只监听明确的内网或 loopback 地址；如必须公开监听，请在防火墙、认证和 TLS 层限制访问。",
            )
        )
    return findings


def _redirect_sensitive_header_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    if not _package_import_aliases(content, "net/http", "http"):
        return []
    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\bCheckRedirect\s*:\s*func\b[^{]*\{", content):
        opening = content.find("{", match.start())
        body, _ = _balanced_body(content, opening, "{", "}")
        if body is None:
            continue
        body_start = opening + 1
        patterns = [
            re.compile(r"\breq\.Header\s*=\s*via\s*\[[^\]]+\]\.Header(?:\.Clone\s*\(\s*\))?"),
            re.compile(r'\breq\.Header\.(?:Add|Set)\s*\(\s*"(?i:Cookie|Authorization|Proxy-Authorization|Set-Cookie|X-Api-Key)"'),
        ]
        for pattern in patterns:
            for header_match in pattern.finditer(body):
                line = content.count("\n", 0, body_start + header_match.start()) + 1
                if _is_suppressed(content, line):
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.redirect-sensitive-header",
                        scenario="information_disclosure",
                        title="重定向时转发敏感请求头",
                        cwes=["CWE-200"],
                        severity="medium",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg="http.Client.CheckRedirect -> req.Header -> redirected request",
                        remediation="重定向时不要复制 Cookie/Authorization 等敏感头；只按目标域白名单转发必要头部。",
                    )
                )
    return findings


def _string_constant_assignments(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in re.finditer(
        r"(?m)^\s*(?:const\s+|var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<value>[\"`][^\"`]*[\"`])",
        _mask_go_comments(content),
    ):
        value = _string_literal_value(match.group("value"))
        if value is not None:
            values[match.group("name")] = value
    return values


def _resolved_string_value(expr: str, values: dict[str, str]) -> str | None:
    value = _string_literal_value(expr)
    if value is not None:
        return value
    return values.get(expr.strip())


def _binds_all_interfaces(address: str) -> bool:
    return bool(address.startswith(":") or address.startswith("0.0.0.0:") or address.startswith("[::]:"))


def _hardcoded_secret_comparison_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    secret_literal = r'"(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{32,}={0,2})"'
    name_pattern = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
    masked = _mask_go_comments(content)
    patterns = [
        re.compile(rf"\b(?P<name>{name_pattern})\b\s*(?:==|!=)\s*{secret_literal}"),
        re.compile(rf"{secret_literal}\s*(?:==|!=)\s*\b(?P<name>{name_pattern})\b"),
    ]
    for comparison_re in patterns:
        for match in comparison_re.finditer(masked):
            name = match.group("name")
            if not name or not _SENSITIVE_FIELD_RE.search(name):
                continue
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.hardcoded-secret-comparison",
                    scenario="hardcoded_credential",
                    title="敏感变量与硬编码高熵字符串比较",
                    cwes=["CWE-798"],
                    severity="high",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"{name} ==/!= hardcoded high-entropy secret",
                    remediation="不要把密码、令牌或密钥硬编码在比较表达式中；使用密钥管理服务或受保护环境变量并轮换已泄露值。",
                )
            )
    return findings


def _ssh_public_key_callback_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\bPublicKeyCallback\s*=\s*func\b(?P<signature>[^{]*)\{", content):
        signature = match.group("signature")
        key_param = re.search(r"\b(?P<name>[A-Za-z_]\w*)\s+PublicKey\b", signature)
        if key_param is None:
            continue
        key_name = key_param.group("name")
        opening = content.find("{", match.start())
        body, _ = _balanced_body(content, opening, "{", "}")
        if body is None:
            continue
        escaped = re.escape(key_name)
        stores_key = re.search(
            rf"(?m)^\s*[A-Za-z_]\w*(?:\[[^\]\n]+\]|\.[A-Za-z_]\w*)?\s*=\s*{escaped}\s*$",
            body,
        )
        if stores_key is None:
            continue
        if not re.search(r"return\s+&Permissions\s*\{\s*\}\s*,\s*nil", body):
            continue
        first_token = re.search(r"\S", stores_key.group(0))
        line_offset = stores_key.start() + (first_token.start() if first_token else 0)
        line = content.count("\n", 0, opening + 1 + line_offset) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.ssh-public-key-callback-bypass",
                scenario="authentication_bypass",
                title="SSH PublicKeyCallback 存储公钥后直接放行",
                cwes=["CWE-287"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"PublicKeyCallback({key_name}) -> store {key_name} -> return &Permissions{{}}, nil",
                remediation="在 PublicKeyCallback 中根据用户和授权公钥白名单做常量时间校验；未授权时返回错误而不是 nil。",
            )
        )
    return findings


def _insecure_write_file_permission_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases: set[str] = set(_package_import_aliases(content, "os", "os"))
    aliases.update(_package_import_aliases(content, "io/ioutil", "ioutil"))
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    findings: list[dict[str, Any]] = []
    for match in re.finditer(rf"\b(?:{alias_pattern})\.WriteFile\s*\(", content):
        arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if len(arguments) < 3:
            continue
        perm = _resolved_file_permission(arguments[2].strip())
        if perm is None or perm <= 0o600:
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.insecure-writefile-permission",
                scenario="insecure_permissions",
                title="WriteFile 使用过宽文件权限",
                cwes=["CWE-276"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"WriteFile perm={arguments[2].strip()} -> file may be readable/executable by other users",
                remediation="写入敏感或应用数据文件时使用 0600；确需共享读取时显式说明并加 suppression。",
            )
        )
    return findings


def _resolved_file_permission(expr: str) -> int | None:
    normalized = expr.strip().removesuffix(",").strip()
    if normalized == "os.ModePerm":
        return 0o777
    if re.fullmatch(r"0[0-7]+", normalized):
        return int(normalized, 8)
    try:
        return int(normalized, 0)
    except ValueError:
        return None


def _gorilla_session_cookie_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "github.com/gorilla/sessions", "sessions")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    findings: list[dict[str, Any]] = []
    for match in re.finditer(rf"&(?:{alias_pattern})\.Options\s*\{{", content):
        opening = content.find("{", match.start())
        body = _balanced_brace_body(content, opening)
        if body is None:
            continue
        line = _session_options_assignment_line(content, match.start())
        if _is_suppressed(content, line):
            continue
        fields = _struct_literal_field_values(body)
        if fields.get("HttpOnly", "").strip() == "false":
            findings.append(
                _cookie_option_finding(
                    file_name,
                    content,
                    line,
                    "secflow.go.semantic.session-cookie-missing-httponly",
                    "session cookie 禁用 HttpOnly",
                    ["CWE-1004"],
                    "sessions.Options.HttpOnly=false -> JavaScript 可读取会话 cookie",
                    "为会话 cookie 设置 HttpOnly: true，降低 XSS 后 cookie 被窃取的风险。",
                )
            )
        if fields.get("Secure", "").strip() == "false" or "Secure" not in fields:
            findings.append(
                _cookie_option_finding(
                    file_name,
                    content,
                    line,
                    "secflow.go.semantic.session-cookie-missing-secure",
                    "session cookie 未强制 Secure",
                    ["CWE-614"],
                    "sessions.Options.Secure!=true -> cookie 可经明文 HTTP 发送",
                    "为会话 cookie 设置 Secure: true，并仅通过 HTTPS 提供会话。",
                )
            )
        if fields.get("SameSite", "").strip().endswith(".SameSiteNoneMode"):
            findings.append(
                _cookie_option_finding(
                    file_name,
                    content,
                    line,
                    "secflow.go.semantic.session-cookie-samesite-none",
                    "session cookie 使用 SameSite=None",
                    ["CWE-1275"],
                    "sessions.Options.SameSite=None -> 跨站请求会携带 cookie",
                    "除必须跨站嵌入外，使用 SameSite=Lax 或 Strict，并结合 CSRF 防护。",
                )
            )
    return findings


def _session_options_assignment_line(content: str, offset: int) -> int:
    line_start = content.rfind("\n", 0, offset) + 1
    assignment_start = content.rfind("\n", 0, line_start - 1) + 1 if line_start > 0 else 0
    candidate = content[assignment_start:line_start]
    if "Options" in candidate and "=" in candidate:
        return content.count("\n", 0, assignment_start) + 1
    return content.count("\n", 0, offset) + 1


def _struct_literal_field_values(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in re.finditer(r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<value>[^,\n}]+)", body):
        fields[match.group("name")] = match.group("value").strip()
    return fields


def _cookie_option_finding(
    file_name: str,
    content: str,
    line: int,
    rule_id: str,
    title: str,
    cwes: list[str],
    dfg: str,
    remediation: str,
) -> dict[str, Any]:
    return _finding(
        rule_id=rule_id,
        scenario="cookie_security",
        title=title,
        cwes=cwes,
        severity="medium",
        confidence="high",
        file_name=file_name,
        line=line,
        snippet=_line(content, line),
        dfg=dfg,
        remediation=remediation,
    )


def _grpc_insecure_server_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "google.golang.org/grpc", "grpc")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    findings: list[dict[str, Any]] = []
    for match in re.finditer(rf"\b(?:{alias_pattern})\.NewServer\s*\(", content):
        arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
        if arguments_text is None:
            continue
        if arguments_text.strip():
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.grpc-insecure-server",
                scenario="insecure_transport",
                title="gRPC server 未配置传输层凭据",
                cwes=["CWE-300"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="grpc.NewServer() without grpc.Creds -> plaintext/insecure gRPC server",
                remediation="为 gRPC server 配置 grpc.Creds(credentials.NewTLS(...)) 或在受控内部信道外层提供等效 TLS。",
            )
        )
    return findings


def _weak_rsa_key_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "crypto/rsa", "rsa")
    if not aliases:
        return []
    constants = _integer_constant_assignments(content)
    findings: list[dict[str, Any]] = []
    for alias in aliases:
        for match in re.finditer(rf"\b{re.escape(alias)}\.GenerateKey\s*\(", content):
            arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if len(arguments) < 2:
                continue
            bits = _resolved_integer(arguments[1].strip(), constants)
            if bits is None or bits >= 2048:
                continue
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.weak-rsa-key",
                    scenario="weak_cryptography",
                    title="RSA 密钥长度低于 2048 位",
                    cwes=["CWE-310", "CWE-326"],
                    severity="high",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"rsa.GenerateKey(..., {arguments[1].strip()}) -> {bits}-bit RSA key",
                    remediation="生成 RSA 密钥至少使用 2048 位；优先采用符合合规要求的 3072/4096 位或现代椭圆曲线算法。",
                )
            )
    return findings


def _pprof_debug_exposure_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    if not re.search(r'(?m)^\s*_\s+"net/http/pprof"\s*$', _mask_go_comments(content)):
        return []
    http_aliases = _package_import_aliases(content, "net/http", "http")
    if not http_aliases:
        return []
    string_values = _string_constant_assignments(content)
    findings: list[dict[str, Any]] = []
    for alias in http_aliases:
        for match in re.finditer(rf"\b{re.escape(alias)}\.ListenAndServe\s*\(", content):
            arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if len(arguments) < 2 or arguments[1].strip() != "nil":
                continue
            address = _resolved_string_value(arguments[0].strip(), string_values)
            if address is None or not _binds_all_interfaces(address):
                continue
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.pprof-debug-exposure",
                    scenario="security_misconfiguration",
                    title="pprof 调试端点暴露在默认 HTTP mux",
                    cwes=["CWE-489", "CWE-200"],
                    severity="medium",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f'blank import net/http/pprof -> {alias}.ListenAndServe("{address}", nil)',
                    remediation="仅在受认证的独立管理监听地址启用 pprof；生产构建默认关闭或绑定 localhost 并加访问控制。",
                )
            )
    return findings


def _xxe_external_entity_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "github.com/lestrrat-go/libxml2/parser", "parser")
    if not aliases:
        return []
    findings: list[dict[str, Any]] = []
    for alias in aliases:
        for match in re.finditer(rf"\b{re.escape(alias)}\.New\s*\(", content):
            arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
            if arguments_text is None:
                continue
            if not re.search(rf"\b{re.escape(alias)}\.XMLParseNoEnt\b", arguments_text):
                continue
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.xxe-external-entities",
                    scenario="xxe",
                    title="XML 解析启用外部实体展开",
                    cwes=["CWE-611"],
                    severity="high",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"{alias}.New({alias}.XMLParseNoEnt) -> external entity expansion enabled",
                    remediation="禁用外部实体和 DTD 解析；不要传入 XMLParseNoEnt，或使用默认安全解析配置。",
                )
            )
    return findings


def _gorilla_websocket_origin_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "github.com/gorilla/websocket", "websocket")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    unsafe_upgraders: set[str] = set()

    for match in re.finditer(
        rf"(?m)^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*&?(?:{alias_pattern})\.Upgrader\s*\{{",
        content,
    ):
        body = _balanced_brace_body(content, content.find("{", match.start()))
        if body is None:
            continue
        if not re.search(r"\bCheckOrigin\s*:", body):
            unsafe_upgraders.add(match.group("name"))
    for match in re.finditer(rf"\bvar\s+(?P<name>[A-Za-z_]\w*)\s+(?:{alias_pattern})\.Upgrader\b", content):
        unsafe_upgraders.add(match.group("name"))
    if not unsafe_upgraders:
        return []

    findings: list[dict[str, Any]] = []
    for function in _FUNCTION_RE.finditer(content):
        function_text = function.group("body")
        base_line = content.count("\n", 0, function.start("body")) + 1
        for upgrader in unsafe_upgraders:
            for match in re.finditer(rf"\b{re.escape(upgrader)}\.Upgrade\s*\(", function_text):
                prefix = function_text[: match.start()]
                if re.search(rf"\b{re.escape(upgrader)}\.CheckOrigin\s*=", prefix):
                    continue
                line = base_line + function_text.count("\n", 0, match.start())
                if _is_suppressed(content, line):
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.websocket-missing-origin-check",
                        scenario="csrf",
                        title="gorilla/websocket Upgrader 缺少 CheckOrigin",
                        cwes=["CWE-352"],
                        severity="medium",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"{upgrader}=websocket.Upgrader{{... no CheckOrigin ...}} -> {upgrader}.Upgrade",
                        remediation="为每个 websocket.Upgrader 配置严格的 CheckOrigin allowlist，拒绝非预期 Origin。",
                    )
                )
    return findings


def _http_smuggling_header_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    http_aliases = _package_import_aliases(content, "net/http", "http")
    if not http_aliases:
        return []
    findings: list[dict[str, Any]] = []
    for function in _FUNCTION_RE.finditer(content):
        text = function.group("body")
        base_line = content.count("\n", 0, function.start("body")) + 1
        header_aliases: set[str] = set()
        for match in re.finditer(r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<writer>[A-Za-z_]\w*)\.Header\s*\(\s*\)", text):
            header_aliases.add(match.group("name"))
        transfer_line = 0
        content_length_line = 0
        for match in re.finditer(
            r"\b(?P<target>[A-Za-z_]\w*(?:\.Header\s*\(\s*\))?)\.Set\s*\(\s*([\"`])(?P<header>Transfer-Encoding|Content-Length)(?:\2)",
            text,
        ):
            target = match.group("target")
            if ".Header" not in target and target not in header_aliases:
                continue
            line = base_line + text.count("\n", 0, match.start())
            header = match.group("header").lower()
            if header == "transfer-encoding":
                transfer_line = line
            elif header == "content-length":
                content_length_line = line
        if not transfer_line or not content_length_line:
            continue
        line = content_length_line
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.http-smuggling-conflicting-headers",
                scenario="http_request_smuggling",
                title="响应同时设置 Transfer-Encoding 和 Content-Length",
                cwes=["CWE-444"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"Header.Set(Transfer-Encoding) line {transfer_line} + Header.Set(Content-Length) line {content_length_line}",
                remediation="不要手工同时设置 Transfer-Encoding 和 Content-Length；交给 net/http 生成一致的长度/分块语义。",
            )
        )
    return findings


def _cross_origin_protection_bypass_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    http_aliases = _package_import_aliases(content, "net/http", "http")
    if not http_aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in http_aliases)
    cop_variables: set[str] = set()
    for match in re.finditer(rf"\bvar\s+(?P<name>[A-Za-z_]\w*)\s+(?:{alias_pattern})\.CrossOriginProtection\b", content):
        cop_variables.add(match.group("name"))
    for match in re.finditer(
        rf"(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:&?(?:{alias_pattern})\.CrossOriginProtection\s*\{{|new\s*\(\s*(?:{alias_pattern})\.CrossOriginProtection\s*\))",
        content,
    ):
        cop_variables.add(match.group("name"))
    if not cop_variables:
        return []
    findings: list[dict[str, Any]] = []
    variable_pattern = "|".join(re.escape(name) for name in cop_variables)
    for match in re.finditer(
        rf"\b(?:{variable_pattern})\.AddInsecureBypassPattern\s*\(\s*([\"`])(?P<pattern>/\*?|https?://\*)(?:\1)\s*\)",
        content,
    ):
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.cross-origin-bypass",
                scenario="cors_misconfiguration",
                title="CrossOriginProtection 配置了全局绕过模式",
                cwes=["CWE-346"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"CrossOriginProtection.AddInsecureBypassPattern({match.group('pattern')})",
                remediation="不要使用全局路径/通配 Origin 绕过跨站保护；按最小范围配置可信路径和来源。",
            )
        )
    return findings


def _unbounded_http_serve_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    http_aliases = _package_import_aliases(content, "net/http", "http")
    net_aliases = _package_import_aliases(content, "net", "net")
    if not http_aliases or not net_aliases:
        return []
    listener_addresses: dict[str, tuple[str, int]] = {}
    string_values = _string_constant_assignments(content)
    for net_alias in net_aliases:
        for match in re.finditer(
            rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*,\s*(?:[A-Za-z_]\w*|_)\s*(?::=|=)\s*{re.escape(net_alias)}\.Listen\s*\(",
            content,
        ):
            arguments_text, _ = _balanced_call_arguments(content, content.find("(", match.start()))
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if len(arguments) < 2:
                continue
            address = _resolved_string_value(arguments[1].strip(), string_values)
            if address is None or not _binds_all_interfaces(address):
                continue
            listener_addresses[match.group("name")] = (address, content.count("\n", 0, match.start()) + 1)
    if not listener_addresses:
        return []

    findings: list[dict[str, Any]] = []
    for http_alias in http_aliases:
        for match in re.finditer(rf"\b{re.escape(http_alias)}\.Serve\s*\(", content):
            arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
            if arguments_text is None:
                continue
            arguments = _split_go_arguments(arguments_text)
            if len(arguments) < 2:
                continue
            listener = arguments[0].strip()
            if listener not in listener_addresses:
                continue
            if arguments[1].strip() not in {"nil", "http.DefaultServeMux", f"{http_alias}.DefaultServeMux"}:
                continue
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            address, listener_line = listener_addresses[listener]
            finding = _finding(
                rule_id="secflow.go.semantic.unbounded-http-serve",
                scenario="resource_exhaustion",
                title="http.Serve 使用默认 mux 且缺少服务端超时",
                cwes=["CWE-676"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f'net.Listen("{address}") line {listener_line} -> http.Serve(listener, nil)',
                remediation="使用 http.Server 并配置 ReadHeaderTimeout、ReadTimeout、WriteTimeout 和 IdleTimeout。",
            )
            finding["source"]["line"] = listener_line
            finding["source"]["snippet"] = _line(content, listener_line)
            finding["path"][0] = finding["source"]
            findings.append(finding)
    return findings


def _smtp_header_injection_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    smtp_aliases = _package_import_aliases(content, "net/smtp", "smtp")
    if not smtp_aliases:
        return []
    findings: list[dict[str, Any]] = []
    for function in _FUNCTION_RE.finditer(content):
        signature_text = content[function.start() : function.start("body")]
        text = function.group("body")
        base_line = content.count("\n", 0, function.start("body")) + 1
        if not _HTTP_REQUEST_PARAM_RE.search(signature_text):
            continue
        tainted = _request_tainted_variables(text, sanitizer_re=_SMTP_ADDRESS_SANITIZER_RE)
        if not tainted:
            continue
        for alias in smtp_aliases:
            for match in re.finditer(rf"\b{re.escape(alias)}\.SendMail\s*\(", text):
                arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
                if arguments_text is None:
                    continue
                arguments = _split_go_arguments(arguments_text)
                if len(arguments) < 4:
                    continue
                if not _expression_mentions_any(",".join(arguments[2:4]), tainted):
                    continue
                line = base_line + text.count("\n", 0, match.start())
                if _is_suppressed(content, line):
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.smtp-header-injection",
                        scenario="header_injection",
                        title="请求输入进入 SMTP envelope/header 字段",
                        cwes=["CWE-93"],
                        severity="medium",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg="HTTP request -> smtp.SendMail(from/to) -> SMTP header/envelope injection",
                        remediation="对邮件地址使用 mail.ParseAddress/白名单校验，拒绝 CR/LF，并限制收件人来源。",
                    )
                )
    return findings


def _unsafe_pointer_string_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "unsafe", "unsafe")
    if not aliases:
        return []
    findings: list[dict[str, Any]] = []
    for alias in aliases:
        for match in re.finditer(rf"\b{re.escape(alias)}\.(?:String|StringData|Slice|SliceData)\s*\(", content):
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.unsafe-pointer-conversion",
                    scenario="memory_safety",
                    title="使用 unsafe 进行指针/字符串/切片转换",
                    cwes=["CWE-242"],
                    severity="medium",
                    confidence="medium",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"{alias}.{match.group(0).split('.', 1)[1]} -> bypass Go memory/type safety checks",
                    remediation="优先使用安全标准库转换；若必须使用 unsafe，封装在小范围并证明生命周期、长度和别名不变式。",
                )
            )
    return findings


def _zip_unbounded_copy_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    zip_aliases = _package_import_aliases(content, "archive/zip", "zip")
    io_aliases = _package_import_aliases(content, "io", "io")
    if not zip_aliases or not io_aliases:
        return []

    zip_readers: set[str] = set()
    for alias in zip_aliases:
        for match in re.finditer(
            rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*,\s*(?:[A-Za-z_]\w*|_)\s*(?::=|=)\s*{re.escape(alias)}\.(?:OpenReader|NewReader)\s*\(",
            content,
        ):
            zip_readers.add(match.group("name"))
    if not zip_readers:
        return []

    findings: list[dict[str, Any]] = []
    reader_pattern = "|".join(re.escape(name) for name in zip_readers)
    for function in _FUNCTION_RE.finditer(content):
        text = function.group("body")
        base_line = content.count("\n", 0, function.start("body")) + 1
        zip_file_vars: set[str] = set()
        entry_readers: set[str] = set()
        for match in re.finditer(rf"\bfor\s+(?:[A-Za-z_]\w*|_)\s*,\s*(?P<file>[A-Za-z_]\w*)\s*:=\s*range\s+(?:{reader_pattern})\.File\b", text):
            zip_file_vars.add(match.group("file"))
        if not zip_file_vars:
            continue
        file_pattern = "|".join(re.escape(name) for name in zip_file_vars)
        for match in re.finditer(
            rf"(?m)^\s*(?P<reader>[A-Za-z_]\w*)\s*,\s*(?:[A-Za-z_]\w*|_)\s*(?::=|=)\s*(?:{file_pattern})\.Open\s*\(",
            text,
        ):
            entry_readers.add(match.group("reader"))
        if not entry_readers:
            continue
        entry_pattern = "|".join(re.escape(name) for name in entry_readers)
        for io_alias in io_aliases:
            for match in re.finditer(rf"\b{re.escape(io_alias)}\.Copy\s*\(", text):
                arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
                if arguments_text is None:
                    continue
                arguments = _split_go_arguments(arguments_text)
                if len(arguments) < 2:
                    continue
                source_arg = arguments[1].strip()
                if not re.fullmatch(rf"(?:{entry_pattern})", source_arg):
                    continue
                if re.search(rf"\b{re.escape(io_alias)}\.LimitReader\s*\(", ",".join(arguments)):
                    continue
                line = base_line + text.count("\n", 0, match.start())
                if _is_suppressed(content, line):
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.zip-unbounded-copy",
                        scenario="resource_exhaustion",
                        title="ZIP 条目解压复制缺少大小限制",
                        cwes=["CWE-409"],
                        severity="medium",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg="zip.OpenReader -> zip.File.Open -> io.Copy without io.LimitReader",
                        remediation="复制压缩条目前按单文件和总解压大小设置上限，并拒绝压缩比异常的归档。",
                    )
                )
    return findings


def _reverse_proxy_director_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "net/http/httputil", "httputil")
    if not aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in aliases)
    proxy_vars: set[str] = set()
    for match in re.finditer(
        rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*)?\s*(?::=|=)\s*(?:{alias_pattern})\.NewSingleHostReverseProxy\s*\(",
        content,
    ):
        proxy_vars.add(match.group("name"))
    for match in re.finditer(
        rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*&(?:{alias_pattern})\.ReverseProxy\s*\{{",
        content,
    ):
        proxy_vars.add(match.group("name"))

    findings: list[dict[str, Any]] = []
    if proxy_vars:
        proxy_pattern = "|".join(re.escape(name) for name in proxy_vars)
        for match in re.finditer(rf"\b(?:{proxy_pattern})\.Director\s*=\s*func\s*\(", content):
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.reverseproxy-director-override",
                    scenario="request_smuggling",
                    title="ReverseProxy 覆盖 Director 可能保留未净化转发状态",
                    cwes=["CWE-115"],
                    severity="medium",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg="httputil.NewSingleHostReverseProxy -> proxy.Director override",
                    remediation="Go 1.20+ 使用 ReverseProxy.Rewrite/ProxyRequest；覆盖 Director 时显式清理 X-Forwarded、Host 与 hop-by-hop 头。",
                )
            )

    for alias in aliases:
        for match in re.finditer(rf"&{re.escape(alias)}\.ReverseProxy\s*\{{", content):
            body = _balanced_brace_body(content, content.find("{", match.start()))
            if body is None:
                continue
            director = re.search(r"\bDirector\s*:\s*func\s*\(", body)
            if director is None:
                continue
            line = content.count("\n", 0, match.start() + director.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.reverseproxy-director-override",
                    scenario="request_smuggling",
                    title="ReverseProxy 字面量设置 Director",
                    cwes=["CWE-115"],
                    severity="medium",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg="&httputil.ReverseProxy{Director: func(...)}",
                    remediation="Go 1.20+ 使用 Rewrite；若必须设置 Director，显式清理转发头、Host 和代理相关状态。",
                )
            )
    return findings


def _shared_url_mutation_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    url_aliases = _package_import_aliases(content, "net/url", "url")
    if not url_aliases:
        return []
    alias_pattern = "|".join(re.escape(alias) for alias in url_aliases)
    shared_urls: set[str] = set()
    for match in re.finditer(
        rf"(?m)^\s*var\s+(?P<name>[A-Za-z_]\w*)\s*(?:,\s*(?:[A-Za-z_]\w*|_))?\s*=\s*(?:{alias_pattern})\.Parse\s*\(",
        content,
    ):
        shared_urls.add(match.group("name"))
    if not shared_urls:
        return []

    findings: list[dict[str, Any]] = []
    shared_pattern = "|".join(re.escape(name) for name in shared_urls)
    for function in _FUNCTION_RE.finditer(content):
        text = function.group("body")
        base_line = content.count("\n", 0, function.start("body")) + 1
        aliases: set[str] = set()
        for match in re.finditer(rf"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:{shared_pattern})\b", text):
            aliases.add(match.group("name"))
        if not aliases:
            continue
        alias_names = "|".join(re.escape(name) for name in aliases)
        for match in re.finditer(rf"\b(?:{alias_names})\.(?:RawQuery|Path|Host|Scheme|Opaque|User|Fragment)\s*=", text):
            line = base_line + text.count("\n", 0, match.start())
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.shared-url-struct-mutation",
                    scenario="data_race",
                    title="共享 URL 指针/结构被请求处理路径变异",
                    cwes=["CWE-436"],
                    severity="medium",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg="package-level url.Parse result -> local alias -> mutable URL field assignment",
                    remediation="不要复用包级 *url.URL 作为可变请求状态；每次请求 deep copy 或重新 Parse/构造 URL。",
                )
            )
    return findings


def _reflect_dynamic_access_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "reflect", "reflect")
    if not aliases:
        return []
    findings: list[dict[str, Any]] = []
    for alias in aliases:
        for match in re.finditer(rf"\b{re.escape(alias)}\.MakeFunc\s*\(", content):
            line = content.count("\n", 0, match.start()) + 1
            if _is_suppressed(content, line):
                continue
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.reflect-makefunc",
                    scenario="code_execution",
                    title="reflect.MakeFunc 动态生成函数",
                    cwes=["CWE-913"],
                    severity="medium",
                    confidence="medium",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg="reflect.MakeFunc -> runtime-generated callable behavior",
                    remediation="避免由外部对象/脚本桥接生成 Go 函数；限制可调用方法和参数类型白名单。",
                )
            )
    for match in re.finditer(r"\.(?P<method>MethodByName|FieldByName)\s*\(", content):
        arguments_text, _ = _balanced_call_arguments(content, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if not arguments or _string_literal_value(arguments[0].strip()) is not None:
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.reflect-by-name-dynamic",
                scenario="unsafe_reflection",
                title="动态名称进入反射字段/方法访问",
                cwes=["CWE-470"],
                severity="medium",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"dynamic expression -> reflect.Value.{match.group('method')}",
                remediation="用显式 allowlist 映射允许的字段/方法名，拒绝外部输入直接驱动反射访问。",
            )
        )
    return findings


def _project_sql_global_findings(code_files: list[dict[str, str]]) -> list[dict[str, Any]]:
    groups: dict[str, list[tuple[str, str]]] = {}
    for code_file in code_files:
        file_name = str(code_file.get("file_name") or "")
        if Path(file_name).suffix.lower() != ".go":
            continue
        groups.setdefault(Path(file_name).parent.as_posix(), []).append((file_name, str(code_file.get("content") or "")))

    findings: list[dict[str, Any]] = []
    for files in groups.values():
        package_sql_globals: dict[str, tuple[str, int]] = {}
        tainted_globals: dict[str, tuple[str, int]] = {}
        for file_name, content in files:
            masked = _mask_go_comments(content)
            for match in re.finditer(
                r"(?m)^\s*var\s+(?P<name>[A-Za-z_]\w*)\s*(?:string\s*)?=\s*(?P<value>[\"`][^\"`]*[\"`])",
                masked,
            ):
                value = _string_literal_value(match.group("value")) or ""
                if _SQL_KEYWORD_RE.search(value):
                    package_sql_globals[match.group("name")] = (
                        file_name,
                        content.count("\n", 0, match.start()) + 1,
                    )

        if not package_sql_globals:
            continue
        global_pattern = "|".join(re.escape(name) for name in package_sql_globals)
        for file_name, content in files:
            for match in re.finditer(
                rf"(?m)^\s*(?P<name>{global_pattern})\s*(?:\+=|=\s*(?P=name)\s*\+)\s*(?P<expr>[^\n;]+)",
                _mask_go_comments(content),
            ):
                if not _SQL_SOURCE_CALL_RE.search(match.group("expr")):
                    continue
                line = content.count("\n", 0, match.start()) + 1
                tainted_globals[match.group("name")] = (file_name, line)
        if not tainted_globals:
            continue

        tainted_pattern = "|".join(re.escape(name) for name in tainted_globals)
        for file_name, content in files:
            for sink in _SQL_SINK_RE.finditer(content):
                arguments = sink.group("arguments")
                matched_name = next(
                    (name for name in tainted_globals if re.search(rf"\b{re.escape(name)}\b", arguments)),
                    "",
                )
                if not matched_name:
                    continue
                line = content.count("\n", 0, sink.start()) + 1
                if _is_suppressed(content, line):
                    continue
                source_file, source_line = tainted_globals[matched_name]
                finding = _finding(
                    rule_id="secflow.go.semantic.project-global-sql-injection",
                    scenario="sql_injection",
                    title="跨文件包级 SQL 变量被外部输入拼接后执行",
                    cwes=["CWE-89"],
                    severity="high",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"{matched_name} package SQL var -> tainted mutation line {source_line} -> {sink.group('method')}",
                    remediation="不要在包级可变 SQL 字符串中拼接外部输入；使用局部固定 SQL 模板和占位符参数。",
                )
                finding["source"]["file"] = source_file
                finding["source"]["line"] = source_line
                finding["source"]["snippet"] = _line(next(c for f, c in files if f == source_file), source_line)
                finding["path"][0] = finding["source"]
                findings.append(finding)
    return findings


def _http_external_url_audit_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    http_aliases = _package_import_aliases(content, "net/http", "http")
    if not http_aliases:
        return []
    package_url_vars: set[str] = set()
    for match in re.finditer(r"(?m)^\s*var\s+(?P<name>[A-Z][A-Za-z_0-9]*(?:URL|Url|URI|Uri)?|URL|URI)\s+string\s*(?:$|//)", content):
        package_url_vars.add(match.group("name"))

    findings: list[dict[str, Any]] = []
    for function in _FUNCTION_RE.finditer(content):
        params = function.group("params")
        parameter_urls = {
            name
            for name in _string_parameter_names(f"func _({params})")
            if re.search(r"(?i)(?:^url$|uri|endpoint|target)", name)
        }
        candidates = package_url_vars | parameter_urls
        if not candidates:
            continue
        text = function.group("body")
        base_line = content.count("\n", 0, function.start("body")) + 1
        candidate_pattern = "|".join(re.escape(name) for name in candidates)
        for alias in http_aliases:
            for match in re.finditer(rf"\b{re.escape(alias)}\.(?:Get|Post|Head)\s*\(", text):
                arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
                if arguments_text is None:
                    continue
                arguments = _split_go_arguments(arguments_text)
                if not arguments or not re.fullmatch(rf"(?:{candidate_pattern})", arguments[0].strip()):
                    continue
                line = base_line + text.count("\n", 0, match.start())
                if _is_suppressed(content, line):
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.external-url-http-client",
                        scenario="ssrf",
                        title="可变外部 URL 进入 HTTP 客户端",
                        cwes=["CWE-88"],
                        severity="medium",
                        confidence="low",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"{arguments[0].strip()} -> {alias}.{match.group(0).split('.', 1)[1]}",
                        remediation="对 URL 参数/包级可变 URL 使用协议、主机、端口 allowlist；避免请求内网、metadata 和本地地址。",
                    )
                )
    return findings


def _syscall_start_process_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    aliases = _package_import_aliases(content, "syscall", "syscall")
    if not aliases:
        return []
    findings: list[dict[str, Any]] = []
    for function in _FUNCTION_RE.finditer(content):
        params = set(_parameter_names(function.group("params")))
        text = function.group("body")
        base_line = content.count("\n", 0, function.start("body")) + 1
        aliases_by_assignment: set[str] = set(params)
        for _ in range(3):
            changed = False
            for match in _COMMAND_ASSIGNMENT_RE.finditer(text):
                target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
                if not target:
                    continue
                if _expression_mentions_any(match.group("value"), aliases_by_assignment) and target not in aliases_by_assignment:
                    aliases_by_assignment.add(target)
                    changed = True
            if not changed:
                break
        for alias in aliases:
            for match in re.finditer(rf"\b{re.escape(alias)}\.StartProcess\s*\(", text):
                arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
                if arguments_text is None:
                    continue
                arguments = _split_go_arguments(arguments_text)
                if not arguments:
                    continue
                executable = arguments[0].strip()
                if _string_literal_value(executable) is not None or not _expression_mentions_any(executable, aliases_by_assignment):
                    continue
                line = base_line + text.count("\n", 0, match.start())
                if _is_suppressed(content, line):
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.syscall-startprocess-variable",
                        scenario="command_execution",
                        title="变量控制 syscall.StartProcess 可执行路径",
                        cwes=["CWE-78"],
                        severity="medium",
                        confidence="medium",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"function parameter/local alias -> {alias}.StartProcess executable",
                        remediation="固定可执行文件绝对路径，禁止由外部或跨边界参数决定 StartProcess 的第一个参数。",
                    )
                )
    return findings


def _gorilla_session_identity_overwrite_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    if not _package_import_aliases(content, "github.com/gorilla/sessions", "sessions"):
        return []
    findings: list[dict[str, Any]] = []
    session_identity_vars: dict[str, list[int]] = {}
    for match in re.finditer(
        r"(?m)^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*)\s*(?:[A-Za-z_][\w.\[\]]+\s*)?"
        r"(?::=|=)\s*(?:[A-Za-z_]\w*\.)?Values\s*\[\s*([\"`])(?:user_?id|account_?id|uid|subject)(?:\2)\s*\]",
        content,
        flags=re.IGNORECASE,
    ):
        session_identity_vars.setdefault(match.group("name"), []).append(match.start())
    if not session_identity_vars:
        return []

    identity_pattern = "|".join(re.escape(name) for name in session_identity_vars)
    for match in re.finditer(
        rf"(?m)^\s*(?P<name>{identity_pattern})\s*=\s*[A-Za-z_]\w*\.(?:query\.params|URL\.Query\(\)|Form|PostForm)",
        content,
    ):
        name = match.group("name")
        starts = [start for start in session_identity_vars.get(name, []) if start < match.start()]
        if not starts:
            continue
        prefix = content[starts[-1] : match.start()]
        if not re.search(rf"\bValidate[A-Za-z_]*\s*\(\s*{re.escape(name)}\s*\)", prefix):
            continue
        line = content.count("\n", 0, match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.session-identity-overwrite",
                scenario="access_control",
                title="已验证 session 身份字段被请求参数覆盖",
                cwes=["CWE-289"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"session.Values identity -> Validate*({name}) -> {name}=request parameter",
                remediation="授权后的主体标识只能来自可信 session/token；请求参数不得覆盖已验证身份字段。",
            )
        )
    return findings


def _integer_constant_assignments(content: str) -> dict[str, int]:
    constants: dict[str, int] = {}
    for match in re.finditer(
        r"(?m)^\s*(?:const|var)\s+(?P<name>[A-Za-z_]\w*)\s*(?:[A-Za-z_]\w*)?\s*=\s*(?P<value>[-+]?(?:0[xX][0-9A-Fa-f]+|0[oO][0-7]+|\d+))\s*(?:$|//)",
        _mask_go_comments(content),
    ):
        value = _integer_value(match.group("value"))
        if value is not None:
            constants[match.group("name")] = value
    return constants


def _package_import_aliases(content: str, package_path: str, default_alias: str) -> dict[str, int]:
    masked = _mask_go_comments(content)
    aliases: dict[str, tuple[str, int]] = {}
    conflicted: set[str] = set()
    for match in _GO_IMPORT_RE.finditer(masked):
        path = match.group("path")
        explicit_alias = match.group("alias")
        alias = explicit_alias or (default_alias if path == package_path else path.rsplit("/", 1)[-1])
        if alias == "_":
            continue
        line = content.count("\n", 0, match.start()) + 1
        existing = aliases.get(alias)
        if existing is not None and existing[0] != path:
            conflicted.add(alias)
        aliases[alias] = (path, line)
    return {
        alias: line
        for alias, (path, line) in aliases.items()
        if alias not in conflicted and path == package_path
    }


def _command_execution_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    exec_aliases = _package_import_aliases(content, "os/exec", "exec")
    otto_aliases = _package_import_aliases(content, "github.com/robertkrimen/otto", "otto")
    if not exec_aliases and not otto_aliases:
        return []

    masked = _mask_go_comments(text)
    tainted = set(_parameter_names(signature_text.partition("(")[2].rpartition(")")[0]))
    lookpath_aliases: set[str] = set()
    for alias in exec_aliases:
        lookpath_aliases.add(rf"{re.escape(alias)}\.LookPath")

    for _ in range(5):
        changed = False
        for match in _COMMAND_ASSIGNMENT_RE.finditer(masked):
            target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
            if not target:
                continue
            expression = match.group("value").strip()
            source_call = bool(_COMMAND_SOURCE_CALL_RE.search(expression))
            propagated = _expression_mentions_any(expression, tainted)
            lookpath_tainted = bool(lookpath_aliases and tainted) and re.search(
                rf"\b(?:{'|'.join(lookpath_aliases)})\s*\([^)]*(?:{'|'.join(re.escape(name) for name in tainted)})",
                expression,
            )
            if (source_call or propagated or lookpath_tainted) and target not in tainted:
                tainted.add(target)
                changed = True
        if not changed:
            break

    findings: list[dict[str, Any]] = []
    for alias in exec_aliases:
        findings.extend(_exec_command_call_findings(file_name, content, text, base_line, alias, tainted))
        findings.extend(_exec_cmd_literal_findings(file_name, content, text, base_line, alias, tainted))
    if otto_aliases:
        findings.extend(_otto_run_findings(file_name, content, text, base_line, tainted))
    return findings


def _exec_command_call_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    alias: str,
    tainted: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    call_re = re.compile(rf"\b{re.escape(alias)}\.(?:Command|CommandContext)\s*\(")
    for match in call_re.finditer(text):
        arguments_text, end = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if not arguments:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        reason = ""
        if _expression_mentions_any(arguments[0], tainted):
            reason = "外部输入控制可执行文件路径"
        shell_index = next((index for index, arg in enumerate(arguments) if _string_literal_value(arg) == "-c"), -1)
        if shell_index >= 0 and shell_index + 1 < len(arguments) and _expression_mentions_any(arguments[shell_index + 1], tainted):
            reason = "外部输入作为 shell -c 脚本执行"
        if not reason and _string_literal_value(arguments[0].strip()) is not None:
            tainted_args = [
                argument
                for argument in arguments[1:]
                if _expression_mentions_any(argument, tainted)
            ]
            if tainted_args:
                reason = "外部输入作为命令参数执行，需确认不会改变命令安全边界"
        if not reason:
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.dangerous-command-execution",
                scenario="command_execution",
                title="外部输入进入命令或脚本执行",
                cwes=["CWE-78", "CWE-94"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{sorted(tainted)[0] if tainted else 'input'} -> {alias}.Command* -> {reason}",
                remediation="固定可执行文件路径，使用参数白名单；禁止把外部输入交给 shell -c。",
            )
        )
    return findings


def _exec_cmd_literal_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    alias: str,
    tainted: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    literal_re = re.compile(rf"&?\s*{re.escape(alias)}\.Cmd\s*\{{")
    for match in literal_re.finditer(text):
        body = _balanced_brace_body(text, text.find("{", match.start()))
        if body is None:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        path_expr = _struct_field_expression(body, "Path")
        args_expr = _struct_field_expression(body, "Args")
        reason = ""
        if path_expr and _expression_mentions_any(path_expr, tainted):
            reason = "外部输入控制 exec.Cmd.Path"
        elif args_expr and _expression_mentions_any(args_expr, tainted):
            reason = "外部输入进入 exec.Cmd.Args"
        if not reason:
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.dangerous-command-execution",
                scenario="command_execution",
                title="外部输入进入 exec.Cmd",
                cwes=["CWE-78", "CWE-94"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{sorted(tainted)[0] if tainted else 'input'} -> exec.Cmd -> {reason}",
                remediation="不要把外部输入放入 Path 或 shell 参数；使用固定命令和逐项白名单参数。",
            )
        )
    return findings


def _otto_run_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    tainted: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\b[A-Za-z_]\w*\.Run\s*\((?P<argument>[^)\n]+)\)", text):
        argument = match.group("argument")
        if not _expression_mentions_any(argument, tainted):
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.dangerous-script-execution",
                scenario="code_execution",
                title="外部输入进入脚本解释器执行",
                cwes=["CWE-94"],
                severity="critical",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{sorted(tainted)[0] if tainted else 'input'} -> otto.Run",
                remediation="禁止执行外部提供的脚本；如确需表达式能力，使用受限 DSL 和能力白名单。",
            )
        )
    return findings


def _text_template_execution_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str,
) -> list[dict[str, Any]]:
    if not _package_import_aliases(content, "text/template", "template"):
        return []
    response_writers = {match.group("name") for match in _HTTP_RESPONSE_PARAM_RE.finditer(signature_text)}
    if not response_writers or not _HTTP_REQUEST_PARAM_RE.search(signature_text):
        return []

    masked = _mask_go_comments(text)
    tainted: set[str] = set()
    for _ in range(5):
        changed = False
        for match in _COMMAND_ASSIGNMENT_RE.finditer(masked):
            target = next((item.strip() for item in match.group("names").split(",") if item.strip() != "_"), "")
            if not target:
                continue
            expression = match.group("value").strip()
            if _HTML_SANITIZER_RE.search(expression):
                tainted.discard(target)
                continue
            if (_COMMAND_SOURCE_CALL_RE.search(expression) or _expression_mentions_any(expression, tainted)) and target not in tainted:
                tainted.add(target)
                changed = True
        if not changed:
            break

    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\b[A-Za-z_]\w*\.Execute(?:Template)?\s*\(", text):
        arguments_text, _ = _balanced_call_arguments(text, match.end() - 1)
        if arguments_text is None:
            continue
        arguments = _split_go_arguments(arguments_text)
        if len(arguments) < 2 or arguments[0].strip() not in response_writers:
            continue
        data_arguments = arguments[1:] if ".Execute(" in match.group(0) else arguments[2:]
        if not any(_expression_mentions_any(argument, tainted) for argument in data_arguments):
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.text-template-response-execution",
                scenario="code_execution",
                title="请求输入进入 text/template Web 输出",
                cwes=["CWE-79", "CWE-94"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"HTTP request -> text/template.Execute*({arguments[0].strip()})",
                remediation="Web HTML 输出使用 html/template；若必须使用 text/template，先按 HTML 上下文编码所有请求数据。",
            )
        )
    return findings


def _literal_assignments(content: str, tls_aliases: dict[str, int]) -> tuple[dict[str, bool], dict[str, int]]:
    bool_values: dict[str, bool] = {}
    version_values: dict[str, int] = {}
    for match in _TLS_ASSIGNMENT_RE.finditer(_mask_go_comments(content)):
        name = match.group("name")
        expr = match.group("expr").strip()
        bool_value = _resolved_bool(expr, bool_values)
        if bool_value is not None:
            bool_values[name] = bool_value
            continue
        version_value = _resolved_tls_version(expr, version_values, tls_aliases)
        if version_value is not None:
            version_values[name] = version_value
    return bool_values, version_values


def _resolved_bool(expr: str, constants: dict[str, bool]) -> bool | None:
    normalized = expr.strip().removesuffix(",").strip()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    if normalized.startswith("!"):
        value = _resolved_bool(normalized[1:].strip(), constants)
        return None if value is None else not value
    return constants.get(normalized)


def _resolved_tls_version(
    expr: str,
    constants: dict[str, int],
    aliases: dict[str, int],
) -> int | None:
    normalized = expr.strip().removesuffix(",").strip()
    if normalized in constants:
        return constants[normalized]
    try:
        return int(normalized, 0)
    except ValueError:
        pass
    selector = re.fullmatch(r"(?P<alias>[A-Za-z_]\w*)\.(?P<version>Version(?:SSL30|TLS1[0-3]))", normalized)
    if selector and selector.group("alias") in aliases:
        return _TLS_VERSION_VALUES.get(selector.group("version"))
    return None


def _expression_mentions_any(expression: str, names: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", expression) for name in names)


def _balanced_call_arguments(text: str, opening: int) -> tuple[str | None, int]:
    if opening < 0 or opening >= len(text) or text[opening] != "(":
        return None, opening
    body, end = _balanced_body(text, opening, "(", ")")
    return body, end


def _balanced_brace_body(text: str, opening: int) -> str | None:
    if opening < 0 or opening >= len(text) or text[opening] != "{":
        return None
    body, _ = _balanced_body(text, opening, "{", "}")
    return body


def _balanced_body(text: str, opening: int, left: str, right: str) -> tuple[str | None, int]:
    depth = 1
    quote = ""
    escaped = False
    index = opening + 1
    while index < len(text):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character in {'"', "'", "`"}:
            quote = character
        elif character == left:
            depth += 1
        elif character == right:
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index], index
        index += 1
    return None, opening


def _split_go_arguments(arguments: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    pairs = {"(": ")", "{": "}", "[": "]"}
    closers = set(pairs.values())
    for index, character in enumerate(arguments):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {'"', "'", "`"}:
            quote = character
            continue
        if character in pairs:
            depth += 1
            continue
        if character in closers and depth:
            depth -= 1
            continue
        if character == "," and depth == 0:
            result.append(arguments[start:index].strip())
            start = index + 1
    tail = arguments[start:].strip()
    if tail:
        result.append(tail)
    return result


def _string_literal_value(expression: str) -> str | None:
    normalized = expression.strip()
    if len(normalized) < 2:
        return None
    if normalized[0] == normalized[-1] == "`":
        return normalized[1:-1]
    if normalized[0] == normalized[-1] == '"':
        try:
            return bytes(normalized[1:-1], "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return normalized[1:-1]
    return None


def _struct_field_expression(body: str, field: str) -> str | None:
    match = re.search(rf"\b{re.escape(field)}\s*:", body)
    if match is None:
        return None
    index = match.end()
    start = index
    depth = 0
    quote = ""
    escaped = False
    pairs = {"(": ")", "{": "}", "[": "]"}
    closers = set(pairs.values())
    while index < len(body):
        character = body[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character in {'"', "'", "`"}:
            quote = character
        elif character in pairs:
            depth += 1
        elif character in closers and depth:
            depth -= 1
        elif character == "," and depth == 0:
            break
        index += 1
    return body[start:index].strip()


def _interprocedural_sql_findings(
    file_name: str,
    content: str,
    source: bytes,
    functions: list[Node],
) -> list[dict[str, Any]]:
    summaries: list[tuple[str, str, int]] = []
    for function in functions:
        name_node = function.child_by_field_name("name")
        body = function.child_by_field_name("body")
        if name_node is None or body is None:
            continue
        name = source[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="replace")
        text = source[body.start_byte : body.end_byte].decode("utf-8", errors="replace")
        summaries.append((name, _mask_go_comments(text), body.start_point.row + 1))

    source_functions: set[str] = set()
    for _ in range(4):
        changed = False
        for name, text, _ in summaries:
            if name in source_functions:
                continue
            return_expressions = re.findall(r"\breturn\s+([^\n;]+)", text)
            if any(
                _SQL_SOURCE_CALL_RE.search(expression)
                or any(re.search(rf"\b{re.escape(source_name)}\s*\(", expression) for source_name in source_functions)
                for expression in return_expressions
            ):
                source_functions.add(name)
                changed = True
        if not changed:
            break

    findings: list[dict[str, Any]] = []
    for _, text, base_line in summaries:
        tainted: set[str] = set()
        sql_variables: set[str] = set()
        builders = set(re.findall(r"\bvar\s+([A-Za-z_]\w*)\s+strings\.Builder\b", text))
        tainted_builders: set[str] = set()

        for match in re.finditer(r"\bfor\s+_\s*,\s*([A-Za-z_]\w*)\s*:=\s*range\s+os\.Args\b", text):
            tainted.add(match.group(1))

        for _ in range(6):
            changed = False
            for match in _SQL_ASSIGNMENT_RE.finditer(text):
                names = [item.strip() for item in match.group("names").split(",")]
                target = next((item for item in names if item != "_"), "")
                expression = match.group("value").strip()
                if not target or _SQL_SANITIZER_RE.search(expression):
                    continue
                source_call = bool(_SQL_SOURCE_CALL_RE.search(expression))
                summarized_call = any(
                    re.search(rf"\b{re.escape(source_name)}\s*\(", expression)
                    for source_name in source_functions
                )
                propagated = any(re.search(rf"\b{re.escape(name)}\b", expression) for name in tainted)
                builder_flow = any(
                    re.search(rf"\b{re.escape(name)}\.String\s*\(", expression)
                    for name in tainted_builders
                )
                if (source_call or summarized_call or propagated or builder_flow) and target not in tainted:
                    tainted.add(target)
                    changed = True
                if (
                    _SQL_KEYWORD_RE.search(expression)
                    and (source_call or summarized_call or propagated or builder_flow)
                    and target not in sql_variables
                ):
                    sql_variables.add(target)
                    changed = True

            for builder in builders:
                for match in re.finditer(rf"\b{re.escape(builder)}\.WriteString\s*\(([^\n)]+)\)", text):
                    argument = match.group(1)
                    if any(re.search(rf"\b{re.escape(name)}\b", argument) for name in tainted):
                        if builder not in tainted_builders:
                            tainted_builders.add(builder)
                            changed = True
            if not changed:
                break

        for sink in _SQL_SINK_RE.finditer(text):
            arguments = sink.group("arguments")
            flowed_names = [
                name
                for name in sql_variables
                if re.search(rf"\b{re.escape(name)}\b", arguments)
            ]
            if not flowed_names:
                continue
            line = base_line + text.count("\n", 0, sink.start())
            if _is_suppressed(content, line):
                continue
            flow_label = flowed_names[0]
            findings.append(
                _finding(
                    rule_id="secflow.go.semantic.interprocedural-sql-injection",
                    scenario="sql_injection",
                    title="跨函数外部输入进入动态 SQL 查询",
                    cwes=["CWE-89"],
                    severity="high",
                    confidence="high",
                    file_name=file_name,
                    line=line,
                    snippet=_line(content, line),
                    dfg=f"HTTP/CLI 输入 -> 函数返回摘要 -> {flow_label} -> {sink.group('method')}",
                    remediation="使用固定 SQL 模板和占位符参数；不要跨函数返回并拼接原始请求值。",
                )
            )
    return findings


def _mask_go_comments(text: str) -> str:
    result = list(text)
    index = 0
    state = "code"
    while index < len(text):
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code" and text[index] == "/" and following == "/":
            result[index] = result[index + 1] = " "
            index += 2
            state = "line"
            continue
        if state == "code" and text[index] == "/" and following == "*":
            result[index] = result[index + 1] = " "
            index += 2
            state = "block"
            continue
        if state == "line":
            if text[index] == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state == "block":
            if text[index] == "*" and following == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "code"
                continue
            if text[index] != "\n":
                result[index] = " "
        index += 1
    return "".join(result)


def _cancel_is_released_or_transferred(
    text: str,
    offset: int,
    cancel: str,
    content: str | None = None,
) -> bool:
    tail = text[offset:]
    escaped = re.escape(cancel)
    if re.search(rf"\b{escaped}\s*\(", tail):
        return True
    if re.search(rf"\breturn\b[^\n]*\b{escaped}\b", tail):
        return True
    for source_line in tail.splitlines():
        line = source_line.split("//", 1)[0]
        if not re.search(rf"\b{escaped}\b", line):
            continue
        if _assignment_discards_name(line, cancel):
            continue
        if content is not None:
            selector_assignment = re.match(
                rf"^\s*(?P<target>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*=\s*{escaped}\b",
                line,
            )
            if selector_assignment:
                field = selector_assignment.group("target").rsplit(".", 1)[1]
                if re.search(rf"\.\s*{re.escape(field)}\s*\(", _mask_go_comments(content)):
                    return True
                continue
            package_assignment = re.match(rf"^\s*(?P<target>[A-Za-z_]\w*)\s*=\s*{escaped}\b", line)
            if package_assignment:
                released = _package_cancel_release_state(content, package_assignment.group("target"))
                if released is not None:
                    if released:
                        return True
                    continue
        return True
    return False


def _assignment_discards_name(line: str, name: str) -> bool:
    if "=" not in line:
        return False
    left, right = line.split("=", 1)
    if not re.search(rf"\b{re.escape(name)}\b", right):
        return False
    left = left.replace(":", "")
    return bool(left.strip()) and all(part.strip() == "_" for part in left.split(","))


def _package_cancel_is_released(content: str, cancel: str) -> bool:
    return _package_cancel_release_state(content, cancel) is True


def _package_cancel_release_state(content: str, cancel: str) -> bool | None:
    escaped = re.escape(cancel)
    masked = _mask_go_comments(content)
    declaration = re.search(
        rf"(?m)^var\s+{escaped}\s+context\.CancelFunc\b",
        masked,
    )
    if declaration is None:
        return None
    return bool(re.search(rf"\b{escaped}\s*\(", masked[declaration.end() :]))


def _context_cancellation_is_observed(text: str, context_name: str) -> bool:
    context = re.escape(context_name)
    return bool(
        re.search(rf"\b{context}\s*\.\s*(?:Done|Err)\s*\(", text)
        or re.search(rf"\bcontext\s*\.\s*Cause\s*\(\s*{context}\s*\)", text)
    )


def _sensitive_serialization_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    serializer_lines = [
        content.count("\n", 0, match.start()) + 1
        for match in _SERIALIZER_RE.finditer(content)
        if not _is_suppressed(content, content.count("\n", 0, match.start()) + 1)
    ]
    if not serializer_lines:
        return []

    findings: list[dict[str, Any]] = []
    for struct_match in _STRUCT_RE.finditer(content):
        type_name = struct_match.group("name")
        if re.search(rf"\bfunc\s*\([^)]*\b{re.escape(type_name)}\b[^)]*\)\s*Marshal(?:JSON|YAML|XML|TOML)\s*\(", content):
            continue
        sensitive_field = _sensitive_exported_field(struct_match.group("body"))
        if sensitive_field is None:
            continue
        if re.search(
            rf"(?is)\b{re.escape(sensitive_field)}\s*:\s*(?:mask|redact|sanitize|scrub)\w*\s*\(",
            content,
        ):
            continue
        line = content.count("\n", 0, struct_match.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.sensitive-data-serialization",
                scenario="sensitive_data_exposure",
                title="敏感结构体字段可能被直接序列化",
                cwes=["CWE-499"],
                severity="high",
                confidence="medium",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{type_name}.{sensitive_field} -> 编码器/Marshal -> 外部表示",
                remediation="为敏感字段设置对应编码器的 '-' 忽略标签，或使用只包含允许公开字段的 DTO。",
            )
        )
    return findings


def _sensitive_exported_field(struct_body: str) -> str | None:
    for source_line in struct_body.splitlines():
        line = source_line.split("//", 1)[0].strip()
        if not line or line.startswith("`"):
            continue
        declaration, _, tag = line.partition("`")
        if re.search(r'(?:json|yaml|xml|toml):"-"', tag, re.IGNORECASE):
            continue
        names_match = re.match(
            r"(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+",
            declaration,
        )
        names = names_match.group("names").split(",") if names_match else []
        sensitive_tag = any(
            _SENSITIVE_FIELD_RE.search(tag_name.replace("-", "_"))
            for tag_name in re.findall(
                r'(?:json|yaml|xml|toml):"([^",]+)',
                tag,
                re.IGNORECASE,
            )
        )
        for name in names:
            field = name.strip().lstrip("*")
            if (
                field
                and field[0].isupper()
                and (_SENSITIVE_FIELD_RE.search(field) or sensitive_tag)
                and not re.match(r"(?i)^(?:max|min|num|count|limit|input|output|total).*tokens?$", field)
            ):
                return field
    return None


def _fixed_nonce_findings(file_name: str, content: str) -> list[dict[str, Any]]:
    fixed_names = {match.group("name") for match in _FIXED_BYTES_RE.finditer(content)}
    fixed_names.update(_zero_slice_aliases(content, fixed_names))
    functions: dict[str, tuple[list[str], str]] = {}
    for match in _FUNCTION_RE.finditer(content):
        parameters = _parameter_names(match.group("params"))
        functions[match.group("name")] = (parameters, match.group("body"))

    findings: list[dict[str, Any]] = []
    for sink in _CRYPTO_NONCE_SINK_RE.finditer(content):
        nonce = (sink.group("stream") or sink.group("aead") or "").strip()
        nonce_name_match = re.fullmatch(
            r"(?:\[\]byte\s*\(\s*)?(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])?\s*\)?",
            nonce,
        )
        nonce_name = nonce_name_match.group("name") if nonce_name_match else ""
        deterministic = bool(
            re.search(r"\[\]byte\s*(?:\(|\{)", nonce)
            or (nonce_name and nonce_name in fixed_names)
            or (nonce_name and _parameter_receives_fixed_value(content, functions, nonce_name))
            or (nonce_name and _has_fixed_element_write(content, nonce_name))
        )
        if not deterministic:
            continue
        if nonce_name and _nonce_is_randomized(content, nonce_name) and not _has_fixed_write_after_random(
            content,
            nonce_name,
            nonce,
        ):
            continue
        line = content.count("\n", 0, sink.start()) + 1
        if _is_suppressed(content, line):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.fixed-crypto-nonce",
                scenario="fixed_cryptographic_nonce",
                title="固定或可预测 nonce 进入密码模式",
                cwes=["CWE-1204"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{nonce or '固定字节'} -> cipher/AEAD nonce",
                remediation="为每次加密生成新的随机 nonce，并使用 io.ReadFull(crypto/rand.Reader, nonce) 填满整个缓冲区。",
            )
        )

    for match in re.finditer(
        r"(?ms)\.Seal\s*\([^\n]*?func\s*\(\s*\)\s*\[\]byte\s*\{.*?return\s+\[\]byte\s*(?:\(|\{)",
        content,
    ):
        line = content.count("\n", 0, match.start()) + 1
        suppression_window = content[match.start() : match.end() + 500]
        if _is_suppressed(content, line) or _NOSEC_RE.search(suppression_window):
            continue
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.fixed-crypto-nonce",
                scenario="fixed_cryptographic_nonce",
                title="内联函数返回固定 nonce",
                cwes=["CWE-1204"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg="固定字节闭包 -> AEAD nonce",
                remediation="内联 nonce 生成函数必须从 crypto/rand 读取完整随机值。",
            )
        )
    for match in re.finditer(
        r"\b(?P<function>[A-Za-z_]\w*)\s*\([^,\n]+,\s*(?P<nonce>[A-Za-z_]\w*)\s*\)",
        content,
    ):
        function_name = match.group("function")
        nonce_name = match.group("nonce")
        if nonce_name not in fixed_names:
            continue
        if not re.search(
            rf"\b{re.escape(function_name)}\s*=\s*cipher\.(?:NewCBCEncrypter|NewCFBEncrypter|NewCTR|NewOFB)\b",
            content,
        ):
            continue
        if _nonce_is_randomized(content, nonce_name) and not _has_fixed_write_after_random(
            content,
            nonce_name,
            nonce_name,
        ):
            continue
        line = content.count("\n", 0, match.start()) + 1
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.fixed-crypto-nonce",
                scenario="fixed_cryptographic_nonce",
                title="间接密码模式调用使用固定 nonce",
                cwes=["CWE-1204"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{nonce_name} -> {function_name}=cipher.New* -> nonce",
                remediation="不要通过函数变量隐藏固定 nonce；每次加密前完整生成新的随机 nonce。",
            )
        )
    return findings


def _zero_slice_aliases(content: str, fixed_names: set[str]) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for match in re.finditer(
            r"\b(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<source>[A-Za-z_]\w*)\s*\[[^\]]*\]",
            content,
        ):
            if match.group("source") not in fixed_names | aliases or match.group("name") in aliases:
                continue
            aliases.add(match.group("name"))
            changed = True
    return aliases


def _parameter_names(parameters: str) -> list[str]:
    names: list[str] = []
    for part in parameters.split(","):
        token = part.strip().split(None, 1)[0] if part.strip() else ""
        if token and re.fullmatch(r"[A-Za-z_]\w*", token):
            names.append(token)
    return names


def _parameter_receives_fixed_value(
    content: str,
    functions: dict[str, tuple[list[str], str]],
    parameter: str,
) -> bool:
    for function_name, (parameters, body) in functions.items():
        if parameter not in parameters or not _CRYPTO_NONCE_SINK_RE.search(body):
            continue
        index = parameters.index(parameter)
        for call in re.finditer(rf"\b{re.escape(function_name)}\s*\((?P<args>[^\n)]*)\)", content):
            arguments = [argument.strip() for argument in call.group("args").split(",")]
            if index >= len(arguments):
                continue
            argument = arguments[index]
            if re.search(r"^(?:\[\]byte\s*\(|make\s*\(\s*\[\]byte\s*,|\")", argument):
                return True
            assignment = re.search(
                rf"(?m)^\s*(?:var\s+|const\s+)?{re.escape(argument)}\s*(?::=|=)\s*"
                rf"(?:\[\]byte\s*(?:\(|\{{)|make\s*\(\s*\[\]byte\s*,|\")",
                content,
            )
            if assignment:
                return True
    return False


def _nonce_is_randomized(content: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(rf"\b(?:rand\.Read|io\.ReadFull)\s*\([^\n]*\b{escaped}\b", content)
        or re.search(rf"\b[A-Za-z_]\w*\.Read\s*\(\s*{escaped}(?:\s*\[[^\]]*\])?\s*\)", content)
        or _nonce_is_randomized_by_helper(content, name)
        or _nonce_is_randomized_by_callback(content, name)
    )


def _nonce_is_randomized_by_helper(content: str, name: str) -> bool:
    randomizing_helpers: set[str] = set()
    for function in _FUNCTION_RE.finditer(content):
        helper_name = function.group("name")
        body = function.group("body")
        for parameter in _parameter_names(function.group("params")):
            escaped_parameter = re.escape(parameter)
            if re.search(rf"\b(?:rand\.Read|io\.ReadFull)\s*\([^\n]*\b{escaped_parameter}\b", body) or re.search(
                rf"\b[A-Za-z_]\w*\.Read\s*\(\s*{escaped_parameter}(?:\s*\[[^\]]*\])?\s*\)",
                body,
            ):
                randomizing_helpers.add(helper_name)
                break
    if not randomizing_helpers:
        return False
    escaped_name = re.escape(name)
    return any(
        re.search(rf"\b{re.escape(helper)}\s*\(\s*{escaped_name}(?:\s*\[[^\]]*\])?\s*\)", content)
        for helper in randomizing_helpers
    )


def _nonce_is_randomized_by_callback(content: str, name: str) -> bool:
    escaped_name = re.escape(name)
    for function in _FUNCTION_RE.finditer(content):
        callback_params = re.findall(
            r"\b(?P<name>[A-Za-z_]\w*)\s+func\s*\(\s*\[\]\s*byte\s*\)",
            function.group("params"),
        )
        if not callback_params:
            continue
        body = function.group("body")
        if any(
            re.search(rf"\b{re.escape(callback)}\s*\(\s*{escaped_name}(?:\s*\[[^\]]*\])?\s*\)", body)
            for callback in callback_params
        ):
            return True
    return False


def _has_fixed_element_write(content: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\s*\[[^\]]+\]\s*=\s*(?:0|1|0[xX][0-9A-Fa-f]+)\b", content))


def _has_fixed_write_after_random(content: str, name: str, nonce_expression: str) -> bool:
    escaped = re.escape(name)
    randomized = re.search(rf"\b(?:rand\.Read|io\.ReadFull)\s*\([^\n]*\b{escaped}\b", content)
    if randomized is None:
        return False
    tail = content[randomized.end() :]
    writes = list(
        re.finditer(
            rf"\b{re.escape(name)}\s*\[\s*(?P<index>[^\]]+)\s*\]\s*=\s*(?:0|1|0[xX][0-9A-Fa-f]+)\b",
            tail,
        )
    )
    if not writes:
        return _has_alias_fixed_write_after_random(tail, name, nonce_expression)
    slice_match = re.search(r":\s*(?P<high>\d+)\s*\]", nonce_expression)
    if slice_match is None:
        nonce_high = None
    else:
        nonce_high = int(slice_match.group("high"))
    for write in writes:
        index = write.group("index").strip()
        constant = _integer_value(index)
        if constant is not None:
            if (nonce_high is None or 0 <= constant < nonce_high) and not _random_read_covers_index(
                tail[write.end() :],
                name,
                constant,
            ):
                return True
            continue
        prefix = tail[: write.start()]
        lower_match = re.search(rf"\b{re.escape(index)}\s*>=\s*(?P<lower>\d+)", prefix)
        if lower_match is None or nonce_high is None or int(lower_match.group("lower")) < nonce_high:
            return True
    return False


def _random_read_covers_index(text: str, name: str, index: int) -> bool:
    escaped = re.escape(name)
    for match in re.finditer(
        rf"\b(?:rand\.Read|io\.ReadFull|[A-Za-z_]\w*\.Read)\s*\([^\n]*\b{escaped}(?:\s*\[(?P<slice>[^\]]*)\])?",
        text,
    ):
        slice_text = match.group("slice") or ""
        if _slice_text_covers_index(slice_text, index):
            return True
    return False


def _slice_text_covers_index(slice_text: str, index: int) -> bool:
    if not slice_text:
        return True
    parts = slice_text.split(":")
    if len(parts) < 2:
        return False
    low = _integer_value(parts[0].strip()) if parts[0].strip() else 0
    high = _integer_value(parts[1].strip()) if parts[1].strip() else None
    if low is None:
        return True
    if high is None:
        return index >= low
    return low <= index < high


def _has_alias_fixed_write_after_random(tail: str, name: str, nonce_expression: str) -> bool:
    aliases: set[str] = set()
    escaped = re.escape(name)
    for match in re.finditer(
        rf"(?m)^\s*(?P<alias>[A-Za-z_]\w*)\s*(?::=|=)\s*{escaped}(?:\s*\[(?P<slice>[^\]]*)\])?\s*(?:$|//)",
        tail,
    ):
        alias = match.group("alias")
        if alias == name:
            continue
        slice_text = match.group("slice") or ""
        alias_tail = tail[match.end() :]
        for write in re.finditer(
            rf"\b{re.escape(alias)}\s*\[\s*(?P<index>[^\]]+)\s*\]\s*=\s*(?:0|1|0[xX][0-9A-Fa-f]+)\b",
            alias_tail,
        ):
            if _alias_write_overlaps_nonce(write.group("index").strip(), slice_text, nonce_expression):
                return True
    return False


def _alias_write_overlaps_nonce(index: str, slice_text: str, nonce_expression: str) -> bool:
    constant = _integer_value(index)
    if constant is None:
        return True
    nonce_slice = re.search(r":\s*(?P<high>\d+)\s*\]", nonce_expression)
    nonce_high = int(nonce_slice.group("high")) if nonce_slice else None
    if not slice_text:
        return nonce_high is None or constant < nonce_high
    lower = 0
    parts = slice_text.split(":", 1)
    if parts and parts[0].strip():
        lower_value = _integer_value(parts[0].strip())
        if lower_value is None:
            return True
        lower = lower_value
    absolute_index = lower + constant
    return nonce_high is None or absolute_index < nonce_high


def _integer_findings(
    file_name: str,
    content: str,
    text: str,
    base_line: int,
    signature_text: str = "",
) -> list[dict[str, Any]]:
    code_text = _mask_go_non_code(text)
    values: dict[str, int] = {}
    source_types: dict[str, str] = {}
    source_ranges: dict[str, tuple[int, int]] = {}
    sequence_types: dict[str, str] = {}
    for match in _INTEGER_PARAMETER_RE.finditer(signature_text):
        for name in match.group("names").split(","):
            normalized_name = name.strip()
            if match.group("slice"):
                sequence_types[normalized_name] = match.group("type")
            else:
                source_types[normalized_name] = match.group("type")
    for match in _DECLARED_INTEGER_RE.finditer(code_text):
        source_types[match.group("name")] = match.group("type")
        value = _integer_value(match.group("value").strip())
        if value is not None:
            values[match.group("name")] = value
    for match in _ASSIGNED_INTEGER_RE.finditer(code_text):
        value = _integer_value(match.group("value").strip())
        if value is not None:
            values[match.group("name")] = value
    for match in _TYPED_INTEGER_ASSIGN_RE.finditer(code_text):
        source_types[match.group("name")] = match.group("type")
        value = _integer_value(match.group("value"))
        if value is not None:
            values[match.group("name")] = value
    for match in _PARSED_INTEGER_RE.finditer(code_text):
        integer_type = f"{'uint' if match.group('kind') == 'Uint' else 'int'}{match.group('bits')}"
        source_types[match.group("name")] = integer_type
        source_ranges[match.group("name")] = _integer_bounds(integer_type)
    for match in _ATOI_RE.finditer(code_text):
        source_types[match.group("name")] = "int"
        source_ranges[match.group("name")] = _integer_bounds("int")
    for match in _RANDOM_INTEGER_RE.finditer(code_text):
        integer_type = {"Int": "int", "Int31": "int32", "Int63": "int64"}[match.group("kind")]
        source_types[match.group("name")] = integer_type
        source_ranges[match.group("name")] = (0, _integer_bounds(integer_type)[1])
    for match in _RANGE_VALUE_RE.finditer(code_text):
        element_type = sequence_types.get(match.group("sequence"))
        if element_type:
            source_types[match.group("value")] = element_type

    for _ in range(4):
        changed = False
        for match in _INTEGER_EXPRESSION_ASSIGN_RE.finditer(code_text):
            name = match.group("name")
            inferred = _integer_expression_range(
                match.group("value"),
                values,
                source_ranges,
                source_types,
                sequence_types,
                code_text[: match.start()],
            )
            if inferred is not None and source_ranges.get(name) != inferred:
                source_ranges[name] = inferred
                changed = True
        if not changed:
            break

    findings: list[dict[str, Any]] = []
    for conversion in _integer_conversions(code_text):
        target = conversion.target
        raw_value = conversion.value.strip()
        value = values.get(raw_value)
        if value is None:
            value = _integer_value(raw_value)
        lower, upper = _integer_bounds(target)
        line = base_line + text.count("\n", 0, conversion.start)
        if _is_suppressed(content, line):
            continue
        source_type = source_types.get(raw_value, "constant")
        confidence = "high"
        if value is not None:
            if lower <= value <= upper:
                continue
            dfg = f"{raw_value}({source_type})={value} -> {target} 范围 [{lower}, {upper}]"
            title = "整数窄化转换确定超出目标范围"
        else:
            source_range = _integer_expression_range(
                raw_value,
                values,
                source_ranges,
                source_types,
                sequence_types,
                code_text[: conversion.start],
            )
            if source_range is None or (lower <= source_range[0] and source_range[1] <= upper):
                continue
            if (
                target == "byte"
                and -128 <= source_range[0]
                and source_range[1] <= 255
                and _has_explicit_signed_byte_compatibility_guard(
                    code_text[: conversion.start],
                    raw_value,
                )
            ):
                continue
            if target in {"int64", "uint64", "rune"}:
                continue
            confidence = "high" if _expression_has_arithmetic(raw_value) else "medium"
            dfg = f"{raw_value}({source_type}) 范围 {source_range} -> {target} 范围 [{lower}, {upper}]"
            title = "整数转换缺少完整目标值域检查"
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.integer-conversion-overflow",
                scenario="integer_overflow",
                title=title,
                cwes=["CWE-190"],
                severity="high",
                confidence=confidence,
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=dfg,
                remediation="转换前显式检查上下界，超界时返回错误；避免把宽整数直接转换为窄整数。",
            )
        )
    return findings


def _mask_go_non_code(text: str) -> str:
    """Replace comments and literals with spaces without changing offsets or lines."""
    result = list(text)
    index = 0
    state = "code"
    escaped = False
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if character == "/" and following == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if character == "/" and following == "*":
                result[index] = result[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if character in {'"', "'", "`"}:
                result[index] = " "
                state = {"\"": "string", "'": "rune", "`": "raw_string"}[character]
                escaped = False
        elif state == "line_comment":
            if character == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state == "block_comment":
            if character == "*" and following == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "code"
                continue
            if character != "\n":
                result[index] = " "
        elif state == "raw_string":
            if character == "`":
                result[index] = " "
                state = "code"
            elif character != "\n":
                result[index] = " "
        else:
            result[index] = " " if character != "\n" else "\n"
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif (state == "string" and character == '"') or (state == "rune" and character == "'"):
                state = "code"
        index += 1
    return "".join(result)


def _integer_conversions(text: str) -> list[_IntegerConversion]:
    target_re = re.compile(r"\b(?P<target>u?int(?:8|16|32|64)|byte|rune)\s*\(")
    result: list[_IntegerConversion] = []
    for match in target_re.finditer(text):
        opening = text.find("(", match.start())
        depth = 1
        quote = ""
        escaped = False
        index = opening + 1
        while index < len(text) and depth:
            character = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif character in {'"', "'", "`"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            index += 1
        if depth:
            continue
        value = text[opening + 1 : index - 1].strip()
        if value and not _has_top_level_comma(value):
            result.append(_IntegerConversion(match.group("target"), value, match.start()))
    return result


def _has_top_level_comma(value: str) -> bool:
    parentheses = brackets = braces = 0
    for character in value:
        parentheses += (character == "(") - (character == ")")
        brackets += (character == "[") - (character == "]")
        braces += (character == "{") - (character == "}")
        if character == "," and parentheses == brackets == braces == 0:
            return True
    return False


def _integer_expression_range(
    expression: str,
    constants: dict[str, int],
    ranges: dict[str, tuple[int, int]],
    source_types: dict[str, str],
    sequence_types: dict[str, str],
    prefix: str,
) -> tuple[int, int] | None:
    value = _strip_integer_parentheses(expression.strip())
    direct = constants.get(value, _integer_value(value))
    if direct is not None:
        return direct, direct
    if value.startswith(('+', '-')) and len(value) > 1:
        nested = _integer_expression_range(value[1:], constants, ranges, source_types, sequence_types, prefix)
        if nested is not None:
            return nested if value[0] == '+' else (-nested[1], -nested[0])

    for operators in (("+", "-"), ("<<", ">>"), ("*", "/", "%", "&")):
        split = _split_top_level_integer_operator(value, operators)
        if split is None:
            continue
        left_text, operator, right_text = split
        left = _integer_expression_range(left_text, constants, ranges, source_types, sequence_types, prefix)
        right = _integer_expression_range(right_text, constants, ranges, source_types, sequence_types, prefix)
        if left is None or right is None:
            return None
        calculated = _apply_integer_range_operator(left, operator, right)
        return _range_after_integer_guards(prefix, value, calculated) if calculated is not None else None

    length_match = re.fullmatch(r"(?:len|cap)\s*\([^)]*\)", value)
    if length_match:
        return 0, _integer_bounds("int")[1]

    atom_match = re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[^]]+\])*", value)
    if atom_match is None:
        return None
    initial = ranges.get(value)
    if initial is None and value in source_types:
        initial = _integer_bounds(source_types[value])
    if initial is None and "[" in value:
        sequence = value.split("[", 1)[0]
        if sequence in sequence_types:
            initial = _integer_bounds(sequence_types[sequence])
    return _range_after_integer_guards(prefix, value, initial)


def _strip_integer_parentheses(value: str) -> str:
    while value.startswith("(") and value.endswith(")"):
        depth = 0
        encloses = True
        for index, character in enumerate(value):
            depth += (character == "(") - (character == ")")
            if depth == 0 and index != len(value) - 1:
                encloses = False
                break
        if not encloses:
            break
        value = value[1:-1].strip()
    return value


def _split_top_level_integer_operator(value: str, operators: tuple[str, ...]) -> tuple[str, str, str] | None:
    parentheses = brackets = 0
    index = len(value) - 1
    while index >= 0:
        character = value[index]
        if character == ")":
            parentheses += 1
        elif character == "(":
            parentheses -= 1
        elif character == "]":
            brackets += 1
        elif character == "[":
            brackets -= 1
        if parentheses == brackets == 0:
            for operator in operators:
                start = index - len(operator) + 1
                if start < 0 or value[start : index + 1] != operator:
                    continue
                if operator in {"+", "-"} and (start == 0 or value[start - 1] in "+-*/<("):
                    continue
                left = value[:start].strip()
                right = value[index + 1 :].strip()
                if left and right:
                    return left, operator, right
        index -= 1
    return None


def _apply_integer_range_operator(
    left: tuple[int, int],
    operator: str,
    right: tuple[int, int],
) -> tuple[int, int] | None:
    if operator == "+":
        return left[0] + right[0], left[1] + right[1]
    if operator == "-":
        return left[0] - right[1], left[1] - right[0]
    if operator == "*":
        products = [a * b for a in left for b in right]
        return min(products), max(products)
    if operator == "/":
        if right[0] <= 0 <= right[1]:
            return None
        quotients = [_truncating_integer_division(a, b) for a in left for b in right]
        return min(quotients), max(quotients)
    if operator == "%" and right[0] == right[1] and right[0] != 0:
        maximum = abs(right[0]) - 1
        if left[0] >= 0:
            return 0, maximum
        if left[1] <= 0:
            return -maximum, 0
        return -maximum, maximum
    if operator == "&":
        if right[0] == right[1] and right[0] >= 0:
            return 0, right[0]
        if left[0] == left[1] and left[0] >= 0:
            return 0, left[0]
    if operator in {"<<", ">>"} and right[0] == right[1] and 0 <= right[0] <= 64:
        shifted = [a << right[0] if operator == "<<" else a >> right[0] for a in left]
        return min(shifted), max(shifted)
    return None


def _truncating_integer_division(left: int, right: int) -> int:
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) != (right < 0) else quotient


def _range_after_integer_guards(
    prefix: str,
    subject: str,
    initial: tuple[int, int] | None,
) -> tuple[int, int] | None:
    constraints: list[tuple[str, int]] = []
    for match in re.finditer(r"(?s)\bif\s+(?P<condition>[^\{]+)\{(?P<body>.*?)\}", prefix):
        condition = match.group("condition")
        body = match.group("body")
        if not re.search(r"\b(?:return|continue|panic\s*\()", body) or "&&" in condition:
            continue
        if _integer_condition_is_tautological_exit(condition, subject):
            return (1, 0)
        clauses = re.split(r"\|\|", condition)
        constraints.extend(
            constraint
            for clause in clauses
            for constraint in _integer_condition_constraints(clause, subject, truth=False)
        )

    for match in re.finditer(r"\bif\s+(?P<condition>[^\{\n]+)\{", prefix):
        opening = match.end() - 1
        condition = match.group("condition")
        if not _integer_block_remains_open(prefix, opening):
            continue
        clauses = [condition] if "||" in condition else re.split(r"&&", condition)
        constraints.extend(
            constraint
            for clause in clauses
            for constraint in _integer_condition_constraints(clause, subject, truth=True)
        )

    for match in re.finditer(
        r"(?s)\bif\s+(?P<condition>[^\{]+)\{.*?\}\s*else\s*\{",
        prefix,
    ):
        opening = match.end() - 1
        if not _integer_block_remains_open(prefix, opening):
            continue
        condition = match.group("condition")
        if "&&" in condition:
            continue
        clauses = re.split(r"\|\|", condition)
        constraints.extend(
            constraint
            for clause in clauses
            for constraint in _integer_condition_constraints(clause, subject, truth=False)
        )

    if not constraints:
        return initial
    lower, upper = initial or _integer_bounds("int")
    for operator, bound in constraints:
        if operator == ">=":
            lower = max(lower, bound)
        elif operator == ">":
            lower = max(lower, bound + 1)
        elif operator == "<=":
            upper = min(upper, bound)
        elif operator == "<":
            upper = min(upper, bound - 1)
    return lower, upper


def _integer_condition_constraints(condition: str, subject: str, *, truth: bool) -> list[tuple[str, int]]:
    subject_pattern = r"\s*".join(re.escape(part) for part in re.split(r"\s+", subject.strip()))
    wrapped_subject = rf"(?:{subject_pattern}|\(\s*{subject_pattern}\s*\))"
    number = r"[-+]?(?:0[xX][0-9A-Fa-f]+|\d+)|math\.(?:Max|Min)(?:Int|Uint)(?:8|16|32|64)?"
    condition = re.sub(
        rf"!\s*\(\s*{wrapped_subject}\s*(<=|>=|<|>)\s*({number})\s*\)",
        lambda match: f"{subject} " + {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}[match.group(1)] + f" {match.group(2)}",
        condition,
    )
    pattern = re.compile(
        rf"^\s*{wrapped_subject}\s*(?P<offset>[+-]\s*\d+)?\s*"
        rf"(?P<operator><=|>=|<|>)\s*(?P<bound>{number})\s*$"
    )
    constraints: list[tuple[str, int]] = []
    match = pattern.fullmatch(condition)
    if match is not None:
        bound = _integer_value(match.group("bound"))
        if bound is not None:
            offset = match.group("offset") or ""
            if offset:
                amount = int(re.sub(r"\s+", "", offset))
                bound -= amount
            operator = match.group("operator")
            if not truth:
                operator = {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}[operator]
            constraints.append((operator, bound))
    reverse_pattern = re.compile(
        rf"^\s*(?P<bound>{number})\s*(?P<operator><=|>=|<|>)\s*{wrapped_subject}\s*$"
    )
    match = reverse_pattern.fullmatch(condition)
    if match is not None:
        bound = _integer_value(match.group("bound"))
        if bound is not None:
            operator = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[match.group("operator")]
            if not truth:
                operator = {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}[operator]
            constraints.append((operator, bound))
    equality_values = [
        _integer_value(value)
        for value in re.findall(rf"{wrapped_subject}\s*==\s*({number})", condition)
    ]
    equality_values = [value for value in equality_values if value is not None]
    if truth and equality_values and "||" in condition:
        constraints.extend(((">=", min(equality_values)), ("<=", max(equality_values))))
    if truth:
        constraints.extend(_inverse_arithmetic_constraints(condition, subject, number))
    if truth:
        inverse_division = re.search(
            rf"(?P<numerator>\d+)\s*/\s*{subject_pattern}\s*<\s*(?P<bound>\d+)",
            condition,
        )
        if inverse_division:
            numerator = int(inverse_division.group("numerator"))
            bound = int(inverse_division.group("bound"))
            if numerator > 0 and bound > 0:
                constraints.append((">", numerator // bound))
    return constraints


def _has_explicit_signed_byte_compatibility_guard(prefix: str, subject: str) -> bool:
    for match in re.finditer(r"(?s)\bif\s+(?P<condition>[^\{]+)\{(?P<body>.*?)\}", prefix):
        if not re.search(r"\b(?:return|continue|panic\s*\()", match.group("body")):
            continue
        clauses = re.split(r"\|\|", match.group("condition"))
        constraints = [
            constraint
            for clause in clauses
            for constraint in _integer_condition_constraints(clause, subject, truth=False)
        ]
        if (">=", -128) in constraints and ("<=", 255) in constraints:
            return True
    return False


def _inverse_arithmetic_constraints(condition: str, subject: str, number: str) -> list[tuple[str, int]]:
    escaped = re.escape(subject)
    result: list[tuple[str, int]] = []
    patterns = (
        (rf"\(?\s*{escaped}\s*<<\s*(?P<amount>\d+)\s*\)?\s*<\s*(?P<bound>{number})", "left_shift"),
        (rf"(?P<bound>{number})\s*>\s*{escaped}\s*<<\s*(?P<amount>\d+)", "left_shift"),
        (rf"{escaped}\s*>>\s*(?P<amount>\d+)\s*<\s*(?P<bound>{number})", "right_shift"),
        (rf"{escaped}\s*\*\s*(?P<amount>\d+)\s*<\s*(?P<bound>{number})", "multiply"),
        (rf"{escaped}\s*/\s*(?P<amount>\d+)\s*<\s*(?P<bound>{number})", "divide"),
        (rf"\(?\s*{escaped}\s*\+\s*(?P<amount>\d+)\s*\)?\s*<\s*(?P<bound>{number})", "add"),
        (rf"\(?\s*(?P<amount>\d+)\s*\+\s*{escaped}\s*\)?\s*<\s*(?P<bound>{number})", "add"),
    )
    for pattern, operation in patterns:
        match = re.search(pattern, condition)
        if match is None:
            continue
        amount = int(match.group("amount"))
        bound = _integer_value(match.group("bound"))
        if bound is None or amount <= 0 or bound <= 0:
            continue
        if operation == "left_shift":
            result.append(("<", (bound + (1 << amount) - 1) // (1 << amount)))
        elif operation == "right_shift":
            result.append(("<", bound << amount))
        elif operation == "multiply":
            result.append(("<", (bound + amount - 1) // amount))
        elif operation == "divide":
            result.append(("<", bound * amount))
        elif operation == "add":
            result.append(("<", bound - amount))
    return result


def _integer_block_remains_open(prefix: str, opening: int) -> bool:
    depth = 0
    for character in prefix[opening:]:
        depth += (character == "{") - (character == "}")
        if depth == 0:
            return False
    return depth > 0


def _integer_condition_is_tautological_exit(condition: str, subject: str) -> bool:
    values = re.findall(rf"{re.escape(subject)}\s*!=\s*([-+]?\d+)", condition)
    return "||" in condition and len(set(values)) >= 2


def _expression_has_arithmetic(value: str) -> bool:
    return any(
        _split_top_level_integer_operator(value, operators) is not None
        for operators in (("+", "-"), ("<<", ">>"), ("*", "/", "%", "&"))
    )


def _bounds_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    sequences: dict[str, _SequenceBounds] = {}
    constants: dict[str, int] = {}
    ranges: dict[str, tuple[int, int]] = {}
    findings: list[dict[str, Any]] = []
    lines = text.splitlines()
    for offset, source_line in enumerate(lines):
        line = base_line + offset
        declaration_line = False
        for match in _MAKE_SLICE_RE.finditer(source_line):
            length = int(match.group("length"))
            capacity = int(match.group("capacity") or length)
            sequences[match.group("name")] = _SequenceBounds(length=length, capacity=capacity)
        for match in _ARRAY_RE.finditer(source_line):
            declaration_line = True
            length = int(match.group("length"))
            sequences[match.group("name")] = _SequenceBounds(length=length, capacity=length)
        for match in _NIL_SLICE_RE.finditer(source_line):
            declaration_line = True
            sequences[match.group("name")] = _SequenceBounds(length=0, capacity=0)
        assigned = _ASSIGNED_INTEGER_RE.match(source_line)
        if assigned and (value := _integer_value(assigned.group("value"))) is not None:
            constants[assigned.group("name")] = value
        for match in _SLICE_ALIAS_RE.finditer(source_line):
            source_bounds = sequences.get(match.group("source"))
            if source_bounds is None:
                continue
            low = _resolved_integer(match.group("low") or "0", constants)
            high = _resolved_integer(match.group("high"), constants)
            maximum = _resolved_integer(match.group("maximum"), constants)
            if low is None or high is None:
                continue
            capacity = maximum - low if maximum is not None else source_bounds.capacity - low
            sequences[match.group("name")] = _SequenceBounds(
                length=max(0, high - low),
                capacity=max(0, capacity),
            )
        for match in _FOR_RANGE_RE.finditer(source_line):
            start = int(match.group("start"))
            end = _resolved_integer(match.group("end"), constants)
            if end is None:
                length_match = re.fullmatch(
                    r"len\s*\(\s*(?P<name>[A-Za-z_]\w*)\s*\)",
                    match.group("end"),
                )
                if length_match and length_match.group("name") in sequences:
                    end = sequences[length_match.group("name")].length
            if end is None:
                for sequence_name, sequence_bounds in sequences.items():
                    if match.group("end") == sequence_name:
                        end = sequence_bounds.length
                        break
            if end is None:
                continue
            operator = match.group("operator")
            if operator.startswith("<"):
                ranges[match.group("name")] = (start, end - (1 if operator == "<" else 0))
            elif operator.startswith(">"):
                ranges[match.group("name")] = (end + (1 if operator == ">" else 0), start)
        for match in _RANGE_INDEX_RE.finditer(source_line):
            sequence_bounds = sequences.get(match.group("sequence"))
            if sequence_bounds is not None and sequence_bounds.length > 0:
                ranges[match.group("name")] = (0, sequence_bounds.length - 1)

        for name in list(sequences):
            escaped = re.escape(name)
            if re.search(rf"\b{escaped}\s*=\s*append\s*\(", source_line):
                sequences.pop(name, None)
                continue
            if re.search(rf"(?:\(|,)\s*&{escaped}\b", source_line):
                sequences.pop(name, None)

        if _is_suppressed(content, line) or declaration_line:
            continue
        for name, bounds in sequences.items():
            index_re = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<index>[^\]:]+)\s*\]")
            for match in index_re.finditer(source_line):
                index_range = _resolved_integer_range(match.group("index"), constants, ranges)
                if index_range is None or (0 <= index_range[0] and index_range[1] < bounds.length):
                    continue
                if _has_nearby_length_guard(lines, offset, name, index_range[1]):
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.static-index-out-of-bounds",
                        scenario="memory_safety",
                        title="静态索引确定超出序列边界",
                        cwes=["CWE-118"],
                        severity="high",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"{name} 长度={bounds.length} -> index 范围={index_range}",
                        remediation="访问前验证 0 <= index < len(slice)，并确保校验覆盖同一执行分支。",
                    )
                )
            slice_re = re.compile(rf"\b{re.escape(name)}\s*\[\s*:\s*(?P<high>[^\]:]+)\s*\]")
            for match in slice_re.finditer(source_line):
                high = _resolved_integer(match.group("high"), constants)
                if high is None or 0 <= high <= bounds.capacity:
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.static-slice-out-of-bounds",
                        scenario="memory_safety",
                        title="静态切片上界确定超过容量",
                        cwes=["CWE-118"],
                        severity="high",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"{name} capacity={bounds.capacity} -> high={high}",
                        remediation="切片前验证上界不超过 cap(slice)，并限制来自外部的边界值。",
                    )
                )
            full_slice_re = re.compile(
                rf"\b{re.escape(name)}\s*\[[^\]]*:[^\]]*:\s*(?P<maximum>[^\]]+)\]"
            )
            for match in full_slice_re.finditer(source_line):
                maximum = _resolved_integer(match.group("maximum"), constants)
                if maximum is None or 0 <= maximum <= bounds.capacity:
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.static-slice-out-of-bounds",
                        scenario="memory_safety",
                        title="静态三索引切片上界确定超过容量",
                        cwes=["CWE-118"],
                        severity="high",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"{name} capacity={bounds.capacity} -> max={maximum}",
                        remediation="三索引切片的 max 必须不超过原切片容量，并验证所有外部边界值。",
                    )
                )
    return findings


def _finding(
    *,
    rule_id: str,
    scenario: str,
    title: str,
    cwes: list[str],
    severity: str,
    confidence: str,
    file_name: str,
    line: int,
    snippet: str,
    dfg: str,
    remediation: str,
) -> dict[str, Any]:
    source = {"kind": "source", "file": file_name, "line": line, "label": title, "snippet": snippet}
    sink = {"kind": "sink", "file": file_name, "line": line, "label": title, "snippet": snippet}
    return {
        "id": "",
        "engine": "go-semantic-analysis",
        "rule_id": rule_id,
        "scenario": scenario,
        "title": title,
        "record_id": "",
        "component": "Go standard library",
        "severity": severity,
        "cwes": cwes,
        "confidence": confidence,
        "source": source,
        "sink": sink,
        "path": [source, sink],
        "ast": {"parser": "tree-sitter", "language": "go"},
        "cfg": "函数内确定路径；需要命中的释放、范围或边界保护未出现。",
        "dfg": dfg,
        "evidence": snippet,
        "remediation": remediation,
        "fixed_snippet": "",
    }


def _parser() -> Any | None:
    if Parser is None or Language is None or tree_sitter_go is None:
        return None
    try:
        return Parser(Language(tree_sitter_go.language()))
    except Exception:  # noqa: BLE001
        return None


def _walk(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_named:
            yield node
        stack.extend(reversed(node.named_children))


def _integer_value(value: str) -> int | None:
    normalized = value.strip().replace("_", "")
    named = {
        "math.MaxUint8": 2**8 - 1,
        "math.MaxUint16": 2**16 - 1,
        "math.MaxUint32": 2**32 - 1,
        "math.MaxUint64": 2**64 - 1,
        "math.MaxUint": 2**64 - 1,
        "math.MaxInt8": 2**7 - 1,
        "math.MaxInt16": 2**15 - 1,
        "math.MaxInt32": 2**31 - 1,
        "math.MaxInt64": 2**63 - 1,
        "math.MaxInt": 2**63 - 1,
        "math.MinInt8": -(2**7),
        "math.MinInt16": -(2**15),
        "math.MinInt32": -(2**31),
        "math.MinInt64": -(2**63),
        "math.MinInt": -(2**63),
    }
    if normalized in named:
        return named[normalized]
    try:
        return int(normalized, 0)
    except ValueError:
        return None


def _integer_bounds(integer_type: str) -> tuple[int, int]:
    normalized = {"byte": "uint8", "rune": "int32", "uint": "uint64", "int": "int64"}.get(
        integer_type,
        integer_type,
    )
    unsigned = normalized.startswith("uint")
    bits = int(normalized.removeprefix("uint").removeprefix("int"))
    return (0, 2**bits - 1) if unsigned else (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1)


def _resolved_integer(value: str | None, constants: dict[str, int]) -> int | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip()
    return constants.get(normalized, _integer_value(normalized))


def _resolved_integer_range(
    value: str,
    constants: dict[str, int],
    ranges: dict[str, tuple[int, int]],
) -> tuple[int, int] | None:
    normalized = value.strip()
    direct = _resolved_integer(normalized, constants)
    if direct is not None:
        return direct, direct
    parts = re.fullmatch(
        r"(?P<base>[A-Za-z_]\w*)(?P<tail>(?:\s*[+-]\s*(?:[A-Za-z_]\w*|-?\d+))+)?",
        normalized,
    )
    if parts is None:
        return None
    base = ranges.get(parts.group("base"))
    if base is None and parts.group("base") in constants:
        constant = constants[parts.group("base")]
        base = (constant, constant)
    if base is None:
        return None
    lower, upper = base
    for operator, operand_text in re.findall(r"([+-])\s*([A-Za-z_]\w*|-?\d+)", parts.group("tail") or ""):
        operand = _resolved_integer(operand_text, constants)
        if operand is None:
            return None
        if operator == "+":
            lower, upper = lower + operand, upper + operand
        else:
            lower, upper = lower - operand, upper - operand
    return lower, upper


def _has_nearby_length_guard(lines: list[str], offset: int, name: str, index: int) -> bool:
    for guard_offset in range(offset - 1, -1, -1):
        guard = lines[guard_offset]
        length = rf"len\s*\(\s*{re.escape(name)}\s*\)"
        match = re.search(rf"{length}\s*>\s*(?P<bound>\d+)", guard)
        if match is None:
            match = re.search(rf"{length}\s*>=\s*(?P<bound>\d+)", guard)
            guaranteed = int(match.group("bound")) - 1 if match else -1
        else:
            guaranteed = int(match.group("bound"))
        if match is None:
            match = re.search(rf"(?P<bound>\d+)\s*<\s*{length}", guard)
            guaranteed = int(match.group("bound")) if match else -1
        if match is None:
            match = re.search(rf"(?P<bound>\d+)\s*<=\s*{length}", guard)
            guaranteed = int(match.group("bound")) - 1 if match else -1
        if match is None or guaranteed < index or "{" not in guard:
            continue
        block = "\n".join(lines[guard_offset: offset + 1])
        if "else" not in block and block.count("{") > block.count("}"):
            return True
    return False


def _is_suppressed(content: str, line: int) -> bool:
    lines = content.splitlines()
    context = "\n".join(lines[max(0, line - 3) : min(len(lines), line + 1)])
    return bool(_NOSEC_RE.search(context))


def _line(content: str, line: int) -> str:
    lines = content.splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""
