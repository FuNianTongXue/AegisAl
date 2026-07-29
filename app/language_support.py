from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

try:
    from tree_sitter import Language, Node, Parser
except Exception:  # pragma: no cover - optional runtime dependency
    Language = None
    Node = Any
    Parser = None


@dataclass(frozen=True)
class LanguageProfile:
    id: str
    extensions: frozenset[str]
    module: str
    functions: frozenset[str]
    types: frozenset[str]
    imports: frozenset[str]
    controls: frozenset[str]
    assignments: frozenset[str]


_COMMON_CONTROLS = frozenset(
    {
        "if_statement",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
        "switch_expression",
        "match_expression",
        "try_statement",
        "catch_clause",
        "with_statement",
        "conditional_expression",
        "ternary_expression",
    }
)

_COMMON_ASSIGNMENTS = frozenset(
    {
        "assignment",
        "assignment_expression",
        "assignment_statement",
        "augmented_assignment",
        "short_var_declaration",
        "let_declaration",
        "init_declarator",
        "variable_declaration",
        "variable_declaration_statement",
    }
)


LANGUAGE_PROFILES: tuple[LanguageProfile, ...] = (
    LanguageProfile(
        "java",
        frozenset({".java"}),
        "tree_sitter_java",
        frozenset({"method_declaration", "constructor_declaration", "lambda_expression"}),
        frozenset({"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"}),
        frozenset({"import_declaration", "package_declaration"}),
        _COMMON_CONTROLS | {"enhanced_for_statement", "synchronized_statement"},
        _COMMON_ASSIGNMENTS | {"local_variable_declaration"},
    ),
    LanguageProfile(
        "python",
        frozenset({".py"}),
        "tree_sitter_python",
        frozenset({"function_definition", "lambda"}),
        frozenset({"class_definition"}),
        frozenset({"import_statement", "import_from_statement"}),
        _COMMON_CONTROLS | {"elif_clause", "except_clause"},
        _COMMON_ASSIGNMENTS | {"named_expression"},
    ),
    LanguageProfile(
        "go",
        frozenset({".go"}),
        "tree_sitter_go",
        frozenset({"function_declaration", "method_declaration", "func_literal"}),
        frozenset({"type_declaration", "struct_type", "interface_type"}),
        frozenset({"import_declaration", "import_spec", "package_clause"}),
        _COMMON_CONTROLS | {"expression_switch_statement", "type_switch_statement", "select_statement"},
        _COMMON_ASSIGNMENTS | {"var_declaration", "const_declaration"},
    ),
    LanguageProfile(
        "c",
        frozenset({".c", ".h"}),
        "tree_sitter_c",
        frozenset({"function_definition"}),
        frozenset({"struct_specifier", "union_specifier", "enum_specifier"}),
        frozenset({"preproc_include", "preproc_def"}),
        _COMMON_CONTROLS | {"case_statement"},
        _COMMON_ASSIGNMENTS | {"declaration"},
    ),
    LanguageProfile(
        "cpp",
        frozenset({".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}),
        "tree_sitter_cpp",
        frozenset({"function_definition", "lambda_expression"}),
        frozenset({"class_specifier", "struct_specifier", "union_specifier", "enum_specifier", "namespace_definition"}),
        frozenset({"preproc_include", "preproc_def", "using_declaration"}),
        _COMMON_CONTROLS | {"case_statement", "try_block"},
        _COMMON_ASSIGNMENTS | {"declaration", "structured_binding_declarator"},
    ),
    LanguageProfile(
        "csharp",
        frozenset({".cs"}),
        "tree_sitter_c_sharp",
        frozenset(
            {
                "method_declaration",
                "constructor_declaration",
                "local_function_statement",
                "lambda_expression",
                "anonymous_method_expression",
            }
        ),
        frozenset(
            {
                "class_declaration",
                "struct_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
            }
        ),
        frozenset(
            {
                "using_directive",
                "namespace_declaration",
                "file_scoped_namespace_declaration",
            }
        ),
        _COMMON_CONTROLS
        | {
            "foreach_statement",
            "lock_statement",
            "using_statement",
            "switch_section",
        },
        _COMMON_ASSIGNMENTS | {"local_declaration_statement", "variable_declarator"},
    ),
    LanguageProfile(
        "rust",
        frozenset({".rs"}),
        "tree_sitter_rust",
        frozenset({"function_item", "closure_expression"}),
        frozenset({"struct_item", "enum_item", "trait_item", "impl_item", "type_item"}),
        frozenset({"use_declaration", "extern_crate_declaration", "mod_item"}),
        _COMMON_CONTROLS | {"if_expression", "for_expression", "while_expression", "loop_expression"},
        _COMMON_ASSIGNMENTS | {"let_declaration"},
    ),
    LanguageProfile(
        "solidity",
        frozenset({".sol"}),
        "tree_sitter_solidity",
        frozenset(
            {
                "function_definition",
                "constructor_definition",
                "modifier_definition",
                "fallback_receive_definition",
            }
        ),
        frozenset({"contract_declaration", "interface_declaration", "library_declaration", "struct_declaration", "enum_declaration"}),
        frozenset({"import_directive", "pragma_directive", "using_directive"}),
        _COMMON_CONTROLS | {"emit_statement", "revert_statement"},
        _COMMON_ASSIGNMENTS | {"state_variable_declaration"},
    ),
)

_PROFILE_BY_ID = {profile.id: profile for profile in LANGUAGE_PROFILES}
_PROFILE_BY_EXTENSION = {
    extension: profile
    for profile in LANGUAGE_PROFILES
    for extension in profile.extensions
}

_AST_PREVIEW_LIMIT = 160
_GRAPH_PREVIEW_LIMIT = 120


def language_for_file(file_name: str) -> str:
    suffix = Path(file_name).suffix.lower()
    profile = _PROFILE_BY_EXTENSION.get(suffix)
    if profile is not None:
        return profile.id
    if suffix in {".kt", ".kts"}:
        return "kotlin"
    if suffix == ".scala":
        return "scala"
    if suffix == ".groovy":
        return "groovy"
    if suffix in {".js", ".jsx"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    return suffix.lstrip(".") or "unknown"


def supported_flow_languages() -> list[str]:
    return [profile.id for profile in LANGUAGE_PROFILES]


def analyze_source_structure(
    file_name: str,
    content: str,
    *,
    language_hint: str | None = None,
    preprocessor_definitions: dict[str, str] | Iterable[str] | None = None,
) -> dict[str, Any]:
    language = language_hint if language_hint in _PROFILE_BY_ID else language_for_file(file_name)
    profile = _PROFILE_BY_ID.get(language)
    if profile is None:
        return _empty_analysis(file_name, language, "没有对应的 Tree-sitter 语法包。")
    parser = _parser_for(profile.id)
    if parser is None:
        return _empty_analysis(file_name, language, "Tree-sitter 语法包不可用。")

    source = content.encode("utf-8", errors="replace")
    compile_definitions = _normalized_preprocessor_definitions(preprocessor_definitions)
    tree, parser_mode, raw_parse_error = _parse_source(
        profile.id,
        source,
        parser,
        preprocessor_definitions=compile_definitions,
    )
    nodes = list(_walk(tree.root_node))
    imports = [_compact_text(node, source) for node in nodes if node.type in profile.imports]
    type_nodes = [node for node in nodes if node.type in profile.types]
    function_nodes = [node for node in nodes if node.type in profile.functions]
    controls = [node for node in nodes if node.type in profile.controls]
    assignments = [node for node in nodes if node.type in profile.assignments]
    cfg_nodes = [node for node in nodes if _is_cfg_node(node, profile)]
    ast_graph = _ast_graph(nodes, source)
    cfg_graph = _cfg_graph(cfg_nodes, function_nodes, controls, source)
    dfg_graph = _dfg_graph(assignments, profile, source)

    return {
        "file": file_name,
        "language": language,
        "parser": "tree-sitter",
        "parser_mode": parser_mode,
        "parse_error": bool(tree.root_node.has_error),
        "raw_parse_error": raw_parse_error,
        "recovered_parse_error": raw_parse_error and not tree.root_node.has_error,
        "parser_error_nodes": _tree_error_metric(tree)[0],
        "preprocessor_definition_count": len(compile_definitions),
        "ast_node_count": len(nodes),
        "imports": list(dict.fromkeys(item for item in imports if item))[:30],
        "types": list(dict.fromkeys(_declaration_name(node, source) for node in type_nodes if _declaration_name(node, source)))[:30],
        "functions": list(dict.fromkeys(_declaration_name(node, source) for node in function_nodes if _declaration_name(node, source)))[:60],
        "control_count": len(controls),
        "assignment_count": len(assignments),
        "cfg_node_count": cfg_graph["node_count"],
        "cfg_edge_count": cfg_graph["edge_count"],
        "dfg_edge_count": dfg_graph["edge_count"],
        "ast_graph": ast_graph,
        "cfg_graph": cfg_graph,
        "dfg_graph": dfg_graph,
    }


def control_flow_steps(
    file_name: str,
    content: str,
    source_line: int,
    sink_line: int,
    *,
    language_hint: str | None = None,
) -> list[dict[str, Any]]:
    language = language_hint if language_hint in _PROFILE_BY_ID else language_for_file(file_name)
    profile = _PROFILE_BY_ID.get(language)
    parser = _parser_for(profile.id) if profile else None
    if profile is None or parser is None or source_line <= 0 or sink_line <= 0:
        return []
    source = content.encode("utf-8", errors="replace")
    tree, _, _ = _parse_source(profile.id, source, parser)
    lower, upper = sorted((source_line, sink_line))
    candidates: list[Node] = []
    for node in _walk(tree.root_node):
        if node.type not in profile.controls:
            continue
        start = node.start_point.row + 1
        end = node.end_point.row + 1
        if start <= upper <= end and end >= lower:
            candidates.append(node)
    candidates.sort(key=lambda node: (node.start_point.row, -(node.end_point.row - node.start_point.row)))
    return [
        {
            "kind": "cfg_condition",
            "file": file_name,
            "line": node.start_point.row + 1,
            "label": f"{profile.id} {node.type} 控制条件",
            "snippet": _compact_text(node, source, limit=240),
        }
        for node in candidates[:8]
    ]


@lru_cache(maxsize=None)
def _parser_for(language_id: str) -> Any | None:
    if Parser is None or Language is None:
        return None
    profile = _PROFILE_BY_ID.get(language_id)
    module_name = "tree_sitter_cuda" if language_id == "cuda" else profile.module if profile else ""
    if not module_name:
        return None
    try:
        module = __import__(module_name)
        # tree-sitter-solidity 1.2.x still exposes a pointer integer; py-tree-sitter
        # 0.25 supports it but emits a compatibility deprecation warning.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="int argument support is deprecated", category=DeprecationWarning)
            return Parser(Language(module.language()))
    except Exception:  # noqa: BLE001 - missing optional grammar must degrade cleanly
        return None


def _empty_analysis(file_name: str, language: str, error: str) -> dict[str, Any]:
    return {
        "file": file_name,
        "language": language,
        "parser": "unavailable",
        "parser_mode": "unavailable",
        "parse_error": True,
        "raw_parse_error": True,
        "recovered_parse_error": False,
        "parser_error_nodes": 0,
        "error": error,
        "ast_node_count": 0,
        "imports": [],
        "types": [],
        "functions": [],
        "control_count": 0,
        "assignment_count": 0,
        "cfg_node_count": 0,
        "cfg_edge_count": 0,
        "dfg_edge_count": 0,
        "ast_graph": {"node_count": 0, "edge_count": 0, "nodes": [], "edges": [], "truncated": False},
        "cfg_graph": {"node_count": 0, "edge_count": 0, "nodes": [], "edges": [], "truncated": False},
        "dfg_graph": {"node_count": 0, "edge_count": 0, "nodes": [], "edges": [], "truncated": False},
    }


def _walk(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_named:
            yield node
        stack.extend(reversed(node.named_children))


def _compact_text(node: Node, source: bytes, *, limit: int = 320) -> str:
    text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    return " ".join(text.split())[:limit]


def _normalized_parser_source(language: str, source: bytes) -> bytes:
    lines = source.splitlines(keepends=True)
    if language in {"c", "cpp"}:
        replacements = {
            b"STATIC": b"static",
            b"CONST": b"const",
            b"VOLATILE": b"volatile",
            b"INLINE": b"inline",
            b"GLOBAL_REMOVE_IF_UNREFERENCED": b"                             ",
            b"PACKED": b"      ",
            b"LZFSE_INLINE": b"inline      ",
            b"ZEXPORT": b"       ",
            b"ZEXPORTVA": b"         ",
            b"ZLIB_INTERNAL": b"             ",
            b"_TFP_GCC_NO_INLINE_": b"                   ",
            b"FAR": b"   ",
            b"local": b"     ",
            b"z_const": b"const  ",
            b"yyconst": b"const  ",
            b"_U_": b"   ",
            b"EFIAPI": b"      ",
            b"OPTIONAL": b"        ",
            b"IN": b"  ",
            b"OUT": b"   ",
        }
        normalized: list[bytes] = []
        for line in lines:
            if line.lstrip().startswith(b"#"):
                if language == "cpp":
                    line = _replace_cpp_preprocessor_not(line)
                normalized.append(line)
                continue
            for token, replacement in replacements.items():
                line = _replace_ascii_word(line, token, replacement)
            normalized.append(line)
        result = b"".join(normalized)
        result = _mask_zlib_of_prototypes(result)
        result = _mask_kr_function_declarations(result)
        result = _mask_uefi_debug_code_blocks(result)
        result = _mask_known_declaration_macro_lines(result)
        if language == "cpp":
            result = _mask_cpp_using_declaration_lists(result)
            result = _replace_ascii_word(result, b"TIXML_EXPLICIT", b"explicit      ")
        return _mask_msvc_asm_blocks(result)
    if language == "csharp" and any(b"var required" in line for line in lines):
        return _replace_ascii_word(source, b"required", b"requireD")
    return source


def _parse_source(
    language: str,
    source: bytes,
    parser: Any,
    *,
    preprocessor_definitions: dict[str, str] | None = None,
) -> tuple[Any, str, bool]:
    normalized = _normalized_parser_source(language, source)
    primary = parser.parse(normalized)
    raw_parse_error = bool(primary.root_node.has_error)
    if not raw_parse_error or language not in {"c", "cpp"}:
        return primary, "native", raw_parse_error

    candidates: list[tuple[str, Any, bytes]] = []
    definitions = preprocessor_definitions or {}

    def add_views(prefix: str, candidate_parser: Any, candidate_source: bytes) -> None:
        extension_source = _compiler_extension_compatibility_source(language, candidate_source)
        candidates.append((f"{prefix}compiler-extensions", candidate_parser, extension_source))
        if definitions:
            defined_source = _conditional_compilation_view_for_definitions(candidate_source, definitions)
            candidates.append((f"{prefix}preprocessor-defs", candidate_parser, defined_source))
            candidates.append(
                (
                    f"{prefix}preprocessor-defs+macro",
                    candidate_parser,
                    _macro_compatibility_source(language, defined_source),
                )
            )
            candidates.append(
                (
                    f"{prefix}preprocessor-defs+macro-functions",
                    candidate_parser,
                    _macro_compatibility_source(language, defined_source, mask_function_calls=True),
                )
            )
        macro_source = _macro_compatibility_source(language, candidate_source)
        candidates.append((f"{prefix}macro", candidate_parser, macro_source))
        candidates.append(
            (
                f"{prefix}macro-functions",
                candidate_parser,
                _macro_compatibility_source(language, candidate_source, mask_function_calls=True),
            )
        )
        for prefer_if_branch, label in ((False, "else"), (True, "if")):
            branch_source = _conditional_compilation_view(candidate_source, prefer_if_branch=prefer_if_branch)
            candidates.append((f"{prefix}preprocessor-{label}", candidate_parser, branch_source))
            candidates.append(
                (
                    f"{prefix}preprocessor-{label}+macro",
                    candidate_parser,
                    _macro_compatibility_source(language, branch_source),
                )
            )
            candidates.append(
                (
                    f"{prefix}preprocessor-{label}+macro-functions",
                    candidate_parser,
                    _macro_compatibility_source(language, branch_source, mask_function_calls=True),
                )
            )

    if language == "cpp" and _looks_like_cuda_source(source):
        cuda_parser = _parser_for("cuda")
        if cuda_parser is not None:
            candidates.append(("cuda-fallback", cuda_parser, normalized))
            add_views("cuda-fallback+", cuda_parser, normalized)
    add_views("", parser, normalized)
    if language == "c":
        cpp_parser = _parser_for("cpp")
        if cpp_parser is not None:
            cpp_source = _normalized_parser_source("cpp", source)
            candidates.insert(1, ("cpp-fallback", cpp_parser, cpp_source))
            add_views("cpp-fallback+", cpp_parser, cpp_source)

    best_tree = primary
    best_mode = "native"
    best_metric = _tree_error_metric(primary)
    for mode, candidate_parser, candidate_source in candidates:
        if len(candidate_source) != len(source):
            continue
        candidate_tree = candidate_parser.parse(candidate_source)
        metric = _tree_error_metric(candidate_tree)
        if metric < best_metric:
            best_tree = candidate_tree
            best_mode = mode
            best_metric = metric
        if metric[0] == 0:
            break
    return best_tree, best_mode, raw_parse_error


def _looks_like_cuda_source(source: bytes) -> bool:
    return any(
        marker in source
        for marker in (b"__global__", b"__device__", b"__host__", b"threadIdx.", b"blockIdx.", b"<<<")
    )


def _normalized_preprocessor_definitions(values: dict[str, str] | Iterable[str] | None) -> dict[str, str]:
    if not values:
        return {}
    result: dict[str, str] = {}
    if isinstance(values, dict):
        candidates = [f"{key}={value}" if value != "" else str(key) for key, value in values.items()]
    else:
        candidates = [str(value) for value in values]
    for candidate in candidates:
        name, separator, value = candidate.strip().partition("=")
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        result[name] = value.strip() if separator else ""
    return result


def _tree_error_metric(tree: Any) -> tuple[int, int]:
    if not tree.root_node.has_error:
        return 0, 0
    count = 0
    covered_bytes = 0
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            count += 1
            covered_bytes += max(1, node.end_byte - node.start_byte)
        stack.extend(node.children)
    return count, covered_bytes


def _macro_compatibility_source(
    language: str,
    source: bytes,
    *,
    mask_function_calls: bool = False,
) -> bytes:
    result = bytearray(source)
    standalone = re.compile(
        rb"^\s*(?P<name>[A-Z][A-Z0-9_]{2,})\s*(?://.*)?(?:\r?\n)?$"
    )
    macro_call = re.compile(
        rb"^\s*(?P<name>[A-Z][A-Z0-9_]{2,})\s*\([^\n]*\)\s*;?\s*(?://.*)?(?:\r?\n)?$"
    )
    class_annotation = re.compile(
        rb"\b(?:class|struct)\s+(?P<name>[A-Z][A-Z0-9_]{2,})\s+(?=[A-Za-z_])"
    )
    declaration_annotation = re.compile(
        rb"\b(?:[A-Z][A-Z0-9_]*(?:EXPORT|INLINE|NOINLINE|API|CALL|CALLBACK|DECL|ATTR|ATTRIBUTE|"
        rb"NODISCARD|NORETURN|NOEXCEPT|PUBLIC_INTERFACE|UNUSED)\w*|"
        rb"ALIGNED|PUBLIC|LOCAL|__cdecl|__stdcall|__fastcall)\b"
    )
    lowercase_declaration_annotation = re.compile(
        rb"(?m)^\s*(?:(?:static|extern|const|inline)\s+)+"
        rb"(?P<name>[a-z_]\w*(?:_cold|_unused|_always_inline|_noinline|_noreturn|_deprecated))\s+"
        rb"(?=(?:void|char|short|int|long|float|double|signed|unsigned|struct|enum)\b)"
    )
    offset = 0
    for line in source.splitlines(keepends=True):
        standalone_match = standalone.match(line)
        if standalone_match is not None:
            name = standalone_match.group("name")
            start = offset + standalone_match.start("name")
            end = offset + standalone_match.end("name")
            if language == "cpp" and (
                name.endswith((b"_NAMESPACE_BEGIN", b"_NS_BEGIN")) or name.endswith(b"_NS")
            ):
                _replace_parser_span(result, start, end, b"namespace{" if end - start >= 10 else b"{")
            elif language == "cpp" and name.endswith((b"_NAMESPACE_END", b"_NS_END")):
                _replace_parser_span(result, start, end, b"}")
            else:
                _replace_parser_span(result, start, end)
            offset += len(line)
            continue

        macro_call_match = macro_call.match(line)
        if macro_call_match is not None:
            _replace_parser_span(
                result,
                offset + macro_call_match.start("name"),
                offset + len(line.rstrip(b"\r\n")),
                b";",
            )
        if language == "cpp":
            for match in class_annotation.finditer(line):
                _replace_parser_span(
                    result,
                    offset + match.start("name"),
                    offset + match.end("name"),
                )
        for match in declaration_annotation.finditer(line):
            _replace_parser_span(result, offset + match.start(), offset + match.end())
        offset += len(line)
    for match in lowercase_declaration_annotation.finditer(source):
        _replace_parser_span(result, match.start("name"), match.end("name"))
    if mask_function_calls:
        _mask_function_like_macros(result, source)
    _mask_sal_annotations(result, source)
    _mask_calling_convention_annotations(result, source)
    _mask_gnu_attributes(result, source)
    _mask_gnu_computed_goto(result, source)
    _mask_bsd_timecmp_operator_macros(result, source)
    _mask_inttypes_format_macros(result, source)
    _mask_adjacent_string_like_macros(result, source)
    _mask_foreach_statement_macros(result, source)
    _mask_statement_like_macro_lines(result, source)
    _mask_known_declaration_macro_invocations(result, source)
    _mask_type_argument_macro_calls(result, source)
    if language == "cpp":
        _mask_qt_parser_extensions(result, source)
    return bytes(result)


def _compiler_extension_compatibility_source(language: str, source: bytes) -> bytes:
    result = bytearray(source)
    _mask_sal_annotations(result, source)
    _mask_calling_convention_annotations(result, source)
    _mask_gnu_attributes(result, source)
    _mask_gnu_computed_goto(result, source)
    _mask_bsd_timecmp_operator_macros(result, source)
    _mask_inttypes_format_macros(result, source)
    _mask_adjacent_string_like_macros(result, source)
    _mask_foreach_statement_macros(result, source)
    _mask_statement_like_macro_lines(result, source)
    _mask_known_declaration_macro_invocations(result, source)
    _mask_type_argument_macro_calls(result, source)
    if language == "cpp":
        _mask_qt_parser_extensions(result, source)
    return bytes(result)


def _mask_gnu_attributes(result: bytearray, source: bytes) -> None:
    start = 0
    token = b"__attribute__"
    while (index := source.find(token, start)) >= 0:
        if _ascii_identifier_byte(source[index - 1] if index else 0):
            start = index + len(token)
            continue
        opening = source.find(b"(", index + len(token))
        if opening < 0:
            start = index + len(token)
            continue
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            start = index + len(token)
            continue
        _replace_parser_span(result, index, closing + 1)
        start = closing + 1


def _mask_calling_convention_annotations(result: bytearray, source: bytes) -> None:
    calling_convention = re.compile(
        rb"\b(?:CALLBACK|WINAPI|APIENTRY|NTAPI|PASCAL|__cdecl|__stdcall|__fastcall)\b"
    )
    for match in calling_convention.finditer(source):
        _replace_parser_span(result, match.start(), match.end())


def _mask_gnu_computed_goto(result: bytearray, source: bytes) -> None:
    for match in re.finditer(rb"(?<![A-Za-z0-9_\)\]])&&[A-Za-z_]\w*", source):
        _replace_parser_span(result, match.start(), match.end(), b"0")

    computed_goto = re.compile(rb"\bgoto\s*\*[^;\r\n]*;")
    for match in computed_goto.finditer(source):
        _replace_parser_span(result, match.start(), match.end(), b"goto L;")


def _mask_bsd_timecmp_operator_macros(result: bytearray, source: bytes) -> None:
    macro_call = re.compile(rb"\b(?:timercmp|timespeccmp)\s*\(", flags=re.IGNORECASE)
    operator_replacements = {
        b"<": b"L",
        b">": b"G",
        b"<=": b"LE",
        b">=": b"GE",
        b"==": b"EQ",
        b"!=": b"NE",
    }
    for match in macro_call.finditer(source):
        opening = source.find(b"(", match.start())
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            continue
        arguments = _top_level_argument_spans(source, opening + 1, closing)
        if len(arguments) != 3:
            continue
        third_start, third_end = arguments[2]
        operator = source[third_start:third_end].strip()
        replacement = operator_replacements.get(operator)
        if replacement is None:
            continue
        leading = third_start
        while leading < third_end and source[leading] in b" \t":
            leading += 1
        _replace_parser_span(result, leading, leading + len(operator), replacement)


def _mask_inttypes_format_macros(result: bytearray, source: bytes) -> None:
    format_macro = re.compile(rb"\b(?:PRI|SCN)[A-Za-z0-9_]+\b")
    for match in format_macro.finditer(source):
        previous_index = match.start() - 1
        while previous_index >= 0 and source[previous_index] in b" \t":
            previous_index -= 1
        next_index = match.end()
        while next_index < len(source) and source[next_index] in b" \t":
            next_index += 1
        if (
            previous_index >= 0
            and source[previous_index] == ord('"')
            or next_index < len(source)
            and source[next_index] == ord('"')
        ):
            _replace_parser_span(result, match.start(), match.end())


def _mask_adjacent_string_like_macros(result: bytearray, source: bytes) -> None:
    adjacent_macro = re.compile(rb"\b(?P<name>[A-Z][A-Z0-9_]{2,})\b[ \t]+(?P=name)\b")
    for match in adjacent_macro.finditer(source):
        line_start = source.rfind(b"\n", 0, match.start()) + 1
        if b"#" in source[line_start : match.start()]:
            continue
        _replace_parser_span(result, match.start(), match.end(), b'""')


def _mask_foreach_statement_macros(result: bytearray, source: bytes) -> None:
    foreach_macro = re.compile(rb"(?m)^[ \t]*(?P<name>FOREACH_[A-Z0-9_]+)\s*\(")
    for match in foreach_macro.finditer(source):
        opening = source.find(b"(", match.start("name"))
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            continue
        next_index = closing + 1
        while next_index < len(source) and source[next_index] in b" \t\r\n":
            next_index += 1
        if next_index >= len(source) or source[next_index] != ord("{"):
            continue
        _replace_parser_span(result, match.start("name"), closing + 1, b"for (;;)")


def _mask_statement_like_macro_lines(result: bytearray, source: bytes) -> None:
    statement_macro = re.compile(rb"(?m)^[ \t]*(?P<name>[A-Z][A-Z0-9_]{2,})\s*\(")
    for match in statement_macro.finditer(source):
        line_start = source.rfind(b"\n", 0, match.start()) + 1
        if b"#" in source[line_start : match.start("name")]:
            continue
        opening = source.find(b"(", match.start("name"))
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            continue
        line_end = source.find(b"\n", match.start())
        if line_end < 0:
            line_end = len(source)
        if closing > line_end:
            continue
        trailing = source[closing + 1 : line_end]
        if re.fullmatch(rb"[ \t]*;?[ \t]*(?://[^\n]*)?", trailing) is None:
            continue
        if _macro_line_is_expression_continuation(source, line_start, line_end):
            continue
        _replace_parser_span(result, match.start("name"), line_end, b";")


def _macro_line_is_expression_continuation(source: bytes, line_start: int, line_end: int) -> bool:
    previous = _previous_significant_line(source, line_start)
    if previous is not None:
        previous_code = previous.split(b"//", 1)[0].rstrip()
        if previous_code.endswith(b"\\") or previous_code.endswith((b"&&", b"||", b"(", b"[", b",")):
            return True
        if re.search(rb"(?:[?:+\-*/%&|^=<>!]|==|!=|<=|>=)$", previous_code):
            return True

    next_line_start = line_end + 1 if line_end < len(source) and source[line_end : line_end + 1] == b"\n" else line_end
    next_line = _next_significant_line(source, next_line_start)
    if next_line is None:
        return False
    next_code = next_line.split(b"//", 1)[0].lstrip()
    return next_code.startswith((b"&&", b"||", b"+", b"-", b"*", b"/", b"%", b"&", b"|", b"^", b"?", b":", b",", b")", b"]"))


def _previous_significant_line(source: bytes, line_start: int) -> bytes | None:
    cursor = line_start
    while cursor > 0:
        previous_end = cursor - 1
        if previous_end >= 0 and source[previous_end] == ord("\n"):
            previous_end -= 1
        previous_start = source.rfind(b"\n", 0, previous_end + 1) + 1
        line = source[previous_start : previous_end + 1].strip()
        if line and not line.startswith(b"//"):
            return line
        cursor = previous_start
    return None


def _next_significant_line(source: bytes, line_start: int) -> bytes | None:
    cursor = line_start
    while cursor < len(source):
        line_end = source.find(b"\n", cursor)
        if line_end < 0:
            line_end = len(source)
        line = source[cursor:line_end].strip()
        if line and not line.startswith(b"//"):
            return line
        cursor = line_end + 1
    return None


def _mask_known_declaration_macro_invocations(result: bytearray, source: bytes) -> None:
    declaration_macro = re.compile(
        rb"(?m)^[ \t]*(?P<name>"
        rb"ui(?:Unix|Windows)?(?:DefineControl|ControlAllDefaults(?:ExceptDestroy)?|ControlDefault[A-Za-z0-9_]*)"
        rb"|G_DEFINE_TYPE(?:_WITH_CODE)?"
        rb")\s*\("
    )
    for match in declaration_macro.finditer(source):
        opening = source.find(b"(", match.start("name"))
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            continue
        end = closing + 1
        while end < len(source) and source[end] in b" \t":
            end += 1
        if end < len(source) and source[end] == ord(";"):
            end += 1
        _replace_parser_span(result, match.start(), end)


def _mask_type_argument_macro_calls(result: bytearray, source: bytes) -> None:
    type_argument_positions = {
        b"uiprivNew": (0,),
        b"uiNew": (0,),
        b"g_new": (0,),
        b"g_new0": (0,),
        b"g_renew": (0,),
        b"g_array_index": (1,),
        b"va_arg": (1,),
    }
    macro_call = re.compile(rb"\b(?P<name>uiprivNew|uiNew|g_new0|g_new|g_renew|g_array_index|va_arg)\s*\(")
    for match in macro_call.finditer(source):
        opening = source.find(b"(", match.start("name"))
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            continue
        arguments = _top_level_argument_spans(source, opening + 1, closing)
        for position in type_argument_positions[match.group("name")]:
            if position < len(arguments):
                _replace_type_argument_with_identifier(result, source, *arguments[position])


def _replace_type_argument_with_identifier(result: bytearray, source: bytes, start: int, end: int) -> None:
    start, end = _trim_argument_span(source, start, end)
    argument = source[start:end]
    identifiers = re.findall(rb"[A-Za-z_]\w*", argument)
    if not identifiers:
        return
    if identifiers[0] in {b"struct", b"union", b"enum"} and len(identifiers) >= 2:
        replacement = identifiers[1]
    elif b"*" in argument or b" " in argument or b"\t" in argument:
        primitive_types = {
            b"char",
            b"short",
            b"int",
            b"long",
            b"float",
            b"double",
            b"signed",
            b"unsigned",
            b"void",
            b"bool",
            b"_Bool",
            b"const",
            b"volatile",
            b"struct",
            b"union",
            b"enum",
        }
        candidates = [
            identifier
            for identifier in identifiers
            if identifier not in primitive_types
        ]
        replacement = candidates[-1] if candidates else b"T"
    else:
        return
    _replace_parser_span(result, start, end, replacement)


def _mask_zlib_of_prototypes(source: bytes) -> bytes:
    result = bytearray(source)
    start = 0
    token = b"OF"
    while (index := source.find(token, start)) >= 0:
        before = source[index - 1] if index else 0
        after_index = index + len(token)
        if _ascii_identifier_byte(before) or (
            after_index < len(source) and _ascii_identifier_byte(source[after_index])
        ):
            start = after_index
            continue
        opening = after_index
        while opening < len(source) and source[opening] in b" \t":
            opening += 1
        if source[opening : opening + 2] != b"((":
            start = after_index
            continue
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            start = after_index
            continue
        _replace_parser_span(result, index, opening + 2, b" " * (opening + 1 - index) + b"(")
        _replace_parser_span(result, closing, closing + 1)
        start = closing + 1
    return bytes(result)


def _mask_kr_function_declarations(source: bytes) -> bytes:
    result = bytearray(source)
    function_header = re.compile(
        rb"\b(?P<name>[A-Za-z_]\w*)\s*\((?P<params>\s*[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*)\)"
    )
    control_names = {b"if", b"for", b"while", b"switch", b"return", b"sizeof"}
    for match in function_header.finditer(source):
        if match.group("name") in control_names:
            continue
        declaration_start = _skip_c_space_and_comments(source, match.end())
        if declaration_start >= len(source) or source[declaration_start] == ord("{"):
            continue
        brace = _kr_declaration_block_brace(source, declaration_start)
        if brace is None:
            continue
        parameters = [
            item.strip()
            for item in match.group("params").split(b",")
            if re.fullmatch(rb"\s*[A-Za-z_]\w*\s*", item)
        ]
        if not parameters or not _looks_like_kr_parameter_declarations(source[declaration_start:brace], parameters):
            continue
        _replace_parser_span(result, match.start("params"), match.end("params"))
        _replace_parser_span(result, match.end(), brace)
    return bytes(result)


def _mask_uefi_debug_code_blocks(source: bytes) -> bytes:
    result = bytearray(source)
    start = 0
    token = b"DEBUG_CODE"
    while (index := source.find(token, start)) >= 0:
        before = source[index - 1] if index else 0
        after_index = index + len(token)
        after = source[after_index] if after_index < len(source) else 0
        if _ascii_identifier_byte(before) or _ascii_identifier_byte(after):
            start = after_index
            continue
        opening = after_index
        while opening < len(source) and source[opening] in b" \t\r\n":
            opening += 1
        if opening >= len(source) or source[opening] != ord("("):
            start = after_index
            continue
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            start = after_index
            continue
        end = closing + 1
        while end < len(source) and source[end] in b" \t\r\n":
            end += 1
        if end < len(source) and source[end] == ord(";"):
            end += 1
        _replace_parser_span(result, index, end)
        start = end
    return bytes(result)


def _mask_known_declaration_macro_lines(source: bytes) -> bytes:
    result = bytearray(source)
    declaration_macro_line = re.compile(
        rb"(?m)^[ \t]*(?:OC_STRUCTORS|OC_ARRAY_STRUCTORS|OC_MAP_STRUCTORS)\s*\([^\n]*\)[ \t]*(?://[^\n]*)?$"
    )
    for match in declaration_macro_line.finditer(source):
        _replace_parser_span(result, match.start(), match.end())
    return bytes(result)


def _mask_cpp_using_declaration_lists(source: bytes) -> bytes:
    result = bytearray(source)
    offset = 0
    for line in source.splitlines(keepends=True):
        content_end = offset + len(line.rstrip(b"\r\n"))
        stripped = line.lstrip()
        if stripped.startswith(b"using std::"):
            statement_end = stripped.find(b";")
            if statement_end >= 0 and b"," in stripped[:statement_end]:
                _replace_parser_span(result, offset, content_end)
        offset += len(line)
    return bytes(result)


def _skip_c_space_and_comments(source: bytes, index: int) -> int:
    while index < len(source):
        if source[index] in b" \t\r\n":
            index += 1
            continue
        if source[index : index + 2] == b"//":
            newline = source.find(b"\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source[index : index + 2] == b"/*":
            closing = source.find(b"*/", index + 2)
            index = len(source) if closing < 0 else closing + 2
            continue
        break
    return index


def _kr_declaration_block_brace(source: bytes, start: int) -> int | None:
    quote = 0
    escaped = False
    paren_depth = 0
    bracket_depth = 0
    index = start
    upper = min(len(source), start + 4096)
    while index < upper:
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else 0
        if quote:
            if escaped:
                escaped = False
            elif character == ord("\\"):
                escaped = True
            elif character == quote:
                quote = 0
        elif character in {ord('"'), ord("'")}:
            quote = character
        elif character == ord("/") and following == ord("/"):
            newline = source.find(b"\n", index + 2, upper)
            index = upper if newline < 0 else newline
        elif character == ord("/") and following == ord("*"):
            closing = source.find(b"*/", index + 2, upper)
            index = upper if closing < 0 else closing + 1
        elif character == ord("("):
            paren_depth += 1
        elif character == ord(")") and paren_depth:
            paren_depth -= 1
        elif character == ord("["):
            bracket_depth += 1
        elif character == ord("]") and bracket_depth:
            bracket_depth -= 1
        elif character == ord("{") and paren_depth == 0 and bracket_depth == 0:
            return index
        elif character == ord("}") and paren_depth == 0 and bracket_depth == 0:
            return None
        index += 1
    return None


def _looks_like_kr_parameter_declarations(declaration_block: bytes, parameters: list[bytes]) -> bool:
    compact = _strip_c_comments(declaration_block).strip()
    if not compact.endswith(b";"):
        return False
    parameter_names = {parameter.decode("ascii", errors="ignore") for parameter in parameters}
    declared_names: set[str] = set()
    for declaration in compact.split(b";"):
        if not declaration.strip():
            continue
        declared_names.update(_kr_declared_parameter_names(declaration))
    return bool(declared_names) and parameter_names.issubset(declared_names) and declared_names.issubset(parameter_names)


def _strip_c_comments(source: bytes) -> bytes:
    result = bytearray(source)
    index = 0
    while index < len(result):
        if result[index : index + 2] == b"//":
            end = source.find(b"\n", index + 2)
            end = len(result) if end < 0 else end
            _replace_parser_span(result, index, end)
            index = end
            continue
        if result[index : index + 2] == b"/*":
            end = source.find(b"*/", index + 2)
            end = len(result) if end < 0 else end + 2
            _replace_parser_span(result, index, end)
            index = end
            continue
        index += 1
    return bytes(result)


def _kr_declared_parameter_names(declaration: bytes) -> set[str]:
    names: set[str] = set()
    for declarator in declaration.split(b","):
        without_arrays = re.sub(rb"\[[^\]]*\]", b"", declarator)
        identifiers = re.findall(rb"\b[A-Za-z_]\w*\b", without_arrays)
        if identifiers:
            names.add(identifiers[-1].decode("ascii", errors="ignore"))
    return names


def _mask_sal_annotations(result: bytearray, source: bytes) -> None:
    sal_annotation = re.compile(
        rb"""
        (?<![A-Za-z0-9])
        (?P<name>
            _(?:
                In|Inout|Out|Outptr|Ret|Deref|Field|Frees|When|At|Success|Check_return|
                Must_inspect_result|Maybe_raises_SEH_exception|Post|Pre|Analysis|IRQL|
                Requires|Acquires|Releases|Guarded_by|Writes|Reads|Printf|Use_decl_annotations|
                Function_class|Dispatch_type|Kernel_float|Kernel_clear|No_competing_thread
            )[A-Za-z0-9_]*
            |
            __drv_[A-Za-z0-9_]+
        )
        """,
        flags=re.VERBOSE,
    )
    for match in sal_annotation.finditer(source):
        end = match.end("name")
        while end < len(source) and source[end] in b" \t":
            end += 1
        if end < len(source) and source[end] == ord("("):
            closing = _matching_parser_parenthesis(source, end)
            if closing is not None:
                end = closing + 1
        _replace_parser_span(result, match.start("name"), end)


def _mask_qt_parser_extensions(result: bytearray, source: bytes) -> None:
    for token in (
        b"Q_OBJECT",
        b"Q_GADGET",
        b"Q_NAMESPACE",
        b"Q_DECLARE_FLAGS",
        b"Q_DECLARE_OPERATORS_FOR_FLAGS",
        b"emit",
    ):
        start = 0
        while (index := source.find(token, start)) >= 0:
            before = source[index - 1] if index else 0
            after_index = index + len(token)
            after = source[after_index] if after_index < len(source) else 0
            if not _ascii_identifier_byte(before) and not _ascii_identifier_byte(after):
                _replace_parser_span(result, index, after_index)
            start = after_index

    access_slots = re.compile(rb"\b(?P<access>public|protected|private)\s+(?:Q_)?slots\s*:", flags=re.IGNORECASE)
    for match in access_slots.finditer(source):
        _replace_parser_span(result, match.start(), match.end(), match.group("access") + b":")

    signal_sections = re.compile(rb"\b(?:Q_SIGNALS|signals|Q_PRIVATE_SLOT)\s*:", flags=re.IGNORECASE)
    for match in signal_sections.finditer(source):
        _replace_parser_span(result, match.start(), match.end(), b"public:")


def _mask_function_like_macros(result: bytearray, source: bytes) -> None:
    macro_start = re.compile(rb"\b(?P<name>[A-Z][A-Z0-9_]{2,})\s*\(")
    for match in macro_start.finditer(source):
        line_start = source.rfind(b"\n", 0, match.start()) + 1
        if b"#" in source[line_start : match.start()]:
            continue
        opening = source.find(b"(", match.start("name"))
        closing = _matching_parser_parenthesis(source, opening)
        if closing is None:
            continue
        prefix = source[line_start : match.start()].strip()
        end = closing + 1
        while end < len(source) and source[end] in b" \t":
            end += 1
        if end < len(source) and source[end] == ord(";"):
            end += 1
        argument = source[opening + 1 : closing].strip()
        replacement = argument if prefix and re.fullmatch(rb"[A-Za-z_]\w*", argument) else b""
        _replace_parser_span(result, match.start(), end, replacement)


def _matching_parser_parenthesis(source: bytes, opening: int) -> int | None:
    depth = 0
    quote = 0
    escaped = False
    index = opening
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else 0
        if quote:
            if escaped:
                escaped = False
            elif character == ord("\\"):
                escaped = True
            elif character == quote:
                quote = 0
        elif character in {ord('"'), ord("'")}:
            quote = character
        elif character == ord("/") and following == ord("/"):
            newline = source.find(b"\n", index + 2)
            index = len(source) if newline < 0 else newline
            continue
        elif character == ord("/") and following == ord("*"):
            end = source.find(b"*/", index + 2)
            index = len(source) if end < 0 else end + 2
            continue
        elif character == ord("("):
            depth += 1
        elif character == ord(")"):
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _top_level_argument_spans(source: bytes, start: int, end: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    argument_start = start
    quote = 0
    escaped = False
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    index = start
    while index < end:
        character = source[index]
        following = source[index + 1] if index + 1 < end else 0
        if quote:
            if escaped:
                escaped = False
            elif character == ord("\\"):
                escaped = True
            elif character == quote:
                quote = 0
        elif character in {ord('"'), ord("'")}:
            quote = character
        elif character == ord("/") and following == ord("/"):
            newline = source.find(b"\n", index + 2, end)
            index = end if newline < 0 else newline
            continue
        elif character == ord("/") and following == ord("*"):
            closing = source.find(b"*/", index + 2, end)
            index = end if closing < 0 else closing + 2
            continue
        elif character == ord("("):
            paren_depth += 1
        elif character == ord(")") and paren_depth:
            paren_depth -= 1
        elif character == ord("["):
            bracket_depth += 1
        elif character == ord("]") and bracket_depth:
            bracket_depth -= 1
        elif character == ord("{"):
            brace_depth += 1
        elif character == ord("}") and brace_depth:
            brace_depth -= 1
        elif character == ord(",") and not (paren_depth or bracket_depth or brace_depth):
            spans.append(_trim_argument_span(source, argument_start, index))
            argument_start = index + 1
        index += 1
    spans.append(_trim_argument_span(source, argument_start, end))
    return spans


def _trim_argument_span(source: bytes, start: int, end: int) -> tuple[int, int]:
    while start < end and source[start] in b" \t\r\n":
        start += 1
    while end > start and source[end - 1] in b" \t\r\n":
        end -= 1
    return start, end


def _conditional_compilation_view(source: bytes, *, prefer_if_branch: bool) -> bytes:
    result = bytearray(source)
    stack: list[tuple[bool, bool]] = []
    active = True
    continuation = False
    offset = 0
    for line in source.splitlines(keepends=True):
        content_end = offset + len(line.rstrip(b"\r\n"))
        stripped = line.lstrip()
        if continuation:
            _replace_parser_span(result, offset, content_end)
            continuation = line.rstrip(b"\r\n").rstrip().endswith(b"\\")
            offset += len(line)
            continue

        if stripped.startswith(b"#"):
            directive = stripped[1:].lstrip().split(None, 1)
            kind = directive[0] if directive else b""
            argument = directive[1] if len(directive) > 1 else b""
            if kind in {b"if", b"ifdef", b"ifndef"}:
                if kind == b"if" and re.match(rb"0(?:\s|$)", argument):
                    selected = False
                elif kind == b"if" and re.match(rb"1(?:\s|$)", argument):
                    selected = True
                elif kind == b"if":
                    selected = _preferred_unknown_preprocessor_branch(argument, prefer_if_branch)
                elif kind == b"ifndef":
                    selected = not prefer_if_branch
                else:
                    selected = prefer_if_branch
                stack.append((active, selected))
                active = active and selected
            elif kind == b"elif" and stack:
                parent_active, branch_taken = stack[-1]
                selected = not branch_taken and prefer_if_branch
                stack[-1] = (parent_active, branch_taken or selected)
                active = parent_active and selected
            elif kind == b"else" and stack:
                parent_active, branch_taken = stack[-1]
                selected = not branch_taken
                stack[-1] = (parent_active, True)
                active = parent_active and selected
            elif kind == b"endif" and stack:
                parent_active, _ = stack.pop()
                active = parent_active
            _replace_parser_span(result, offset, content_end)
            continuation = line.rstrip(b"\r\n").rstrip().endswith(b"\\")
        elif not active:
            _replace_parser_span(result, offset, content_end)
        offset += len(line)
    return bytes(result)


def _preferred_unknown_preprocessor_branch(argument: bytes, prefer_if_branch: bool) -> bool:
    argument_text = argument.split(b"//", 1)[0].strip().decode("utf-8", errors="ignore")
    if re.fullmatch(r"!\s*0+", argument_text):
        return True
    if re.fullmatch(r"!\s*[1-9][0-9]*", argument_text):
        return False
    if re.fullmatch(r"!\s*(?:defined\s*\(\s*)?[A-Za-z_]\w*(?:\s*\))?", argument_text):
        return not prefer_if_branch
    if re.fullmatch(r"(?:defined\s*\(\s*)?[A-Za-z_]\w*(?:\s*\))?", argument_text):
        return prefer_if_branch
    return prefer_if_branch


def _conditional_compilation_view_for_definitions(source: bytes, definitions: dict[str, str]) -> bytes:
    result = bytearray(source)
    stack: list[tuple[bool, bool]] = []
    active = True
    continuation = False
    offset = 0
    for line in source.splitlines(keepends=True):
        content_end = offset + len(line.rstrip(b"\r\n"))
        stripped = line.lstrip()
        if continuation:
            _replace_parser_span(result, offset, content_end)
            continuation = line.rstrip(b"\r\n").rstrip().endswith(b"\\")
            offset += len(line)
            continue

        if stripped.startswith(b"#"):
            directive = stripped[1:].lstrip().split(None, 1)
            kind = directive[0] if directive else b""
            argument = directive[1] if len(directive) > 1 else b""
            if kind in {b"if", b"ifdef", b"ifndef"}:
                selected = _preprocessor_condition_enabled(kind, argument, definitions)
                stack.append((active, selected))
                active = active and selected
            elif kind == b"elif" and stack:
                parent_active, branch_taken = stack[-1]
                selected = (not branch_taken) and _preprocessor_condition_enabled(b"if", argument, definitions)
                stack[-1] = (parent_active, branch_taken or selected)
                active = parent_active and selected
            elif kind == b"else" and stack:
                parent_active, branch_taken = stack[-1]
                selected = not branch_taken
                stack[-1] = (parent_active, True)
                active = parent_active and selected
            elif kind == b"endif" and stack:
                parent_active, _ = stack.pop()
                active = parent_active
            _replace_parser_span(result, offset, content_end)
            continuation = line.rstrip(b"\r\n").rstrip().endswith(b"\\")
        elif not active:
            _replace_parser_span(result, offset, content_end)
        offset += len(line)
    return bytes(result)


def _preprocessor_condition_enabled(kind: bytes, argument: bytes, definitions: dict[str, str]) -> bool:
    argument_text = argument.split(b"//", 1)[0].strip().decode("utf-8", errors="ignore")
    if kind == b"ifdef":
        return argument_text.split(None, 1)[0] in definitions
    if kind == b"ifndef":
        return argument_text.split(None, 1)[0] not in definitions
    if re.fullmatch(r"0+", argument_text):
        return False
    if re.fullmatch(r"[1-9][0-9]*", argument_text):
        return True
    for pattern, negate in (
        (r"defined\s*\(\s*([A-Za-z_]\w*)\s*\)", False),
        (r"defined\s+([A-Za-z_]\w*)", False),
        (r"!\s*defined\s*\(\s*([A-Za-z_]\w*)\s*\)", True),
        (r"!\s*defined\s+([A-Za-z_]\w*)", True),
    ):
        match = re.fullmatch(pattern, argument_text)
        if match:
            present = match.group(1) in definitions
            return not present if negate else present
    match = re.fullmatch(r"([A-Za-z_]\w*)", argument_text)
    if match:
        return _preprocessor_macro_truthy(match.group(1), definitions)
    match = re.fullmatch(r"!\s*([A-Za-z_]\w*)", argument_text)
    if match:
        return not _preprocessor_macro_truthy(match.group(1), definitions)
    return False


def _preprocessor_macro_truthy(name: str, definitions: dict[str, str]) -> bool:
    if name not in definitions:
        return False
    value = definitions[name].strip()
    if value == "":
        return True
    try:
        return int(value, 0) != 0
    except ValueError:
        return True


def _replace_parser_span(result: bytearray, start: int, end: int, replacement: bytes = b"") -> None:
    if end <= start or len(replacement) > end - start:
        return
    original = bytes(result[start:end])
    padding = bytearray()
    for character in original[len(replacement) :]:
        padding.append(character if character in {10, 13} else 32)
    result[start:end] = replacement + bytes(padding)


def _replace_ascii_word(value: bytes, token: bytes, replacement: bytes) -> bytes:
    if len(token) != len(replacement):
        raise ValueError("parser token replacements must preserve byte offsets")
    result = bytearray(value)
    start = 0
    while (index := value.find(token, start)) >= 0:
        before = value[index - 1] if index else 0
        after_index = index + len(token)
        after = value[after_index] if after_index < len(value) else 0
        if not _ascii_identifier_byte(before) and not _ascii_identifier_byte(after):
            result[index:after_index] = replacement
        start = after_index
    return bytes(result)


def _replace_cpp_preprocessor_not(line: bytes) -> bytes:
    marker = b"not"
    index = line.find(marker)
    if index < 0 or b"#" not in line[:index] or b"if" not in line[:index]:
        return line
    return _replace_ascii_word(line, marker, b"!  ")


def _mask_msvc_asm_blocks(source: bytes) -> bytes:
    result = bytearray(source)
    start = 0
    while (token_index := source.find(b"__asm", start)) >= 0:
        if _ascii_identifier_byte(source[token_index - 1] if token_index else 0):
            start = token_index + 5
            continue
        opening = source.find(b"{", token_index + 5)
        if opening < 0:
            break
        depth = 1
        closing = opening + 1
        while closing < len(source) and depth:
            if source[closing] == ord("{"):
                depth += 1
            elif source[closing] == ord("}"):
                depth -= 1
            closing += 1
        if depth:
            break
        for index in range(token_index, closing):
            if index in {opening, closing - 1} or source[index] in {10, 13}:
                continue
            result[index] = 32
        start = closing
    return bytes(result)


def _ascii_identifier_byte(value: int) -> bool:
    return value == 95 or 48 <= value <= 57 or 65 <= value <= 90 or 97 <= value <= 122


def _declaration_name(node: Node, source: bytes) -> str:
    direct = node.child_by_field_name("name")
    if direct is not None:
        return _compact_text(direct, source, limit=120)
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        nested = declarator
        for _ in range(8):
            next_declarator = nested.child_by_field_name("declarator")
            if next_declarator is None:
                break
            nested = next_declarator
        if nested.type in {"identifier", "field_identifier", "type_identifier"}:
            return _compact_text(nested, source, limit=120)
        identifiers = [item for item in _walk(declarator) if item.type in {"identifier", "field_identifier", "type_identifier"}]
        if identifiers:
            return _compact_text(identifiers[0], source, limit=120)
    identifiers = [item for item in node.named_children if item.type in {"identifier", "type_identifier"}]
    return _compact_text(identifiers[0], source, limit=120) if identifiers else node.type


def _is_cfg_node(node: Node, profile: LanguageProfile) -> bool:
    return (
        node.type in profile.functions
        or node.type in profile.controls
        or node.type.endswith("_statement")
        or node.type in {"return_expression", "break_expression", "continue_expression", "expression_statement", "match_arm"}
    )


def _ast_graph(nodes: list[Node], source: bytes) -> dict[str, Any]:
    node_ids = {_node_key(node): f"ast-{index}" for index, node in enumerate(nodes)}
    preview = nodes[:_AST_PREVIEW_LIMIT]
    preview_ids = {_node_key(node) for node in preview}
    edges = [
        {"from": node_ids[_node_key(node.parent)], "to": node_ids[_node_key(node)], "kind": "child"}
        for node in preview
        if node.parent is not None and _node_key(node.parent) in preview_ids
    ]
    return {
        "node_count": len(nodes),
        "edge_count": max(0, len(nodes) - 1),
        "nodes": [
            {
                "id": node_ids[_node_key(node)],
                "kind": node.type,
                "line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
                "snippet": _compact_text(node, source, limit=120),
            }
            for node in preview
        ],
        "edges": edges,
        "truncated": len(nodes) > len(preview),
    }


def _cfg_graph(
    cfg_nodes: list[Node],
    function_nodes: list[Node],
    controls: list[Node],
    source: bytes,
) -> dict[str, Any]:
    terminal_types = {"return_statement", "return_expression", "break_statement", "continue_statement"}
    control_types = {node.type for node in controls}
    relevant_descendant_types = control_types | terminal_types
    ordered = sorted(
        (
            node
            for node in cfg_nodes
            if not (
                node.type == "expression_statement"
                and any(child.type in relevant_descendant_types for child in list(_walk(node))[1:])
            )
        ),
        key=lambda node: (node.start_byte, -node.end_byte, node.type),
    )
    node_ids = {_node_key(node): f"cfg-{index}" for index, node in enumerate(ordered)}
    function_ids = {_node_key(node) for node in function_nodes}

    def owner(node: Node) -> tuple[int, int, str] | None:
        if _node_key(node) in function_ids:
            return _node_key(node)
        parent = node.parent
        while parent is not None:
            if _node_key(parent) in function_ids:
                return _node_key(parent)
            parent = parent.parent
        return None

    groups: dict[tuple[int, int, str] | None, list[Node]] = {}
    for node in ordered:
        groups.setdefault(owner(node), []).append(node)

    edges: list[dict[str, str]] = []
    edge_keys: set[tuple[str, str, str]] = set()

    def add_edge(start: Node, end: Node, kind: str) -> None:
        if _node_key(start) == _node_key(end):
            return
        key = (node_ids[_node_key(start)], node_ids[_node_key(end)], kind)
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({"from": key[0], "to": key[1], "kind": kind})

    for members in groups.values():
        for current, following in zip(members, members[1:]):
            if current.type not in terminal_types and current.type not in control_types:
                add_edge(current, following, "next")

    for control in controls:
        members = groups.get(owner(control), [])
        contained = [
            node
            for node in members
            if _node_key(node) != _node_key(control) and _is_descendant(node, control)
        ]
        following = next((node for node in members if node.start_byte >= control.end_byte), None)
        if "switch" in control.type or control.type == "match_expression":
            cases = [node for node in contained if "case" in node.type or node.type == "match_arm"]
            for case in cases:
                add_edge(control, case, "case")
            if not cases and contained:
                add_edge(control, contained[0], "case")
        elif control.type.startswith("if") or control.type in {"conditional_expression", "ternary_expression"}:
            consequence = _first_field(control, "consequence", "body")
            alternative = _first_field(control, "alternative")
            true_target = _first_cfg_member(consequence, contained) or (contained[0] if contained else None)
            false_target = _first_cfg_member(alternative, contained) or following
            if true_target is not None:
                add_edge(control, true_target, "branch_true")
            if false_target is not None:
                add_edge(control, false_target, "branch_false")
        else:
            body = _first_field(control, "body")
            target = _first_cfg_member(body, contained) or (contained[0] if contained else None)
            if target is not None:
                add_edge(control, target, "branch_true")
            if following is not None:
                add_edge(control, following, "branch_false")
        if contained and _is_loop_control(control) and contained[-1].type not in terminal_types:
            add_edge(contained[-1], control, "loop_back")

    preview = ordered[:_GRAPH_PREVIEW_LIMIT]
    preview_ids = {node_ids[_node_key(node)] for node in preview}
    preview_edges = [
        edge
        for edge in edges
        if edge["from"] in preview_ids and edge["to"] in preview_ids
    ][:_GRAPH_PREVIEW_LIMIT]
    return {
        "node_count": len(ordered),
        "edge_count": len(edges),
        "nodes": [
            {
                "id": node_ids[_node_key(node)],
                "kind": node.type,
                "line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
                "snippet": _compact_text(node, source, limit=160),
            }
            for node in preview
        ],
        "edges": preview_edges,
        "truncated": len(ordered) > len(preview) or len(edges) > len(preview_edges),
    }


def _dfg_graph(assignments: list[Node], profile: LanguageProfile, source: bytes) -> dict[str, Any]:
    graph_nodes: dict[tuple[str, str], dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str, int, str]] = set()

    for assignment in assignments:
        left, right = _assignment_sides(assignment, profile)
        if left is None or right is None:
            continue
        targets = _identifier_names(left, source)
        if not targets:
            continue
        source_identifiers = _identifier_names(right, source)
        sources = source_identifiers or [_compact_text(right, source, limit=120) or "<expression>"]
        scope = _scope_name(assignment, profile, source)
        line = assignment.start_point.row + 1
        for name in sources:
            key = (scope, name)
            graph_nodes.setdefault(
                key,
                {
                    "id": f"dfg-{len(graph_nodes)}",
                    "name": name,
                    "scope": scope,
                    "kind": "variable" if source_identifiers else "expression",
                },
            )
        for name in targets:
            key = (scope, name)
            graph_nodes.setdefault(
                key,
                {"id": f"dfg-{len(graph_nodes)}", "name": name, "scope": scope, "kind": "variable"},
            )
        for source_name in sources:
            for target_name in targets:
                source_id = graph_nodes[(scope, source_name)]["id"]
                target_id = graph_nodes[(scope, target_name)]["id"]
                key = (source_id, target_id, line, assignment.type)
                if key in edge_keys:
                    continue
                edge_keys.add(key)
                edges.append(
                    {
                        "from": source_id,
                        "to": target_id,
                        "kind": assignment.type,
                        "line": line,
                        "expression": _compact_text(assignment, source, limit=180),
                    }
                )

    nodes = list(graph_nodes.values())
    preview_nodes = nodes[:_GRAPH_PREVIEW_LIMIT]
    preview_ids = {node["id"] for node in preview_nodes}
    preview_edges = [
        edge
        for edge in edges
        if edge["from"] in preview_ids and edge["to"] in preview_ids
    ][:_GRAPH_PREVIEW_LIMIT]
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": preview_nodes,
        "edges": preview_edges,
        "truncated": len(nodes) > len(preview_nodes) or len(edges) > len(preview_edges),
    }


def _assignment_sides(node: Node, profile: LanguageProfile) -> tuple[Node | None, Node | None]:
    left = next(
        (node.child_by_field_name(field) for field in ("left", "pattern", "name", "declarator") if node.child_by_field_name(field) is not None),
        None,
    )
    right = next(
        (node.child_by_field_name(field) for field in ("right", "value") if node.child_by_field_name(field) is not None),
        None,
    )
    if profile.id == "csharp" and node.type == "variable_declarator" and right is None:
        name = node.child_by_field_name("name")
        right = next(
            (child for child in node.named_children if name is None or _node_key(child) != _node_key(name)),
            None,
        )
    if left is None and profile.id == "solidity":
        declarations = [child for child in _walk(node) if child.type in {"variable_declaration", "state_variable_declaration"}]
        if declarations:
            left = declarations[0].child_by_field_name("name") or declarations[0]
    return left, right


def _first_field(node: Node, *names: str) -> Node | None:
    return next((value for name in names if (value := node.child_by_field_name(name)) is not None), None)


def _first_cfg_member(root: Node | None, members: list[Node]) -> Node | None:
    if root is None:
        return None
    root_key = _node_key(root)
    return next(
        (
            member
            for member in members
            if _node_key(member) == root_key or _is_descendant(member, root)
        ),
        None,
    )


def _identifier_names(node: Node | None, source: bytes) -> list[str]:
    if node is None:
        return []
    names = [
        _compact_text(child, source, limit=120)
        for child in _walk(node)
        if child.type in {"identifier", "field_identifier", "property_identifier", "package_identifier"}
    ]
    return list(dict.fromkeys(name for name in names if name))


def _scope_name(node: Node, profile: LanguageProfile, source: bytes) -> str:
    parent = node.parent
    while parent is not None:
        if parent.type in profile.functions:
            return _declaration_name(parent, source)
        parent = parent.parent
    return "<module>"


def _is_loop_control(node: Node) -> bool:
    return "loop" in node.type or node.type.startswith(("for", "while", "do_"))


def _is_descendant(node: Node, ancestor: Node) -> bool:
    ancestor_key = _node_key(ancestor)
    parent = node.parent
    while parent is not None:
        if _node_key(parent) == ancestor_key:
            return True
        parent = parent.parent
    return False


def _node_key(node: Node) -> tuple[int, int, str]:
    return (node.start_byte, node.end_byte, node.type)
