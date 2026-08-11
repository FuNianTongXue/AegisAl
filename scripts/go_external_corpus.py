from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

import yaml
from tree_sitter import Language, Node, Parser
import tree_sitter_go


GOSEC_REPOSITORY = "https://github.com/securego/gosec.git"
GOSEC_COMMIT = "45b083a0cb42119d61b1e0e364d8c62c68f6f5cd"
SEMGREP_RULES_REPOSITORY = "https://github.com/semgrep/semgrep-rules.git"
SEMGREP_RULES_COMMIT = "647d58eb2e085440618782963ff094178d98d2fe"

_ANNOTATION_RE = re.compile(r"//\s*(ruleid|ok)\s*:\s*([^\n]+)")
_CWE_RE = re.compile(r"CWE-(\d+)", flags=re.IGNORECASE)
_RULE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_GOSEC_RULE_RE = re.compile(r"g(\d+)_samples\.go$", flags=re.IGNORECASE)


def ensure_checkout(url: str, commit: str, destination: Path) -> Path:
    if not (destination / ".git").is_dir():
        destination.parent.mkdir(parents=True, exist_ok=True)
        completed = _git("clone", "--filter=blob:none", "--no-checkout", url, str(destination), timeout=900)
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout).strip())
    current = _git("rev-parse", "HEAD", cwd=destination)
    if current.returncode != 0 or current.stdout.strip() != commit:
        fetched = _git("fetch", "--depth", "1", "origin", commit, cwd=destination, timeout=900)
        if fetched.returncode != 0:
            raise RuntimeError((fetched.stderr or fetched.stdout).strip())
        checked = _git("checkout", "--force", "--detach", commit, cwd=destination, timeout=900)
        if checked.returncode != 0:
            raise RuntimeError((checked.stderr or checked.stdout).strip())
    return destination


def extract_gosec_cases(root: Path, *, include_code: bool = False) -> list[dict[str, Any]]:
    rule_cwes = _gosec_rule_cwes(root / "issue" / "issue.go")
    parser = Parser(Language(tree_sitter_go.language()))
    cases: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    for path in sorted((root / "testutils").glob("*_samples.go")):
        match = _GOSEC_RULE_RE.search(path.name)
        if not match:
            continue
        external_rule = f"G{match.group(1)}"
        cwe = rule_cwes.get(external_rule)
        if not cwe:
            continue
        source = path.read_bytes()
        tree = parser.parse(source)
        sample_groups = [
            node
            for node in _walk(tree.root_node)
            if node.type == "composite_literal" and _is_code_sample_slice(node, source)
        ]
        for group_index, group in enumerate(sample_groups):
            body = group.child_by_field_name("body")
            if body is None:
                continue
            for sample_index, element in enumerate(body.named_children):
                code_files, error_count = _code_sample_value(element, source)
                if not code_files or error_count is None:
                    continue
                code_hash = _code_files_hash(code_files)
                if code_hash in seen_hashes:
                    continue
                seen_hashes.add(code_hash)
                case: dict[str, Any] = {
                    "id": f"gosec:{external_rule}:{path.name}:{group_index}:{sample_index}",
                    "source": "securego/gosec",
                    "source_path": path.relative_to(root).as_posix(),
                    "group_index": group_index,
                    "sample_index": sample_index,
                    "external_rules": [external_rule],
                    "cwes": [f"CWE-{cwe}"],
                    "vulnerable": error_count > 0,
                    "code_hash": code_hash,
                    "file_count": len(code_files),
                }
                if include_code:
                    case["code_files"] = [item.decode("utf-8", errors="replace") for item in code_files]
                cases.append(case)
    return cases


def extract_semgrep_cases(root: Path) -> list[dict[str, Any]]:
    rule_cwes = _semgrep_rule_cwes(root)
    cases_by_location: dict[tuple[str, int, bool], dict[str, Any]] = {}
    ambiguous_locations: set[tuple[str, int]] = set()
    for path in sorted(root.rglob("*.go")):
        relative = path.relative_to(root).as_posix()
        if not _is_semgrep_security_path(relative):
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for annotation_line, line in enumerate(lines, start=1):
            for annotation in _ANNOTATION_RE.finditer(line):
                vulnerable = annotation.group(1) == "ruleid"
                target_line = _annotation_target_line(lines, annotation_line, annotation.start())
                if target_line is None:
                    continue
                external_rules = [
                    token
                    for token in (item.strip() for item in annotation.group(2).split(","))
                    if _RULE_TOKEN_RE.fullmatch(token) and token in rule_cwes
                ]
                if not external_rules:
                    continue
                location = (relative, target_line)
                if any(key[:2] == location and key[2] != vulnerable for key in cases_by_location):
                    ambiguous_locations.add(location)
                    continue
                key = (relative, target_line, vulnerable)
                case = cases_by_location.setdefault(
                    key,
                    {
                        "id": f"semgrep-rules:{relative}:{target_line}:{'positive' if vulnerable else 'negative'}",
                        "source": "semgrep/semgrep-rules",
                        "source_path": relative,
                        "line": target_line,
                        "external_rules": [],
                        "cwes": [],
                        "vulnerable": vulnerable,
                        "code_hash": hashlib.sha256(path.read_bytes()).hexdigest(),
                    },
                )
                case["external_rules"] = sorted(set(case["external_rules"]) | set(external_rules))
                case["cwes"] = sorted(
                    set(case["cwes"])
                    | {f"CWE-{cwe}" for rule in external_rules for cwe in rule_cwes[rule]},
                    key=_cwe_sort_key,
                )
    return [
        case
        for key, case in sorted(cases_by_location.items())
        if key[:2] not in ambiguous_locations
    ]


def materialize_gosec_cases(cases: Iterable[dict[str, Any]], destination: Path) -> dict[str, list[str]]:
    destination.mkdir(parents=True, exist_ok=True)
    paths_by_case: dict[str, list[str]] = {}
    for case in cases:
        code_files = case.get("code_files") or []
        case_directory = destination / _safe_case_name(str(case["id"]))
        case_directory.mkdir(parents=True, exist_ok=True)
        paths: list[str] = []
        for index, content in enumerate(code_files):
            file_path = case_directory / f"source-{index}.go"
            file_path.write_text(str(content), encoding="utf-8")
            paths.append(file_path.as_posix())
        paths_by_case[str(case["id"])] = paths
    return paths_by_case


def materialize_semgrep_files(cases: Iterable[dict[str, Any]], source_root: Path, destination: Path) -> dict[str, str]:
    destination.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for case in cases:
        relative = str(case["source_path"])
        if relative in paths:
            continue
        source = source_root / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        paths[relative] = target.as_posix()
    return paths


def normalized_cwes(metadata: dict[str, Any]) -> set[str]:
    values = metadata.get("cwe") or []
    if not isinstance(values, list):
        values = [values]
    result: set[str] = set()
    for value in values:
        match = _CWE_RE.search(str(value))
        if match:
            result.add(f"CWE-{int(match.group(1))}")
    return result


def _git(*args: str, cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "http.proxy=", "-c", "https.proxy=", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _walk(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _is_code_sample_slice(node: Node, source: bytes) -> bool:
    node_type = node.child_by_field_name("type")
    return node_type is not None and b"CodeSample" in source[node_type.start_byte : node_type.end_byte]


def _code_sample_value(element: Node, source: bytes) -> tuple[list[bytes], int | None]:
    code_files: list[bytes] = []
    for node in _walk(element):
        if node.type != "composite_literal":
            continue
        node_type = node.child_by_field_name("type")
        body = node.child_by_field_name("body")
        if node_type is None or body is None:
            continue
        normalized_type = re.sub(rb"\s+", b"", source[node_type.start_byte : node_type.end_byte])
        if normalized_type != b"[]string":
            continue
        for expression in body.named_children:
            value = _go_string_expression(expression, source)
            if value is not None:
                code_files.append(value)
        break
    integers = [
        int(source[node.start_byte : node.end_byte])
        for node in _walk(element)
        if node.type == "int_literal"
    ]
    return code_files, integers[0] if integers else None


def _go_string_expression(node: Node, source: bytes) -> bytes | None:
    if node.type == "literal_element" and len(node.named_children) == 1:
        return _go_string_expression(node.named_children[0], source)
    if node.type == "raw_string_literal":
        return source[node.start_byte + 1 : node.end_byte - 1]
    if node.type == "interpreted_string_literal":
        return _unquote_go_string(source[node.start_byte + 1 : node.end_byte - 1])
    if node.type == "parenthesized_expression" and len(node.named_children) == 1:
        return _go_string_expression(node.named_children[0], source)
    if node.type != "binary_expression":
        return None
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    operator = source[left.end_byte : right.start_byte].strip()
    if operator != b"+":
        return None
    left_value = _go_string_expression(left, source)
    right_value = _go_string_expression(right, source)
    if left_value is None or right_value is None:
        return None
    return left_value + right_value


def _unquote_go_string(value: bytes) -> bytes | None:
    result = bytearray()
    index = 0
    simple = {
        ord("a"): 0x07,
        ord("b"): 0x08,
        ord("f"): 0x0C,
        ord("n"): 0x0A,
        ord("r"): 0x0D,
        ord("t"): 0x09,
        ord("v"): 0x0B,
        ord("\\"): ord("\\"),
        ord('"'): ord('"'),
        ord("'"): ord("'"),
    }
    while index < len(value):
        current = value[index]
        if current != ord("\\"):
            result.append(current)
            index += 1
            continue
        index += 1
        if index >= len(value):
            return None
        escaped = value[index]
        if escaped in simple:
            result.append(simple[escaped])
            index += 1
            continue
        if escaped in b"01234567":
            digits = value[index : index + 3]
            if len(digits) != 3 or any(item not in b"01234567" for item in digits):
                return None
            result.append(int(digits, 8))
            index += 3
            continue
        widths = {ord("x"): 2, ord("u"): 4, ord("U"): 8}
        width = widths.get(escaped)
        if width is None:
            return None
        digits = value[index + 1 : index + 1 + width]
        if len(digits) != width or not re.fullmatch(rb"[0-9A-Fa-f]+", digits):
            return None
        codepoint = int(digits, 16)
        try:
            result.extend(chr(codepoint).encode("utf-8"))
        except (ValueError, UnicodeEncodeError):
            return None
        index += width + 1
    return bytes(result)


def _code_files_hash(code_files: list[bytes]) -> str:
    normalized = [re.sub(rb"\s+", b" ", content).strip() for content in code_files]
    return hashlib.sha256(b"\n--FILE--\n".join(normalized)).hexdigest()


def _gosec_rule_cwes(path: Path) -> dict[str, str]:
    content = path.read_text(encoding="utf-8")
    block_match = re.search(r"var ruleToCWE = map\[string\]string\{(?P<body>.*?)\n\}", content, flags=re.DOTALL)
    if not block_match:
        raise RuntimeError(f"Unable to parse gosec rule-to-CWE map: {path}")
    return dict(re.findall(r'"(G\d+)"\s*:\s*"(\d+)"', block_match.group("body")))


def _semgrep_rule_cwes(root: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    roots = [root / "go", root / "problem-based-packs", root / "ai", root / "generic" / "secrets"]
    for rules_root in roots:
        if not rules_root.is_dir():
            continue
        for path in rules_root.rglob("*.yaml"):
            try:
                payload = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
            except yaml.YAMLError:
                continue
            for rule in payload.get("rules") or []:
                rule_id = str(rule.get("id") or "")
                values = (rule.get("metadata") or {}).get("cwe") or []
                if not isinstance(values, list):
                    values = [values]
                cwes = {
                    str(int(match.group(1)))
                    for value in values
                    if (match := _CWE_RE.search(str(value)))
                }
                if rule_id and cwes:
                    result[rule_id] = sorted(cwes, key=int)
    return result


def _is_semgrep_security_path(relative: str) -> bool:
    normalized = f"/{relative}"
    return any(
        marker in normalized
        for marker in ("/security/", "/audit/", "/secrets/", "/problem-based-packs/", "/ai-best-practices/")
    )


def _annotation_target_line(lines: list[str], annotation_line: int, comment_start: int) -> int | None:
    if lines[annotation_line - 1][:comment_start].strip():
        return annotation_line
    index = annotation_line
    while index < len(lines) and (not lines[index].strip() or lines[index].lstrip().startswith("//")):
        index += 1
    return index + 1 if index < len(lines) else None


def _safe_case_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _cwe_sort_key(value: str) -> int:
    match = re.search(r"(\d+)", value)
    return int(match.group(1)) if match else 0


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
