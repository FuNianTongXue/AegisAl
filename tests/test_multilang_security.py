from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.dependencies import scan_dependency_attachments
from app.language_support import _macro_compatibility_source, analyze_source_structure, supported_flow_languages
from app.semgrep_tool import SemgrepTool
from scripts.score_labeled_security_corpus import binomial_upper_bound, zero_event_upper_bound


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test-fixtures" / "multilang-security"


class MultiLanguageSyntaxTests(unittest.TestCase):
    def test_zero_event_sample_floor_supports_half_percent_upper_bound(self) -> None:
        self.assertGreater(zero_event_upper_bound(597), 0.005)
        self.assertLess(zero_event_upper_bound(598), 0.005)
        self.assertGreater(binomial_upper_bound(1, 598), 0.005)

    def test_tree_sitter_parses_every_supported_flow_language(self) -> None:
        samples = {
            "sample.py": "def run(value):\n    if value:\n        result = value\n        return result\n",
            "sample.go": 'package sample\nfunc run(value string) string { result := value; if result != "" { return result }; return "" }',
            "sample.c": "int run(int value) { int result = value; if (result) { return result; } return 0; }",
            "sample.cpp": "class Demo { public: int run(int value) { int result = value; return result ? 1 : 0; } };",
            "sample.cs": "class Demo { public int Run(int value) { var result = value; return result > 0 ? 1 : 0; } }",
            "sample.rs": "fn run(value: bool) -> bool { let result = value; if result { true } else { false } }",
            "sample.sol": "pragma solidity ^0.8.20; contract Demo { function run(bool value) public { bool result = value; if (result) { return; } } }",
        }

        analyses = [analyze_source_structure(name, source) for name, source in samples.items()]

        self.assertEqual(set(supported_flow_languages()), {"java", "python", "go", "c", "cpp", "csharp", "rust", "solidity"})
        self.assertTrue(all(item["parser"] == "tree-sitter" for item in analyses))
        self.assertTrue(all(not item["parse_error"] for item in analyses))
        self.assertTrue(all(item["ast_node_count"] > 0 for item in analyses))
        self.assertTrue(all(item["cfg_node_count"] > 0 for item in analyses))
        self.assertTrue(all(item["cfg_edge_count"] > 0 for item in analyses))
        self.assertTrue(all(item["dfg_edge_count"] > 0 for item in analyses))
        self.assertTrue(all(item["ast_graph"]["nodes"] and item["ast_graph"]["edges"] for item in analyses))
        self.assertTrue(all(item["cfg_graph"]["nodes"] and item["cfg_graph"]["edges"] for item in analyses))
        self.assertTrue(all(item["dfg_graph"]["nodes"] and item["dfg_graph"]["edges"] for item in analyses))

    def test_cfg_records_distinct_true_and_false_branches(self) -> None:
        analysis = analyze_source_structure(
            "sample.py",
            "def run(value):\n    if value:\n        return 1\n    else:\n        return 2\n",
        )
        branches = [edge for edge in analysis["cfg_graph"]["edges"] if edge["kind"].startswith("branch_")]

        self.assertEqual({edge["kind"] for edge in branches}, {"branch_true", "branch_false"})
        self.assertEqual(len({edge["to"] for edge in branches}), 2)

    def test_parser_compatibility_preserves_valid_macro_and_contextual_syntax(self) -> None:
        c_analysis = analyze_source_structure(
            "firmware.c",
            "STATIC\nEFI_STATUS\nEFIAPI\nRun (IN CHAR16 *Value OPTIONAL) { return 0; }\n",
        )
        cpp_analysis = analyze_source_structure(
            "display.cpp",
            "#if not FEATURE_ENABLED\nint value = 1;\n#endif\n",
        )
        csharp_analysis = analyze_source_structure(
            "layout.cs",
            "class Layout { void Run() { var required = 0.0; required += this.Width; } double Width; }",
        )
        header_analysis = analyze_source_structure(
            "box.h",
            "template<class T> class Box { T value; };",
            language_hint="cpp",
        )

        self.assertTrue(all(not item["parse_error"] for item in (c_analysis, cpp_analysis, csharp_analysis, header_analysis)))
        self.assertEqual(header_analysis["language"], "cpp")

    def test_parser_compatibility_recovers_macro_namespaces_and_conditional_declarations(self) -> None:
        macro_analysis = analyze_source_structure(
            "macro.hpp",
            """
#define DEMO_NS namespace demo {
#define DEMO_NS_END }
DEMO_NS
class DEMO_EXPORT Service {
    DEMO_DECLARE_MEMBERS(
        Service
    )
public:
    int Run() { return 1; }
};
DEMO_NS_END
""",
        )
        conditional_analysis = analyze_source_structure(
            "conditional.c",
            """
int run(
#if FEATURE_ENABLED
    int value
#else
    void
#endif
) { return 0; }
""",
        )
        windows_analysis = analyze_source_structure(
            "windows.c",
            "BOOL WINAPI Run(HANDLE value) { return value != 0; }\n",
        )

        self.assertTrue(all(not item["parse_error"] for item in (macro_analysis, conditional_analysis, windows_analysis)))
        self.assertTrue(all(item["recovered_parse_error"] for item in (macro_analysis, conditional_analysis, windows_analysis)))
        self.assertNotEqual(macro_analysis["parser_mode"], "native")

    def test_cpp_parser_uses_cuda_grammar_for_cuda_extensions(self) -> None:
        analysis = analyze_source_structure(
            "kernel.hpp",
            "__global__ void kernel(int *values) { values[threadIdx.x] = 1; }\n",
            language_hint="cpp",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertEqual(analysis["parser_mode"], "cuda-fallback")

    def test_parser_compatibility_recovers_windows_sal_and_qt_extensions(self) -> None:
        sal_analysis = analyze_source_structure(
            "driver.c",
            """
NTSTATUS NTAPI Run(
    _In_ HANDLE value,
    _Out_writes_bytes_(size) char *out,
    size_t size
) { return value != 0 && out != 0; }

ALIGNED BOOL Duplicate(HANDLE value) { return value != 0; }
""",
        )
        qt_analysis = analyze_source_structure(
            "widget.cpp",
            """
class Demo : public QObject {
    Q_OBJECT public slots: void run();
signals: void changed();
    void dispatch() { emit changed(); }
};
""",
        )

        self.assertTrue(all(not item["parse_error"] for item in (sal_analysis, qt_analysis)))
        self.assertTrue(all(item["recovered_parse_error"] for item in (sal_analysis, qt_analysis)))
        self.assertIn("Run", sal_analysis["functions"])
        self.assertIn("Duplicate", sal_analysis["functions"])
        self.assertIn("Demo", qt_analysis["types"])

    def test_parser_compatibility_recovers_gnu_attribute_declarators(self) -> None:
        analysis = analyze_source_structure(
            "netfilter.c",
            """
int send_request(void) {
    char buf[1024] __attribute__ ((aligned));
    return sizeof(buf);
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("send_request", analysis["functions"])

    def test_parser_compatibility_recovers_gnu_computed_goto(self) -> None:
        analysis = analyze_source_structure(
            "lzvn.c",
            """
void decode(unsigned char opc) {
#if HAVE_LABELS_AS_VALUES
    static const void *opc_tbl[2] = { &&sml_d, &&invalid_match_distance };
    goto *opc_tbl[opc];
#else
    for (;;) {
      switch (opc) {
#endif
sml_d:
    return;
invalid_match_distance:
    return;
#if !HAVE_LABELS_AS_VALUES
      }
    }
#endif
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("decode", analysis["functions"])

    def test_parser_compatibility_recovers_bsd_timecmp_operator_macros(self) -> None:
        analysis = analyze_source_structure(
            "pcap-dos.c",
            """
struct timeval now;
struct timeval expiry;
int wait_for_packet(void) {
    if (timercmp(&now, &expiry, >))
       return 1;
    if (timespeccmp(&now, &expiry, <=))
       return 2;
    return 0;
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("wait_for_packet", analysis["functions"])

    def test_parser_compatibility_recovers_win32_calling_convention_annotations(self) -> None:
        analysis = analyze_source_structure(
            "area.cpp",
            """
static LRESULT CALLBACK areaWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("areaWndProc", analysis["functions"])

    def test_parser_compatibility_recovers_unused_annotations_and_statement_macros(self) -> None:
        analysis = analyze_source_structure(
            "gdns.c",
            """
static void dns_worker (void GO_UNUSED (*ptr_data)) {
    if (ptr_data)
        FATAL("unexpected pointer")
}

void geoip_get_country(char *location, GO_UNUSED GTypeIP type_ip) {}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("dns_worker", analysis["functions"])
        self.assertIn("geoip_get_country", analysis["functions"])

    def test_parser_compatibility_recovers_va_arg_type_arguments(self) -> None:
        analysis = analyze_source_structure(
            "snprintf.c",
            """
void append_format(void) {
    int ch = va_arg(ap, unsigned char*);
    void *ptr = va_arg(ap, void*);
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("append_format", analysis["functions"])

    def test_parser_compatibility_recovers_statement_and_foreach_macros(self) -> None:
        analysis = analyze_source_structure(
            "gstorage.c",
            """
void map_data(void) {
    CHECKLEN(p + 1, base->np)
    np = base->np;
    FOREACH_MODULE (idx, module_list) {
        module = module_list[idx];
    }
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("map_data", analysis["functions"])

    def test_parser_compatibility_recovers_dos_far_pointer_qualifiers(self) -> None:
        analysis = analyze_source_structure(
            "pktdrvr.c",
            """
typedef int BOOL;
typedef int BYTE;
typedef int RX_ELEMENT;
extern void far PktReceiver (void);
LOCAL __inline BOOL CheckElement (RX_ELEMENT _far *rx)
{
    return 1;
}
PUBLIC int PktReceive (BYTE *buf, int max)
{
    RX_ELEMENT far *head = (RX_ELEMENT far*) MK_FP (_DS, rxOutOfs);
    return CheckElement(head);
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("CheckElement", analysis["functions"])
        self.assertIn("PktReceive", analysis["functions"])

    def test_parser_compatibility_combines_preprocessor_and_compiler_extension_views(self) -> None:
        analysis = analyze_source_structure(
            "print-isakmp.c",
            """
void parse_payload(void) {
#if UNKNOWN_FEATURE
    if (
#else
    CHECKLEN(p + 1, base->np)
#endif
    np = base->np;
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertEqual(analysis["parser_mode"], "preprocessor-else+compiler-extensions")
        self.assertIn("parse_payload", analysis["functions"])

    def test_parser_compatibility_recovers_cpp_new_pointer_arrays(self) -> None:
        analysis = analyze_source_structure(
            "c-api.cc",
            """
struct Result { int count; };
void Decode(Result *r, int total_length) {
    char *tokens = new char[total_length]{};
    char **tokens_temp = new char *[r->count];
    tokens_temp[0] = tokens;
}
SHERPA_ONNX_API void SherpaMnnWriteWaveToBuffer(const float *samples,
                                                int n,
                                                char *buffer) {
    buffer[0] = 0;
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("Decode", analysis["functions"])
        self.assertIn("SherpaMnnWriteWaveToBuffer", analysis["functions"])

    def test_parser_compatibility_recovers_uefi_variable_name_string_macros(self) -> None:
        analysis = analyze_source_structure(
            "BdsEntry.c",
            """
typedef unsigned short CHAR16;
CHAR16 *mReadOnlyVariables[] = {
    EFI_PLATFORM_LANG_CODES_VARIABLE_NAME
    EFI_LANG_CODES_VARIABLE_NAME,
    EFI_BOOT_OPTION_SUPPORT_VARIABLE_NAME,
    EFI_OS_INDICATIONS_SUPPORT_VARIABLE_NAME
};
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertGreater(analysis["ast_node_count"], 0)

    def test_parser_compatibility_keeps_macro_calls_in_expression_continuations(self) -> None:
        analysis = analyze_source_structure(
            "pcap-netfilter-linux.c",
            """
int f(int type) {
    char buf[1024] __attribute__((aligned));
    if (NFNL_SUBSYS_ID(type) == NFNL_SUBSYS_ULOG &&
        NFNL_MSG_TYPE(type) == NFULNL_MSG_PACKET)
        return 1;
    return buf[0];
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertEqual(analysis["parser_mode"], "compiler-extensions")
        self.assertIn("f", analysis["functions"])

    def test_macro_compatibility_keeps_standalone_macro_arguments(self) -> None:
        source = b"""
void f(void) {
    Result = AsciiStrCmp (
               MachoGetSymbolName (&Context, Symbol),
               KXLD_WEAK_TEST_SYMBOL
               );
    FATAL_ERROR()
}
"""

        masked = _macro_compatibility_source("c", source)

        self.assertIn(b"KXLD_WEAK_TEST_SYMBOL", masked)
        self.assertNotIn(b"FATAL_ERROR()", masked)

    def test_parser_compatibility_recovers_flex_action_macros_after_case_labels(self) -> None:
        analysis = analyze_source_structure(
            "scanner.c",
            """
int yylex(int yy_act) {
    switch (yy_act) {
case 1:
YY_RULE_SETUP
return DST;
    YY_BREAK
default:
YY_RULE_SETUP
return 0;
    }
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("yylex", analysis["functions"])

    def test_parser_compatibility_recovers_adjacent_string_macros(self) -> None:
        analysis = analyze_source_structure(
            "websocket.c",
            """
void respond(void) {
    ws_append_str(&str, CRLF CRLF);
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("respond", analysis["functions"])

    def test_parser_compatibility_recovers_c_type_argument_macros(self) -> None:
        analysis = analyze_source_structure(
            "attrlist.c",
            """
struct attr { int end; };
typedef struct child uiprivChild;
struct list { int pages; };
void run(struct list *t) {
    struct attr *a;
    uiprivChild *page;
    a = uiprivNew(struct attr);
    page = g_array_index(t->pages, uiprivChild *, 0);
    a = g_new0(struct attr, 1);
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertIn("run", analysis["functions"])

    def test_parser_compatibility_recovers_libui_and_glib_declaration_macros(self) -> None:
        button_analysis = analyze_source_structure(
            "button.c",
            """
struct uiButton { int x; };
uiUnixControlAllDefaults(uiButton)

static void onClicked(void) {}
""",
        )
        table_analysis = analyze_source_structure(
            "table.c",
            """
struct uiTable { int x; };
uiUnixDefineControl(
    uiTable // type name
)

void uiTableSetModel(void) {}
""",
        )
        glib_analysis = analyze_source_structure(
            "tablemodel.c",
            """
typedef int GtkTreeModelIface;
static void uiTableModel_treeModel_init(GtkTreeModelIface *);
G_DEFINE_TYPE_WITH_CODE(uiTableModel, uiTableModel, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(GTK_TYPE_TREE_MODEL, uiTableModel_treeModel_init))

static void uiTableModel_init(void) {}
""",
        )

        self.assertTrue(all(not item["parse_error"] for item in (button_analysis, table_analysis, glib_analysis)))
        self.assertTrue(all(item["recovered_parse_error"] for item in (button_analysis, table_analysis, glib_analysis)))
        self.assertIn("onClicked", button_analysis["functions"])
        self.assertIn("uiTableSetModel", table_analysis["functions"])
        self.assertIn("uiTableModel_init", glib_analysis["functions"])

    def test_parser_compatibility_normalizes_libpcap_unused_annotations(self) -> None:
        analysis = analyze_source_structure(
            "pcap.c",
            """
typedef int YY_BUFFER_STATE;
static int pcap_inject_acn(pcap_t *p _U_, const void *buf _U_, size_t size _U_) {
    return 0;
}
YY_BUFFER_STATE pcap__scan_string (yyconst char *yy_str);
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertEqual(analysis["parser_mode"], "native")
        self.assertIn("pcap_inject_acn", analysis["functions"])

    def test_parser_compatibility_normalizes_zlib_of_prototypes(self) -> None:
        analysis = analyze_source_structure(
            "inflate.c",
            """
typedef struct inflate_state inflate_state;
typedef int block_state;
typedef block_state (*compress_func) OF((inflate_state *state, int flush));
local void fixedtables OF((struct inflate_state FAR *state));
int inflate(void) { return 0; }
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertEqual(analysis["parser_mode"], "native")
        self.assertIn("inflate", analysis["functions"])

    def test_parser_compatibility_normalizes_legacy_kr_function_definitions(self) -> None:
        analysis = analyze_source_structure(
            "legacy.c",
            """
static char *
sdup(s)
    register const char *s;
{
    return (char *)s;
}

static char *
any(cp, match)
    char *cp;
    char *match;
{
    return cp ? match : 0;
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertEqual(analysis["parser_mode"], "native")
        self.assertIn("sdup", analysis["functions"])
        self.assertIn("any", analysis["functions"])

    def test_parser_compatibility_normalizes_uefi_debug_code_blocks(self) -> None:
        analysis = analyze_source_structure(
            "uefi.c",
            """
void expand(void) {
    int Index = 0;
    DEBUG_CODE (
      for (Index = 0; Index < 1; Index++) {
        DEBUG ((DEBUG_VERBOSE, "accepted %d\\n", Index));
      }
      );
    Index++;
}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertEqual(analysis["parser_mode"], "native")
        self.assertIn("expand", analysis["functions"])

    def test_parser_compatibility_normalizes_opencore_declaration_macros(self) -> None:
        analysis = analyze_source_structure(
            "OcConfigurationLib.c",
            """
#include <Library/OcConfigurationLib.h>

OC_STRUCTORS (OC_ACPI_ADD_ENTRY, ())
OC_ARRAY_STRUCTORS (OC_ACPI_ADD_ARRAY)
OC_MAP_STRUCTORS (OC_DEV_PROP_ADD_MAP)

void OcConfigurationInit(void) {}
void OcConfigurationFree(void) {}
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertEqual(analysis["parser_mode"], "native")
        self.assertIn("OcConfigurationInit", analysis["functions"])
        self.assertIn("OcConfigurationFree", analysis["functions"])

    def test_parser_compatibility_normalizes_cpp_using_declaration_lists(self) -> None:
        analysis = analyze_source_structure(
            "btop_collect.cpp",
            """
#include <algorithm>
using std::clamp, std::string_literals::operator""s, std::cmp_equal, std::round;
int collect() { return 0; }
""",
        )

        self.assertFalse(analysis["parse_error"])
        self.assertEqual(analysis["parser_mode"], "native")
        self.assertIn("collect", analysis["functions"])

    def test_parser_compatibility_uses_compile_command_definitions(self) -> None:
        analysis = analyze_source_structure(
            "feature.c",
            """
int run(
#ifdef FEATURE_ENABLED
    int value
#else
    void
#endif
) { return 0; }
""",
            preprocessor_definitions={"FEATURE_ENABLED": "1"},
        )

        self.assertFalse(analysis["parse_error"])
        self.assertTrue(analysis["recovered_parse_error"])
        self.assertEqual(analysis["parser_mode"], "preprocessor-defs")
        self.assertEqual(analysis["preprocessor_definition_count"], 1)

    def test_external_go_qualification_manifest_is_balanced_and_unique(self) -> None:
        manifest = json.loads(
            (ROOT / "config" / "evaluation" / "go-external-random-598x2-2026-07-24-v2.json").read_text(
                encoding="utf-8"
            )
        )
        cases = [case for case in manifest["cases"] if case["partition"] == "qualification"]
        positives = [case for case in cases if case["vulnerable"]]
        negatives = [case for case in cases if not case["vulnerable"]]

        self.assertEqual(len(positives), 598)
        self.assertEqual(len(negatives), 598)
        self.assertEqual(len({case["id"] for case in cases}), 1196)
        self.assertEqual({case["source"] for case in cases}, {"securego/gosec", "semgrep/semgrep-rules"})
        self.assertEqual(manifest["methodology"]["negative_label_scope"], "external_rule_specific")

    def test_project_manifests_are_recognized_across_new_languages(self) -> None:
        result = scan_dependency_attachments(
            [
                {"file_name": "requirements.txt", "content": "requests==2.32.4\n"},
                {"file_name": "go.mod", "content": "module example.test/app\nrequire github.com/gin-gonic/gin v1.10.0\n"},
                {"file_name": "vcpkg.json", "content": '{"dependencies":[{"name":"openssl","version>=":"3.3.0"}]}'},
                {"file_name": "Cargo.toml", "content": '[dependencies]\nreqwest = "0.12.5"\n'},
                {"file_name": "package.json", "content": '{"dependencies":{"@openzeppelin/contracts":"5.0.2"}}'},
                {"file_name": "app.csproj", "content": '<Project><ItemGroup><PackageReference Include="Dapper" Version="2.1.66" /></ItemGroup></Project>'},
            ]
        )
        dependencies = {(item["ecosystem"], item["name"]): item["version"] for item in result["dependencies"]}

        self.assertEqual(dependencies[("PyPI", "requests")], "2.32.4")
        self.assertEqual(dependencies[("Go", "github.com/gin-gonic/gin")], "v1.10.0")
        self.assertEqual(dependencies[("vcpkg", "openssl")], "3.3.0")
        self.assertEqual(dependencies[("crates.io", "reqwest")], "0.12.5")
        self.assertEqual(dependencies[("npm", "@openzeppelin/contracts")], "5.0.2")
        self.assertEqual(dependencies[("NuGet", "Dapper")], "2.1.66")

    def test_semgrep_tool_skips_archive_materialized_symlink_source_stubs(self) -> None:
        tool = SemgrepTool()

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = tool.analyze(
                [
                    {
                        "file_name": "apps/frameworks/sherpa-mnn/c-api-examples/asr-microphone-example/alsa.cc",
                        "content": "../../sherpa-onnx/csrc/alsa.cc",
                    },
                    {"file_name": "src/main.cc", "content": "int main() { return 0; }\n"},
                ],
                {"files": [], "dependencies": []},
                [],
            )

        self.assertEqual([item["file_name"] for item in result["files"]], ["src/main.cc"])
        self.assertEqual(result["syntax_summary"]["parse_error_file_names"], [])
        self.assertEqual(result["syntax_summary"]["parsed_files"], 1)


class MultiLanguageRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.semgrep = Path(sys.executable).with_name("semgrep")
        if not cls.semgrep.is_file():
            raise unittest.SkipTest("Semgrep executable is not installed next to the test interpreter")

    def test_labeled_multilang_smoke_corpus_has_no_false_results(self) -> None:
        ground_truth = json.loads((FIXTURES / "ground-truth.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = Path(temp_dir) / "results.json"
            completed = subprocess.run(
                [
                    str(self.semgrep),
                    "scan",
                    "--config",
                    str(ROOT / "config" / "semgrep"),
                    "--json-output",
                    str(result_path),
                    "--dataflow-traces",
                    "--metrics=off",
                    "--disable-version-check",
                    "--no-git-ignore",
                    str(FIXTURES),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
            payload = json.loads(result_path.read_text(encoding="utf-8"))

        detected = {
            (
                str(item.get("path") or "").split("multilang-security/", 1)[-1],
                "secflow." + str(item.get("check_id") or "").split("secflow.", 1)[-1],
            )
            for item in payload.get("results") or []
        }
        outcomes = []
        for item in ground_truth:
            matched = (item["file"], item["rule"]) in detected
            outcomes.append("TP" if item["vulnerable"] and matched else "FN" if item["vulnerable"] else "FP" if matched else "TN")

        self.assertEqual(outcomes.count("TP"), 16)
        self.assertEqual(outcomes.count("TN"), 16)
        self.assertEqual(outcomes.count("FP"), 0)
        self.assertEqual(outcomes.count("FN"), 0)

    def test_go_finding_contains_tree_sitter_and_semgrep_flow_evidence(self) -> None:
        source = (FIXTURES / "vulnerable" / "app.go").read_text(encoding="utf-8")
        tool = SemgrepTool(executable=str(self.semgrep))

        result = tool.analyze(
            [{"file_name": "app.go", "content": source}],
            {"files": [{"file_name": "app.go", "kind": "code"}], "dependencies": []},
            [],
        )

        self.assertEqual(result["mode"], "bundled-cli")
        self.assertEqual(result["syntax_summary"]["languages"], ["go"])
        self.assertEqual(result["syntax_summary"]["parse_error_file_names"], [])
        self.assertGreater(result["syntax_summary"]["ast_node_count"], 0)
        finding = next(item for item in result["findings"] if item["rule_id"] == "secflow.go.command-injection")
        self.assertEqual(finding["ast"]["parser"], "tree-sitter")
        self.assertIn("source", [item["kind"] for item in finding["path"]])
        self.assertIn("sink", [item["kind"] for item in finding["path"]])
        self.assertIn("→", finding["dfg"])

    def test_compile_commands_definitions_feed_tree_sitter_parser_context(self) -> None:
        tool = SemgrepTool()
        source = """
int run(
#ifdef FEATURE_ENABLED
    int value
#else
    void
#endif
) { return 0; }
"""
        compile_commands = json.dumps(
            [
                {
                    "directory": "/work/project",
                    "file": "/work/project/src/feature.c",
                    "arguments": ["clang", "-DFEATURE_ENABLED=1", "-c", "src/feature.c"],
                }
            ]
        )

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = tool.analyze(
                [
                    {"file_name": "src/feature.c", "content": source},
                    {"file_name": "build/compile_commands.json", "content": compile_commands},
                ],
                {"files": [], "dependencies": []},
                [],
            )

        syntax = result["files"][0]["syntax"]
        self.assertFalse(syntax["parse_error"])
        self.assertEqual(syntax["parser_mode"], "preprocessor-defs")
        self.assertEqual(syntax["preprocessor_definition_count"], 1)

    def test_cmake_definitions_feed_tree_sitter_parser_context(self) -> None:
        tool = SemgrepTool()
        source = """
int run(
#ifdef FEATURE_FROM_CMAKE
    int value
#else
    void
#endif
) { return 0; }
"""

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = tool.analyze(
                [
                    {"file_name": "src/feature.c", "content": source},
                    {"file_name": "CMakeLists.txt", "content": "add_compile_definitions(FEATURE_FROM_CMAKE=1)\n"},
                ],
                {"files": [], "dependencies": []},
                [],
            )

        syntax = result["files"][0]["syntax"]
        self.assertFalse(syntax["parse_error"])
        self.assertEqual(syntax["parser_mode"], "preprocessor-defs")
        self.assertEqual(syntax["preprocessor_definition_count"], 1)


if __name__ == "__main__":
    unittest.main()
