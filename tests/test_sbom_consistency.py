from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agent.task_agent import TaskAgentGraph, collect_project_sbom
from app.dependencies import (
    parse_code_dependencies,
    read_project_identities,
    scan_dependency_attachments,
    split_dependency_layers,
)
from app.language_support import language_for_file
from app.langgraph.sbom_graph import ProjectSBOMSubgraph

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.demo</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.10</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
"""

APP_JAVA = """
package com.example.demo;
import com.example.demo.util.Helper;
import com.google.gson.Gson;
import com.squareup.okhttp3.OkHttpClient;
import org.apache.commons.lang3.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
public class App { }
"""

HELPER_JAVA = """
package com.example.demo.util;
import io.jsonwebtoken.Jwts;
public class Helper { }
"""

DECLARED_GROUND_TRUTH = {
    ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10"),
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
}

EXPECTED_INFERRED = {
    ("Maven", "com.google.gson"),
    ("Maven", "com.squareup.okhttp3"),
    ("Maven", "org.apache.commons:commons-lang3"),
    ("Maven", "io.jsonwebtoken"),
}


def _write_demo_project(root: Path) -> None:
    (root / "pom.xml").write_text(POM, encoding="utf-8")
    src = root / "src" / "main" / "java" / "com" / "example" / "demo"
    (src / "util").mkdir(parents=True)
    (src / "App.java").write_text(APP_JAVA, encoding="utf-8")
    (src / "util" / "Helper.java").write_text(HELPER_JAVA, encoding="utf-8")


def _declared_set(scan: dict) -> set[tuple[str, str, str]]:
    return {
        (str(item.get("ecosystem")), str(item.get("name")), str(item.get("version")))
        for item in scan.get("dependencies") or []
    }


def _inferred_set(scan: dict) -> set[tuple[str, str]]:
    return {
        (str(item.get("ecosystem")), str(item.get("name")))
        for item in scan.get("inferred_dependencies") or []
    }


def fake_language_scanner(language, attachments, _dependency_scan, rules, cancelled):
    if cancelled():
        raise RuntimeError("cancelled")
    source_files = [
        item
        for item in attachments
        if language_for_file(str(item.get("file_name") or "")) == language
    ]
    count = len(source_files)
    return {
        "status": "completed",
        "mode": "test",
        "syntax_summary": {
            "languages": [language],
            "parsed_files": count,
            "parse_error_files": 0,
            "ast_node_count": count * 10,
            "cfg_node_count": count * 2,
            "cfg_edge_count": count,
            "dfg_edge_count": count,
        },
        "findings": [],
        "finding_count": 0,
        "diagnostics": [],
        "rules": rules,
    }


class ProjectIdentityTests(unittest.TestCase):
    def test_pom_group_id_is_extracted_as_identity(self) -> None:
        identities = read_project_identities([{"file_name": "pom.xml", "content": POM}])

        self.assertIn("com.example.demo", identities)

    def test_package_json_go_mod_and_pyproject_identities(self) -> None:
        identities = read_project_identities(
            [
                {"file_name": "package.json", "content": '{"name": "@scope/web-app"}'},
                {"file_name": "go.mod", "content": "module example.com/team/service\n"},
                {"file_name": "pyproject.toml", "content": '[project]\nname = "my-service"\n'},
            ]
        )

        self.assertIn("@scope/web-app", identities)
        self.assertIn("example.com/team/service", identities)
        self.assertIn("my-service", identities)
        self.assertIn("my_service", identities)

    def test_pom_group_id_falls_back_to_parent(self) -> None:
        child_pom = POM.replace(
            "  <groupId>com.example.demo</groupId>\n",
            "  <parent>\n    <groupId>com.example.platform</groupId>\n"
            "    <artifactId>parent</artifactId>\n    <version>1.0</version>\n  </parent>\n",
        )
        identities = read_project_identities([{"file_name": "module/pom.xml", "content": child_pom}])

        self.assertIn("com.example.platform", identities)


class JvmFallbackTests(unittest.TestCase):
    def test_class_names_are_stripped_from_fallback_group(self) -> None:
        facts = parse_code_dependencies("Helper.java", "import io.jsonwebtoken.Jwts;\n")

        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].name, "io.jsonwebtoken")
        self.assertEqual(facts[0].confidence, "low")

    def test_static_import_method_segments_are_stripped(self) -> None:
        facts = parse_code_dependencies(
            "Helper.java",
            "import static com.example.demo.util.Helpers.isBlank;\n",
        )

        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].name, "com.example.demo")

    def test_known_mapping_stays_medium_confidence(self) -> None:
        facts = parse_code_dependencies("App.java", "import com.fasterxml.jackson.databind.ObjectMapper;\n")

        self.assertEqual(facts[0].name, "com.fasterxml.jackson.core:jackson-databind")
        self.assertEqual(facts[0].confidence, "medium")


class DependencyLayerSplitTests(unittest.TestCase):
    def test_self_references_are_dropped_from_inferred_layer(self) -> None:
        dependencies = [
            {"ecosystem": "Maven", "name": "com.example.demo", "source_type": "code", "version": ""},
            {"ecosystem": "Maven", "name": "com.google.gson", "source_type": "code", "version": ""},
            {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "source_type": "pom", "version": "2.14.1"},
        ]

        declared, inferred = split_dependency_layers(dependencies, ["com.example.demo"])

        self.assertEqual([item["name"] for item in declared], ["org.apache.logging.log4j:log4j-core"])
        self.assertEqual([item["name"] for item in inferred], ["com.google.gson"])
        self.assertEqual(declared[0]["layer"], "declared")
        self.assertEqual(inferred[0]["layer"], "inferred")

    def test_own_group_manifest_entries_are_dropped_from_declared_layer(self) -> None:
        dependencies = [
            {"ecosystem": "Maven", "name": "org.apache.kafka:kafka-streams", "source_type": "gradle", "version": "3.9.2"},
            {"ecosystem": "Maven", "name": "com.example.demo:module-a", "source_type": "pom", "version": "1.0.0"},
            {"ecosystem": "Maven", "name": "org.slf4j:slf4j-api", "source_type": "gradle", "version": "1.7.36"},
        ]

        declared, inferred = split_dependency_layers(dependencies, ["org.apache.kafka", "com.example"])

        self.assertEqual([item["name"] for item in declared], ["org.slf4j:slf4j-api"])
        self.assertEqual(inferred, [])


class CollectProjectSBOMTests(unittest.TestCase):
    def test_declared_layer_matches_manifest_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_demo_project(root)

            scan = collect_project_sbom(root)

        self.assertEqual(_declared_set(scan), DECLARED_GROUND_TRUTH)
        self.assertEqual(scan["dependency_count"], 2)
        self.assertTrue(all(item["layer"] == "declared" for item in scan["dependencies"]))

    def test_self_package_never_appears_in_any_layer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_demo_project(root)

            scan = collect_project_sbom(root)

        all_names = {item["name"] for item in scan["dependencies"]} | {
            item["name"] for item in scan["inferred_dependencies"]
        }
        self.assertFalse(any(name == "com.example.demo" or name.startswith("com.example.demo.") for name in all_names))

    def test_inferred_layer_keeps_third_party_imports_without_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_demo_project(root)

            scan = collect_project_sbom(root)

        self.assertEqual(_inferred_set(scan), EXPECTED_INFERRED)
        for item in scan["inferred_dependencies"]:
            self.assertEqual(item["layer"], "inferred")
            self.assertEqual(item["version"], "")
        # jackson 的 import 已映射回清单声明组件，不会重复出现在 inferred 层。
        self.assertNotIn(("Maven", "com.fasterxml.jackson.core:jackson-databind"), _inferred_set(scan))

    def test_collection_ignores_workspace_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_demo_project(root)

            with (
                patch("app.agent.task_agent.MAX_WORKSPACE_FILES", 1),
                patch("app.agent.task_agent.MAX_WORKSPACE_MANIFEST_FILES", 1),
                patch("app.agent.task_agent.MAX_WORKSPACE_TOTAL_BYTES", 64),
            ):
                scan = collect_project_sbom(root)

        self.assertEqual(_declared_set(scan), DECLARED_GROUND_TRUTH)
        self.assertGreaterEqual(int(scan["inventory"]["source_files"]), 2)

    def test_single_file_workspace_stays_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "requirements.txt"
            selected.write_text("requests==2.32.4\n", encoding="utf-8")
            (root / "sibling.py").write_text("import flask\n", encoding="utf-8")

            scan = collect_project_sbom(selected)

        self.assertEqual(scan["dependency_count"], 1)
        self.assertEqual(scan["dependencies"][0]["name"], "requests")
        self.assertEqual(scan["inferred_count"], 0)


class GradleCentralizedMapTests(unittest.TestCase):
    DEPENDENCIES_GRADLE = """
ext {
  versions = [:]
  libs = [:]
}

def defaultScala213Version = '2.13.18'
versions["scala"] = defaultScala213Version

versions += [
  activation: "1.1.1",
  commonsValidator: "1.10.1",
  checkstyle: project.hasProperty('checkstyleVersion') ? checkstyleVersion : "12.2.0",
  slf4j: "1.7.36",
]

libs += [
  activation: "javax.activation:activation:$versions.activation",
  commonsValidator: "commons-validator:commons-validator:$versions.commonsValidator",
  checkstyle: "com.puppycrawl.tools:checkstyle:$versions.checkstyle",
  scalaLib: "org.scala-lang:scala-library:$versions.scala",
  slf4jApi: "org.slf4j:slf4j-api:$versions.slf4j",
  slf4jReload4j: "org.slf4j:slf4j-reload4j:$versions.slf4j",
]
"""

    BUILD_GRADLE = """
dependencies {
    implementation libs.commonsValidator
    implementation libs.slf4jApi
    compileOnly libs.activation
    annotationProcessor libs.checkstyle
    implementation libs.scalaLib
    implementation project(':clients')
    testImplementation libs.slf4jReload4j
}
"""

    def _scan(self) -> dict:
        return scan_dependency_attachments(
            [
                {"file_name": "gradle/dependencies.gradle", "content": self.DEPENDENCIES_GRADLE},
                {"file_name": "build.gradle", "content": self.BUILD_GRADLE},
            ],
            max_dependencies=None,
            include_all_attachments=True,
        )

    def test_libs_accessors_resolve_with_versions(self) -> None:
        by_name = {item["name"]: item for item in self._scan()["dependencies"]}

        self.assertEqual(by_name["commons-validator:commons-validator"]["version"], "1.10.1")
        self.assertEqual(by_name["org.slf4j:slf4j-api"]["version"], "1.7.36")
        self.assertEqual(by_name["org.slf4j:slf4j-reload4j"]["version"], "1.7.36")
        self.assertEqual(by_name["javax.activation:activation"]["version"], "1.1.1")
        for item in by_name.values():
            self.assertEqual(item["source_type"], "gradle")
            self.assertEqual(item["confidence"], "high")

    def test_ternary_version_falls_back_to_quoted_default(self) -> None:
        by_name = {item["name"]: item for item in self._scan()["dependencies"]}

        self.assertEqual(by_name["com.puppycrawl.tools:checkstyle"]["version"], "12.2.0")

    def test_bracket_assignment_resolves_def_variable(self) -> None:
        by_name = {item["name"]: item for item in self._scan()["dependencies"]}

        self.assertEqual(by_name["org.scala-lang:scala-library"]["version"], "2.13.18")

    def test_internal_project_modules_are_not_components(self) -> None:
        names = {item["name"] for item in self._scan()["dependencies"]}

        self.assertFalse(any("clients" in name for name in names))
        self.assertEqual(len(names), 6)


class ScanFlowConsistencyTests(unittest.TestCase):
    def test_complete_scan_and_sbom_scan_share_the_same_component_basis(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_demo_project(root)

            complete = TaskAgentGraph(language_scanner=fake_language_scanner).invoke(
                task_id="task-sbom-consistency",
                objective="scan demo project",
                workspace_path=str(root),
                user_id="analyst",
            )
            sbom_state = ProjectSBOMSubgraph._extract_dependencies(
                {"workspace_path": str(root), "trace": []}
            )

        complete_scan = complete["dependency_scan"]
        sbom_scan = sbom_state["dependency_scan"]
        self.assertEqual(_declared_set(complete_scan), DECLARED_GROUND_TRUTH)
        self.assertEqual(_declared_set(complete_scan), _declared_set(sbom_scan))
        self.assertEqual(_inferred_set(complete_scan), _inferred_set(sbom_scan))
        self.assertEqual(complete["result"]["dependency_count"], 2)
        self.assertEqual(complete["result"]["inferred_dependency_count"], len(EXPECTED_INFERRED))

    def test_adaptive_switch_does_not_change_sbom_basis(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_demo_project(root)

            frozen = TaskAgentGraph(language_scanner=fake_language_scanner).invoke(
                task_id="evaluation-sbom-consistency",
                objective="scan demo project frozen",
                workspace_path=str(root),
                user_id="evaluation",
            )
            upload = TaskAgentGraph(
                language_scanner=fake_language_scanner,
                adaptive_upload=True,
            ).invoke(
                task_id="task-sbom-consistency-upload",
                objective="scan demo project upload",
                workspace_path=str(root),
                user_id="analyst",
            )

        self.assertEqual(
            _declared_set(frozen["dependency_scan"]),
            _declared_set(upload["dependency_scan"]),
        )
        self.assertEqual(_declared_set(frozen["dependency_scan"]), DECLARED_GROUND_TRUTH)


if __name__ == "__main__":
    unittest.main()
