from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from app.dependencies import (
    is_allowed_attachment_name,
    parse_c_cpp_manifest_dependencies,
    parse_code_dependencies,
    parse_gradle_dependencies,
    parse_go_manifest_dependencies,
    parse_pom_dependencies,
    scan_dependency_attachments,
)
from app.graph import KnowledgeSecurityGraph, empty_knowledge_graph
from app.reports import ReportStore


class DependencyAttachmentTests(unittest.TestCase):
    def test_attachment_allowlist_accepts_pom_gradle_and_code_only(self) -> None:
        self.assertTrue(is_allowed_attachment_name("pom.xml"))
        self.assertTrue(is_allowed_attachment_name("build.gradle"))
        self.assertTrue(is_allowed_attachment_name("build.gradle.kts"))
        self.assertTrue(is_allowed_attachment_name("settings.gradle"))
        self.assertTrue(is_allowed_attachment_name("gradle/libs.versions.toml"))
        self.assertTrue(is_allowed_attachment_name("gradle.properties"))
        self.assertTrue(is_allowed_attachment_name("src/main/java/Demo.java"))
        self.assertTrue(is_allowed_attachment_name("frontend/App.tsx"))
        self.assertTrue(is_allowed_attachment_name("requirements-dev.txt"))
        self.assertTrue(is_allowed_attachment_name("requirements/base.txt"))
        self.assertTrue(is_allowed_attachment_name("src/App/App.csproj"))
        self.assertTrue(is_allowed_attachment_name("Directory.Packages.props"))
        self.assertTrue(is_allowed_attachment_name("obj/project.assets.json"))
        self.assertTrue(is_allowed_attachment_name("compile_commands.json"))
        self.assertFalse(is_allowed_attachment_name("report.pdf"))
        self.assertFalse(is_allowed_attachment_name("advisory.json"))

    def test_parse_pom_dependencies_resolves_properties(self) -> None:
        dependencies = parse_pom_dependencies(
            "pom.xml",
            """
            <project>
              <properties>
                <log4j.version>2.14.1</log4j.version>
              </properties>
              <dependencies>
                <dependency>
                  <groupId>org.apache.logging.log4j</groupId>
                  <artifactId>log4j-core</artifactId>
                  <version>${log4j.version}</version>
                </dependency>
              </dependencies>
            </project>
            """,
        )

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].ecosystem, "Maven")
        self.assertEqual(dependencies[0].name, "org.apache.logging.log4j:log4j-core")
        self.assertEqual(dependencies[0].version, "2.14.1")
        self.assertEqual(dependencies[0].confidence, "high")

    def test_go_mod_parser_only_uses_require_directives(self) -> None:
        dependencies = parse_go_manifest_dependencies(
            "go.mod",
            """
            module example.com/secflow/demo

            go 1.24

            require github.com/gin-gonic/gin v1.10.1
            require (
                golang.org/x/crypto v0.40.0
                golang.org/x/sys v0.34.0 // indirect
            )

            replace github.com/gin-gonic/gin => ../local-gin
            exclude golang.org/x/crypto v0.39.0
            retract v1.0.0
            """,
        )

        self.assertEqual(
            [(dependency.name, dependency.version) for dependency in dependencies],
            [
                ("github.com/gin-gonic/gin", "v1.10.1"),
                ("golang.org/x/crypto", "v0.40.0"),
                ("golang.org/x/sys", "v0.34.0"),
            ],
        )
        self.assertTrue(all(dependency.source_file == "go.mod" for dependency in dependencies))

    def test_dotnet_manifests_resolve_central_and_locked_nuget_versions(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "Directory.Packages.props",
                    "content": """
                    <Project><ItemGroup>
                      <PackageVersion Include="Serilog" Version="3.1.1" />
                    </ItemGroup></Project>
                    """,
                },
                {
                    "file_name": "src/App/App.csproj",
                    "content": """
                    <Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
                      <PackageReference Include="Serilog" />
                      <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
                    </ItemGroup></Project>
                    """,
                },
                {
                    "file_name": "src/App/packages.lock.json",
                    "content": """
                    {"version": 1, "dependencies": {"net8.0": {
                      "Serilog": {"type": "Direct", "requested": "[3.1.1, )", "resolved": "3.1.2"},
                      "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.3"}
                    }}}
                    """,
                },
            ]
        )
        dependencies = {(item["ecosystem"], item["name"]): item for item in result["dependencies"]}

        self.assertEqual(dependencies[("NuGet", "Serilog")]["version"], "3.1.2")
        self.assertEqual(dependencies[("NuGet", "Newtonsoft.Json")]["version"], "13.0.3")
        self.assertEqual(len(dependencies), 2)
        self.assertTrue(all(item["source_type"] == "dotnet_manifest" for item in dependencies.values()))

    def test_dotnet_manifests_inherit_directory_build_props_versions(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "Directory.Build.props",
                    "content": """
                    <Project><PropertyGroup>
                      <NewtonsoftJsonVersion>13.0.3</NewtonsoftJsonVersion>
                      <SerilogVersion>3.1.1</SerilogVersion>
                    </PropertyGroup></Project>
                    """,
                },
                {
                    "file_name": "Directory.Packages.props",
                    "content": """
                    <Project><ItemGroup>
                      <PackageVersion Include="Newtonsoft.Json" Version="$(NewtonsoftJsonVersion)" />
                    </ItemGroup></Project>
                    """,
                },
                {
                    "file_name": "src/App/App.csproj",
                    "content": """
                    <Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
                      <PackageReference Include="Newtonsoft.Json" />
                      <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
                    </ItemGroup></Project>
                    """,
                },
            ]
        )
        dependencies = {(item["ecosystem"], item["name"]): item for item in result["dependencies"]}

        self.assertEqual(dependencies[("NuGet", "Newtonsoft.Json")]["version"], "13.0.3")
        self.assertEqual(dependencies[("NuGet", "Serilog")]["version"], "3.1.1")
        self.assertEqual(len(dependencies), 2)

    def test_cmake_find_package_resolves_version_variables(self) -> None:
        dependencies = parse_c_cpp_manifest_dependencies(
            "CMakeLists.txt",
            """
            set(OPENSSL_VERSION "3.3.0")
            find_package(OpenSSL ${OPENSSL_VERSION} REQUIRED)
            find_package(ZLIB 1.3 REQUIRED)
            """,
        )
        by_name = {dependency.name: dependency for dependency in dependencies}

        self.assertEqual(by_name["OpenSSL"].ecosystem, "CMake")
        self.assertEqual(by_name["OpenSSL"].version, "3.3.0")
        self.assertEqual(by_name["ZLIB"].version, "1.3")

    def test_go_mod_is_authoritative_for_source_imports_and_sibling_go_sum(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "cmd/server/main.go",
                    "content": """
                    package main
                    import (
                        "example.com/secflow/demo/internal/server"
                        "github.com/gin-gonic/gin/binding"
                    )
                    """,
                },
                {
                    "file_name": "go.sum",
                    "content": """
                    github.com/obsolete/dependency v9.9.9 h1:old
                    github.com/gin-gonic/gin v1.9.0/go.mod h1:old
                    """,
                },
                {
                    "file_name": "go.mod",
                    "content": """
                    module example.com/secflow/demo
                    go 1.24
                    require github.com/gin-gonic/gin v1.10.1
                    """,
                },
            ]
        )

        self.assertEqual(result["files"][0], {"file_name": "go.mod", "kind": "go_manifest"})
        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "github.com/gin-gonic/gin")
        self.assertEqual(result["dependencies"][0]["version"], "v1.10.1")
        self.assertEqual(result["dependencies"][0]["source_file"], "go.mod")
        self.assertNotIn("obsolete", str(result["dependencies"]))
        self.assertNotIn("example.com/secflow/demo/internal", str(result["dependencies"]))

    def test_go_mod_is_prioritized_before_attachment_limit(self) -> None:
        attachments = [
            {
                "file_name": "000.go",
                "content": 'package demo\nimport "example.com/secflow/demo/internal/first"\n',
            },
            {
                "file_name": "001.go",
                "content": 'package demo\nimport "example.com/secflow/demo/internal/second"\n',
            },
            {
                "file_name": "go.mod",
                "content": """
                module example.com/secflow/demo
                require github.com/gin-gonic/gin v1.10.1
                """,
            },
        ]

        with patch("app.dependencies.MAX_ASK_ATTACHMENTS", 2):
            result = scan_dependency_attachments(attachments)

        self.assertEqual(result["files"][0]["file_name"], "go.mod")
        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "github.com/gin-gonic/gin")
        self.assertEqual(result["dependencies"][0]["version"], "v1.10.1")

    def test_complete_dependency_scan_ignores_attachment_and_dependency_caps(self) -> None:
        attachments = [
            {"file_name": "requirements.txt", "content": "requests==2.32.4\n"},
            {
                "file_name": "pom.xml",
                "content": """
                <project><dependencies><dependency>
                  <groupId>org.example</groupId><artifactId>payments</artifactId><version>1.0.0</version>
                </dependency></dependencies></project>
                """,
            },
            {
                "file_name": "package.json",
                "content": '{"dependencies":{"express":"5.1.0"}}',
            },
        ]

        with patch("app.dependencies.MAX_ASK_ATTACHMENTS", 2):
            bounded = scan_dependency_attachments(attachments, max_dependencies=2)
            complete = scan_dependency_attachments(
                attachments,
                max_dependencies=None,
                include_all_attachments=True,
            )

        self.assertEqual(bounded["dependency_count"], 2)
        self.assertEqual(complete["dependency_count"], 3)
        self.assertEqual({item["name"] for item in complete["dependencies"]}, {"requests", "org.example:payments", "express"})

    def test_requirements_is_authoritative_before_pyproject_and_python_imports(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "src/app.py",
                    "content": "import requests\nimport flask\n",
                },
                {
                    "file_name": "pyproject.toml",
                    "content": """
                    [project]
                    dependencies = ["requests==9.9.9", "Flask==3.1.1"]
                    """,
                },
                {
                    "file_name": "requirements.txt",
                    "content": "requests==2.32.4\n",
                },
            ]
        )

        by_name = {dependency["name"].lower(): dependency for dependency in result["dependencies"]}
        self.assertEqual(result["files"][0], {"file_name": "requirements.txt", "kind": "python_manifest"})
        self.assertEqual(result["dependency_count"], 2)
        self.assertEqual(by_name["requests"]["version"], "2.32.4")
        self.assertEqual(by_name["requests"]["source_file"], "requirements.txt")
        self.assertEqual(by_name["flask"]["version"], "3.1.1")
        self.assertEqual(by_name["flask"]["source_file"], "pyproject.toml")
        self.assertNotIn("9.9.9", str(result["dependencies"]))

    def test_code_imports_are_mapped_to_dependency_packages(self) -> None:
        dependencies = parse_code_dependencies(
            "Demo.java",
            """
            import java.util.List;
            import org.apache.logging.log4j.LogManager;
            import com.fasterxml.jackson.databind.ObjectMapper;
            """,
        )
        names = {dependency.name for dependency in dependencies}

        self.assertIn("org.apache.logging.log4j:log4j-core", names)
        self.assertIn("com.fasterxml.jackson.core:jackson-databind", names)
        self.assertNotIn("java.util", names)

    def test_multi_pom_scan_resolves_root_dependency_management_without_counting_it_as_declared(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "pom.xml",
                    "content": """
                    <project>
                      <properties><hutool.version>5.8.40</hutool.version></properties>
                      <dependencyManagement><dependencies><dependency>
                        <groupId>cn.hutool</groupId><artifactId>hutool-all</artifactId>
                        <version>${hutool.version}</version>
                      </dependency></dependencies></dependencyManagement>
                    </project>
                    """,
                },
                {
                    "file_name": "module/pom.xml",
                    "content": """
                    <project><dependencies><dependency>
                      <groupId>cn.hutool</groupId><artifactId>hutool-all</artifactId>
                    </dependency></dependencies></project>
                    """,
                },
            ]
        )

        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "cn.hutool:hutool-all")
        self.assertEqual(result["dependencies"][0]["version"], "5.8.40")
        self.assertEqual(result["dependencies"][0]["source_file"], "module/pom.xml")

    def test_spring_boot_starter_uses_explicit_parent_version(self) -> None:
        dependencies = parse_pom_dependencies(
            "pom.xml",
            """
            <project>
              <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>4.1.0</version>
              </parent>
              <dependencies><dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-actuator</artifactId>
              </dependency></dependencies>
            </project>
            """,
        )

        self.assertEqual(dependencies[0].version, "4.1.0")

    def test_module_inherits_spring_boot_parent_version_from_uploaded_root_pom(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "pom.xml",
                    "content": """
                    <project><parent>
                      <groupId>org.springframework.boot</groupId>
                      <artifactId>spring-boot-starter-parent</artifactId>
                      <version>3.5.14</version>
                    </parent></project>
                    """,
                },
                {
                    "file_name": "module/pom.xml",
                    "content": """
                    <project>
                      <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0</version></parent>
                      <dependencies><dependency>
                        <groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId>
                      </dependency></dependencies>
                    </project>
                    """,
                },
            ]
        )

        self.assertEqual(result["dependencies"][0]["version"], "3.5.14")

    def test_scan_dependency_attachments_rejects_unsupported_files(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "pom.xml",
                    "content": """
                    <project>
                      <dependencies>
                        <dependency>
                          <groupId>org.yaml</groupId>
                          <artifactId>snakeyaml</artifactId>
                          <version>1.33</version>
                        </dependency>
                      </dependencies>
                    </project>
                    """,
                },
                {"file_name": "notes.json", "content": "{}"},
            ]
        )

        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "org.yaml:snakeyaml")
        self.assertEqual(result["rejected_files"], ["notes.json"])

    def test_parse_gradle_dependencies_supports_string_and_map_notation(self) -> None:
        dependencies = parse_gradle_dependencies(
            "build.gradle",
            """
            dependencies {
                implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
                testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
                implementation group: 'org.yaml', name: 'snakeyaml', version: '1.33'
            }
            """,
        )
        by_name = {dependency.name: dependency for dependency in dependencies}

        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"].version, "2.14.1")
        self.assertEqual(by_name["org.junit.jupiter:junit-jupiter"].version, "5.10.2")
        self.assertEqual(by_name["org.yaml:snakeyaml"].version, "1.33")
        self.assertEqual(by_name["org.yaml:snakeyaml"].source_type, "gradle")
        self.assertEqual(by_name["org.yaml:snakeyaml"].confidence, "high")

    def test_parse_gradle_dependencies_resolves_variables(self) -> None:
        dependencies = parse_gradle_dependencies(
            "build.gradle",
            """
            def jacksonVersion = '2.13.0'
            dependencies {
                implementation "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
            }
            """,
        )

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].name, "com.fasterxml.jackson.core:jackson-databind")
        self.assertEqual(dependencies[0].version, "2.13.0")

    def test_gradle_version_catalog_accessors_resolve_to_dependencies(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "gradle/libs.versions.toml",
                    "content": """
                    [versions]
                    log4j = "2.14.1"

                    [libraries]
                    log4j-core = { module = "org.apache.logging.log4j:log4j-core", version.ref = "log4j" }
                    junit-jupiter = { group = "org.junit.jupiter", name = "junit-jupiter", version = "5.10.2" }

                    [bundles]
                    test-libs = ["junit-jupiter"]
                    """,
                },
                {
                    "file_name": "build.gradle.kts",
                    "content": """
                    dependencies {
                        implementation(libs.log4j.core)
                        testImplementation(libs.bundles.test.libs)
                    }
                    """,
                },
            ]
        )
        by_name = {dependency["name"]: dependency for dependency in result["dependencies"]}

        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"]["version"], "2.14.1")
        self.assertEqual(by_name["org.junit.jupiter:junit-jupiter"]["version"], "5.10.2")
        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"]["source_type"], "gradle")
        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"]["source_file"], "build.gradle.kts")

    def test_gradle_manifest_dependency_overrides_code_import_without_version(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "src/main/java/Demo.java",
                    "content": "import org.apache.logging.log4j.LogManager;",
                },
                {
                    "file_name": "build.gradle",
                    "content": """
                    dependencies {
                        implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
                    }
                    """,
                },
            ]
        )

        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(result["dependencies"][0]["version"], "2.14.1")
        self.assertEqual(result["dependencies"][0]["source_type"], "gradle")


class DependencyAssistantGraphTests(unittest.TestCase):
    def test_attachment_question_generates_dependency_vulnerability_report(self) -> None:
        record = {
            "id": "CVE-2021-44228",
            "title": "Log4j remote code execution",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "summary": "Apache Log4j vulnerable lookup handling.",
            "affected_versions": ["Maven / org.apache.logging.log4j:log4j-core: >= 2.0.0, < 2.15.0"],
            "fixed_versions": ["Maven / org.apache.logging.log4j:log4j-core: 2.15.0"],
            "code_snippets": ["logger.info(userControlledMessage);"],
            "fixed_code_snippets": ["// upgrade log4j-core to 2.15.0 or later"],
            "reference_links": ["https://example.test/CVE-2021-44228"],
            "components": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "affected": [">= 2.0.0, < 2.15.0"],
                    "fixed": ["2.15.0"],
                }
            ],
            "matched_dependencies": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "version": "2.14.1",
                    "source_file": "pom.xml",
                    "source_type": "pom",
                    "declaration": "org.apache.logging.log4j:log4j-core:2.14.1",
                    "confidence": "high",
                }
            ],
            "aliases": ["CVE-2021-44228"],
            "updated_at": "2026-07-16T00:00:00+00:00",
        }
        graph = KnowledgeSecurityGraph()
        pom = """
        <project>
          <dependencies>
            <dependency>
              <groupId>org.apache.logging.log4j</groupId>
              <artifactId>log4j-core</artifactId>
              <version>2.14.1</version>
            </dependency>
          </dependencies>
        </project>
        """

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("app.graph.report_store", ReportStore(Path(temp_dir))),
            patch("app.graph.active_model_from_env", return_value=None),
            patch("app.graph.memory_service.build_context", return_value={"enabled": True, "stats": {}, "injectedMessages": []}),
            patch("app.graph.memory_service.add_exchange"),
            patch(
                "app.graph.intelligence_service.query_dependencies",
                return_value={
                    "records": [record],
                    "graph": empty_knowledge_graph("dependency-scan"),
                    "trace": [],
                },
            ) as query_dependencies,
        ):
            result = graph.invoke(
                "请根据附件依赖生成漏洞报告",
                top_k=5,
                attachments=[{"file_name": "pom.xml", "content": pom}],
            )

        query_dependencies.assert_called_once()
        dependency_query = query_dependencies.call_args.args[0]
        self.assertEqual(dependency_query[0]["name"], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(dependency_query[0]["version"], "2.14.1")
        self.assertEqual(result["mode"], "dependency_vulnerability_report")
        self.assertIn("依赖漏洞与代码漏洞分析报告", result["summary"])
        self.assertIn("CVE-2021-44228", result["summary"])
        self.assertIn("org.apache.logging.log4j:log4j-core", result["summary"])
        self.assertNotIn("logger.info", result["summary"])
        self.assertNotIn("upgrade log4j-core", result["summary"])
        self.assertEqual(result["vulnerability_card"]["漏洞编号"], "CVE-2021-44228")
        self.assertIn("logger.info", result["vulnerability_card"]["代码片段"])
        self.assertNotIn("records", result)


if __name__ == "__main__":
    unittest.main()
