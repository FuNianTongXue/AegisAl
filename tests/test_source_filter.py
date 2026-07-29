from __future__ import annotations

import unittest
from pathlib import Path

from app.source_filter import is_analyzable_source_path, is_excluded_source_path, is_symlink_like_source_stub


class SourceFilterTests(unittest.TestCase):
    def test_excludes_vendored_and_documentation_source_variants(self) -> None:
        self.assertTrue(is_excluded_source_path("3rd-party/eigen/src/Core/Array.h"))
        self.assertTrue(is_excluded_source_path("thirdparty/lib/source.c"))
        self.assertTrue(is_excluded_source_path("docs/snippets/example.cpp"))

    def test_keeps_main_java_sources(self) -> None:
        self.assertTrue(is_analyzable_source_path("module/src/main/java/com/example/App.java"))
        self.assertFalse(is_excluded_source_path(Path("module/src/main/java/com/example/App.java")))
        self.assertTrue(is_analyzable_source_path("module/src/main/java/com/secflow/demo/App.java"))
        self.assertTrue(is_analyzable_source_path("src/main/java/com/example/service/App.java"))

    def test_excludes_common_test_and_benchmark_layouts(self) -> None:
        excluded = [
            "module/src/test/java/com/example/AppTest.java",
            "geode-core/src/distributedTest/java/org/apache/geode/Demo.java",
            "module/src/integrationTest/java/com/example/IT.java",
            "module/src/integration/java/com/example/IT.java",
            "geode-dunit/src/main/java/org/apache/geode/TestCase.java",
            "it/common/src/main/java/org/apache/project/FakeProduction.java",
            "module/src/jmh/java/com/example/Bench.java",
            "examples/java/src/main/java/org/apache/demo/Example.java",
            "example/src/main/java/com/vendor/sample/SampleController.java",
            "sample/src/main/java/com/vendor/payment/SampleController.java",
            "module/src/main/java/org/apache/project/sql/example/ExamplePipeline.java",
            "module/src/main/java/org/apache/project/tutorial/QuickStart.java",
            "module/benchmarks/src/main/java/com/example/Bench.java",
            "module/perf/src/main/java/com/example/Load.java",
            "module/third_party/flatbuffers/parser.cpp",
            "module/vendor/libxml/parser.c",
            "cola-archetypes/archetype-resources/src/main/java/App.java",
            "sdk/testdata/project/main.go",
        ]

        for path in excluded:
            with self.subTest(path=path):
                self.assertTrue(is_excluded_source_path(path))

    def test_detects_archive_materialized_symlink_source_stubs(self) -> None:
        accepted = {
            "apps/frameworks/sherpa-mnn/c-api-examples/asr-microphone-example/alsa.cc": (
                "../../sherpa-onnx/csrc/alsa.cc"
            ),
            "src/alias.h": "../include/real_target.hpp",
            "src/alias.cpp": "./generated/real_target.cc",
            "src/alias.c": "lib/real_target.c",
        }

        for path, content in accepted.items():
            with self.subTest(path=path, content=content):
                self.assertTrue(is_symlink_like_source_stub(path, content))

    def test_rejects_normal_source_and_unsafe_symlink_like_text(self) -> None:
        rejected = {
            "src/app.cc": "int main() { return 0; }\n",
            "src/comment.cc": "../../target.cc // prose",
            "src/url.cc": "https://example.com/source.cc",
            "src/absolute.cc": "/tmp/source.cc",
            "src/mid_parent.cc": "safe/../target.cc",
            "src/git.cc": "../.git/config.cc",
            "src/non_code_target.cc": "../README.md",
            "src/unsafe_char.cc": "../evil shell/target.cc",
            "src/non_code_file.txt": "../target.cc",
        }

        for path, content in rejected.items():
            with self.subTest(path=path, content=content):
                self.assertFalse(is_symlink_like_source_stub(path, content))


if __name__ == "__main__":
    unittest.main()
