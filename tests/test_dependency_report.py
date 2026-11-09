"""Tests for the standalone dependency-check HTML report."""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.render_dependency_report import render_report


class DependencyReportTestCase(unittest.TestCase):
    def test_report_summarizes_packages_and_escapes_external_text(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "audit.json"
            destination = Path(temporary_directory) / "report.html"
            source.write_text(
                json.dumps(
                    {
                        "dependencies": [
                            {"name": "safe-package", "version": "1.2.3", "vulns": []},
                            {
                                "name": "affected-package",
                                "version": "0.1.0",
                                "vulns": [
                                    {
                                        "id": "GHSA-test",
                                        "aliases": ["CVE-2099-1234"],
                                        "description": "<script>alert(1)</script>",
                                        "fix_versions": ["0.2.0"],
                                    }
                                ],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            render_report(source, destination)
            output = destination.read_text(encoding="utf-8")

        self.assertIn("Проверено пакетов: 2", output)
        self.assertIn("Найдено уязвимостей: 1", output)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output)
        self.assertNotIn("<script>alert(1)</script>", output)


if __name__ == "__main__":
    unittest.main()
