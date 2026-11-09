"""Render pip-audit JSON as a standalone, browser-readable HTML report."""

from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _dependency_row(dependency: dict[str, Any]) -> str:
    vulnerabilities = dependency.get("vulns", [])
    if vulnerabilities:
        details = []
        for vulnerability in vulnerabilities:
            identifiers = [vulnerability.get("id", "Unknown ID")]
            identifiers.extend(vulnerability.get("aliases", []))
            fix_versions = vulnerability.get("fix_versions", [])
            description = vulnerability.get("description", "")
            details.append(
                "<li><strong>{}</strong><p>{}</p><p>Исправление: {}</p></li>".format(
                    _escape(", ".join(str(value) for value in identifiers)),
                    _escape(description or "Описание отсутствует"),
                    _escape(", ".join(str(value) for value in fix_versions) or "Не указано"),
                )
            )
        finding_cell = "<ul>{}</ul>".format("".join(details))
        status = '<span class="vulnerable">Уязвимости найдены</span>'
    else:
        finding_cell = "Нет известных уязвимостей"
        status = '<span class="clean">Проверено</span>'

    return (
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _escape(dependency.get("name", "Unknown package")),
            _escape(dependency.get("version", "Unknown version")),
            status,
            finding_cell,
        )
    )


def render_report(source: Path, destination: Path) -> None:
    report = json.loads(source.read_text(encoding="utf-8"))
    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list):
        raise ValueError("pip-audit JSON must contain a dependencies array")

    vulnerability_count = sum(
        len(dependency.get("vulns", [])) for dependency in dependencies
    )
    summary_class = "vulnerable" if vulnerability_count else "clean"
    summary = (
        "Найдено уязвимостей: {}".format(vulnerability_count)
        if vulnerability_count
        else "Известных уязвимостей не найдено"
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = "\n".join(_dependency_row(dependency) for dependency in dependencies)

    document = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dependency Check Report</title>
  <style>
    :root {{ color-scheme: light; font-family: system-ui, sans-serif; }}
    body {{ margin: 0; padding: 2rem; color: #17212b; background: #f4f7fa; }}
    main {{ max-width: 1100px; margin: auto; }}
    h1 {{ margin-bottom: .25rem; }}
    .meta {{ color: #526170; }}
    .summary {{ padding: 1rem; margin: 1.5rem 0; border-radius: .5rem; background: white; }}
    .clean {{ color: #137333; font-weight: 700; }}
    .vulnerable {{ color: #b3261e; font-weight: 700; }}
    .table-wrap {{ overflow-x: auto; background: white; border-radius: .5rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: .75rem; border-bottom: 1px solid #d9e0e7; text-align: left; vertical-align: top; }}
    th {{ background: #eaf0f5; }}
    ul {{ margin: 0; padding-left: 1.25rem; }}
    li + li {{ margin-top: .75rem; }}
    p {{ margin: .3rem 0; }}
  </style>
</head>
<body>
  <main>
    <h1>Dependency Check Report</h1>
    <p class="meta">Источник: pip-audit · Сформирован: {generated_at}</p>
    <div class="summary"><strong class="{summary_class}">{summary}</strong><br>Проверено пакетов: {package_count}</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Пакет</th><th>Версия</th><th>Статус</th><th>Уязвимости и исправления</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </main>
</body>
</html>
""".format(
        generated_at=_escape(generated_at),
        summary=_escape(summary),
        package_count=len(dependencies),
        summary_class=summary_class,
        rows=rows,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="pip-audit JSON input")
    parser.add_argument("destination", type=Path, help="HTML report output")
    arguments = parser.parse_args()
    render_report(arguments.source, arguments.destination)


if __name__ == "__main__":
    main()
