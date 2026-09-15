"""Regression tests that keep CLI documentation aligned with Click metadata."""

from __future__ import annotations

import re
from pathlib import Path

from actionscope.cli import main

CLI_REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "cli-reference.md"
SCAN_HEADING = "## `actionscope scan [PATH] [OPTIONS]`"
SCAN_OPTIONS_HEADING = "### Options"


def _scan_command():
    command = main.commands.get("scan")
    assert command is not None, "scan command is missing from actionscope.cli.main"
    return command


def _public_scan_long_options() -> list[str]:
    names: list[str] = []
    for param in _scan_command().params:
        if getattr(param, "hidden", False):
            continue
        long_opts = [
            opt
            for opt in getattr(param, "opts", [])
            if opt.startswith("--") and opt != "--help"
        ]
        names.extend(long_opts)
    return names


def _scan_options_section(text: str) -> str:
    heading_at = text.find(SCAN_HEADING)
    assert heading_at != -1, f"missing {SCAN_HEADING!r} in {CLI_REFERENCE}"
    section = text[heading_at:]
    options_at = section.find(SCAN_OPTIONS_HEADING)
    assert options_at != -1, f"missing {SCAN_OPTIONS_HEADING!r} under scan command"
    section = section[options_at:]
    next_headings = [
        index
        for marker in ("\n## ", "\n### ")
        if (index := section.find(marker, 1)) != -1
    ]
    if next_headings:
        section = section[: min(next_headings)]
    return section


def _documented_scan_options(text: str) -> set[str]:
    options: set[str] = set()
    for line in _scan_options_section(text).splitlines():
        if not line.startswith("|"):
            continue
        first_cell = line.split("|", 2)[1]
        options.update(re.findall(r"`(--[a-z0-9-]+)`", first_cell))
    return options


def test_cli_reference_lists_every_scan_option() -> None:
    docs = CLI_REFERENCE.read_text(encoding="utf-8")
    documented_options = _documented_scan_options(docs)
    missing = [
        option
        for option in _public_scan_long_options()
        if option not in documented_options
    ]
    assert not missing, (
        "scan options missing from the CLI reference Options section: "
        + ", ".join(missing)
    )


def test_scan_options_section_excludes_later_examples() -> None:
    docs = (
        f"{SCAN_HEADING}\n\n{SCAN_OPTIONS_HEADING}\n\n"
        "| Flag | Description |\n|---|---|\n"
        "| `--listed` | Mentions `--description-only` |\n\n"
        "### Common Scan Examples\n\n`actionscope scan . --example-only`\n"
    )

    section = _scan_options_section(docs)
    documented_options = _documented_scan_options(docs)

    assert "--listed" in section
    assert "--example-only" not in section
    assert documented_options == {"--listed"}
