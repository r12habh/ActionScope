"""Regression tests that keep CLI documentation aligned with Click metadata."""

from __future__ import annotations

import re
from pathlib import Path

from actionscope.cli import main

CLI_REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "cli-reference.md"
SCAN_HEADING = "## `actionscope scan [PATH] [OPTIONS]`"
CORPUS_SCAN_HEADING = "## `actionscope corpus scan MANIFEST [OPTIONS]`"
SCAN_OPTIONS_HEADING = "### Options"


def _command(*path: str):
    command = main
    for name in path:
        command = command.commands.get(name)
        assert command is not None, f"{' '.join(path)} is missing from the CLI"
    return command


def _public_long_options(*path: str) -> list[str]:
    names: list[str] = []
    for param in _command(*path).params:
        if getattr(param, "hidden", False):
            continue
        long_opts = [
            opt
            for opt in getattr(param, "opts", [])
            if opt.startswith("--") and opt != "--help"
        ]
        names.extend(long_opts)
    return names


def _scan_options_section(text: str, heading: str = SCAN_HEADING) -> str:
    heading_at = text.find(heading)
    assert heading_at != -1, f"missing {heading!r} in {CLI_REFERENCE}"
    section = text[heading_at:]
    options_at = section.find(SCAN_OPTIONS_HEADING)
    assert options_at != -1, f"missing {SCAN_OPTIONS_HEADING!r} under {heading!r}"
    section = section[options_at:]
    next_headings = [
        index
        for marker in ("\n## ", "\n### ")
        if (index := section.find(marker, 1)) != -1
    ]
    if next_headings:
        section = section[: min(next_headings)]
    return section


def _documented_scan_options(text: str, heading: str = SCAN_HEADING) -> set[str]:
    options: set[str] = set()
    for line in _scan_options_section(text, heading).splitlines():
        if not line.startswith("|"):
            continue
        first_cell = line.split("|", 2)[1]
        options.update(re.findall(r"`(--[a-z0-9-]+)`", first_cell))
    return options


def _assert_options_documented(heading: str, *command_path: str) -> None:
    docs = CLI_REFERENCE.read_text(encoding="utf-8")
    documented_options = _documented_scan_options(docs, heading)
    missing = [
        option
        for option in _public_long_options(*command_path)
        if option not in documented_options
    ]
    assert not missing, (
        f"{' '.join(command_path)} options missing from the CLI reference: "
        + ", ".join(missing)
    )


def test_cli_reference_lists_every_scan_option() -> None:
    _assert_options_documented(SCAN_HEADING, "scan")


def test_cli_reference_lists_every_corpus_scan_option() -> None:
    _assert_options_documented(CORPUS_SCAN_HEADING, "corpus", "scan")


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
