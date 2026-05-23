#!/usr/bin/env python3
"""Maintenance helper for the known-compromised actions database."""

from __future__ import annotations

from pathlib import Path

DB_PATH = Path("actionscope/data/compromised_actions.json")


def main() -> None:
    print("ActionScope compromised actions database updater")
    print()
    print(f"Current database: {DB_PATH}")
    print()
    print("MVP maintenance workflow:")
    print("1. Review StepSecurity supply-chain advisories:")
    print("   https://www.stepsecurity.io/blog")
    print("2. Review GitHub Security Advisories for GitHub Actions:")
    print("   https://github.com/advisories?query=type%3Areviewed+github+actions")
    print("3. Add documented compromised actions to compromised_actions.json.")
    print("4. Include advisory URL, compromise date, affected refs, and description.")
    print("5. Run: pytest tests/test_compromised_actions.py")
    print()
    print("No automatic remote feed is currently bundled with ActionScope.")


if __name__ == "__main__":
    main()
