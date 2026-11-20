#!/usr/bin/env python3
"""Compatibility wrapper for ActionScope's compromised-action cache updater."""

from __future__ import annotations

import argparse
import os

from actionscope.compromised_db import update_compromised_actions_cache


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-file")
    parser.add_argument("--ttl-hours", type=_positive_int, default=24)
    args = parser.parse_args()

    result = update_compromised_actions_cache(
        github_token=os.environ.get("GITHUB_TOKEN"),
        cache_file=args.cache_file,
        ttl_hours=args.ttl_hours,
    )
    for source, status in result.source_status.items():
        print(f"{source}: {status}")
    for warning in result.warnings:
        print(f"Warning: {warning}")
    if result.wrote_cache:
        print(f"Wrote {result.action_count} entries to {result.cache_file}")
    else:
        print("No cache written; the existing cache or bundled data remains active.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
