"""Tests for GitHub Action pin resolution."""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

from actionscope.resolvers.pin_resolver import (
    ResolvedPin,
    format_pinned_replacement,
    resolve_pins_for_workflow,
    resolve_tag_to_sha,
)

FULL_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
TAG_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_resolve_tag_to_sha_returns_sha_for_valid_tag() -> None:
    payload = {"object": {"type": "commit", "sha": FULL_SHA}}

    with patch("urllib.request.urlopen", return_value=FakeResponse(payload)):
        pin = resolve_tag_to_sha("actions/checkout", "v4")

    assert pin.resolved_sha == FULL_SHA
    assert pin.pinned_ref == f"actions/checkout@{FULL_SHA}  # v4"


def test_resolve_tag_to_sha_handles_annotated_tags() -> None:
    ref_payload = {"object": {"type": "tag", "sha": TAG_SHA}}
    tag_payload = {"object": {"type": "commit", "sha": FULL_SHA}}

    with patch(
        "urllib.request.urlopen",
        side_effect=[FakeResponse(ref_payload), FakeResponse(tag_payload)],
    ):
        pin = resolve_tag_to_sha("actions/setup-python", "v5")

    assert pin.resolved_sha == FULL_SHA


def test_resolve_tag_to_sha_returns_error_for_404() -> None:
    error = urllib.error.HTTPError("url", 404, "not found", {}, None)

    with patch("urllib.request.urlopen", side_effect=error):
        pin = resolve_tag_to_sha("actions/checkout", "missing")

    assert pin.error == "tag not found"


def test_resolve_tag_to_sha_returns_error_for_403() -> None:
    error = urllib.error.HTTPError("url", 403, "forbidden", {}, None)

    with patch("urllib.request.urlopen", side_effect=error):
        pin = resolve_tag_to_sha("actions/checkout", "v4")

    assert pin.error == "rate limited"


def test_resolve_pins_for_workflow_deduplicates_refs() -> None:
    workflow = {
        "jobs": {
            "test": {
                "steps": [
                    {"uses": "actions/checkout@v4"},
                    {"uses": "actions/checkout@v4"},
                ]
            }
        }
    }

    with patch(
        "actionscope.resolvers.pin_resolver.resolve_tag_to_sha",
        return_value=ResolvedPin(
            "actions/checkout@v4",
            "actions/checkout",
            "v4",
            FULL_SHA,
            "pinned",
            None,
        ),
    ) as resolver:
        pins = resolve_pins_for_workflow(workflow, "ci.yml", delay_seconds=0)

    assert len(pins) == 1
    resolver.assert_called_once()


def test_resolve_pins_for_workflow_skips_local_actions() -> None:
    workflow = {"jobs": {"test": {"steps": [{"uses": "./.github/actions/local"}]}}}

    pins = resolve_pins_for_workflow(workflow, "ci.yml", delay_seconds=0)

    assert pins == []


def test_resolve_pins_for_workflow_skips_sha_pinned_actions() -> None:
    workflow = {"jobs": {"test": {"steps": [{"uses": f"actions/checkout@{FULL_SHA}"}]}}}

    pins = resolve_pins_for_workflow(workflow, "ci.yml", delay_seconds=0)

    assert pins == []


def test_format_pinned_replacement_includes_original_tag_comment() -> None:
    pin = ResolvedPin(
        "actions/checkout@v4",
        "actions/checkout",
        "v4",
        FULL_SHA,
        f"actions/checkout@{FULL_SHA}  # v4",
        None,
    )

    assert "# v4" in format_pinned_replacement(pin)


def test_format_pinned_replacement_handles_resolution_error() -> None:
    pin = ResolvedPin(
        "actions/checkout@v4",
        "actions/checkout",
        "v4",
        None,
        None,
        "rate limited",
    )

    assert "unresolved: rate limited" in format_pinned_replacement(pin)


def test_resolve_pins_for_workflow_respects_delay_between_calls() -> None:
    workflow = {
        "jobs": {
            "test": {
                "steps": [
                    {"uses": "actions/checkout@v4"},
                    {"uses": "actions/setup-python@v5"},
                ]
            }
        }
    }

    with (
        patch(
            "actionscope.resolvers.pin_resolver.resolve_tag_to_sha",
            return_value=ResolvedPin("x@y", "x", "y", FULL_SHA, "pinned", None),
        ),
        patch("time.sleep") as sleep,
    ):
        resolve_pins_for_workflow(workflow, "ci.yml", delay_seconds=0.25)

    sleep.assert_called_once_with(0.25)
