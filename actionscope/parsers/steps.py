"""Expand workflow steps into the individual steps GitHub runs."""

from __future__ import annotations

from typing import Any


def expand_steps(steps: Any) -> list[dict]:
    """Return the step mappings in ``steps`` with ``parallel`` groups expanded.

    A ``parallel`` group is a step whose value is a list of ordinary steps
    that run concurrently. Background steps (``background: true``) are
    ordinary steps. ``wait``, ``wait-all``, and ``cancel`` steps have no
    ``uses`` or ``run`` and are returned unchanged, so detectors skip them.
    Non-mapping entries are dropped.
    """
    if not isinstance(steps, list):
        return []
    expanded: list[dict] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        group = step.get("parallel")
        if isinstance(group, list):
            expanded.extend(expand_steps(group))
        else:
            expanded.append(step)
    return expanded


def job_steps(job: Any) -> list[dict]:
    """Return a job's steps with ``parallel`` groups expanded."""
    if not isinstance(job, dict):
        return []
    return expand_steps(job.get("steps"))
