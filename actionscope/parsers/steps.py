"""Expand workflow steps into the individual steps GitHub runs."""

from __future__ import annotations

from typing import Any

_END = object()


def expand_steps(steps: Any) -> list[dict]:
    """Return the step mappings in ``steps`` with ``parallel`` groups expanded.

    A ``parallel`` group is a step whose value is a list of ordinary steps
    that run concurrently. Background steps (``background: true``) are
    ordinary steps. ``wait``, ``wait-all``, and ``cancel`` steps have no
    ``uses`` or ``run`` and are returned unchanged, so detectors skip them.
    Non-mapping entries are dropped.

    Expansion is iterative, and a group that contains itself through a YAML
    alias is not entered again, so a crafted workflow cannot exhaust the
    recursion limit and abort the scan.
    """
    if not isinstance(steps, list):
        return []
    expanded: list[dict] = []
    open_groups = [id(steps)]
    pending = [iter(steps)]
    while pending:
        step = next(pending[-1], _END)
        if step is _END:
            pending.pop()
            open_groups.pop()
        elif isinstance(step, dict):
            group = step.get("parallel")
            if not isinstance(group, list):
                expanded.append(step)
            elif id(group) not in open_groups:
                open_groups.append(id(group))
                pending.append(iter(group))
    return expanded


def job_steps(job: Any) -> list[dict]:
    """Return a job's steps with ``parallel`` groups expanded."""
    if not isinstance(job, dict):
        return []
    return expand_steps(job.get("steps"))


def concurrent_step_groups(job: Any) -> list[list[dict]]:
    """Return a job's steps grouped by their entry in ``jobs.<id>.steps``.

    The steps of one ``parallel`` group run concurrently and form one group.
    Every other entry is a group of one step.
    """
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        return []
    groups = [expand_steps([entry]) for entry in job["steps"]]
    return [group for group in groups if group]


def runs_in_background(step: dict) -> bool:
    """Return True if ``step`` may still be running when later steps start.

    The workflow loaders keep YAML booleans as strings, and an expression
    such as ``${{ inputs.background }}`` is treated as background because
    its value is not known statically.
    """
    value = step.get("background")
    if isinstance(value, str):
        return value.strip().lower() not in ("", "false")
    return value is True
