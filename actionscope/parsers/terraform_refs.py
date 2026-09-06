"""Traversal-aware parsing helpers for Terraform resource references."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TerraformResourceReference:
    """A Terraform resource declaration and its optional instance selector."""

    declaration_address: str
    instance_address: str


def parse_resource_reference(
    value: object,
    resource_type: str,
) -> TerraformResourceReference | None:
    """Parse a Terraform resource traversal without splitting inside indexes."""
    if not isinstance(value, str):
        return None

    reference = value.strip()
    if len(reference) >= 2 and reference[0] == reference[-1] == '"':
        reference = reference[1:-1].strip()
    if reference.startswith("${") and reference.endswith("}"):
        reference = reference[2:-1].strip()

    prefix = f"{resource_type}."
    if not reference.startswith(prefix):
        return None

    position = len(prefix)
    name_start = position
    while position < len(reference) and reference[position] not in ".[":
        position += 1
    if position == name_start:
        return None

    declaration = reference[:position]
    while position < len(reference) and reference[position] == "[":
        closing = _index_end(reference, position)
        if closing is None:
            return None
        position = closing + 1

    if position < len(reference) and reference[position] != ".":
        return None

    return TerraformResourceReference(
        declaration_address=declaration,
        instance_address=reference[:position],
    )


def _index_end(reference: str, start: int) -> int | None:
    """Return the closing bracket for an index, respecting quoted strings."""
    depth = 0
    quote: str | None = None
    escaped = False

    for position in range(start, len(reference)):
        character = reference[position]
        if escaped:
            escaped = False
            continue
        if quote and character == "\\":
            escaped = True
            continue
        if character in {'"', "'"}:
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
            continue
        if quote is not None:
            continue
        if character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
            if depth == 0:
                return position

    return None
