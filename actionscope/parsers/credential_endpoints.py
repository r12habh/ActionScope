"""Conservative endpoint evidence for non-AWS S3 credential uses."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit

_ENV_REFERENCE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
_GITHUB_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")
_MAX_RESOLVED_LENGTH = 8192
_UNRESOLVED = "UNRESOLVED_EXPRESSION"
_GLOBAL_VALUE_OPTIONS = {
    "--ca-bundle",
    "--cli-connect-timeout",
    "--cli-read-timeout",
    "--color",
    "--endpoint-url",
    "--output",
    "--profile",
    "--region",
}


def uses_only_non_aws_s3(run: object, env: dict[str, str]) -> bool:
    """Prove that each simple command targets a recognized non-AWS S3 service.

    This deliberately does not infer a provider from secret names, region, or
    an arbitrary custom endpoint. Unsupported shell constructs remain unknown.
    """
    if not isinstance(run, str) or not run.strip():
        return False
    if any(marker in run for marker in ("$(", "`", "#")):
        return False
    text = _GITHUB_EXPRESSION.sub(_UNRESOLVED, run)
    lexer = shlex.shlex(
        text.replace("\\\n", ""), posix=True, punctuation_chars=";&|()<>\n"
    )
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    commands: list[list[str]] = []
    command: list[str] = []
    try:
        for token in lexer:
            separator = token.strip()
            if not separator or separator in {";", "&&", "||"}:
                if command:
                    commands.append(command)
                    command = []
            elif any(character in token for character in ";&|()<>"):
                return False
            else:
                command.append(token)
    except ValueError:
        return False
    if command:
        commands.append(command)
    return bool(commands) and all(_targets_non_aws_s3(cmd, env) for cmd in commands)


def _targets_non_aws_s3(command: list[str], env: dict[str, str]) -> bool:
    if not command or command[0] != "aws":
        return False
    index = 1
    while index < len(command) and command[index].startswith("--"):
        option = command[index].split("=", 1)[0]
        index += 1
        if option in _GLOBAL_VALUE_OPTIONS and "=" not in command[index - 1]:
            index += 1
    if index >= len(command) or command[index] not in {"s3", "s3api"}:
        return False

    # An explicit CLI endpoint overrides the service-specific and global env.
    endpoint: str | None = None
    for index, argument in enumerate(command):
        if argument == "--endpoint-url":
            if index + 1 >= len(command):
                return False
            endpoint = command[index + 1]
        elif argument.startswith("--endpoint-url="):
            endpoint = argument.partition("=")[2]
    if endpoint is None:
        ignore_endpoints = _resolve_env(
            env.get("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", ""), env
        )
        if ignore_endpoints.strip().lower() != "false" and ignore_endpoints.strip():
            return False
        endpoint = env.get("AWS_ENDPOINT_URL_S3") or env.get("AWS_ENDPOINT_URL")
    if not endpoint:
        return False

    endpoint = _resolve_env(endpoint, env)
    if _UNRESOLVED in endpoint or _ENV_REFERENCE.search(endpoint):
        return False
    try:
        parsed = urlsplit(endpoint)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or parsed.username is not None:
            return False
        # Only a statically resolved hostname establishes the provider.
        return hostname.endswith(".r2.cloudflarestorage.com")
    except ValueError:
        return False


def _resolve_env(value: str, env: dict[str, str]) -> str:
    if len(value) > _MAX_RESOLVED_LENGTH:
        return _UNRESOLVED
    for _ in range(4):
        parts: list[str] = []
        size = 0
        position = 0
        for match in _ENV_REFERENCE.finditer(value):
            literal = value[position:match.start()]
            replacement = env.get(match.group(1) or match.group(2), match.group())
            size += len(literal) + len(replacement)
            if size > _MAX_RESOLVED_LENGTH:
                return _UNRESOLVED
            parts.extend((literal, replacement))
            position = match.end()
        tail = value[position:]
        if size + len(tail) > _MAX_RESOLVED_LENGTH:
            return _UNRESOLVED
        parts.append(tail)
        resolved = "".join(parts)
        if resolved == value:
            break
        value = resolved
    return _GITHUB_EXPRESSION.sub(_UNRESOLVED, value)
