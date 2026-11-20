"""Question-driven review of local agent workflow changes."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import click

from actionscope.evidence import SCOPE, compare, snapshot
from actionscope.retrieval import Evidence, exact_action_rows, load_encoder, rank_rows


def _git(repo, *args):
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args],
        capture_output=True,
        timeout=20,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""},
    )
    if result.returncode:
        raise ValueError(
            "Cannot read local Git checkout or base revision. "
            "Check --repo and --base-ref."
        )
    return result.stdout


def git_diff(repo, ref):
    root = Path(os.fsdecode(_git(repo, "rev-parse", "--show-toplevel").rstrip(b"\n")))
    commit = (
        _git(root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
        .decode("ascii")
        .strip()
    )
    with TemporaryDirectory() as tmp:
        dest = Path(tmp) / ".github/workflows"
        dest.mkdir(parents=True)
        tree = commit
        for dirname in (".github", "workflows"):
            item = _git(root, "ls-tree", tree, "--", dirname)
            if not item:
                break
            mode, kind, oid = item.split(b"\t", 1)[0].split()
            if kind != b"tree":
                raise ValueError("Base workflow directory is not a Git tree.")
            tree = oid.decode("ascii")
        else:
            entries = _git(root, "ls-tree", "-l", "-z", tree).split(b"\0")
            for entry in filter(None, entries):
                metadata, filename = entry.split(b"\t", 1)
                if not filename.endswith((b".yml", b".yaml")):
                    continue
                mode, kind, oid, size = metadata.split()
                if (
                    mode not in (b"100644", b"100755")
                    or kind != b"blob"
                    or b"/" in filename
                    or int(size) > 1024 * 1024
                ):
                    raise ValueError("Base workflow is not a bounded regular file.")
                (dest / os.fsdecode(filename)).write_bytes(
                    _git(root, "cat-file", "blob", oid.decode("ascii"))
                )
        return compare(snapshot(Path(tmp)), snapshot(root)), commit


def _changes(result):
    groups = {}
    for i, agent in enumerate(result["agents"]):
        for fact in agent["facts"]:
            if fact["status"] == "unchanged":
                continue
            key = (i, fact["field"])
            groups.setdefault(key, []).append(fact)
    rows, sources = [], {}
    for (i, field), facts in groups.items():
        agent = result["agents"][i]
        location = f"{agent['workflow']} / {agent['job']} / {agent['agent_step']}"
        pointer = str(len(rows))
        text = field + ": " + "; ".join(f["value"] for f in facts)
        rows.append(Evidence(pointer, location, text, field))
        sources[pointer] = facts
    return rows, sources


def _demo():
    directory = Path(__file__).parent / "data/agent-review-demo"
    if not (directory / "head/.github/workflows/review.yml").is_file():
        raise ValueError("Demo fixtures missing from this installation.")
    return compare(snapshot(directory / "base"), snapshot(directory / "head"))


@click.command("review")
@click.argument("question", default="What access changed for this agent?")
@click.option(
    "--repo",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Git checkout (default: current directory).",
)
@click.option("--base-ref", help="Local commit or branch (default: HEAD).")
@click.option("--demo", is_flag=True, help="Review the bundled Bedrock migration.")
@click.option("--limit", default=3, type=click.IntRange(1, 20), show_default=True)
@click.option("--download-model", is_flag=True, help="Allow fetching pinned weights.")
def review(question, repo, base_ref, demo, limit, download_model):
    """Find cited access changes relevant to QUESTION, using local AI."""
    if not question.strip() or (demo and (repo is not None or base_ref is not None)):
        raise click.UsageError("Provide a question; use either --demo or a checkout.")
    try:
        if demo:
            result, label = _demo(), "Bundled example: API key to Bedrock"
        else:
            result, commit = git_diff(repo or Path.cwd(), base_ref or "HEAD")
            label = f"Base {commit[:12]} vs local working tree"
        rows, sources = _changes(result)
        click.echo(label)
        click.echo(SCOPE)
        if not result["agents"]:
            click.echo("No supported direct Claude Code action found on either side.")
            return
        if not rows:
            click.echo("No changes in the access declarations this reviewer covers.")
            return
        rows = exact_action_rows(question, rows)
        if not rows:
            click.echo(
                "No changed declaration explicitly names that IAM action. "
                "Effective access is unknown."
            )
            return
        matches = rank_rows(question, rows, load_encoder(download_model), limit)
        if not matches:
            click.echo("No relevant changed records retrieved.")
            return
        click.echo(
            f"Closest changed fields ({len(matches)} shown; ranked by relevance):"
        )
        for row in matches:
            lines = [f"{row.location}: {row.check}"]
            for fact in sources[row.pointer]:
                side = "base" if fact["status"] == "removed" else "head"
                lines.append(
                    f"  {fact['status']}: {fact['value']} "
                    f"[{side}:{fact[side + '_source']}]"
                )
            if row.check == "role policy evidence":
                lines.append(
                    "  Credential setup does not establish AWS permissions. "
                    "Verify the role and its policy before approving."
                )
            for line in lines:
                click.echo("".join(c if c.isprintable() else " " for c in line))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise click.ClickException(str(exc)) from exc
