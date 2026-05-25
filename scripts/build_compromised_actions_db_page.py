#!/usr/bin/env python3
"""Generate `docs/compromised-actions-database.md` from the bundled DB.

The auto-generated page becomes the canonical browsable reference for every
known-compromised GitHub Action ActionScope detects. Each entry gets its own
`##` heading (and so a stable URL anchor) so searches like
`is tj-actions/changed-files compromised` land directly on the relevant
section.

Run before `mkdocs build`. Safe to commit the output, but the build workflow
re-runs this on every deploy so the page is always fresh.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / "actionscope" / "data" / "compromised_actions.json"
OUT_PATH = REPO_ROOT / "docs" / "compromised-actions-database.md"


HEADER = """\
# Compromised GitHub Actions Database

ActionScope ships a curated database of GitHub Actions with documented
supply-chain compromises. This page is the canonical browsable view of every
entry — each one has its own permalink, so you can deep-link from advisories,
incident-response runbooks, or post-mortems.

To check whether *your* repository uses any of these actions:

```bash
pip install actionscope
actionscope scan .
```

Mutable-tag references to a compromised action (e.g. `@v3` of
`actions-cool/issues-helper`) produce a **CRITICAL** finding. Full-SHA pins
to an action that has been compromised but where the specific SHA is not in
the published affected-refs list produce a **HIGH** finding so a human can
confirm whether the pinned commit predates the compromise.

For background on how detection works, see
[Compromised Actions detector](compromised-actions.md).

---

"""

TEMPLATE = """\
## {name}

- **Action:** [`{name}`](https://github.com/{name})
- **First compromised:** `{compromised_at}`
- **Status:** {status_label}
- **Affected references:** {affected_refs_md}
- **Advisory:** <{advisory_url}>

{description}

### Are you affected?

```bash
# Scan your repo for *this* compromised action:
actionscope scan . | grep -A 5 '{name}'
```

### Remediation

1. **Remove the action** from your workflow, OR
2. **Pin to a verified pre-compromise SHA** if one exists (consult the
   advisory linked above).
3. **Rotate any credentials** the workflow had access to during the
   compromised window. Treat the compromise window as a credential
   disclosure.

---

"""

STATUS_LABELS = {
    "compromised": (
        "⛔ **Compromised** — actively malicious as of the published advisory"
    ),
    "historical": (
        "📜 **Historical** — past compromise, included for repos still pinned "
        "to a pre-fix tag"
    ),
}


def _format_affected_refs(refs: list[str]) -> str:
    if not refs:
        return (
            "_All tags treated as ambiguous — "
            "SHA pins must be individually verified._"
        )
    return ", ".join(f"`{r}`" for r in refs)


def build_page() -> str:
    db = json.loads(DB_PATH.read_text(encoding="utf-8"))
    chunks: list[str] = [HEADER]

    entries = sorted(db["actions"], key=lambda e: (e["status"], e["action"].lower()))

    for entry in entries:
        chunks.append(
            TEMPLATE.format(
                name=entry["action"],
                compromised_at=entry["compromised_at"],
                status_label=STATUS_LABELS.get(
                    entry["status"], f"`{entry['status']}`"
                ),
                affected_refs_md=_format_affected_refs(entry.get("affected_refs", [])),
                advisory_url=entry["advisory_url"],
                description=entry["description"],
            )
        )

    chunks.append(
        "## Reporting a new compromise\n\n"
        "Found a compromised action that is not on this list? Please open an "
        "[issue using the report template]"
        "(https://github.com/r12habh/ActionScope/issues/new"
        "?template=compromised_action_report.yml) so we can add it.\n"
    )
    return "".join(chunks)


def main() -> None:
    OUT_PATH.write_text(build_page(), encoding="utf-8")
    print(f"Wrote {OUT_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
