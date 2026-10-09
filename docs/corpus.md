# Corpus Scans

`actionscope corpus scan` runs ActionScope's static analysis over many
repositories, each pinned to an exact commit, and writes tables you can analyze
or share. It is meant for empirical studies of how GitHub Actions workflows
reach AWS credentials, and for owners auditing many of their own repositories
at once.

```bash
actionscope corpus scan manifest.csv --output-dir results/
```

## Manifest

The manifest lists one repository per row. CSV files need a header row; files
ending in `.json` must contain an array of objects with the same keys.

| Column | Required | Description |
|--------|----------|-------------|
| `repo_url` | yes | An `https://` URL, a `file://` URL, or a local path. Relative paths are resolved against the manifest's directory. |
| `commit` | yes | The full 40-character commit SHA to scan. Branch names, tags, and short SHAs are rejected so a manifest always describes the same code. |
| `path` | no | A subdirectory to scan instead of the repository root, for example a project inside a monorepo. It must be relative and must not contain `..`. |

Other columns are ignored, so you can keep notes in the same file. Duplicate
rows are skipped and counted in the summary.

```csv
repo_url,commit,path,notes
https://github.com/octo/service,5c1f0c9e8a7b6d5c4b3a29180f7e6d5c4b3a2918,,main deploy repo
https://github.com/octo/platform,9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c,services/api,monorepo service
```

Rows with an unsupported URL scheme (`http://`, `ssh://`, `git@host:`), an
invalid commit, or an unsafe path are not fatal. They appear in the results with
the status `invalid_entry`.

To scan private repositories, clone them yourself and list the local paths.
Corpus scans never use your git credentials.

## What happens for each entry

1. **Fetch.** ActionScope fetches only the pinned commit (shallow, without tags,
   submodules, or LFS objects) into a temporary directory and checks that the
   checked-out commit matches. Git runs without your global or system
   configuration, never prompts for credentials, and only uses the `https` and
   `file` transports. Symlinks are checked out as plain files, so repository
   content cannot point the scanner at files outside the checkout.
2. **Scan.** The checkout is scanned in a separate process with the same static
   pipeline as `actionscope scan --offline`. A scan that hangs or crashes is
   recorded as a failed row and the run continues.
3. **Clean up.** The checkout is deleted.

Every entry is scanned under the same conditions so results stay comparable:

- **Offline.** External reusable workflows are not fetched; they appear as
  coverage gaps, exactly as in an offline single-repository scan.
- **Bundled database.** Known-compromised actions are matched against the
  database shipped with the installed ActionScope version, never a local cache
  refreshed by `actionscope update-db`.
- **No repository configuration.** A scanned repository's own
  `.actionscope.yml` is ignored, so one repository's suppressions cannot change
  its results.
- **No live AWS access.** `--aws-verify` is not available in corpus mode.

The host must allow fetching a commit by SHA. GitHub, GitLab, and local
repositories do.

## Outputs

```text
results/
├── summary.json         run metadata and totals
├── repositories.csv     one row per manifest entry
├── repositories.json    the same rows as JSON
├── bindings.csv         one row per workflow credential binding
├── bindings.json        the same rows as JSON
├── workflow_locks.csv   dependency-lock coverage per workflow
├── workflow_locks.json  the same rows as JSON
└── _private/            identifying data — do not publish
```

The CSV and JSON tables hold the same rows. In JSON, a value that does not
apply is `null`; in CSV it is an empty cell.

### `repositories` columns

| Column | Description |
|--------|-------------|
| `entry_id` | Anonymized ID of this manifest entry. |
| `repo_id` | Anonymized ID of the repository. Entries for different commits or paths of the same repository share it. |
| `status` | `scanned`, `invalid_entry`, `fetch_failed`, `fetch_timeout`, `scan_failed`, or `scan_timeout`. |
| `workflow_count` | Workflow files analyzed. |
| `credential_bindings` | AWS credential configurations found in workflows. |
| `static_matches` | Bindings linked to repository-local IAM policy evidence. |
| `policy_not_found` | Bindings with a literal role whose policy is not in the repository. |
| `dynamic_references` | Bindings whose role comes from a secret, variable, input, or other expression. |
| `no_role` | Bindings with no role to correlate, usually static access keys. |
| `overall_risk` | Highest finding severity in the scan. |
| `coverage_status` | `complete` or `partial`, as reported by a normal scan. |
| `oidc_trust_findings`, `script_injection_findings`, `artifact_poisoning_findings`, `ai_agent_findings`, `compromised_action_findings`, `environment_findings`, `exposure_paths`, `unpinned_actions` | Finding counts per detector. |
| `dependency_lock_workflows` | Workflows measured for dependency-lock coverage. |
| `fully_locked_workflows`, `partially_locked_workflows` | Workflows whose external dependencies are fully or partially covered by valid `actions.lock` entries. |
| `error_count` | Analyzer errors reported during the scan. |
| `elapsed_seconds` | Time spent on this entry, including the fetch. |

Measurement columns are empty for entries that were not scanned. An empty value
means unknown, not zero.

### `bindings` columns

| Column | Description |
|--------|-------------|
| `entry_id`, `repo_id` | Join keys to `repositories`. |
| `binding_index` | Position of the binding within its entry. |
| `workflow_id` | Anonymized ID of the workflow file. |
| `uses_oidc`, `uses_access_keys` | How the workflow obtains AWS credentials. |
| `role_reference_kind` | Where the role came from: `literal_arn`, `literal_name`, `secret`, `variable`, `environment`, `input`, `expression`, or `absent`. |
| `policy_source` | Evidence linked to the role: `terraform`, `json`, `cloudformation`, or `workflow` when matched; otherwise `not_found`, `dynamic_reference`, or `no_role`. |
| `matched` | Whether repository-local policy evidence was linked. |
| `match_confidence` | Confidence of the link (`high`, `medium`, `low`, or `none`). |
| `matched_risk` | Highest risk among the linked policy's actions. |
| `has_privilege_escalation` | Whether the linked policy contains a known escalation path. |
| `action_count` | IAM actions in the linked policy. |
| `policy_coverage_complete` | `false` when the linked policy has attachments or elements ActionScope could not resolve. |

### `workflow_locks` columns

| Column | Description |
|--------|-------------|
| `entry_id`, `repo_id` | Join keys to `repositories`. |
| `workflow_id` | Anonymized workflow identifier. |
| `status` | `fully_locked`, `partially_locked`, `not_locked`, `invalid`, or `no_dependencies`. |
| `schema_version` | Parsed `actions.lock` schema version, when valid. |
| `direct_dependencies`, `locked_direct_dependencies` | External direct references and the subset covered by valid exact lock entries. |
| `transitive_dependencies` | Additional valid locked dependencies recorded for the workflow. |
| `uncovered_dependencies`, `invalid_dependencies` | Counts of uncovered direct refs and referenced malformed/missing lock entries. |

Role ARNs and AWS account IDs are never written to any output, including
`_private/`.

### `summary.json`

The summary records the ActionScope version, the SHA-256 of the manifest file,
the timeouts, status counts, binding totals by `policy_source` and
`role_reference_kind`, and `static_match_rate` (static matches divided by
credential bindings).

## Anonymization

By default the shareable tables contain no repository URLs, commit SHAs, paths,
or workflow, job, or step names. Repositories, entries, and workflows are
identified by keyed hashes (HMAC-SHA256) using a random salt created for the
run. Because the salt is secret, the IDs cannot be reversed by hashing
candidate repository names.

`_private/` holds what is needed to audit or resume the run:

- `salt` — the key for the anonymized IDs
- `repositories.csv`, `bindings.csv`, `workflow_locks.csv` — the same tables
  with repository URLs, commits, paths, workflow, job, and step names, and
  error messages
- `progress.jsonl`, `run.json` — the resume log and run settings

Do not publish `_private/`, and do not publish the manifest of an anonymized
study: it lists the repositories.

Before finishing, ActionScope checks every shareable file for IAM ARNs with
account IDs, temporary checkout paths, and (when anonymizing) the manifest's
repository locations and commits. If anything is found, it deletes the
shareable files and exits with an error instead of leaving them behind.

Hashing hides names, not patterns. In a small corpus, a repository with an
unusual combination of counts may still be recognizable to someone who knows
it. Aggregate before publishing when that matters.

Strings copied from scanned repositories (workflow paths and job and step
names) are prefixed with `'` in CSV files when they start with a character a
spreadsheet would treat as a formula. The JSON tables keep the original text.

### Scanning your own repositories

`--no-anonymize` adds `repo_url`, `commit`, `path`, `workflow_path`, `job`, and
`step` columns to the shareable tables. Role ARNs are still never written.

## Resuming

Progress is saved after each entry. If a run is interrupted, rerun the same
command with `--resume`:

```bash
actionscope corpus scan manifest.csv --output-dir results/ --resume
```

Entries that were scanned are kept. Every other entry, including failures, is
tried again. The manifest file, the `--no-anonymize` setting, and the
ActionScope version must match the original run. Without `--resume`,
ActionScope refuses to write into a directory that already holds a run or any
other files.

## Reporting results

To let others reproduce a study, report the ActionScope version and the
manifest SHA-256 from `summary.json`, the timeouts, and the date of the run.
If the repositories can be named, publish the manifest; anyone with the same
ActionScope version can rerun it and get the same tables, with new anonymized
IDs because the salt differs.

## Worked example

[`examples/corpus/manifest.csv`](https://github.com/r12habh/ActionScope/blob/main/examples/corpus/manifest.csv)
pins five fixture projects inside this repository to the v0.5.0 release commit:

```bash
actionscope corpus scan examples/corpus/manifest.csv --output-dir corpus-example/
```

It finds six credential bindings: five linked to policies in their project and
one literal role whose policy is absent. These fixtures were written to exercise
the scanner, so their match rate says nothing about real repositories.
