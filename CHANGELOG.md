# Changelog

All notable changes to ActionScope are documented here.

## [Unreleased]

### Added
- `actionscope update-db` refreshes a local compromised-actions cache from
  GitHub's malware advisory feed and conditionally probes OpenSSF's malicious
  packages dataset.
- `actionscope scan --offline` guarantees scan-time GitHub and AWS API calls
  are disabled while still allowing bundled or cached advisory data.

### Changed
- ActionScope's own CI, release, documentation, and Marketplace composite
  action dependencies are pinned to verified full commit SHAs. A regression
  test prevents mutable action tags from returning.

## [0.4.0] - 2026-07-12

### Added
- GitHub OIDC trust-policy analysis now flags `ForAllValues:StringLike` and
  `ForAllValues:StringEquals` on single-valued claims such as `sub` and `aud`,
  while allowing the multivalued `amr` claim. Findings include a corrected
  condition block in terminal, JSON, Markdown, and SARIF reports.
- OIDC subject analysis now recognizes broad patterns including `repo:*`,
  wildcard owners, repository-wide contexts, branch wildcards, and environment
  wildcards.
- Reusable workflow inspection now discovers `jobs.<id>.uses` calls, follows
  local workflows recursively, reports mutable external refs, and optionally
  fetches external workflow YAML through the GitHub API when `--github-token`
  or `GITHUB_TOKEN` is supplied. Traversal is cycle-safe, caches duplicate
  targets, and preserves caller/callee provenance in terminal, JSON, Markdown,
  and SARIF output (AS015 reports delegated workflows that were not inspected).
- `--resolve-pins` now resolves tagged reusable-workflow refs while preserving
  the full `.github/workflows/<file>` path in the suggested SHA replacement.
- Correlated exposure paths now connect mutable or known-compromised actions
  to AWS credentials and high-risk IAM permissions in the same workflow job.
  Terminal, JSON, Markdown, and SARIF reports expose the path; AS016 links a
  matched IAM policy as a related location when available.

### Fixed
- GitHub OIDC `Deny` statements and statements that do not grant
  `sts:AssumeRoleWithWebIdentity` are no longer treated as role-assumption
  trust grants. `Allow` statements expressed with `NotAction` are analyzed when
  they still permit web-identity role assumption.

## [0.3.6] - 2026-06-24

### Fixed
- **Known-compromised action findings now stay focused on actually risky
  refs.** Full 40-character SHA pins are no longer reported for historical
  compromised actions unless the exact SHA is listed in the bundled database
  as known malicious. Mutable tag refs remain CRITICAL.
- **`id-token: write` calibration now recognizes common non-AWS OIDC
  consumers.** PyPI trusted publishing, GitHub Pages deployment, GCP/Azure
  auth actions, Atlas, Sigstore, SLSA generator actions, and explicit OIDC
  request patterns now downgrade intentional token minting to informational
  instead of HIGH.
- **GitHub Environment findings are less noisy.** Jobs are no longer treated
  as deploy jobs solely because they configure AWS credentials; the detector
  now looks for deploy-oriented job names, deploy commands/actions, or deploy
  role naming before recommending environment protection.

## [0.3.5] - 2026-05-30

### Fixed
- **JSON policy file discovery now pre-filters by content before applying
  the cap.** Each candidate file's first 4 KB is checked for both
  `"Statement"` and `"Effect"` substrings; only files that pass count toward
  the `--max-policy-files` cap. Live impact on monorepos:

  | Repo | Before | After |
  |---|---|---|
  | `aws/aws-cdk` (13,860 JSON files) | 13,060 silently dropped | 1,591 dropped (87% reduction) |
  | `boto/boto3` (2,056 JSON files) | 1,256 silently dropped | cap warning silent |
  | `aws-amplify/amplify-cli` (2,371 JSON files) | 1,571 silently dropped | cap warning silent |

  Files in the well-known policy directories (`iam/`, `policies/`,
  `.github/`, `infra/`, `infrastructure/`, `terraform/`) bypass the
  pre-filter entirely so the v0.3.3 "always scan common dirs" invariant
  is preserved. Surfaced by live-scanning 8 production repos (aws-cdk,
  karpenter, sentry, serverless, goreleaser, boto3, iceberg, amplify-cli).

## [0.3.4] - 2026-05-30

### Fixed
- **SHA pins of `tj-actions/changed-files` to non-malicious commits no longer
  produce false-positive findings.** The bundled DB entry now lists the
  documented malicious commit (`0e58ed867288e6711d10da9293b8db84f3f3ed85`,
  per [GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3))
  via a new optional `malicious_shas` field. The detector treats SHA pins
  outside that list as safe when the list is present, instead of flagging
  all SHA pins as ambiguous. Tag-pin detection and the conservative
  "ambiguous SHA pin" behavior for actions without documented malicious
  commits (`actions-cool/maintain-one-comment`, `aquasecurity/trivy-action`)
  are unchanged.

  Surfaced by live-scanning four production repos (Vault, Prowler,
  LocalStack, Argo CD) — Prowler and Argo CD both pin
  `tj-actions/changed-files` to the same pre-compromise SHA
  (`9426d40962ed5378910ee2e21d5f8c6fcbf2dd96`), which was producing 42
  false-positive findings between them.

### Added
- New optional `malicious_shas: [str]` field in the compromised-actions
  database schema. Entries with documented malicious commits should list
  them here. The detector uses this list to distinguish "we know this
  specific SHA is bad" from "we know the action was compromised but cannot
  say which SHA specifically."

## [0.3.3] - 2026-05-30

### Fixed
- **JSON policy file discovery no longer silently truncates at 200 files.**
  The previous single flat cap of 200 could drop IAM policies in
  non-standard locations on repos with large numbers of test/schema/fixture
  JSON files. Files in the well-known policy directories (`iam/`,
  `policies/`, `.github/`, `infra/`, `infrastructure/`, `terraform/`) are
  now always scanned in full regardless of total count. The cap on "other"
  JSON files is raised from `200` to `800` and is configurable via a new
  `--max-policy-files <N>` CLI flag (use `0` to disable entirely). The
  warning emitted when the cap is hit now names the count of skipped files
  and the flag to override it.
  Surfaced by the live-test scan against
  [`apache/airflow`](https://github.com/r12habh/ActionScope/pull/67766)
  (393 JSON files; the old cap silently dropped 193 of them).

## [0.3.2] - 2026-05-25

### Fixed
- **Summary risk counts now include every detector, not just IAM policy
  actions.** Live-scanning real repos showed
  `Critical: 0 | High: 0 | Medium: 0` even when GITHUB_TOKEN, OIDC trust,
  script injection, and environment detectors had emitted high/medium
  findings — because the terminal and Markdown summary panels were
  counting only IAM-action risk levels. Counts now reflect the actual
  set of findings shown in the report.
- **SARIF artifact locations are now repo-relative.** Previously, scans
  run against an absolute path (e.g. `/tmp/<test-repo>`) emitted SARIF
  `artifactLocation.uri` values containing that absolute path, which
  GitHub Code Scanning would not match against repository files. The
  reporter now resolves locations relative to `scan_path` and uses the
  `%SRCROOT%` `uriBaseId`, with a graceful fallback when a finding's
  workflow file is outside the scan path.
- **Policy JSON parser is quiet for malformed non-policy JSON/JSONC.**
  Files like `.devcontainer/devcontainer.json` (which contain `//`
  comments and trailing commas, valid JSONC but invalid JSON) no longer
  emit a noisy warning when they happen to live under a path
  ActionScope checks for IAM policies.

All three issues were surfaced by live-scanning the
[`rubygems/rubygems.org`](https://github.com/rubygems/rubygems.org) repo
during prep for the upstream ActionScope rollout there
([rubygems/rubygems.org#6565](https://github.com/rubygems/rubygems.org/pull/6565)).

## [0.3.1] - 2026-05-23

### Fixed
- `action.yml`: the `findings-json` output was silently dropped on every
  invocation because the heredoc closing delimiter `JSON_EOF` was appended to
  the closing `}` of the scan result rather than placed on its own line
  (caused by the JSON reporter not emitting a trailing newline). GitHub
  Actions emitted "Unable to process file command 'output' successfully" and
  the output was empty. Users consuming `steps.x.outputs.findings-json` now
  receive the full JSON document as documented. Discovered by the new
  Action E2E CI check.

### Changed
- Minimum required Click version bumped from `>=8.0` to `>=8.2`. The test
  suite relies on `Result.stdout` / `Result.stderr` being separate attributes
  (added in Click 8.2). Runtime CLI behavior is unchanged; most installs
  already resolve Click 8.2+ transitively via other dependencies.

## [0.3.0] - 2026-05-21

### Added
- Known-compromised actions database for actions-cool/issues-helper,
  actions-cool/maintain-one-comment, tj-actions/changed-files, and
  aquasecurity/trivy-action, with CRITICAL flagging for compromised tags and
  SARIF rule AS013.
- GitHub Environments OIDC analyzer: detects AWS deploy jobs without
  environment protection and trust policies not scoped to environments. SARIF
  rule AS014.
- Scan delta/diff mode: `--save-state` and `--load-state` persist scan results
  and generate risk-change summaries for PR comments.
- GitHub Actions artifact-based state persistence for CI delta tracking.
- Auto-pin resolver: `--resolve-pins` resolves unpinned action tags to current
  SHAs via the GitHub API with ready-to-paste replacement strings.

### Security Response
- Immediate response coverage for the actions-cool/issues-helper supply-chain
  attack disclosed on 2026-05-18. Repositories using affected mutable tags now
  receive a CRITICAL finding with advisory and remediation guidance.

## [0.2.0] - 2026-05-21

### Added
- OIDC trust policy analyzer: detects wildcard org subjects, missing sub/aud
  conditions, and insufficient branch scoping in GitHub Actions OIDC trust
  policies
- Script injection detector: finds direct interpolation of attacker-controlled
  GitHub context values (PR titles, issue bodies, branch names) into run blocks
- Artifact poisoning detector: identifies workflow_run workflows that download
  and execute potentially untrusted artifacts from fork PR workflows
- AI agent prompt injection surface detector: identifies Claude Code, Copilot
  Agent, and other AI coding agent workflows that may be vulnerable to prompt
  injection via PR/issue content
- Short SHA-like refs: distinguishes partial/short SHA-like references from
  full immutable 40-character commit SHAs in action references
- SARIF rules AS007-AS012 for all new finding types
- All new finding types included in terminal, JSON, SARIF, and PR comment
  markdown output

### Changed
- ScanResult now includes oidc_trust_findings, script_injection_findings,
  artifact_poisoning_findings, and ai_agent_injection_findings.

## [0.1.1] - 2026-05-17

### Changed
- Removed employment-title language from packaged README and research copy.
- Updated package metadata version for a PyPI description-only patch release.

## [0.1.0] - 2026-05-16

### Added
- GitHub Actions workflow parser: detects AWS credential configurations
- IAM policy risk classifier using policy-sentry action database
- Terraform HCL parser for IAM resource definitions
- JSON IAM policy file parser
- GITHUB_TOKEN permission analyzer
- Privilege escalation path detector (8 common paths)
- Terminal reporter with Rich color output
- JSON output format for CI integration
- Markdown output format for GitHub PR comments
- GitHub Action integration (actionscope@v0)
- `--aws-verify` flag for live AWS IAM API verification

### Security
- All analysis is read-only and deterministic
- No data is sent to external services
- AWS verification uses minimum required IAM permissions
