# Changelog

All notable changes to ActionScope are documented here.

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
