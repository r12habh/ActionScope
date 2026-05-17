# Changelog

All notable changes to ActionScope are documented here.

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
