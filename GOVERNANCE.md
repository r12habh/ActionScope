# Project Governance

ActionScope uses a maintainer-led governance model. The goal is to keep
decisions visible, make contribution paths predictable, and preserve the
security and evidence semantics of the project as it grows.

## Roles

### Maintainer

Rishabh Singh (`@r12habh`) is the current project maintainer. The maintainer is
responsible for releases, security response, roadmap decisions, repository
administration, and the final decision on changes merged into the project.

### Contributors

Anyone who reports an issue, improves documentation, submits code, reviews a
change, or contributes research evidence is a contributor. Contributions are
credited through Git history, release notes, and acknowledgements where
appropriate.

Sustained contributors may be invited to help triage issues or review pull
requests. Expanded permissions are based on demonstrated judgment and ongoing
participation, not employment or affiliation.

## Decision Making

Routine changes are discussed in issues and pull requests and decided through
review, automated checks, and maintainer approval. Decisions should favor:

1. Defensible attribution of findings to observed evidence
2. Explicit uncertainty instead of treating unknowns as safe
3. Backward-compatible behavior for existing CLI and Action users
4. Reproducible tests and documented security rationale
5. Maintainable, narrowly scoped implementations

Substantial changes should begin with a public issue before implementation.
Examples include new cloud providers, output contracts, policy semantics,
network behavior, or changes that can make CI fail. The issue should describe
the user need, alternatives considered, security implications, and acceptance
criteria.

The maintainer seeks rough consensus but may make a final decision when views
remain split. The rationale should be recorded publicly. Decisions may be
revisited when new evidence or user experience warrants it.

## Reviews and Merges

Pull requests require passing automated checks and review before merge. The
contribution guide documents the up-to-date branch and merge policy. Security-
sensitive changes receive additional scrutiny and should include regression
tests.

## Releases

ActionScope follows semantic versioning while it remains pre-1.0. Releases are
tagged, recorded in `CHANGELOG.md`, built by GitHub Actions, and published to
PyPI through trusted publishing. The latest release is the supported version.

## Security and Conduct

Security vulnerabilities follow `SECURITY.md` and should not be disclosed in a
public issue before coordinated review. Community participation follows
`CODE_OF_CONDUCT.md`.

## Continuity

If the maintainer can no longer maintain ActionScope, they will seek an active
contributor willing to assume stewardship. A transfer should preserve the
project's MIT license, public history, package name, security contacts, and
published artifacts. If no successor is available, the repository will be
archived with its final support status documented.

## Changing This Document

Governance changes use the same public issue and pull-request process as other
substantial changes. Material changes should explain the reason and provide a
reasonable opportunity for contributor feedback.
