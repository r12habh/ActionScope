# CI-to-Cloud Impact Roadmap

Updated: November 6, 2026. This is a prioritized plan, not a release promise.
Open pull requests are not treated as shipped functionality.

## Focus

Stay AWS-deep: connect workflow execution, credential identity, role-policy
evidence, and the limits of that evidence. Workflow linting and advisory checks
support that analysis rather than define the product. Expand cloud providers
when concrete user requests justify the maintenance cost.

## Now: Reliability and Positioning

| Work | Tracking | Status |
| --- | --- | --- |
| Parallel/background workflow steps | [#154](https://github.com/r12habh/ActionScope/issues/154), [PR #155](https://github.com/r12habh/ActionScope/pull/155) | In review |
| Dependency lock coverage and locked compromised dependencies | [#151](https://github.com/r12habh/ActionScope/issues/151), [PR #156](https://github.com/r12habh/ActionScope/pull/156) | In review |
| Conservative R2 credential classification | [PR #159](https://github.com/r12habh/ActionScope/pull/159) | In review |
| Local-composite OIDC consumer calibration | [#160](https://github.com/r12habh/ActionScope/issues/160) | Open |
| Verified pin resolution and offline pre-commit gates | [#93](https://github.com/r12habh/ActionScope/issues/93), [PR #164](https://github.com/r12habh/ActionScope/pull/164) | In review; release documentation still required |

GitHub announced workflow dependency lockfiles generally available on
[October 28, 2026](https://github.blog/changelog/2026-10-28-github-actions-workflow-lockfiles-are-generally-available/).
Locking fixes which commits execute, not whether those commits are trustworthy.
Our lockfile work should distinguish missing, partial, stale, and valid coverage
and inspect locked transitive dependencies for known-bad commits. Missing locking
is a hardening observation, not evidence of compromise. Explicit SHA pins remain
a valid protection; lack of a lockfile alone should not imply mutable execution.

## Next: Evidence and Coverage

1. Join workflow checkouts with explicit local IAM evidence roots
   ([#165](https://github.com/r12habh/ActionScope/issues/165)), before
   adding organization-wide repository discovery ([#26](https://github.com/r12habh/ActionScope/issues/26)).
   Preserve repository, revision, and file provenance; ambiguous identities must
   remain unresolved. Proposed CLI syntax must not be documented as available.
2. Audit conditions, explicit denies, permission boundaries, SCPs, session and
   resource policies, and role chaining. Expose unsupported constraints before
   attempting a partial effective-permissions evaluator
   ([#166](https://github.com/r12habh/ActionScope/issues/166)).
3. Extend OIDC reachability ([#150](https://github.com/r12habh/ActionScope/issues/150))
   to explicitly supplied custom subject/claim configuration. Do not infer
   repository/organization claim settings from workflow YAML alone.
4. Validate the live IAM path against owned, known-ground-truth roles
   ([#145](https://github.com/r12habh/ActionScope/issues/145)). This requires
   explicit account authorization; no automatic AWS provisioning or calls are
   part of this roadmap change.
5. Establish a versioned JSON/Python contract before adding cross-repository
   consumers ([#153](https://github.com/r12habh/ActionScope/issues/153)).

## Evaluation and Research

Use [#143](https://github.com/r12habh/ActionScope/issues/143) for reproducible
corpus workflows and [#144](https://github.com/r12habh/ActionScope/issues/144)
for labeled, shared-rule comparisons. Freeze input commits and scanner versions;
report false positives and false negatives per rule with annotation methods.
Keep unknown IAM coverage separate from a successful low-risk finding.

A longitudinal rerun needs two comparisons: old and new scanners on the same
historical snapshots to measure tool changes, then one fixed scanner on old and
new snapshots to measure ecosystem changes. Where historical snapshots or fields
are unavailable, disclose non-comparability. A new env-var-aware collector does
not by itself make its percentages directly comparable with the original
collector's static-key lower bound. Do not rerun scans or publish private paper
assets as a side effect of documentation work.

## Evidence of Use

Record public, inspectable outcomes rather than assume adoption. Our
[Terratest issue](https://github.com/gruntwork-io/terratest/issues/1980) was
addressed by its maintainer in [PR #1981](https://github.com/gruntwork-io/terratest/pull/1981),
pinning 46 references across nine workflows and adding maintenance checks.
That is a remediation outcome, not an ActionScope installation, IAM-verifier
validation, measured time saving, or proof of widespread use.

Track opted-in users, external contributions, reproducible remediation cases,
and references separately. Download counts can include CI, bots, and repeat
installs and must not be presented as unique users. Keep private user identities
and quotes private unless their owners approve publication.

JOSS evaluates research software separately from an empirical-results paper.
Its [current requirements](https://joss.readthedocs.io/en/latest/submitting.html)
include more than six months of active public development and demonstrated
research use, at minimum by the developers. Outside contributors and adopters
are positive evidence, not mandatory numerical quotas. Recheck actual public
history, software quality, impact evidence, and AI disclosure before a December
submission; reaching an anniversary alone does not establish eligibility.

## Maintenance Boundaries

The advisory updater already exists; improve coverage and provenance rather than
promise a new feed command. Validate feed ecosystem/ref semantics and distinguish
historical incidents from confirmed affected commits. Avoid introducing an
automatic network dependency into offline scans.

At a mid-2027 review, assess independent usage and the tool's distinct value
against maintained alternatives. Consider narrowing or archiving if that value
is absent; do not automatically archive based only on a date or star count.
