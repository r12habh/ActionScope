# Owner-Led Validation

This protocol tests two different questions:

1. Does ActionScope recover and describe the supplied workflow/IAM evidence correctly?
2. Does the report help an owner make a security decision beyond their existing approach?

Neither question is answered by a successful demo scan alone. This document is
a procedure, not a claim that an external user study or live AWS validation has
been completed.

## Participation and Data Handling

Participation is voluntary. The owner chooses one workflow and the IAM roles it
uses, approves the scope, and can stop at any point. Do not send unsolicited
integration pull requests as part of this procedure.

- Use repositories and IAM evidence you own or are authorized to review.
- Start locally in report-only mode. Do not install a new CI gate for the trial.
- Do not share GitHub tokens, AWS credentials, secret values, or public links to
  confidential policy exports. Stored GitHub secrets are not readable inputs.
- Keep raw reports, exports, account IDs, role ARNs, and local checkout paths
  outside the repository. Do not attach them to public issues or pull requests.
- Publication of names, quotes, examples, or aggregate results requires separate
  approval. Agree who retains raw evidence and when it will be deleted.

Owners can keep all raw evidence locally and provide a redacted decision record.
Redaction can change matching or policy semantics; label a modified fixture as
such rather than presenting its result as an unchanged production scan.

## Choose One Review Task

Before looking at ActionScope's output, record:

- The workflow and job being reviewed, plus the repository commit.
- The owner's question, such as which IAM grants should be reviewed if that job
  is compromised.
- The role identity and policy evidence available to the owner. Note whether the
  role is literal, secret-backed, or resolved through another expression.
- The owner's existing review approach and the specific decision being made.
- The expected grants and relevant denies, conditions, boundaries, session or
  resource policies, organization restrictions, and chained-role dependencies.

Do not assume that an attached Allow grant is an effective permission. If the
owner cannot establish the applicable policy context, keep the answer unknown.
An authorized export supports comparison; it is not a new proof of live state.

## Record the Software and Run Offline

For a reproducible released-package trial, use an isolated environment and record
the package version and installation origin. If using source instead, record the
exact Git commit and any local modifications. A version string alone can be
insufficient when unreleased main still has the previous release's version.

Create an output directory outside the repository, then run:

```bash
umask 077
EVIDENCE="$(mktemp -d "${TMPDIR:-/tmp}/actionscope-validation.XXXXXX")"
REPO="/path/to/owned/repository"

actionscope --version
git -C "$REPO" rev-parse HEAD
actionscope scan "$REPO" --offline \
  --output-format json --output-file "$EVIDENCE/static.json"
```

Store the tool identity, repository revision, configuration/suppressions, and
commands privately with the result. Retain the original output before making any
changes. Installing the tool may require network access; `--offline` disables
scan-time API calls, not package installation.

The current CLI does not have an IAM snapshot-import flag, `--iam-path`, or a
secret-to-role mapping flag. Do not describe a manual join as automatic recovery.
An export outside the scanned tree can be compared manually, but is not ingested
by the command above. If an owner adds policy evidence to a disposable repository
copy, label that run as evidence-augmented, not the original repository result.

## Optional Authorized Live Comparison

This phase is optional and performed by the owner. It requires existing AWS
access approved for the trial; the protocol does not ask maintainers to provision
resources or purchase cloud services.

Use an existing profile with the minimal
[read-only IAM permissions](aws-verify-permissions.md). Never use administrator
credentials just to make a scan pass.

```bash
AWS_PROFILE="existing-read-only-iam-profile" \
  actionscope scan "$REPO" --aws-verify \
  --output-format json --output-file "$EVIDENCE/live.json"
```

Do not combine `--offline` and `--aws-verify`. The live command reads IAM policy
state; it does not evaluate all AWS authorization constraints or establish
exploitability. Dynamic role expressions are skipped, so the flag alone does not
resolve secret-backed role identities. Record unsupported identities and
constraints rather than manufacturing a complete result.

If the owner manually identifies a role using authorized infrastructure records,
record that as supplied ground truth. Never expose secret values, commit a
production role just for a demonstration, or count a manually rewritten workflow
as automatically resolved.

## Compare Correctness and Usefulness Separately

Fill in this record privately. Leave unknown or unmeasured values explicit.

| Item | Record |
| --- | --- |
| Tool/package identity and repository commit | Exact version/source and revision |
| Workflow/job and expected role | Owner-confirmed identity, kept private |
| Evidence available | In-repo, external export, or authorized live reads |
| Automatic role/policy recovery | Recovered, supplied manually, or unresolved |
| Expected vs reported grants | Agreements, omissions, and overstatements |
| Unsupported constraints | Denies, conditions, boundaries, or other missing context |
| Existing review approach | What the owner normally uses |
| Incremental information | What was new, if anything, and how it was confirmed |
| Decision or remediation | What the owner actually changed, or no change |
| Review effort | Observed times or unmeasured; do not invent savings |
| Willingness to use again | Owner's answer and reason, including a negative answer |
| Retention/publication agreement | Approved fields, owner, and deletion point |

A same-person, unblinded review or a retrospective time estimate is not a
controlled usability experiment. Disclose those limits. A fixture proves an
implemented behavior; an IAM read checks fetched evidence; neither by itself
measures effective authorization or operational usefulness.

## Continue or Stop

Continue a narrow product experiment only when the owner confirms useful
incremental information or a concrete review improvement, with the reported
constraints and mismatches understood. A willingness to install the tool is not
the same as a demonstrated outcome.

If the report only repeats what the owner already has, requires disproportionate
manual setup, or fails to support the chosen task, record that result. Do not
replace it with a synthetic success case. If no owner or authorized evidence is
available, mark validation blocked and remain in maintenance mode.

Software correctness failures should become minimal, sanitized regression cases
with the owner's permission. New architecture or input modes should follow a
demonstrated need, not precede it. See the [roadmap](roadmap.md).
