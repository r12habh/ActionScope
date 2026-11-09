# Offline IAM Evidence

ActionScope can join GitHub Actions workflows with IAM evidence supplied by an
authorized owner, without contacting AWS. These development-version flags are
not available in the existing PyPI 0.5.0 release; use the source commit containing
this guide until a release includes them.

## Inputs

```bash
# Existing Terraform, CloudFormation/SAM, or JSON IAM in a separate checkout.
actionscope scan ./app --iam-path ./infra --offline

# Owner-supplied IAM export and explicit identity mapping, both kept private.
actionscope scan ./app --iam-snapshot /private/iam.json \
  --role-map /private/roles.json --offline

# Optional cloud-first candidates, without claiming to know a secret's value.
actionscope scan ./app --iam-snapshot /private/iam.json \
  --github-repo example/app --offline
```

`--iam-path` is repeatable. Duplicate and nested roots are deduplicated; evidence
records include a root label, relative source file, and SHA-256 content digest.
Explicit directories must be symlink-free. Supported-format files larger than
20 MiB are rejected before parsing. Separate roots are parsed independently:
Terraform references must resolve within a root, not across arbitrary checkouts.
Same-name ambiguous roles remain unresolved. A known different ARN/account is
not matched by its role name.
Path/name-only policy matches without an exact ARN do not establish account
identity; external-root matches retain that gap and are at most medium confidence.

## Snapshot Format

Use the JSON shape of AWS
[GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html):
`RoleDetailList`, optionally `Policies`, and `IsTruncated: false`. Obtain an export
only through an existing authorized process; the importer never requests AWS
credentials or creates resources. A snapshot is historical owner-supplied evidence,
not live verification, and its authenticity/freshness is not independently attested.

Roles retain their full ARN, inline policies, managed attachments, trust policy,
and boundary references. Managed policies are taken from exactly the version with
`IsDefaultVersion: true`; missing documents/versions remain unresolved attachments.
Truncated exports, duplicate identities/JSON keys, malformed documents, and files
larger than 20 MiB are rejected. API-encoded and plain JSON policy documents are
supported. Exact snapshot identities take precedence over repository policy
matches, so old IaC grants are not silently unioned into the selected snapshot.
Trust-policy checks are attached only to roles referenced by the scanned inputs
or separately derived as candidates. Other snapshot roles remain unmatched audit
context rather than raising the workflow's CI risk.

## Explicit Role Mapping

```json
{
  "version": 1,
  "roles": [{
    "workflow": ".github/workflows/deploy.yml",
    "job": "deploy",
    "step": "Configure AWS",
    "role_arn": "arn:aws:iam::111111111111:role/ci-deploy"
  }]
}
```

The account ID above is synthetic. The workflow path is relative to the scanned
repository. Each entry must select exactly one credential source; `step` is
required when a job has multiple sources. Unknown, overlapping, escaping, and
literal-conflicting mappings fail rather than choosing an identity. The map is
limited to 256 KiB and is never auto-loaded from a scanned repository.

A mapped identity is labeled `owner_mapping`, with the original expression and
mapping-file hash retained. Match confidence is medium because it is conditional
on the supplied identity assertion. It is not proof of the stored secret's value.
Literal `env.NAME` references can also be resolved from workflow/job/step YAML
in one bounded substitution; secrets, variables, nested expressions, runtime shell changes, and
arbitrary expressions are not evaluated. These matches are labeled `literal_env`.

## Cloud-First Candidates

With an explicit `--github-repo`, the importer indexes snapshot trust statements
before comparing local job contexts. The supported subset requires a same-account
GitHub federated principal, `sts:AssumeRoleWithWebIdentity`, and only exact
`StringEquals` audience (`sts.amazonaws.com`) and subject claims. It matches a
literal job environment, or one literal branch in a push-only workflow.

Additional claims/operators, wildcard subjects, trust Deny statements, dynamic
environments, and reusable-workflow caller contexts are not inferred. At most
1,000 candidates are returned. This is deliberately a conservative subset, not a
complete OIDC authorization solver; unsupported cases can be false negatives.

Candidates are separate `trust_candidate` bindings at medium confidence. A job
must have `id-token: write` (or `write-all`). The original unknown configured role
remains unknown. A candidate may also exist for a token-capable job with no AWS
action, since compromise could permit a direct token request. Candidates are not
fed back as verified credentials into AI-agent, deployment, or dependency exposure
correlation. Job conditions, runner policy, environment approvals, token issuance,
and actual AWS acceptance are not verified. A candidate is not proof of an attack
or that the workflow is configured to use that role.

## Evidence, Not Effective Authorization

The report inventories Allow grants and retains original Deny, Condition,
NotAction/NotResource, and boundary evidence. It does not subtract denies, evaluate
request conditions/boundaries, or solve session, resource, organization-policy,
or chained-role authorization. These limits are machine-readable partial-coverage
items. `authorization_evaluated` is false; even a high-confidence identity/policy
match does not establish exploitability. Empty grants are not proof of safety.

JSON includes full `policy_evidence` and source hashes. Terminal, Markdown, and
SARIF distinguish identity provenance and authorization limits; saved reports
preserve those distinctions. CI confidence and severity describe observed evidence,
not effective AWS permission. Start report-only rather than gating on a candidate.

## Privacy and Evaluation

Raw exports, maps, and reports can contain private role ARNs, conditions and
resource names. Keep them outside the repository, limit permissions, and review
them before uploading comments or SARIF. Saved baseline state retains fingerprints,
not raw policy documents or mapping contents. Snapshot/map input makes no cloud
calls; `--offline` additionally disables the scanner's other API paths.

The [synthetic reference](https://github.com/r12habh/ActionScope/tree/main/examples/offline-iam-evidence) exercises
known cases without AWS or an external participant. It is software correctness
evidence, not real-world precision/recall, live AWS validation, or demonstrated
operational usefulness. Those require authorized real evidence and human review.
