# 2027 roadmap: reviewing access for coding agents

The decision we want to help with is simple: **should I merge this change to a
coding agent's workflow, and what evidence do I still need?** The first supported
integration is the Claude Code GitHub Action with optional AWS Bedrock. The
existing CLI, scan schema, SARIF and gates remain supported. Model ranking is
report-only. Do not base a merge or a claim about effective access on it.

## Available from this checkout

- [Compare two revisions](agent-review.md) with no AWS credentials. See
  agent-job token declarations, triggers, preceding AWS setups and differences
  in supplied policy records. Unresolved roles remain unknown.
- Give the local model the intended task. Read its prioritized questions
  alongside the complete deterministic diff. No hosted inference or execution
  of the reviewed workflow. The separate composite action returns a JSON file.
- Use `explain` to find cited records in an existing scan. Search relevance is
  not permission evidence; lack of a named action is not proof of a denial.

## Why this workflow

[Anthropic](https://code.claude.com/docs/en/github-actions) documents both
GitHub App authentication and Bedrock federation for code review.
[AWS CheckNoNewAccess](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoNewAccess.html)
already compares IAM policies. The question here is which **agent job**
a proposed change affects and what a maintainer can establish from the checkout.
These sources establish a real configuration, not demand for this tool.

## Next decisions, in order

1. [Evaluate the review](https://github.com/r12habh/ActionScope/issues/173)
   on held-out positive, unchanged and ambiguous changes.
   Compare the same inputs against a deterministic diff and a coding agent.
   Track incorrect claims, missing changes, source accuracy and abstentions.
   Correct citations on a synthetic fixture are not field precision.
2. Invite willing owners to compare their usual review against the tool on
   comparable PRs. Measure decision correctness and time; ask whether they
   use it on a second PR. Use the [owner protocol](owner-validation.md) for
   consent/evidence handling. Never request tokens or send installation PRs.
3. Only after evidence of repeat value, add GitHub Agentic Workflows. The
   [architecture](https://github.github.io/gh-aw/introduction/architecture/)
   separates the agent job from validated writes in other jobs. Model those
   separately; do not assign every downstream permission to the agent.
4. Prioritize evidence completeness ([#165](https://github.com/r12habh/ActionScope/issues/165))
   and unsupported constraints ([#166](https://github.com/r12habh/ActionScope/issues/166)).
   Do not add broad cloud discovery, auto-remediation, a dashboard or IDE
   extension just to expand the feature list.

If a factual diff alone works as well, keep it and simplify the AI layer. If
owners do not use either version twice, revisit the task before adding adapters.
[Terratest's workflow remediation](https://github.com/gruntwork-io/terratest/pull/1981)
predates this direction; it is not evidence for agent-review adoption.
