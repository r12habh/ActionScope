# Local Workflow Checks

The hooks in this change are unreleased. Use an exact commit containing
`.pre-commit-hooks.yaml`; existing release tags do not contain these hooks.

```yaml
repos:
  - repo: https://github.com/r12habh/ActionScope
    rev: FULL_COMMIT_SHA_CONTAINING_THE_HOOKS
    hooks:
      - id: actionscope-pins
```

Install pre-commit and run `pre-commit install`, then
`pre-commit run actionscope-pins --all-files`.

`actionscope-pins` checks all workflow YAML files once per invocation. It rejects
mutable action references, including version tags, branches, short SHAs, and
external reusable workflow references. Both `.yml` and `.yaml` are inspected.
It runs offline, needs no credentials, and exits 1 for unpinned dependencies or
2 for a workflow it cannot parse. It does not inspect external action code or
local composite action metadata. The check deliberately requires explicit pins;
it does not accept a dependency lockfile as a substitute for a full-SHA reference.

For the broader static scan, select `id: actionscope` instead. Its default is
`actionscope scan . --offline --fail-on critical`; it is not a pinning-only gate
and does not fail on ordinary medium-risk unpinned-action findings. Customize
that command using the hook's `entry` override when a different threshold is
appropriate. Both hooks use `pass_filenames: false` and `require_serial: true` to
avoid repeating the scan for each changed file.

After installing a checkout containing this change, the narrow gate is also
available as `actionscope-check-pins [PATH]`. It emits plain-text findings to
stderr and is independent of IAM policy evidence and other security rules.

## Reviewable Pin Suggestions

```bash
actionscope scan . --resolve-pins
```

Resolution preserves the original tag and action subpath; it does not upgrade
the action to a new major version. Annotated tags are followed through a bounded,
cycle-checked chain, and only an explicit commit target yields a suggestion.
Repeated repository/tag pairs share a cache for this scan only, including failed
lookups. A current SHA is not a security attestation: review the upstream release
and advisory information before using it. No workflow files are changed.

For automated maintenance, add a `github-actions` entry with `directory: /` to
your existing Dependabot configuration and retain version comments beside pins.
Review major-version changes separately. Confirm updates actually run rather
than assuming that an accepted configuration proves scheduled operation.

Terratest's [merged hardening change](https://github.com/gruntwork-io/terratest/pull/1981)
illustrates pinning plus regression prevention and update maintenance. It acted
on our report; this is not a claim that Terratest installed ActionScope.

## Contributor Verification

```bash
pip install -e '.[dev]'
pre-commit validate-manifest .pre-commit-hooks.yaml
pre-commit try-repo . actionscope-pins --all-files
```

The source checkout intentionally includes unsafe test fixtures. To exercise the
fixture gate directly, `actionscope-check-pins tests/fixtures/coverage_repo`
should exit 1, not 0. Run installation checks in a clean checkout after committing
the hooks, because pre-commit installs from Git rather than the working tree.
