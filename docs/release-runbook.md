# ActionScope Release Runbook

This runbook captures the manual checklist for publishing ActionScope to PyPI,
GitHub Releases, and GitHub Marketplace.

> **Before merging any release-related PR**, follow the
> [Merging Pull Requests](../CONTRIBUTING.md#merging-pull-requests) policy:
> the branch must be up to date with `main` and CI must be green on the
> rebased commit, not on a stale base. This catches conflicts that
> `mergeable: true` does not.

## PyPI Trusted Publishing

1. Open [PyPI Trusted Publishers](https://pypi.org/manage/account/publishing/).
2. Confirm the pending or active publisher:
   - Project name: `actionscope`
   - Owner: `r12habh`
   - Repository: `ActionScope`
   - Workflow: `release.yml`
   - Environment: `release`
3. If the project already exists, manage the publisher from the project page:
   [actionscope on PyPI](https://pypi.org/project/actionscope/).
4. Do not create or store a PyPI API token for the release workflow. The
   workflow uses GitHub OIDC and PyPI trusted publishing.

## GitHub Release Environment Approval

1. Open
   [repository environments](https://github.com/r12habh/ActionScope/settings/environments).
2. Confirm an environment named `release` exists.
3. Require manual approval from the repository owner before deployment.
4. Keep the `release.yml` workflow using `environment: release` so PyPI
   publication cannot happen from an unreviewed tag push.

## Version Bump Flow

1. Update the version across project files:

   ```bash
   python scripts/bump_version.py OLD_VERSION NEW_VERSION
   ```

2. Update `CHANGELOG.md` with the release date and the changes.
3. Run the pre-release checks:

   ```bash
   pip install -e ".[dev,aws]"
   python scripts/pre_release_check.py
   ```

4. Commit the version bump:

   ```bash
   git add pyproject.toml actionscope/__init__.py action.yml CHANGELOG.md
   git commit -m "Release vNEW_VERSION"
   git push origin main
   ```

5. Create and push the tag:

   ```bash
   git tag vNEW_VERSION
   git push origin vNEW_VERSION
   ```

6. Approve the `release` environment deployment in GitHub Actions.

## Updating the `v0` Major Tag

Marketplace users install the action with `uses: r12habh/ActionScope@v0`.
After a successful `v0.x.y` release, move the `v0` tag to the new release:

```bash
git tag -f v0 vNEW_VERSION
git push origin v0 --force
```

Only move `v0` after PyPI publication and the GitHub Release are both healthy.

## GitHub Marketplace Checklist

1. Open the release page:
   [ActionScope releases](https://github.com/r12habh/ActionScope/releases).
2. Edit the latest release.
3. Confirm "Publish this Action to the GitHub Marketplace" is enabled.
4. Confirm metadata from `action.yml` is valid:
   - Name: `ActionScope`
   - Description is concise and accurate
   - Icon: `shield`
   - Color: `orange`
   - Primary category: `Security`
   - Secondary category: `Continuous integration`
5. Confirm the README renders correctly and links to PyPI, docs, research, and
   SARIF setup.

## Rollback Plan

If PyPI publish fails before a package is uploaded:

1. Fix the release workflow or metadata.
2. Delete the failed GitHub Release if it was created.
3. Re-run the release workflow from the same tag after the fix is merged, or
   create a patch tag if the tag contents changed.

If PyPI publish succeeds but the GitHub Release fails:

1. Keep the PyPI package. PyPI releases are immutable.
2. Re-run or repair the GitHub Release manually using the built artifacts.
3. Do not reuse the same version with different code.

If a broken package is published:

1. Yank the version on PyPI instead of deleting it:
   [actionscope release history](https://pypi.org/project/actionscope/#history).
2. Publish a patch release, for example `0.1.2`.
3. Move the `v0` tag only after the patch release is verified.
4. Add a short note to `CHANGELOG.md` explaining the yanked release and fix.
