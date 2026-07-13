# Compromised GitHub Actions Database

ActionScope ships a curated database of GitHub Actions with documented
supply-chain compromises. This page is the canonical browsable view of every
entry — each one has its own permalink, so you can deep-link from advisories,
incident-response runbooks, or post-mortems.

To check whether *your* repository uses any of these actions:

```bash
pip install actionscope
actionscope scan .
```

Mutable-tag references to a compromised action (e.g. `@v3` of
`actions-cool/issues-helper`) produce a **CRITICAL** finding. Full-SHA pins
are reported only when that exact commit appears in the entry's
`malicious_shas` list; a different immutable SHA is not exposed to tag
redirection.

Refresh public advisory intelligence between ActionScope releases with:

```bash
actionscope update-db
```

For background on how detection works, see
[Compromised Actions detector](compromised-actions.md).

---

## actions-cool/issues-helper

- **Action:** [`actions-cool/issues-helper`](https://github.com/actions-cool/issues-helper)
- **First compromised:** `2026-05-18T19:10:24Z`
- **Status:** ⛔ **Compromised** — actively malicious as of the published advisory
- **Affected references:** `v3`, `v3.8.0`, `v3.7.6`, `v3.7.5`, `v3.7.4`, `v3.7.3`, `v3.7.2`, `v3.7.1`, `v3.7.0`, `v3.6.3`, `v3.6.2`, `v3.6.1`, `v3.6.0`, `v3.5.2`, `v3.5.1`, `v3.5.0`
- **Advisory:** <https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials>

All version tags redirected to imposter commit. Malicious code reads Runner.Worker process memory to exfiltrate CI/CD secrets. Exfiltration domain: t.m-kosche[.]com.

### Are you affected?

```bash
# Scan your repo for *this* compromised action:
actionscope scan . | grep -A 5 'actions-cool/issues-helper'
```

### Remediation

1. **Remove the action** from your workflow, OR
2. **Pin to a verified pre-compromise SHA** if one exists (consult the
   advisory linked above).
3. **Rotate any credentials** the workflow had access to during the
   compromised window. Treat the compromise window as a credential
   disclosure.

---

## actions-cool/maintain-one-comment

- **Action:** [`actions-cool/maintain-one-comment`](https://github.com/actions-cool/maintain-one-comment)
- **First compromised:** `2026-05-18T19:10:24Z`
- **Status:** ⛔ **Compromised** — actively malicious as of the published advisory
- **Affected references:** _All mutable tags are treated as affected; full SHAs are only reported when the exact commit is known malicious._
- **Advisory:** <https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials>

All 15 version tags redirected to imposter commit. Same exfiltration technique and domain as issues-helper. Coordinated attack.

### Are you affected?

```bash
# Scan your repo for *this* compromised action:
actionscope scan . | grep -A 5 'actions-cool/maintain-one-comment'
```

### Remediation

1. **Remove the action** from your workflow, OR
2. **Pin to a verified pre-compromise SHA** if one exists (consult the
   advisory linked above).
3. **Rotate any credentials** the workflow had access to during the
   compromised window. Treat the compromise window as a credential
   disclosure.

---

## aquasecurity/trivy-action

- **Action:** [`aquasecurity/trivy-action`](https://github.com/aquasecurity/trivy-action)
- **First compromised:** `2026-03-19T00:00:00Z`
- **Status:** 📜 **Historical** — past compromise, included for repos still pinned to a pre-fix tag
- **Affected references:** _All mutable tags are treated as affected; full SHAs are only reported when the exact commit is known malicious._
- **Advisory:** <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23>

Official trivy-action and setup-trivy GitHub Actions compromised alongside Trivy scanner binary. Injected credential-stealing malware.

### Are you affected?

```bash
# Scan your repo for *this* compromised action:
actionscope scan . | grep -A 5 'aquasecurity/trivy-action'
```

### Remediation

1. **Remove the action** from your workflow, OR
2. **Pin to a verified pre-compromise SHA** if one exists (consult the
   advisory linked above).
3. **Rotate any credentials** the workflow had access to during the
   compromised window. Treat the compromise window as a credential
   disclosure.

---

## tj-actions/changed-files

- **Action:** [`tj-actions/changed-files`](https://github.com/tj-actions/changed-files)
- **First compromised:** `2025-03-19T00:00:00Z`
- **Status:** 📜 **Historical** — past compromise, included for repos still pinned to a pre-fix tag
- **Affected references:** _All mutable tags are treated as affected; full SHAs are only reported when the exact commit is known malicious._
- **Advisory:** <https://github.com/advisories/GHSA-mrrh-fwg8-r2c3>

All version tags redirected to malicious commit. Exfiltrated secrets via workflow logs. Affected 23,000+ repositories.

### Are you affected?

```bash
# Scan your repo for *this* compromised action:
actionscope scan . | grep -A 5 'tj-actions/changed-files'
```

### Remediation

1. **Remove the action** from your workflow, OR
2. **Pin to a verified pre-compromise SHA** if one exists (consult the
   advisory linked above).
3. **Rotate any credentials** the workflow had access to during the
   compromised window. Treat the compromise window as a credential
   disclosure.

---

## Reporting a new compromise

Found a compromised action that is not on this list? Please open an [issue using the report template](https://github.com/r12habh/ActionScope/issues/new?template=compromised_action_report.yml) so we can add it.
