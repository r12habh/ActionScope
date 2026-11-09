# Synthetic Offline IAM Reference

All identities, exports, and mappings here are authored test data. The workflow
uses a deliberately non-executable placeholder SHA and must not be installed as
a real deployment. No AWS resources or external participants were involved.

From a source checkout containing the new flags:

```bash
pip install -e .
actionscope scan examples/offline-iam-evidence --offline --output-format json
actionscope scan examples/offline-iam-evidence --offline --output-format json \
  --iam-snapshot examples/offline-iam-evidence/synthetic-iam.json \
  --role-map examples/offline-iam-evidence/synthetic-role-map.json
actionscope scan examples/offline-iam-evidence --offline --output-format json \
  --iam-snapshot examples/offline-iam-evidence/synthetic-iam.json \
  --github-repo example/app
```

Expected observations:

| Run | Configured identity | Policy join | What remains unknown |
| --- | --- | --- | --- |
| No extra evidence | Secret expression | None | Secret value and IAM permissions |
| Snapshot plus role map | Owner-supplied identity, medium confidence | Exact snapshot ARN | Effective authorization; input assertion not independently verified |
| Snapshot plus repository identity | Secret expression remains unresolved; separate trust candidate | Potential OIDC role, medium confidence | Configured role, executable run, effective authorization |

The policy has an explicit Deny of the same action as its Allow. The inventory
retains both; the Allow entry is not proof that deletion is permitted. All
snapshot results are partial authorization evidence, not live verification.

Run `python scripts/evaluate_offline_evidence.py` for machine-checked observations
with input digests. This is a reproducible reference analysis of supplied test
data, not an empirical user study, a field recovery rate, or JOSS eligibility.
