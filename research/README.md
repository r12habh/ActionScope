# ActionScope Research

This directory contains findings from scanning 493 public GitHub repositories
that use AWS via GitHub Actions.

## Reproducing This Research

```bash
# Install dependencies
pip install requests tqdm

# Run the scanner (requires GitHub PAT with public_repo scope)
export GITHUB_TOKEN=your_token_here
python research/scan_public_repos.py --limit 500 --output research/findings_may2026.json

# Generate the report
python research/generate_report.py \
  --input research/findings_may2026.json \
  --output research/FINDINGS.md \
  --csv research/findings_summary.csv
```

## What We Measured

We analyzed only public workflow YAML files. We did not:

- Access any AWS account
- Call any AWS APIs for external repos
- Store any repository credentials or secrets
- Make any changes to any repository

## Findings

See [FINDINGS.md](FINDINGS.md).

The raw scanner JSON keeps repository names locally so interrupted runs can
resume cleanly. Public artifacts generated from it use `repo_hash` and omit
repository names.

## Technical Paper

A technical paper draft exists locally but is intentionally not linked from
public documentation until publication. Do not add PDF, arXiv, or preprint
links here until the paper has been approved for public sharing.

## Using ActionScope on Your Own Repo

The workflow-level statistics above show what's visible from outside.
To see the actual AWS blast radius of your own workflows:

```bash
pip install actionscope
actionscope scan .                    # static analysis (no AWS needed)
actionscope scan . --aws-verify       # live AWS verification
```
