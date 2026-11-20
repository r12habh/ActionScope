#!/usr/bin/env python3
"""
ActionScope Public Repository Research Scanner

Scans public GitHub repositories that use AWS via GitHub Actions
and collects workflow-level security statistics.

Usage:
  python research/scan_public_repos.py --token YOUR_PAT --output findings.json
  python research/scan_public_repos.py --token YOUR_PAT --resume --output findings.json
  python research/scan_public_repos.py --report --output findings.json

Requirements:
  pip install requests tqdm
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests
from tqdm import tqdm

GITHUB_API = "https://api.github.com"
SEARCH_QUERY = "aws-actions/configure-aws-credentials path:.github/workflows"
ACTIONSCOPE_VERSION = "0.1.1"
FULL_SHA_RE = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
ROLE_ARN_RE = re.compile(r"arn:aws:iam::\d{12}:role/")
USES_RE = re.compile(r"^\s*uses\s*:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
EXTERNAL_ACTION_RE = re.compile(
    r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[^\s@#]+)?@(.+)$"
)


@dataclass
class WorkflowFinding:
    """Workflow-level security finding for one public GitHub Actions file."""

    repo_hash: str
    repo_full_name: str
    workflow_filename: str
    uses_oidc: bool
    uses_access_keys: bool
    has_role_arn: bool
    role_arn_is_dynamic: bool
    has_write_all: bool
    has_contents_write: bool
    has_pr_write: bool
    has_actions_write: bool
    has_packages_write: bool
    uses_pull_request_target: bool
    dangerous_prt_combo: bool
    uses_unpinned_actions: bool
    scanned_at: str
    error: str | None


class GitHubAPI:
    """Wrapper around GitHub REST API with rate limiting."""

    def __init__(self, token: str):
        self.token = token
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "actionscope-public-research",
            }
        )
        self.requests_made = 0

    def get(self, url: str, params: dict | None = None) -> Any | None:
        """Make a GET request and handle GitHub rate limits automatically."""
        response = self._get_response(url, params=params)
        if response is None:
            return None
        try:
            return response.json()
        except ValueError as exc:
            print(f"GitHub API returned invalid JSON for {url}: {exc}", file=sys.stderr)
            return None

    def search_code(self, query: str, per_page: int = 100) -> list[dict]:
        """Search GitHub code and return up to GitHub's 1000-result cap."""
        items: list[dict] = []
        for page in range(1, 11):
            data = self.get(
                f"{GITHUB_API}/search/code",
                params={
                    "q": query,
                    "per_page": per_page,
                    "page": page,
                },
            )
            if not isinstance(data, dict):
                break

            total_count = int(data.get("total_count", 0) or 0)
            if page == 1 and total_count > 1000:
                print(
                    "Warning: GitHub code search returned "
                    f"{total_count} results; only first 1000 are available.",
                    file=sys.stderr,
                )

            page_items = data.get("items", [])
            if not isinstance(page_items, list) or not page_items:
                break

            items.extend(item for item in page_items if isinstance(item, dict))
            if len(items) >= min(total_count, 1000):
                break

            time.sleep(6)

        return items[:1000]

    def get_workflow_files(self, repo_full_name: str) -> list[dict]:
        """Get workflow YAML file metadata for a public repository."""
        data = self.get(
            f"{GITHUB_API}/repos/{repo_full_name}/contents/.github/workflows"
        )
        if not isinstance(data, list):
            return []

        files: list[dict] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            download_url = item.get("download_url")
            if not isinstance(name, str) or not name.endswith((".yml", ".yaml")):
                continue
            if not isinstance(download_url, str):
                continue
            files.append({"name": name, "download_url": download_url})
        return files

    def get_file_content(self, download_url: str) -> str | None:
        """Download raw file content. Return None on error."""
        response = self._get_response(download_url)
        if response is None:
            return None
        return response.text

    def _get_response(
        self,
        url: str,
        params: dict | None = None,
        retry: bool = True,
    ) -> requests.Response | None:
        try:
            response = self.session.get(url, params=params, timeout=30)
        except requests.RequestException as exc:
            print(f"GitHub request failed for {url}: {exc}", file=sys.stderr)
            return None

        self.requests_made += 1
        self._sleep_if_rate_limit_low(response)

        if response.status_code == 404:
            return None

        if response.status_code in {403, 429} and retry:
            print(
                f"GitHub rate limit or throttling response ({response.status_code}); "
                "sleeping 60s before retry.",
                file=sys.stderr,
            )
            time.sleep(60)
            return self._get_response(url, params=params, retry=False)

        if response.status_code >= 400:
            print(
                f"GitHub request failed for {url}: {response.status_code} "
                f"{response.text[:200]}",
                file=sys.stderr,
            )
            return None

        return response

    def _sleep_if_rate_limit_low(self, response: requests.Response) -> None:
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset = response.headers.get("X-RateLimit-Reset")
        if remaining is None or reset is None:
            return
        if not remaining.isdigit() or not reset.isdigit():
            return
        if int(remaining) >= 5:
            return

        sleep_seconds = max(0, int(reset) - int(time.time()) + 1)
        if sleep_seconds:
            print(
                f"GitHub rate limit nearly exhausted; sleeping {sleep_seconds}s.",
                file=sys.stderr,
            )
            time.sleep(sleep_seconds)


def hash_repo(repo_full_name: str) -> str:
    """Return first 12 chars of SHA256 of repo name for anonymization."""
    return hashlib.sha256(repo_full_name.encode()).hexdigest()[:12]


def analyze_workflow_content(
    content: str,
    filename: str,
    repo_full_name: str,
) -> WorkflowFinding:
    """Analyze a single workflow file with minimal inline detection."""
    normalized = content.lower()
    has_configure_aws = "aws-actions/configure-aws-credentials" in normalized
    has_role_to_assume = "role-to-assume" in normalized
    has_id_token_write = bool(re.search(r"id-token\s*:\s*write", content, re.I))

    has_write_all = "write-all" in normalized
    has_contents_write = bool(re.search(r"contents\s*:\s*write", content, re.I))
    has_pr_write = bool(re.search(r"pull-requests\s*:\s*write", content, re.I))
    has_actions_write = bool(re.search(r"actions\s*:\s*write", content, re.I))
    has_packages_write = bool(re.search(r"packages\s*:\s*write", content, re.I))
    uses_pull_request_target = bool(
        re.search(r"(^|\s|-\s*)pull_request_target\s*:", content, re.I | re.M)
        or "pull_request_target" in normalized
    )
    dangerous_prt_combo = uses_pull_request_target and (
        has_pr_write or has_write_all or has_contents_write
    )

    return WorkflowFinding(
        repo_hash=hash_repo(repo_full_name),
        repo_full_name=repo_full_name,
        workflow_filename=filename,
        uses_oidc=has_configure_aws and has_role_to_assume and has_id_token_write,
        uses_access_keys=has_configure_aws and "aws-access-key-id" in normalized,
        has_role_arn=ROLE_ARN_RE.search(content) is not None,
        role_arn_is_dynamic=bool(
            re.search(r"role-to-assume\s*:\s*[^\n]*\$\{\{", content, re.I)
        ),
        has_write_all=has_write_all,
        has_contents_write=has_contents_write,
        has_pr_write=has_pr_write,
        has_actions_write=has_actions_write,
        has_packages_write=has_packages_write,
        uses_pull_request_target=uses_pull_request_target,
        dangerous_prt_combo=dangerous_prt_combo,
        uses_unpinned_actions=_uses_unpinned_actions(content),
        scanned_at=datetime.now(UTC).isoformat(),
        error=None,
    )


def scan_repo(repo_full_name: str, api: GitHubAPI) -> list[WorkflowFinding]:
    """Scan all AWS-using workflow files in a public repository."""
    findings: list[WorkflowFinding] = []
    for workflow_file in api.get_workflow_files(repo_full_name):
        content = api.get_file_content(workflow_file["download_url"])
        if content is None:
            continue
        if "aws-actions/configure-aws-credentials" not in content.lower():
            continue
        findings.append(
            analyze_workflow_content(
                content,
                workflow_file["name"],
                repo_full_name,
            )
        )
    return findings


def load_progress(output_file: str) -> tuple[set[str], list[dict]]:
    """Load previously scanned repos and findings from an output file."""
    path = Path(output_file)
    if not path.exists():
        return set(), []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"Could not load progress from {output_file}: {exc}", file=sys.stderr)
        return set(), []

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    metadata = data.get("metadata", {})
    scanned_repos = set()
    if isinstance(metadata, dict):
        raw_scanned = metadata.get("scanned_repos", [])
        if isinstance(raw_scanned, list):
            scanned_repos.update(str(repo) for repo in raw_scanned)

    for finding in findings:
        if isinstance(finding, dict) and finding.get("repo_full_name"):
            scanned_repos.add(str(finding["repo_full_name"]))

    return scanned_repos, [f for f in findings if isinstance(f, dict)]


def save_progress(
    output_file: str,
    findings: list[dict],
    metadata: dict,
) -> None:
    """Save findings and metadata to a JSON output file."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_out = {
        "scanned_at": metadata.get("scanned_at", datetime.now(UTC).isoformat()),
        "total_repos_scanned": metadata.get("total_repos_scanned", 0),
        "total_workflows_analyzed": metadata.get(
            "total_workflows_analyzed",
            len(findings),
        ),
        "github_api_requests": metadata.get("github_api_requests", 0),
        "actionscope_version": ACTIONSCOPE_VERSION,
    }
    for key, value in metadata.items():
        if key not in metadata_out:
            metadata_out[key] = value

    payload = {
        "metadata": metadata_out,
        "findings": findings,
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan public GitHub repos for workflow-level AWS patterns."
    )
    parser.add_argument(
        "--token",
        required=False,
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub PAT (or set GITHUB_TOKEN env var)",
    )
    parser.add_argument("--output", default="research/findings.json")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from existing output file",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Max repos to scan (default: 500)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate markdown report from existing findings.json",
    )
    args = parser.parse_args()

    if args.report:
        from generate_report import generate_markdown_report, write_csv_summary

        findings_data = json.loads(Path(args.output).read_text(encoding="utf-8"))
        report = generate_markdown_report(findings_data)
        report_path = args.output.replace(".json", "_report.md")
        csv_path = args.output.replace(".json", "_summary.csv")
        Path(report_path).write_text(report, encoding="utf-8")
        write_csv_summary(findings_data, csv_path)
        print(f"Report written to {report_path}")
        print(f"CSV summary written to {csv_path}")
        return

    if not args.token:
        print("Error: GitHub token required. Set GITHUB_TOKEN or use --token")
        sys.exit(1)

    api = GitHubAPI(args.token)

    print("Searching for repositories using aws-actions/configure-aws-credentials...")
    search_results = api.search_code(SEARCH_QUERY)

    repos = sorted(
        {
            item["repository"]["full_name"]
            for item in search_results
            if isinstance(item.get("repository"), dict)
            and item["repository"].get("full_name")
        }
    )
    print(f"Found {len(repos)} repositories. Scanning up to {args.limit}...")

    already_scanned: set[str] = set()
    all_findings: list[dict] = []
    if args.resume and Path(args.output).exists():
        already_scanned, all_findings = load_progress(args.output)
        print(f"Resuming: {len(already_scanned)} repos already scanned")

    repos_to_scan = [r for r in repos[: args.limit] if r not in already_scanned]
    scanned_repos = set(already_scanned)

    for index, repo in enumerate(tqdm(repos_to_scan, desc="Scanning repos"), start=1):
        findings = scan_repo(repo, api)
        scanned_repos.add(repo)
        for finding in findings:
            all_findings.append(asdict(finding))

        if index % 10 == 0:
            save_progress(
                args.output,
                all_findings,
                {
                    "in_progress": True,
                    "scanned_at": datetime.now(UTC).isoformat(),
                    "total_repos_scanned": len(scanned_repos),
                    "total_workflows_analyzed": len(all_findings),
                    "github_api_requests": api.requests_made,
                    "scanned_repos": sorted(scanned_repos),
                },
            )

        time.sleep(0.5)

    save_progress(
        args.output,
        all_findings,
        {
            "in_progress": False,
            "scanned_at": datetime.now(UTC).isoformat(),
            "total_repos_scanned": len(scanned_repos),
            "total_workflows_analyzed": len(all_findings),
            "github_api_requests": api.requests_made,
            "scanned_repos": sorted(scanned_repos),
        },
    )

    print(
        f"\nScan complete. {len(all_findings)} workflow findings "
        f"saved to {args.output}"
    )
    print(
        "Generate report: "
        f"python research/scan_public_repos.py --report --output {args.output}"
    )


def _uses_unpinned_actions(content: str) -> bool:
    for match in USES_RE.finditer(content):
        uses_value = match.group(1).strip()
        if uses_value.startswith(("./", "../")):
            continue
        action_match = EXTERNAL_ACTION_RE.match(uses_value)
        if not action_match:
            continue
        ref = action_match.group(1).strip()
        if FULL_SHA_RE.fullmatch(ref) is None:
            return True
    return False


if __name__ == "__main__":
    main()
