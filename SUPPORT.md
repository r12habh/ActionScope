# Support

ActionScope is maintained as a public open-source project. Support is provided
on a best-effort basis without a guaranteed response time or service-level
agreement.

## Where to Ask

Use the channel that matches the request:

| Request | Channel |
|---|---|
| Usage question or design discussion | [GitHub Discussions](https://github.com/r12habh/ActionScope/discussions) |
| Reproducible bug | [Bug report](https://github.com/r12habh/ActionScope/issues/new?template=bug_report.yml) |
| Feature proposal | [Feature request](https://github.com/r12habh/ActionScope/issues/new?template=feature_request.yml) |
| Security vulnerability | [Private security advisory](https://github.com/r12habh/ActionScope/security/advisories/new) |
| Contribution | [Pull request](https://github.com/r12habh/ActionScope/pulls) |

Please include the ActionScope version, command, relevant workflow or policy
snippet, output format, expected behavior, and actual behavior. Remove account
IDs, role ARNs, secrets, repository names, and other sensitive identifiers when
they are not necessary to reproduce the problem.

## Supported Versions

Security fixes and bug fixes target the latest released version. Before filing
a bug, reproduce it with the latest release when possible:

```bash
python -m pip install --upgrade actionscope
actionscope --version
```

Python versions and optional dependency groups supported by the current
release are listed in `pyproject.toml` and tested in CI.

## Response Expectations

Issues are triaged as maintainer availability permits. Confirmed security
reports and regressions that produce incorrect high-confidence findings take
priority over enhancements and general usage questions. Inactive issues may be
closed when they cannot be reproduced or lack requested information; they can
be reopened when that information becomes available.

## Scope of Support

The project can help explain ActionScope behavior and improve reproducible
detector defects. It cannot review an organization's complete AWS security
posture, guarantee that a workflow is secure, recover policies unavailable to
the scanner, or provide incident-response and compliance certification.
