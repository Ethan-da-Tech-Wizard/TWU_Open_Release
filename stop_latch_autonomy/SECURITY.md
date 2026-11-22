# Security policy

## Reporting a problem
Open a private report to the maintainer using the contact listed in the repository profile, or use the repository's
private vulnerability-reporting form if it is enabled. Please do not post exploit details or real credentials in a public issue.
Include: what you ran, what you expected, what happened, and the Python version and operating system.

## What this project is, and is not
A cooperative stop file and a policy lookup table. It does not stop a process that never calls it, and it does not enforce the policy on
anything: callers must ask and obey. Anyone who can create a file at the STOP path can stop every worker that watches it (by design, a
denial of service for cooperating workers); anyone who can edit the policy file can change what is AUTO, except that the seeded NEVER rules
cannot be loosened without an explicit widen marker and a future expiry date.

## Honest limits
- These tools are checks and guardrails written with AI coding agents and reviewed by the maintainer. They are not a security
  boundary, not a sandbox you can rely on against a determined attacker, and not an independent audit.
- Anything that runs as the same user can read, change or delete what the tools protect; cooperative tools only help cooperating code.
- Tests are the project's own. A passing test run shows the tested behaviour, not that the code is free of defects.
- Nothing here has been penetration-tested. The README of this component lists what was and was not checked.

## Supported versions
Only the latest commit is maintained. There is no release process or support promise yet.
