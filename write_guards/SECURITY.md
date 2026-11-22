# Security policy

## Reporting a problem
Open a private report to the maintainer using the contact listed in the repository profile, or use the repository's
private vulnerability-reporting form if it is enabled. Please do not post exploit details or real credentials in a public issue.
Include: what you ran, what you expected, what happened, and the Python version and operating system.

## What this project is, and is not
Advisory locking and a test-time signal filter. They protect cooperating code from accidents, not from an adversary.

## Honest limits
- These tools are checks and guardrails written with the help of AI coding agents. They are not a security
  boundary, not a sandbox you can rely on against a determined attacker, and not an independent audit.
- Anything that runs as the same user can read, change or delete what the tools protect; cooperative tools only help cooperating code.
- Tests are the project's own. A passing test run shows the tested behaviour, not that the code is free of defects.
- Nothing here has been penetration-tested. Adversarial testing done so far is listed in the README of this component.

## Supported versions
Only the latest commit is maintained. There is no release process or support promise yet.
