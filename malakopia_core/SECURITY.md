# Security policy

## Reporting a problem
Open a private report to the maintainer using the contact listed in the repository profile, or use the repository's
private vulnerability-reporting form if it is enabled. Please do not post exploit details or real credentials in a public issue.
Include: what you ran, what you expected, what happened, and the Python version and operating system.

## What this project is, and is not
A local workflow engine and job queue. It does not authenticate users, does not isolate code, and does not defend against a malicious
handler you register yourself: handlers are ordinary Python running with your permissions. The queue keeps its state in a directory
that only the current user may use; it creates that directory with mode 0700 and refuses to use an existing directory that is open to
group or other users (it never changes the permissions of a directory it did not create).

## Honest limits
- These tools are checks and guardrails written with AI coding agents and reviewed by the maintainer. They are not a security
  boundary, not a sandbox you can rely on against a determined attacker, and not an independent audit.
- Anything that runs as the same user can read, change or delete what the tools protect; cooperative tools only help cooperating code.
- Tests are the project's own. A passing test run shows the tested behaviour, not that the code is free of defects.
- Nothing here has been penetration-tested. The README of this component lists what was and was not checked.

## Duplicated queue module (report against both copies)
`malakopia_job_queue.py` (the hardened job queue) is shipped twice: in `malakopia_core/scripts/` and in `enki_waypoint/scripts/`.
The two copies, and their test file `test_malakopia_job_queue.py`, must stay byte-identical. Each component records the expected
SHA-256 of both files in `scripts/queue_copy_sha256.txt`, and `scripts/test_queue_sync.py` fails if a copy drifts from the record
or from its sibling. A vulnerability in the queue affects both components: please name both copies in a report, and a fix must be
applied to both (then update both `queue_copy_sha256.txt` files).

## Supported versions
Only the latest commit is maintained. There is no release process or support promise yet.
