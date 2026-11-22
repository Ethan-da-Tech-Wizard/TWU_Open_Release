# Security policy

## Reporting a problem
Open a private report with the maintainer through the contact in the repository profile, or use the repository's
private vulnerability-reporting form if it is enabled. Please do not post exploit details or real credentials in a
public issue. Include what you ran, what you expected, what happened, and the Python version and operating system.
The repository-wide policy is in [../SECURITY.md](../SECURITY.md) and applies to this component too.

## What this project is, and is not
User-level monitors that raise an alarm when network exposure or startup items change. They run as the same user
they watch, so anything running as that user can disable them, edit the baseline or edit the allow lists.

## Honest limits
- These tools are checks and guardrails written with AI coding agents and reviewed by a person. They are not a
  security boundary, not a sandbox, and not an independent audit.
- No name is trusted. Earlier versions treated startup items with certain name prefixes as harmless; that was
  removed because any program can choose its own file name. Exemptions are opt-in, exact, and (for the startup
  guard) bound to a content digest. An exemption file is still ordinary same-user data: whoever can write it can
  silence the findings it names. Pin the network allow files with the `*_SHA256` variables and keep them read-only.
- Anything that runs as the same user can read, change or delete what the tools protect. Cooperative tools only
  help cooperating code.
- Without root, `lsof` and `ss` show only this user's sockets; listeners owned by other users or root are not seen.
- External commands are run from fixed system folders (`/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`), not through
  `PATH`, and only if root owns them and nobody else can write them. A missing or unsafe tool is reported as
  `sensor-unavailable`, never as a clean result.
- The unit tests are the project's own. A passing run shows the tested behaviour, not that the code is free of
  defects. Nothing here has been penetration-tested.

## Supported versions
Only the latest commit is maintained. There is no release process or support promise yet.
