# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Please report suspected vulnerabilities privately by emailing **ateeqdesktop@gmail.com** with the subject `TraceVeil security report`. Do not include raw production telemetry, credentials, or customer data in the report. A minimal synthetic reproduction, affected version, impact assessment, and suggested mitigation are helpful.

We will acknowledge a credible report within seven days and coordinate a fix and disclosure timeline. Public GitHub issues are appropriate for non-sensitive bugs and feature requests only.

## Security scope

The highest-priority reports are raw-value disclosure through evidence, SARIF/JUnit, CLI output, error handling, or logs; evidence/signature verification bypasses; policy parsing that causes unexpected export behavior; and path handling that reads or overwrites unintended files.

