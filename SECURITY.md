# Security policy

## Supported line

Only the latest private development line is maintained. At this checkpoint that
is AEGIS `1.2.x`; earlier research archives are historical and unsupported.

## Reporting a vulnerability

Report vulnerabilities privately through the repository's GitHub Security
Advisory interface. Do not open a normal issue containing exploit steps,
credentials, sensitive logs, customer information or patent-sensitive details.

Include, where safely possible:

- affected version and component;
- defensive reproduction conditions;
- impact and prerequisites;
- sanitized logs or a minimal synthetic reproducer; and
- suggested mitigation, if known.

Do not test against systems you do not own or have explicit written permission
to assess. Do not access, modify, retain or exfiltrate other people's data.

## Product-security boundary

AEGIS `1.2.x` is an unsigned Research Edition. It is not approved for production
enforcement. The platform deliberately forbids hack-back, malware deployment,
human attribution from a model score, and automatic containment that bypasses
the deterministic Safety Kernel.

The project does not promise a disclosure bounty or legal safe harbour. Any
future coordinated-disclosure terms must be established in writing before
testing beyond the reporter's own authorized environment.
