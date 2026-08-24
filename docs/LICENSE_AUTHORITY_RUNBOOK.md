# AEGIS offline license-authority runbook

Version 1.2.0 · administrative prototype · 23 August 2026

## Purpose

This runbook explains how an authorized publisher can generate an encrypted
Ed25519 authority key, issue an offline AEGIS license, verify it independently
and install only the public material on an endpoint.

The included authority utility is a research-administration tool. It is not a
hosted licensing service, HSM integration, PKI ceremony or production key-
management system.

## Separation of material

| Material | Location | Endpoint deployment |
| --- | --- | --- |
| Encrypted private Ed25519 key | Offline authority machine or HSM | Never |
| Public Ed25519 key | Release trust-anchor input | Yes |
| Signed `license.json` | Customer delivery package | Yes |
| Private-key password | Secret manager/operator ceremony | Never |

Do not create a real vendor private key inside this repository, a source
archive, CI workspace or endpoint bundle.

## 1. Generate an authority key pair

Run on an offline administrative machine from the AEGIS source checkpoint:

```bash
python tools/license_authority.py keygen \
  --private-key /secure/offline/aegis-license-private.pem \
  --public-key /secure/export/aegis-license-public.pem
```

The command prompts for a password of at least 12 UTF-8 bytes and writes an
encrypted PKCS#8 private key. It refuses to overwrite either output. Record the
printed `ED25519-…` key ID in the authority ceremony log.

For controlled non-interactive automation, `--password-env VARIABLE_NAME` reads
the password from the named environment variable. Do not place the password in
the command line, shell history or CI log.

## 2. Issue a license

```bash
python tools/license_authority.py issue \
  --private-key /secure/offline/aegis-license-private.pem \
  --output /secure/export/customer-aegis-license.json \
  --license-id LIC-AEGIS-CUSTOMER-0001 \
  --customer "Authorized Customer Name" \
  --edition ENTERPRISE \
  --max-nodes 250 \
  --valid-days 365 \
  --deployment-id CUSTOMER-PROD-01
```

Without explicit `--entitlement` flags, the administrative prototype includes
all currently known entitlements. A narrower envelope can repeat the flag:

```bash
--entitlement desktop_control_plane \
--entitlement resident_node \
--entitlement local_audit
```

Issuance refuses unknown entitlements, node counts outside `1..100000`, validity
periods outside `1..3650` days and an incorrect private-key type or password.

## 3. Verify before delivery

```bash
python tools/license_authority.py verify \
  --license /secure/export/customer-aegis-license.json \
  --public-key /secure/export/aegis-license-public.pem
```

Successful verification requires state `VALID`, `valid: true` and
`signature_verified: true`. Independently compare the printed key ID, customer,
license ID, node limit, validity window and entitlement list with the approved
order record.

## 4. Install with the Windows executable bundle

From an elevated PowerShell terminal inside the built release bundle:

```powershell
.\Install-AEGIS-Desktop.ps1 `
  -LicensePath "C:\SecureDelivery\license.json" `
  -LicensePublicKeyPath "C:\SecureDelivery\aegis-license-public.pem" `
  -DesktopShortcut
```

Both parameters are required together. The installer copies them to
`%ProgramData%\AEGIS` under a protected ACL, then the resident service verifies
them offline. The Access & Audit workspace must show `VALID`, `SIGNED` and the
expected customer/key claims before commercial operation.

## 5. Rotation and revocation boundary

Version 1.2 supports local reload and time-window expiry. It does not yet
implement a revocation list, online status protocol, multi-key trust store,
grace period, renewal server or signed key-rotation statement.

Safe production evolution:

1. embed one or more vendor root public keys in the code-signed executable;
2. sign a versioned intermediate-key manifest with the offline root;
3. place day-to-day issuance keys in an HSM;
4. separate request approval, issuance and delivery roles;
5. record serials and revocation state in an append-only authority ledger;
6. support signed offline revocation/renewal packages for disconnected sites;
7. test clock rollback and trusted-time behavior; and
8. rotate before expiry with an overlap window and rollback plan.

## 6. Required ceremony record

For each real issuance, retain outside AEGIS:

- authority key ID and custody location;
- operator/reviewer identities and approval ticket;
- exact signed-envelope SHA-256 digest;
- customer and deployment identifiers;
- edition, entitlements, node limit and validity window;
- delivery channel and recipient verification;
- revocation/renewal decision; and
- software release and code-signing identity the license applies to.

This runbook is technical guidance, not legal, export-control, accounting or
contract advice.
