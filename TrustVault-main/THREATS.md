# TrustVault Threat Model

Status: starter threat model; update this as implementation and tests evolve.

## Assets
- Confidential document bytes and metadata
- User credentials and access tokens
- Per-document permission grants
- Audit events and their integrity

## Threats and current controls

| Threat | Current mitigation | Test / remaining work |
|---|---|---|
| Insecure direct object reference (guessing another document ID) | Every document endpoint checks current ownership/grant in the backend | `tests/test_security.py`; expand tests for every endpoint |
| Direct download URL bypass | Files are not mounted as a public static directory; download goes through API check | Test unauthenticated and cross-user downloads |
| Permission revoked after token issued | Grants are checked against the database for each document request | Revocation test; do not introduce long-lived signed download URLs |
| Viewer changes metadata | Edit endpoint requires owner or edit grant | Cross-user edit test; add tests for read-only grantees |
| Viewer deletes document | Delete endpoint only permits the owner | Cross-user delete test |
| Unauthorised grant/revoke | Only the document owner can grant or revoke | Add explicit tests for attempted grant/revoke by non-owner |
| Audit event modified | Hash chain detects individual edits and broken chain | Not sufficient against full database rewrite; add signed external checkpoints |
| File type spoofing / malicious upload | Extension allowlist and size cap | Not sufficient; add magic-byte checks and malware scanning |
| Brute-force login | No rate limiting yet | Accepted only for local prototype; add rate limiting before deployment |
| Token theft | Short-lived JWT | No refresh/logout revocation yet; use TLS, secure token storage and server-side token revocation in production |
| CSRF / browser token exposure | API uses bearer tokens rather than cookie auth | Do not store bearer token in localStorage for a production browser app; use a carefully designed secure session strategy |
| Race between permission check and operation | Current simple implementation checks before streaming/updating | Strengthen transaction boundaries and test concurrent revocation |
| Path traversal | Random server-generated storage names; original filename is only download metadata | Keep storage outside public web root |
| Admin abuse | Admin does not automatically bypass document grants; audit view is role restricted | Add least-privilege admin policies and external audit review |
| Database/file mismatch | Upload cleans up the file if metadata insert fails | Add crash-recovery reconciliation jobs |

## Deliberately not built in the starter
- External identity provider / MFA
- Antivirus scanning
- Document versioning and retention policy
- Signed, externally anchored audit checkpoints
- Production rate limiting and monitoring
- Multi-tenant organisation boundaries
- Secure browser UI and hardened deployment

Do not claim the audit log is tamper-proof: the hash chain is tamper-evident only while its trusted starting point or checkpoint remains outside an attacker's control.
