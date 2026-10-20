# TrustVault — secure document sharing prototype

A learning / challenge starter using FastAPI, SQLite, JWT bearer authentication, private local storage, per-document grants, and a hash-chained audit log.

## Requirements
- Python 3.10+
- Windows PowerShell or a POSIX shell

## Setup (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:TRUSTVAULT_SECRET = "replace-with-a-long-random-secret-before-use"
uvicorn main:app --reload
```

Open http://127.0.0.1:8000/docs.

## Development seed accounts
- Admin: `admin` / `Admin-ChangeMe-123!`
- Owner: `owner` / `Owner-ChangeMe-123!`
- Viewer: `viewer` / `Viewer-ChangeMe-123!`

These are development-only credentials. Change them before any shared demo. Do not expose this prototype publicly with these passwords.

## How to use the API
1. In `/docs`, call `POST /token` using form fields `username` and `password`.
2. Click **Authorize** and enter the returned token as a Bearer token.
3. As `owner`, upload a `.txt` or `.pdf` file through `POST /documents`.
4. Grant `viewer` read access with `POST /documents/{id}/grants`.
5. Authorize as `viewer` and download the granted file.
6. Revoke access as `owner`, then repeat the download: it should fail.
7. Sign in as `admin` and inspect `/admin/audit` and `/admin/audit/verify`.

## Tests
```powershell
pytest -q
```

## Endpoints and access policy
| Endpoint | Allowed caller |
|---|---|
| `POST /token` | Public login endpoint |
| `GET /me` | Authenticated user |
| `POST /documents` | Authenticated user (uploads as owner) |
| `GET /documents` | Authenticated user; only own/granted documents |
| `GET /documents/{id}` | Owner or current read/edit grantee |
| `GET /documents/{id}/download` | Owner or current read/edit grantee |
| `PATCH /documents/{id}` | Owner or current edit grantee |
| `POST /documents/{id}/grants` | Document owner only |
| `DELETE /documents/{id}/grants/{username}` | Document owner only |
| `DELETE /documents/{id}` | Document owner only |
| `GET /admin/audit` | Admin role |
| `GET /admin/audit/verify` | Admin role |

## Important security limitations
This is not a production-ready service. Before public deployment, add:
- PostgreSQL or another production database, migrations, and tested transaction semantics
- HTTPS, secret management, account provisioning and password changes
- Login rate limiting, MFA, account lockout and token revocation
- File signature/MIME validation, malware scanning, quotas and storage encryption
- A safer browser session design, CSRF strategy if cookies are used, and secure headers
- Audit events written transactionally with operations; signed audit checkpoints stored outside the database
- Concurrent revocation/download tests and comprehensive authorisation tests
- Backups, retention/deletion policy, monitoring and deployment hardening

A SHA-256 hash chain alone is not a tamper-proof audit trail: someone who can rewrite the whole database can recompute the chain. The verification endpoint is a basic integrity check, not independent proof.
