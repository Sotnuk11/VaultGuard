# VaultGuard

[![CI](https://github.com/Sotnuk11/VaultGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Sotnuk11/VaultGuard/actions/workflows/ci.yml)

A small team password vault with folder-level access control, server-side AES encryption and a dead man's switch.
Built as a security-focused full-stack project: **FastAPI + PostgreSQL** backend, **React (Vite)** frontend.

## Features

- **Authentication**: bcrypt password hashing, JWT access tokens (8 h), roles (`admin` / `user`) always read from the database, never from the client.
- **Folders with access control**: admins create folders and choose which users may open them. Every item and decrypt request is checked against folder access.
- **Encrypted secrets**: each secret is encrypted with AES-256-GCM. The key is derived from a master password with PBKDF2-HMAC-SHA256 (600 000 iterations) and a random salt. The master password is never stored, so a database leak exposes only ciphertext.
- **Dead man's switch** (`checker.py`): if the admin sends no heartbeat for a configurable time, the vault ciphertext is emailed to a trusted person, encrypted with their RSA public key (hybrid RSA-OAEP + AES-GCM).
- **Tests**: 19 automated tests covering crypto, authentication and authorization rules.

## Security design

| Threat | Mitigation |
|---|---|
| Database leak | Secrets stored as AES-GCM ciphertext; passwords as bcrypt hashes |
| Forged role / privilege escalation | Role loaded from DB on each request; admin endpoints use an `admin_required` dependency (covered by tests) |
| Access to other users' folders | Folder membership checked on list, create, decrypt; "missing" and "forbidden" return the same 404 (`Not found`) |
| Tampered ciphertext | GCM authentication tag; decryption fails on any change |
| User enumeration via login | Identical error and constant bcrypt work for unknown users |
| Secrets in the repo | Configuration only through environment variables; `.env`, `*.pem`, `keys/` are git-ignored |
| Open CORS | Explicit allow-list via `CORS_ORIGINS` |
| Weak defaults | No default admin password: `ADMIN_PASSWORD` (min. 12 chars) and `JWT_SECRET` (min. 32 chars) are required |

### Known limitations

This is a portfolio project, not a production password manager. Not implemented: login rate limiting / lockout, refresh tokens and token revocation, audit log, password change flow, HTTPS enforcement (use a TLS-terminating host), and the master password is sent to the server over TLS for encryption/decryption (not zero-knowledge).

## Project layout

```
main.py          FastAPI app: models, auth, folders, items
security.py      bcrypt, JWT, AES-GCM vault encryption, RSA+AES wrapping
checker.py       dead man's switch watcher (separate process)
generate_keys.py creates the recipient RSA key pair in keys/ (git-ignored)
tests/           pytest suite (crypto + API authorization)
frontend/        React + Vite UI
```

## Run locally

Requirements: Python 3.11+, Node 20+, a PostgreSQL database.

```bash
# backend
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # then fill DATABASE_URL, JWT_SECRET, ADMIN_PASSWORD
uvicorn main:app --reload                             # http://127.0.0.1:8000/docs

# frontend
cd frontend
cp .env.example .env.local                            # VITE_API_URL
npm install && npm run dev                            # http://localhost:5173
```

Generate a JWT secret: `python -c "import secrets; print(secrets.token_urlsafe(48))"`

### Dead man's switch (optional)

```bash
python generate_keys.py        # give keys/recipient_public.pem to the server, keep the private key offline
# fill SMTP_* and RECIPIENT_* in .env (use an app password, not your account password)
python checker.py
```

The recipient decrypts an emailed block with `security.unwrap_with_private_key(payload, private_key_pem)`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## API overview

All endpoints except `POST /api/login` require `Authorization: Bearer <token>`.

| Method | Path | Access |
|---|---|---|
| POST | `/api/login` | public |
| POST | `/api/iamhere` | any user (heartbeat) |
| GET / POST | `/api/users` | admin |
| GET | `/api/folders` | user (own folders) / admin (all) |
| POST / PUT / DELETE | `/api/folders[/{id}/access]` | admin |
| GET | `/api/folders/{id}/items` | folder members |
| POST | `/api/encrypt`, `/api/decrypt` | folder members |
| DELETE | `/api/items/{id}` | admin |

## Tech stack

Python, FastAPI, SQLAlchemy, PostgreSQL, PyCryptodome, bcrypt, PyJWT, pytest, React, Vite, Axios.

## License

MIT
