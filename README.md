# Task Management API

FastAPI + SQLite: users, JWT auth, projects, tasks, comments, labels, attachments, webhooks, search, audit log, SSE stream.

## Run

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Optional seed data (needs the server running). Passwords are not hardcoded; set a local-only value:

```bash
export TASK_DEMO_PASSWORD='your-local-password'
python demo.py
```

## Auth

- Register: `POST /auth/register` (JSON body)
- Token: `POST /auth/token` (form: `username`, `password`)
- Protected routes: header `Authorization: Bearer <access_token>`

There are no OAuth client ID/secret values; login is username/password only.

## Docs

- Swagger: http://localhost:8000/docs  
- OpenAPI JSON: http://localhost:8000/openapi.json  

## appctl

[appctl](https://github.com/Esubaalew/appctl) drives an agent from your OpenAPI spec (sync tools, then chat or run against this API). With the server on port 8000:

```bash
appctl sync --openapi http://localhost:8000/openapi.json
appctl chat
# optional UI: appctl serve --open
```

Use `appctl setup` or `--app-dir` if you keep config under this repo’s `.appctl/`. Point sync at a **Bearer** token or `Authorization: Bearer env:YOUR_TOKEN_VAR` when tools need auth.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `SECRET_KEY` | dev string | JWT signing key |
| `TOKEN_EXPIRE_MINUTES` | `60` | Access token lifetime |
| `UPLOAD_DIR` | `.uploads` | Attachment files |
| `DB_PATH` | `appctl_test.db` | SQLite path |
| `TASK_DEMO_PASSWORD` | — | Required for `demo.py`; demo user password |
| `TASK_API_BASE` | `http://localhost:8000` | Override API base URL for `demo.py` |

Set `SECRET_KEY` in production.
