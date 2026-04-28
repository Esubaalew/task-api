from __future__ import annotations

import io
import json
import os
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator, Optional

import bcrypt as _bcrypt
import uvicorn
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field

# Configuration

SECRET_KEY = os.getenv("SECRET_KEY", "appctl-dev-secret-change-in-production-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", ".uploads"))
DB_PATH = Path(os.getenv("DB_PATH", "appctl_test.db"))

UPLOAD_DIR.mkdir(exist_ok=True)

# Database


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


DB = Depends(get_db)


def init_db() -> None:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                username    TEXT UNIQUE NOT NULL,
                email       TEXT UNIQUE NOT NULL,
                full_name   TEXT,
                hashed_pw   TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'member',
                is_active   INTEGER NOT NULL DEFAULT 1,
                bio         TEXT,
                avatar_url  TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT,
                owner_id    TEXT NOT NULL REFERENCES users(id),
                status      TEXT NOT NULL DEFAULT 'active',
                emoji       TEXT DEFAULT '📁',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS project_members (
                project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role        TEXT NOT NULL DEFAULT 'contributor',
                joined_at   TEXT NOT NULL,
                PRIMARY KEY (project_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                description TEXT,
                project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                assignee_id TEXT REFERENCES users(id),
                status      TEXT NOT NULL DEFAULT 'todo',
                priority    TEXT NOT NULL DEFAULT 'medium',
                due_date    TEXT,
                created_by  TEXT NOT NULL REFERENCES users(id),
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS comments (
                id          TEXT PRIMARY KEY,
                task_id     TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                author_id   TEXT NOT NULL REFERENCES users(id),
                body        TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS labels (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                color       TEXT NOT NULL DEFAULT '#6b7280',
                project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS task_labels (
                task_id     TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                label_id    TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
                PRIMARY KEY (task_id, label_id)
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id            TEXT PRIMARY KEY,
                task_id       TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                stored_name   TEXT NOT NULL,
                size_bytes    INTEGER NOT NULL,
                content_type  TEXT,
                uploaded_by   TEXT NOT NULL REFERENCES users(id),
                uploaded_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS webhooks (
                id          TEXT PRIMARY KEY,
                url         TEXT NOT NULL,
                events      TEXT NOT NULL,
                secret      TEXT,
                is_active   INTEGER NOT NULL DEFAULT 1,
                owner_id    TEXT NOT NULL REFERENCES users(id),
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          TEXT PRIMARY KEY,
                actor_id    TEXT REFERENCES users(id),
                action      TEXT NOT NULL,
                resource    TEXT NOT NULL,
                resource_id TEXT,
                detail      TEXT,
                ts          TEXT NOT NULL
            );
        """)
        conn.commit()


# Auth helpers

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")


def hash_pw(pw: str) -> str:
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()


def verify_pw(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


def make_token(data: dict, expires_delta: timedelta | None = None) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    payload["exp"] = expire
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2), db: sqlite3.Connection = DB):
    creds_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise creds_exc
    except JWTError:
        raise creds_exc
    row = db.execute("SELECT * FROM users WHERE id=? AND is_active=1", (user_id,)).fetchone()
    if not row:
        raise creds_exc
    return dict(row)


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


def audit(db: sqlite3.Connection, actor_id: str, action: str, resource: str,
          resource_id: str = None, detail: str = None):
    db.execute(
        "INSERT INTO audit_log VALUES (?,?,?,?,?,?,?)",
        (new_id(), actor_id, action, resource, resource_id, detail, now_iso()),
    )


# Pydantic schemas


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, examples=["alice"])
    email: EmailStr = Field(..., examples=["alice@example.com"])
    password: str = Field(..., min_length=6, examples=["secret123"])
    full_name: Optional[str] = Field(None, examples=["Alice Wonderland"])


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    bio: Optional[str]
    avatar_url: Optional[str]
    created_at: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, examples=["Launch v1"])
    description: Optional[str] = Field(None, examples=["Everything needed for the v1 launch"])
    emoji: Optional[str] = Field("📁", examples=["🚀"])


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|archived|paused)$")
    emoji: Optional[str] = None


class ProjectOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    owner_id: str
    status: str
    emoji: str
    created_at: str
    updated_at: str


class MemberAdd(BaseModel):
    user_id: str
    role: str = Field("contributor", pattern="^(owner|admin|contributor|viewer)$")


class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, examples=["Write unit tests"])
    description: Optional[str] = Field(None, examples=["Cover all edge cases in auth module"])
    assignee_id: Optional[str] = None
    priority: str = Field("medium", pattern="^(low|medium|high|critical)$")
    due_date: Optional[str] = Field(None, examples=["2025-12-31"])


class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    assignee_id: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(todo|in_progress|in_review|done|cancelled)$")
    priority: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    due_date: Optional[str] = None


class TaskStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(todo|in_progress|in_review|done|cancelled)$",
                        examples=["in_progress"])


class TaskAssign(BaseModel):
    assignee_id: Optional[str] = Field(None, description="User ID to assign, or null to unassign")


class TaskOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    project_id: str
    assignee_id: Optional[str]
    status: str
    priority: str
    due_date: Optional[str]
    created_by: str
    created_at: str
    updated_at: str


class CommentCreate(BaseModel):
    body: str = Field(..., min_length=1, examples=["Working on this now, should be done today."])


class CommentUpdate(BaseModel):
    body: str = Field(..., min_length=1)


class CommentOut(BaseModel):
    id: str
    task_id: str
    author_id: str
    body: str
    created_at: str
    updated_at: str


class LabelCreate(BaseModel):
    name: str = Field(..., examples=["bug"])
    color: str = Field("#6b7280", examples=["#ef4444"])


class LabelOut(BaseModel):
    id: str
    name: str
    color: str
    project_id: str


class AttachmentOut(BaseModel):
    id: str
    task_id: str
    original_name: str
    size_bytes: int
    content_type: Optional[str]
    uploaded_by: str
    uploaded_at: str


class WebhookCreate(BaseModel):
    url: str = Field(..., examples=["https://myserver.com/hooks/appctl"])
    events: list[str] = Field(..., examples=[["task.created", "task.updated"]])
    secret: Optional[str] = None


class WebhookOut(BaseModel):
    id: str
    url: str
    events: list[str]
    is_active: bool
    owner_id: str
    created_at: str


class SearchResult(BaseModel):
    tasks: list[TaskOut]
    projects: list[ProjectOut]
    total: int


class StatsOut(BaseModel):
    total_tasks: int
    by_status: dict[str, int]
    by_priority: dict[str, int]
    overdue_count: int
    completion_rate: float


class HealthOut(BaseModel):
    status: str
    version: str
    db: str
    uptime_seconds: float


# App

START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    UPLOAD_DIR.mkdir(exist_ok=True)
    yield


app = FastAPI(
    title="Task Management API",
    description="Projects, tasks, comments, labels, attachments, webhooks. JWT auth via `/auth/token`.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def rows_to(model, rows) -> list:
    return [model(**dict(r)) for r in rows]


# Auth

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post(
    "/register",
    response_model=UserOut,
    status_code=201,
    summary="Register a new user",
    description="Create a new account. Username and email must be unique.",
)
def register(body: UserRegister, db: sqlite3.Connection = DB):
    if db.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
        raise HTTPException(400, "Username already taken")
    if db.execute("SELECT 1 FROM users WHERE email=?", (body.email,)).fetchone():
        raise HTTPException(400, "Email already registered")
    uid = new_id()
    ts = now_iso()
    db.execute(
        "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (uid, body.username, body.email, body.full_name,
         hash_pw(body.password), "member", 1, None, None, ts, ts),
    )
    db.commit()
    return UserOut(id=uid, username=body.username, email=body.email,
                   full_name=body.full_name, role="member", is_active=True,
                   bio=None, avatar_url=None, created_at=ts)


@auth_router.post(
    "/token",
    response_model=TokenOut,
    summary="Login and obtain an access token",
    description="Submit username + password via form-data. Returns a Bearer token.",
)
def login(form: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = DB):
    row = db.execute("SELECT * FROM users WHERE username=?", (form.username,)).fetchone()
    if not row or not verify_pw(form.password, row["hashed_pw"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if not row["is_active"]:
        raise HTTPException(status_code=403, detail="Account disabled")
    token = make_token({"sub": row["id"]}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return TokenOut(access_token=token)


@auth_router.get(
    "/me",
    response_model=UserOut,
    summary="Get the currently authenticated user",
    description="Returns the full profile of the logged-in user.",
)
def me(current: dict = Depends(get_current_user)):
    return UserOut(**{k: current[k] for k in UserOut.model_fields})


@auth_router.patch(
    "/me",
    response_model=UserOut,
    summary="Update your own profile",
    description="Update full_name, bio, or avatar_url for the currently authenticated user.",
)
def update_me(body: UserUpdate, current: dict = Depends(get_current_user),
              db: sqlite3.Connection = DB):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        sets = ", ".join(f"{k}=?" for k in updates) + ", updated_at=?"
        db.execute(f"UPDATE users SET {sets} WHERE id=?",
                   (*updates.values(), now_iso(), current["id"]))
        db.commit()
    row = db.execute("SELECT * FROM users WHERE id=?", (current["id"],)).fetchone()
    return UserOut(**dict(row))


app.include_router(auth_router)


# Users

users_router = APIRouter(prefix="/users", tags=["Users"])


@users_router.get(
    "",
    response_model=list[UserOut],
    summary="List all active users",
    description="Returns every active user in the system. Useful for finding user IDs when assigning tasks.",
)
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: sqlite3.Connection = DB,
    _=Depends(get_current_user),
):
    rows = db.execute(
        "SELECT * FROM users WHERE is_active=1 ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, skip),
    ).fetchall()
    return rows_to(UserOut, rows)


@users_router.get(
    "/{user_id}",
    response_model=UserOut,
    summary="Get a user by ID",
    description="Fetch full profile of any user by their UUID.",
)
def get_user(user_id: str, db: sqlite3.Connection = DB, _=Depends(get_current_user)):
    row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(404, "User not found")
    return UserOut(**dict(row))


@users_router.patch(
    "/{user_id}/deactivate",
    summary="Deactivate a user (admin only)",
    description="Soft-delete a user. They can no longer log in.",
)
def deactivate_user(user_id: str, db: sqlite3.Connection = DB, admin=Depends(require_admin)):
    db.execute("UPDATE users SET is_active=0, updated_at=? WHERE id=?", (now_iso(), user_id))
    db.commit()
    return {"message": f"User {user_id} deactivated"}


app.include_router(users_router)


# Projects

projects_router = APIRouter(prefix="/projects", tags=["Projects"])


@projects_router.post(
    "",
    response_model=ProjectOut,
    status_code=201,
    summary="Create a new project",
    description="Creates a project owned by the authenticated user. The creator is automatically added as owner.",
)
def create_project(body: ProjectCreate, current=Depends(get_current_user),
                   db: sqlite3.Connection = DB):
    pid = new_id()
    ts = now_iso()
    db.execute(
        "INSERT INTO projects VALUES (?,?,?,?,?,?,?,?)",
        (pid, body.name, body.description, current["id"], "active", body.emoji or "📁", ts, ts),
    )
    db.execute("INSERT INTO project_members VALUES (?,?,?,?)",
               (pid, current["id"], "owner", ts))
    audit(db, current["id"], "create", "project", pid, body.name)
    db.commit()
    return ProjectOut(id=pid, name=body.name, description=body.description,
                      owner_id=current["id"], status="active",
                      emoji=body.emoji or "📁", created_at=ts, updated_at=ts)


@projects_router.get(
    "",
    response_model=list[ProjectOut],
    summary="List all projects",
    description="Returns all projects. Filter by status with ?status=active|archived|paused",
)
def list_projects(
    status: Optional[str] = Query(None, pattern="^(active|archived|paused)$"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: sqlite3.Connection = DB,
    _=Depends(get_current_user),
):
    if status:
        rows = db.execute(
            "SELECT * FROM projects WHERE status=? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            (status, limit, skip),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM projects ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            (limit, skip),
        ).fetchall()
    return rows_to(ProjectOut, rows)


@projects_router.get(
    "/{project_id}",
    response_model=ProjectOut,
    summary="Get a project by ID",
)
def get_project(project_id: str, db: sqlite3.Connection = DB, _=Depends(get_current_user)):
    row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Project not found")
    return ProjectOut(**dict(row))


@projects_router.patch(
    "/{project_id}",
    response_model=ProjectOut,
    summary="Update a project",
    description="Update name, description, status (active/archived/paused), or emoji.",
)
def update_project(project_id: str, body: ProjectUpdate, current=Depends(get_current_user),
                   db: sqlite3.Connection = DB):
    row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Project not found")
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        sets = ", ".join(f"{k}=?" for k in updates) + ", updated_at=?"
        db.execute(f"UPDATE projects SET {sets} WHERE id=?",
                   (*updates.values(), now_iso(), project_id))
        audit(db, current["id"], "update", "project", project_id)
        db.commit()
    row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    return ProjectOut(**dict(row))


@projects_router.delete(
    "/{project_id}",
    status_code=204,
    summary="Delete a project",
    description="Permanently deletes a project and all its tasks, comments, and labels.",
)
def delete_project(project_id: str, current=Depends(get_current_user),
                   db: sqlite3.Connection = DB):
    row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Project not found")
    db.execute("DELETE FROM projects WHERE id=?", (project_id,))
    audit(db, current["id"], "delete", "project", project_id)
    db.commit()


@projects_router.get(
    "/{project_id}/members",
    summary="List project members",
    description="Returns all members of a project with their roles.",
)
def list_members(project_id: str, db: sqlite3.Connection = DB, _=Depends(get_current_user)):
    rows = db.execute("""
        SELECT u.id, u.username, u.email, u.full_name, u.avatar_url, pm.role, pm.joined_at
        FROM project_members pm
        JOIN users u ON u.id = pm.user_id
        WHERE pm.project_id = ?
    """, (project_id,)).fetchall()
    return [dict(r) for r in rows]


@projects_router.post(
    "/{project_id}/members",
    status_code=201,
    summary="Add a member to a project",
    description="Add a user to the project. Role can be owner, admin, contributor, or viewer.",
)
def add_member(project_id: str, body: MemberAdd, current=Depends(get_current_user),
               db: sqlite3.Connection = DB):
    if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
        raise HTTPException(404, "Project not found")
    if not db.execute("SELECT 1 FROM users WHERE id=?", (body.user_id,)).fetchone():
        raise HTTPException(404, "User not found")
    db.execute("INSERT OR REPLACE INTO project_members VALUES (?,?,?,?)",
               (project_id, body.user_id, body.role, now_iso()))
    audit(db, current["id"], "add_member", "project", project_id, body.user_id)
    db.commit()
    return {"message": "Member added", "user_id": body.user_id, "role": body.role}


@projects_router.delete(
    "/{project_id}/members/{user_id}",
    status_code=204,
    summary="Remove a member from a project",
)
def remove_member(project_id: str, user_id: str, current=Depends(get_current_user),
                  db: sqlite3.Connection = DB):
    db.execute("DELETE FROM project_members WHERE project_id=? AND user_id=?",
               (project_id, user_id))
    audit(db, current["id"], "remove_member", "project", project_id, user_id)
    db.commit()


@projects_router.get(
    "/{project_id}/stats",
    response_model=StatsOut,
    summary="Get project statistics",
    description="Returns task counts by status, priority distribution, overdue count, and completion rate.",
)
def project_stats(project_id: str, db: sqlite3.Connection = DB, _=Depends(get_current_user)):
    if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
        raise HTTPException(404, "Project not found")
    rows = db.execute("SELECT status, priority FROM tasks WHERE project_id=?",
                      (project_id,)).fetchall()
    by_status: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        by_priority[r["priority"]] = by_priority.get(r["priority"], 0) + 1
    total = len(rows)
    done = by_status.get("done", 0)
    today = datetime.now(timezone.utc).date().isoformat()
    overdue = db.execute(
        "SELECT COUNT(*) FROM tasks WHERE project_id=? AND due_date < ? AND status NOT IN ('done','cancelled')",
        (project_id, today),
    ).fetchone()[0]
    return StatsOut(
        total_tasks=total,
        by_status=by_status,
        by_priority=by_priority,
        overdue_count=overdue,
        completion_rate=round(done / total, 2) if total else 0.0,
    )


app.include_router(projects_router)


# Tasks

tasks_router = APIRouter(prefix="/projects/{project_id}/tasks", tags=["Tasks"])


def _get_task(project_id: str, task_id: str, db: sqlite3.Connection) -> dict:
    row = db.execute(
        "SELECT * FROM tasks WHERE id=? AND project_id=?", (task_id, project_id)
    ).fetchone()
    if not row:
        raise HTTPException(404, "Task not found")
    return dict(row)


@tasks_router.post(
    "",
    response_model=TaskOut,
    status_code=201,
    summary="Create a task in a project",
    description="Add a new task. Status defaults to 'todo'. Priority can be low, medium, high, or critical.",
)
def create_task(project_id: str, body: TaskCreate, current=Depends(get_current_user),
                db: sqlite3.Connection = DB):
    if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
        raise HTTPException(404, "Project not found")
    tid = new_id()
    ts = now_iso()
    db.execute(
        "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (tid, body.title, body.description, project_id, body.assignee_id,
         "todo", body.priority, body.due_date, current["id"], ts, ts),
    )
    audit(db, current["id"], "create", "task", tid, body.title)
    db.commit()
    return TaskOut(id=tid, title=body.title, description=body.description,
                   project_id=project_id, assignee_id=body.assignee_id,
                   status="todo", priority=body.priority, due_date=body.due_date,
                   created_by=current["id"], created_at=ts, updated_at=ts)


@tasks_router.get(
    "",
    response_model=list[TaskOut],
    summary="List tasks in a project",
    description="Filter by status, priority, or assignee. Sort by created_at descending.",
)
def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    assignee_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: sqlite3.Connection = DB,
    _=Depends(get_current_user),
):
    q = "SELECT * FROM tasks WHERE project_id=?"
    params: list = [project_id]
    if status:
        q += " AND status=?"
        params.append(status)
    if priority:
        q += " AND priority=?"
        params.append(priority)
    if assignee_id:
        q += " AND assignee_id=?"
        params.append(assignee_id)
    q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, skip]
    return rows_to(TaskOut, db.execute(q, params).fetchall())


@tasks_router.get(
    "/{task_id}",
    response_model=TaskOut,
    summary="Get a specific task",
)
def get_task(project_id: str, task_id: str, db: sqlite3.Connection = DB,
             _=Depends(get_current_user)):
    return TaskOut(**_get_task(project_id, task_id, db))


@tasks_router.patch(
    "/{task_id}",
    response_model=TaskOut,
    summary="Update a task",
    description="Update any field of a task: title, description, assignee, status, priority, due_date.",
)
def update_task(project_id: str, task_id: str, body: TaskUpdate,
                current=Depends(get_current_user), db: sqlite3.Connection = DB):
    _get_task(project_id, task_id, db)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        sets = ", ".join(f"{k}=?" for k in updates) + ", updated_at=?"
        db.execute(f"UPDATE tasks SET {sets} WHERE id=?",
                   (*updates.values(), now_iso(), task_id))
        audit(db, current["id"], "update", "task", task_id)
        db.commit()
    return TaskOut(**_get_task(project_id, task_id, db))


@tasks_router.patch(
    "/{task_id}/status",
    response_model=TaskOut,
    summary="Change task status",
    description="Move a task through its lifecycle: todo → in_progress → in_review → done (or cancelled).",
)
def change_status(project_id: str, task_id: str, body: TaskStatusUpdate,
                  current=Depends(get_current_user), db: sqlite3.Connection = DB):
    _get_task(project_id, task_id, db)
    db.execute("UPDATE tasks SET status=?, updated_at=? WHERE id=?",
               (body.status, now_iso(), task_id))
    audit(db, current["id"], "status_change", "task", task_id, body.status)
    db.commit()
    return TaskOut(**_get_task(project_id, task_id, db))


@tasks_router.patch(
    "/{task_id}/assign",
    response_model=TaskOut,
    summary="Assign (or unassign) a task",
    description="Set assignee_id to a user ID to assign, or null to unassign.",
)
def assign_task(project_id: str, task_id: str, body: TaskAssign,
                current=Depends(get_current_user), db: sqlite3.Connection = DB):
    _get_task(project_id, task_id, db)
    db.execute("UPDATE tasks SET assignee_id=?, updated_at=? WHERE id=?",
               (body.assignee_id, now_iso(), task_id))
    audit(db, current["id"], "assign", "task", task_id, body.assignee_id)
    db.commit()
    return TaskOut(**_get_task(project_id, task_id, db))


@tasks_router.delete(
    "/{task_id}",
    status_code=204,
    summary="Delete a task",
    description="Permanently deletes a task and all its comments, labels, and attachments.",
)
def delete_task(project_id: str, task_id: str, current=Depends(get_current_user),
                db: sqlite3.Connection = DB):
    _get_task(project_id, task_id, db)
    db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    audit(db, current["id"], "delete", "task", task_id)
    db.commit()


app.include_router(tasks_router)


# Comments

comments_router = APIRouter(
    prefix="/projects/{project_id}/tasks/{task_id}/comments", tags=["Comments"]
)


@comments_router.post(
    "",
    response_model=CommentOut,
    status_code=201,
    summary="Add a comment to a task",
    description="Post a text comment on any task. Supports plain text.",
)
def add_comment(project_id: str, task_id: str, body: CommentCreate,
                current=Depends(get_current_user), db: sqlite3.Connection = DB):
    if not db.execute("SELECT 1 FROM tasks WHERE id=? AND project_id=?",
                      (task_id, project_id)).fetchone():
        raise HTTPException(404, "Task not found")
    cid = new_id()
    ts = now_iso()
    db.execute("INSERT INTO comments VALUES (?,?,?,?,?,?)",
               (cid, task_id, current["id"], body.body, ts, ts))
    audit(db, current["id"], "comment", "task", task_id)
    db.commit()
    return CommentOut(id=cid, task_id=task_id, author_id=current["id"],
                      body=body.body, created_at=ts, updated_at=ts)


@comments_router.get(
    "",
    response_model=list[CommentOut],
    summary="List comments on a task",
)
def list_comments(project_id: str, task_id: str, db: sqlite3.Connection = DB,
                  _=Depends(get_current_user)):
    rows = db.execute(
        "SELECT * FROM comments WHERE task_id=? ORDER BY created_at ASC", (task_id,)
    ).fetchall()
    return rows_to(CommentOut, rows)


@comments_router.patch(
    "/{comment_id}",
    response_model=CommentOut,
    summary="Edit a comment",
    description="Update the body of a comment. Only the original author can edit.",
)
def edit_comment(project_id: str, task_id: str, comment_id: str, body: CommentUpdate,
                 current=Depends(get_current_user), db: sqlite3.Connection = DB):
    row = db.execute("SELECT * FROM comments WHERE id=?", (comment_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Comment not found")
    if row["author_id"] != current["id"] and current["role"] != "admin":
        raise HTTPException(403, "Cannot edit another user's comment")
    db.execute("UPDATE comments SET body=?, updated_at=? WHERE id=?",
               (body.body, now_iso(), comment_id))
    db.commit()
    row = db.execute("SELECT * FROM comments WHERE id=?", (comment_id,)).fetchone()
    return CommentOut(**dict(row))


@comments_router.delete(
    "/{comment_id}",
    status_code=204,
    summary="Delete a comment",
)
def delete_comment(project_id: str, task_id: str, comment_id: str,
                   current=Depends(get_current_user), db: sqlite3.Connection = DB):
    row = db.execute("SELECT * FROM comments WHERE id=?", (comment_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Comment not found")
    if row["author_id"] != current["id"] and current["role"] != "admin":
        raise HTTPException(403, "Forbidden")
    db.execute("DELETE FROM comments WHERE id=?", (comment_id,))
    db.commit()


app.include_router(comments_router)


# Labels

labels_router = APIRouter(prefix="/projects/{project_id}/labels", tags=["Labels"])


@labels_router.post(
    "",
    response_model=LabelOut,
    status_code=201,
    summary="Create a label",
    description="Create a colour-coded label scoped to a project (e.g. 'bug', 'feature', 'blocked').",
)
def create_label(project_id: str, body: LabelCreate, current=Depends(get_current_user),
                 db: sqlite3.Connection = DB):
    if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
        raise HTTPException(404, "Project not found")
    lid = new_id()
    db.execute("INSERT INTO labels VALUES (?,?,?,?)", (lid, body.name, body.color, project_id))
    db.commit()
    return LabelOut(id=lid, name=body.name, color=body.color, project_id=project_id)


@labels_router.get(
    "",
    response_model=list[LabelOut],
    summary="List labels in a project",
)
def list_labels(project_id: str, db: sqlite3.Connection = DB, _=Depends(get_current_user)):
    rows = db.execute("SELECT * FROM labels WHERE project_id=?", (project_id,)).fetchall()
    return rows_to(LabelOut, rows)


@labels_router.delete(
    "/{label_id}",
    status_code=204,
    summary="Delete a label",
)
def delete_label(project_id: str, label_id: str, current=Depends(get_current_user),
                 db: sqlite3.Connection = DB):
    db.execute("DELETE FROM labels WHERE id=? AND project_id=?", (label_id, project_id))
    db.commit()


@labels_router.post(
    "/{label_id}/tasks/{task_id}",
    status_code=201,
    summary="Attach a label to a task",
    description="Tag a task with an existing label from the same project.",
)
def attach_label(project_id: str, label_id: str, task_id: str,
                 current=Depends(get_current_user), db: sqlite3.Connection = DB):
    db.execute("INSERT OR IGNORE INTO task_labels VALUES (?,?)", (task_id, label_id))
    db.commit()
    return {"message": "Label attached", "task_id": task_id, "label_id": label_id}


@labels_router.delete(
    "/{label_id}/tasks/{task_id}",
    status_code=204,
    summary="Detach a label from a task",
)
def detach_label(project_id: str, label_id: str, task_id: str,
                 current=Depends(get_current_user), db: sqlite3.Connection = DB):
    db.execute("DELETE FROM task_labels WHERE task_id=? AND label_id=?", (task_id, label_id))
    db.commit()


@labels_router.get(
    "/_tasks/{task_id}",
    response_model=list[LabelOut],
    summary="Get all labels on a task",
)
def task_labels(project_id: str, task_id: str, db: sqlite3.Connection = DB,
                _=Depends(get_current_user)):
    rows = db.execute("""
        SELECT l.* FROM labels l
        JOIN task_labels tl ON tl.label_id = l.id
        WHERE tl.task_id = ?
    """, (task_id,)).fetchall()
    return rows_to(LabelOut, rows)


app.include_router(labels_router)


# Attachments

files_router = APIRouter(
    prefix="/projects/{project_id}/tasks/{task_id}/attachments", tags=["Attachments"]
)


@files_router.post(
    "",
    response_model=AttachmentOut,
    status_code=201,
    summary="Upload a file attachment to a task",
    description="Upload any file (PDF, image, doc, etc.) and attach it to a task. Max 50 MB.",
)
def upload_attachment(
    project_id: str,
    task_id: str,
    file: UploadFile = File(...),
    current=Depends(get_current_user),
    db: sqlite3.Connection = DB,
):
    if not db.execute("SELECT 1 FROM tasks WHERE id=? AND project_id=?",
                      (task_id, project_id)).fetchone():
        raise HTTPException(404, "Task not found")
    aid = new_id()
    stored = f"{aid}_{file.filename}"
    dest = UPLOAD_DIR / stored
    content = file.file.read()
    dest.write_bytes(content)
    ts = now_iso()
    db.execute("INSERT INTO attachments VALUES (?,?,?,?,?,?,?,?)",
               (aid, task_id, file.filename, stored, len(content),
                file.content_type, current["id"], ts))
    db.commit()
    return AttachmentOut(id=aid, task_id=task_id, original_name=file.filename,
                         size_bytes=len(content), content_type=file.content_type,
                         uploaded_by=current["id"], uploaded_at=ts)


@files_router.get(
    "",
    response_model=list[AttachmentOut],
    summary="List attachments on a task",
)
def list_attachments(project_id: str, task_id: str, db: sqlite3.Connection = DB,
                     _=Depends(get_current_user)):
    rows = db.execute("SELECT * FROM attachments WHERE task_id=?", (task_id,)).fetchall()
    return rows_to(AttachmentOut, rows)


@files_router.get(
    "/{attachment_id}/download",
    summary="Download a file attachment",
    description="Returns the raw file bytes as a streaming download.",
)
def download_attachment(project_id: str, task_id: str, attachment_id: str,
                        db: sqlite3.Connection = DB, _=Depends(get_current_user)):
    row = db.execute("SELECT * FROM attachments WHERE id=?", (attachment_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Attachment not found")
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        raise HTTPException(404, "File not found on disk")
    return StreamingResponse(
        io.BytesIO(path.read_bytes()),
        media_type=row["content_type"] or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{row["original_name"]}"'},
    )


@files_router.delete(
    "/{attachment_id}",
    status_code=204,
    summary="Delete an attachment",
)
def delete_attachment(project_id: str, task_id: str, attachment_id: str,
                      current=Depends(get_current_user), db: sqlite3.Connection = DB):
    row = db.execute("SELECT * FROM attachments WHERE id=?", (attachment_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Attachment not found")
    path = UPLOAD_DIR / row["stored_name"]
    if path.exists():
        path.unlink()
    db.execute("DELETE FROM attachments WHERE id=?", (attachment_id,))
    db.commit()


app.include_router(files_router)


# Webhooks

webhooks_router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

VALID_EVENTS = {
    "task.created", "task.updated", "task.deleted", "task.status_changed",
    "project.created", "project.updated", "project.deleted",
    "comment.created", "member.added",
}


@webhooks_router.post(
    "",
    response_model=WebhookOut,
    status_code=201,
    summary="Register a webhook",
    description=f"Subscribe to one or more events. Valid events: {', '.join(sorted(VALID_EVENTS))}",
)
def create_webhook(body: WebhookCreate, current=Depends(get_current_user),
                   db: sqlite3.Connection = DB):
    invalid = set(body.events) - VALID_EVENTS
    if invalid:
        raise HTTPException(400, f"Unknown events: {invalid}")
    wid = new_id()
    ts = now_iso()
    db.execute("INSERT INTO webhooks VALUES (?,?,?,?,?,?,?)",
               (wid, body.url, json.dumps(body.events), body.secret, 1, current["id"], ts))
    db.commit()
    return WebhookOut(id=wid, url=body.url, events=body.events,
                      is_active=True, owner_id=current["id"], created_at=ts)


@webhooks_router.get(
    "",
    response_model=list[WebhookOut],
    summary="List your webhooks",
)
def list_webhooks(current=Depends(get_current_user), db: sqlite3.Connection = DB):
    rows = db.execute("SELECT * FROM webhooks WHERE owner_id=?", (current["id"],)).fetchall()
    return [WebhookOut(
        id=r["id"], url=r["url"], events=json.loads(r["events"]),
        is_active=bool(r["is_active"]), owner_id=r["owner_id"], created_at=r["created_at"],
    ) for r in rows]


@webhooks_router.delete(
    "/{webhook_id}",
    status_code=204,
    summary="Delete a webhook",
)
def delete_webhook(webhook_id: str, current=Depends(get_current_user),
                   db: sqlite3.Connection = DB):
    db.execute("DELETE FROM webhooks WHERE id=? AND owner_id=?", (webhook_id, current["id"]))
    db.commit()


app.include_router(webhooks_router)


# Search


@app.get(
    "/search",
    response_model=SearchResult,
    tags=["Search"],
    summary="Full-text search across tasks and projects",
    description="Search by keyword across task titles, task descriptions, and project names. Returns matching tasks and projects.",
)
def search(
    q: str = Query(..., min_length=1, description="Search keyword", examples=["login bug"]),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: sqlite3.Connection = DB,
    _=Depends(get_current_user),
):
    pattern = f"%{q}%"
    task_rows = db.execute(
        "SELECT * FROM tasks WHERE title LIKE ? OR description LIKE ? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        (pattern, pattern, limit, skip),
    ).fetchall()
    proj_rows = db.execute(
        "SELECT * FROM projects WHERE name LIKE ? OR description LIKE ? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        (pattern, pattern, limit, skip),
    ).fetchall()
    tasks = rows_to(TaskOut, task_rows)
    projects = rows_to(ProjectOut, proj_rows)
    return SearchResult(tasks=tasks, projects=projects, total=len(tasks) + len(projects))


# Audit


@app.get(
    "/audit",
    tags=["Audit"],
    summary="View the audit log",
    description="Returns recent actions taken in the system. Useful for compliance and debugging.",
)
def get_audit(
    resource: Optional[str] = Query(None, description="Filter by resource type (task, project, etc.)"),
    actor_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: sqlite3.Connection = DB,
    _=Depends(require_admin),
):
    q = "SELECT * FROM audit_log WHERE 1=1"
    params: list = []
    if resource:
        q += " AND resource=?"
        params.append(resource)
    if actor_id:
        q += " AND actor_id=?"
        params.append(actor_id)
    q += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(q, params).fetchall()
    return [dict(r) for r in rows]


# SSE task stream


@app.get(
    "/stream/tasks",
    tags=["Streaming"],
    summary="Server-Sent Events stream of task updates",
)
def stream_tasks(
    project_id: Optional[str] = Query(None, description="Filter stream to one project"),
    _=Depends(get_current_user),
):
    def generator():
        yield "data: {\"connected\": true}\n\n"
        last_ts = now_iso()
        seen: set[str] = set()
        for _ in range(120):  # stream for ~60 seconds then close
            import time as _time
            _time.sleep(0.5)
            with sqlite3.connect(str(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                q = "SELECT * FROM tasks WHERE updated_at >= ? ORDER BY updated_at ASC"
                rows = conn.execute(q, (last_ts,)).fetchall()
                for row in rows:
                    d = dict(row)
                    if d["id"] not in seen:
                        if not project_id or d["project_id"] == project_id:
                            seen.add(d["id"])
                            last_ts = d["updated_at"]
                            yield f"data: {json.dumps(d)}\n\n"
        yield "data: {\"closed\": true}\n\n"

    return StreamingResponse(generator(), media_type="text/event-stream")


# Health / info


@app.get(
    "/health",
    response_model=HealthOut,
    tags=["System"],
    summary="Health check",
)
def health():
    try:
        with sqlite3.connect(str(DB_PATH)) as c:
            c.execute("SELECT 1")
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"
    return HealthOut(
        status="ok",
        version="1.0.0",
        db=db_status,
        uptime_seconds=round(time.time() - START_TIME, 1),
    )


@app.get("/info", tags=["System"], summary="Capability summary")
def info():
    return {
        "name": "Task Management API",
        "version": "1.0.0",
        "resources": ["users", "projects", "tasks", "comments", "labels", "attachments", "webhooks"],
        "task_statuses": ["todo", "in_progress", "in_review", "done", "cancelled"],
        "task_priorities": ["low", "medium", "high", "critical"],
        "project_statuses": ["active", "archived", "paused"],
        "webhook_events": sorted(VALID_EVENTS),
    }


# Entry

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
