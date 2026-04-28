#!/usr/bin/env python3
"""Seed sample users, projects, tasks, and related data. Requires the API at BASE."""

import httpx

BASE = "http://localhost:8000"
client = httpx.Client(base_url=BASE, timeout=10)


def pr(label, r):
    ok = r.status_code < 300
    body = r.json() if ok else r.text[:120]
    print(f"  {'OK' if ok else 'ERR'} {label}: {r.status_code} {body}")
    return r


print("\nRegistering users...")
alice = pr("register alice", client.post("/auth/register", json={
    "username": "alice",
    "email": "alice@example.com",
    "password": "secret123",
    "full_name": "Alice Wonderland",
})).json()

bob = pr("register bob", client.post("/auth/register", json={
    "username": "bob",
    "email": "bob@example.com",
    "password": "secret123",
    "full_name": "Bob Builder",
})).json()

print("\nLogging in...")
tok = pr("login", client.post("/auth/token", data={
    "username": "alice",
    "password": "secret123",
})).json()

token = tok["access_token"]
headers = {"Authorization": f"Bearer {token}"}

print("\nCreating projects...")
p1 = pr("project Launch v1", client.post("/projects", headers=headers, json={
    "name": "Launch v1",
    "description": "Everything needed for the v1 public launch",
    "emoji": "🚀",
})).json()

pr("project Internal Tools", client.post("/projects", headers=headers, json={
    "name": "Internal Tools",
    "description": "Internal developer productivity improvements",
    "emoji": "🛠️",
})).json()

pid1 = p1["id"]

print("\nAdding members...")
pr("add bob", client.post(f"/projects/{pid1}/members", headers=headers, json={
    "user_id": bob["id"],
    "role": "contributor",
}))

print("\nLabels...")
bug = pr("bug", client.post(f"/projects/{pid1}/labels", headers=headers, json={
    "name": "bug", "color": "#ef4444",
})).json()
feature = pr("feature", client.post(f"/projects/{pid1}/labels", headers=headers, json={
    "name": "feature", "color": "#3b82f6",
})).json()
blocked = pr("blocked", client.post(f"/projects/{pid1}/labels", headers=headers, json={
    "name": "blocked", "color": "#f59e0b",
})).json()

print("\nTasks...")
tasks_data = [
    {"title": "Fix login redirect bug", "description": "Users are redirected to 404 after OAuth login", "priority": "critical"},
    {"title": "Write unit tests for auth module", "description": "Cover edge cases: expired tokens, invalid creds, MFA", "priority": "high"},
    {"title": "Set up CI/CD pipeline", "description": "GitHub Actions: lint, test, build, deploy to staging", "priority": "high"},
    {"title": "Design landing page", "description": "Hero section, features, pricing, CTA", "priority": "medium"},
    {"title": "Write API documentation", "description": "OpenAPI spec + getting started guide", "priority": "medium"},
    {"title": "Add dark mode support", "priority": "low"},
    {"title": "Performance audit", "description": "Lighthouse score must exceed 90", "priority": "medium"},
    {"title": "Set up error monitoring", "description": "Integrate Sentry or Axiom", "priority": "medium"},
]

task_ids = []
for td in tasks_data:
    t = pr(f"task {td['title'][:40]}", client.post(
        f"/projects/{pid1}/tasks", headers=headers, json=td
    )).json()
    task_ids.append(t["id"])

print("\nTask statuses...")
pr("in_progress", client.patch(
    f"/projects/{pid1}/tasks/{task_ids[0]}/status", headers=headers,
    json={"status": "in_progress"},
))
pr("in_review", client.patch(
    f"/projects/{pid1}/tasks/{task_ids[1]}/status", headers=headers,
    json={"status": "in_review"},
))
pr("done", client.patch(
    f"/projects/{pid1}/tasks/{task_ids[2]}/status", headers=headers,
    json={"status": "done"},
))

print("\nAssignments...")
pr("assign to bob", client.patch(
    f"/projects/{pid1}/tasks/{task_ids[0]}/assign", headers=headers,
    json={"assignee_id": bob["id"]},
))
pr("assign to alice", client.patch(
    f"/projects/{pid1}/tasks/{task_ids[1]}/assign", headers=headers,
    json={"assignee_id": alice["id"]},
))

print("\nLabel attachments...")
pr("t0 bug", client.post(
    f"/projects/{pid1}/labels/{bug['id']}/tasks/{task_ids[0]}", headers=headers,
))
pr("t1 feature", client.post(
    f"/projects/{pid1}/labels/{feature['id']}/tasks/{task_ids[1]}", headers=headers,
))
pr("t5 blocked", client.post(
    f"/projects/{pid1}/labels/{blocked['id']}/tasks/{task_ids[5]}", headers=headers,
))

print("\nComments...")
pr("c1", client.post(
    f"/projects/{pid1}/tasks/{task_ids[0]}/comments", headers=headers,
    json={"body": "Root cause found — the callback URL is missing the trailing slash."},
))
pr("c2", client.post(
    f"/projects/{pid1}/tasks/{task_ids[1]}/comments", headers=headers,
    json={"body": "I'll start with the token expiry tests, should be done by EOD."},
))
pr("c3", client.post(
    f"/projects/{pid1}/tasks/{task_ids[0]}/comments", headers=headers,
    json={"body": "PR submitted. Ready for review!"},
))

print("\nWebhook...")
pr("webhook", client.post("/webhooks", headers=headers, json={
    "url": "https://webhook.site/test-appctl",
    "events": ["task.created", "task.updated", "task.status_changed", "comment.created"],
}))

print("\nStats...")
stats = pr("stats", client.get(f"/projects/{pid1}/stats", headers=headers)).json()
print(f"  total_tasks={stats['total_tasks']} completion_rate={stats['completion_rate']}")

print("\nDone. OpenAPI: http://localhost:8000/openapi.json  Docs: http://localhost:8000/docs")
