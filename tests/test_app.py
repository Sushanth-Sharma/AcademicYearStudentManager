"""Regression + behavior tests for the Student Management Portal.

Run with:  pytest
"""

import re
import sqlite3
import urllib.parse

import pytest

from app import app as flask_app
from models import init_db


@pytest.fixture()
def client(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)  # no demo users: tests register their own accounts
    flask_app.config.update(
        TESTING=True,
        DATABASE=db_path,
        SECRET_KEY="test-secret",
    )
    with flask_app.test_client() as c:
        c.db_path = db_path
        yield c


@pytest.fixture()
def db(client):
    conn = sqlite3.connect(client.db_path)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def csrf(client, path="/login"):
    resp = client.get(path)
    token = re.search(r'name="csrf-token" content="([^"]+)"', resp.get_data(as_text=True)).group(1)
    return token


def register_and_login(client, username, password="strongpass123"):
    token = csrf(client)
    r = client.post("/register", data={"username": username, "password": password, "csrf_token": token})
    assert r.status_code == 302
    r = client.post("/login", data={"username": username, "password": password, "csrf_token": token},
                    follow_redirects=False)
    assert r.status_code == 302


def add_student(client, name, course_id=1):
    token = csrf(client, "/add")
    return client.post("/add", data={"name": name, "course_id": course_id, "csrf_token": token})


# ---------------------------------------------------------------- auth

def test_login_page_renders_and_hides_demo_credentials(client):
    body = client.get("/login").get_data(as_text=True)
    assert "Login to Your Account" in body
    # The old login page printed the default passwords; never again.
    assert "2023pass" not in body


def test_registration_and_login_flow(client):
    register_and_login(client, "year2026")
    r = client.get("/dashboard")
    assert r.status_code == 200


def test_registration_rejects_weak_password(client):
    token = csrf(client)
    r = client.post("/register", data={"username": "shorty", "password": "short", "csrf_token": token})
    assert "between 8 and 128" in r.get_data(as_text=True)


def test_login_rate_limiting_blocks_brute_force(client):
    register_and_login(client, "target")
    c2 = client.application.test_client()
    token = csrf(c2)
    for _ in range(5):
        c2.post("/login", data={"username": "target", "password": "wrong", "csrf_token": token})
    r = c2.post("/login", data={"username": "target", "password": "strongpass123", "csrf_token": token})
    assert r.status_code == 429
    assert "Too many failed attempts" in r.get_data(as_text=True)


# ---------------------------------------------------------------- csrf

def test_post_without_csrf_token_rejected(client):
    register_and_login(client, "yearA")
    r = client.post("/add", data={"name": "Eve", "course_id": 1})
    assert r.status_code == 400


def test_csrf_required_on_json_endpoints(client):
    register_and_login(client, "yearA")
    add_student(client, "Alice")
    r = client.post("/attendance/mark", json={"student_id": 1, "date": "2026-10-04", "present": 1})
    assert r.status_code == 400
    assert "CSRF" in r.get_json()["error"]


def test_logout_requires_post(client):
    register_and_login(client, "yearA")
    assert client.get("/logout").status_code == 405
    token = csrf(client)
    assert client.post("/logout", data={"csrf_token": token}).status_code == 302
    assert client.get("/dashboard").status_code == 302  # session gone


# ---------------------------------------------------------------- tenant isolation / IDOR

def test_cross_tenant_student_access_denied(client):
    register_and_login(client, "owner")
    add_student(client, "Bob")  # student id 1, owned by 'owner'

    c2 = client.application.test_client()
    register_and_login(c2, "intruder")
    assert c2.get("/student/1").status_code == 302     # redirected away
    assert c2.get("/edit/1").status_code == 302
    headers = {"X-CSRF-Token": csrf(c2)}
    assert c2.put("/api/students/1", json={"name": "Hijacked", "course_id": 1},
                  headers=headers).status_code == 404
    assert c2.delete("/api/students/1", headers=headers).status_code == 404
    # and the student is untouched
    assert b"Hijacked" not in client.get("/student/1").get_data()


def test_attendance_idor_fixed(client):
    """The exact bug from the review: another user writing attendance for a
    student they do not own must now fail."""
    register_and_login(client, "ownerA")
    add_student(client, "Protected")
    student_id = db_of(client).execute("SELECT id FROM students").fetchone()[0]

    c2 = client.application.test_client()
    register_and_login(c2, "otherUser")
    r = c2.post("/attendance/mark",
                json={"student_id": student_id, "date": "2026-10-04", "present": 1},
                headers={"X-CSRF-Token": csrf(c2)})
    assert r.status_code == 404
    count = sqlite3.connect(client.db_path).execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
    assert count == 0


def db_of(client):
    conn = sqlite3.connect(client.db_path)
    return conn


# ---------------------------------------------------------------- validation

def test_marks_must_be_numeric_and_in_range(client):
    register_and_login(client, "teacher")
    add_student(client, "Alice")
    sid = db_of(client).execute("SELECT id FROM students").fetchone()[0]
    token = csrf(client)
    headers = {"X-CSRF-Token": token}

    r = client.post("/marks/add", json={"student_id": sid, "subject": "Math", "marks": "huge"}, headers=headers)
    assert r.status_code == 400
    r = client.post("/marks/add", json={"student_id": sid, "subject": "Math", "marks": 150}, headers=headers)
    assert r.status_code == 400
    r = client.post("/marks/add", json={"student_id": sid, "subject": "Math", "marks": 85.5}, headers=headers)
    assert r.status_code == 200


def test_attendance_validates_date_and_present(client):
    register_and_login(client, "teacher2")
    add_student(client, "Alice")
    sid = db_of(client).execute("SELECT id FROM students").fetchone()[0]
    headers = {"X-CSRF-Token": csrf(client)}

    r = client.post("/attendance/mark", json={"student_id": sid, "date": "not-a-date", "present": 1}, headers=headers)
    assert r.status_code == 400
    r = client.post("/attendance/mark", json={"student_id": sid, "date": "2026-10-04", "present": "maybe"}, headers=headers)
    assert r.status_code == 400


def test_add_student_rejects_invalid_course(client):
    register_and_login(client, "teacher3")
    r = add_student(client, "Alice", course_id=9999)
    assert "required" in r.get_data(as_text=True)
    assert db_of(client).execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0


# ---------------------------------------------------------------- attendance semantics

def test_attendance_upsert_one_row_per_day(client):
    register_and_login(client, "teacher4")
    add_student(client, "Alice")
    sid = db_of(client).execute("SELECT id FROM students").fetchone()[0]
    headers = {"X-CSRF-Token": csrf(client)}

    client.post("/attendance/mark", json={"student_id": sid, "date": "2026-10-04", "present": 1}, headers=headers)
    client.post("/attendance/mark", json={"student_id": sid, "date": "2026-10-04", "present": 0}, headers=headers)
    rows = db_of(client).execute("SELECT present FROM attendance WHERE student_id = ?", (sid,)).fetchall()
    assert len(rows) == 1 and rows[0][0] == 0


# ---------------------------------------------------------------- deletion / cascade

def test_ui_delete_is_cascading(client, db):
    register_and_login(client, "teacher5")
    add_student(client, "Alice")
    sid = db.execute("SELECT id FROM students").fetchone()[0]
    headers = {"X-CSRF-Token": csrf(client)}
    client.post("/attendance/mark", json={"student_id": sid, "date": "2026-10-04", "present": 1}, headers=headers)
    client.post("/marks/add", json={"student_id": sid, "subject": "Math", "marks": 90}, headers=headers)

    r = client.post(f"/delete/{sid}", data={"csrf_token": csrf(client)})
    assert r.status_code == 302
    assert db.execute("SELECT COUNT(*) FROM attendance").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM marks").fetchone()[0] == 0


def test_api_delete_cascades(client, db):
    register_and_login(client, "teacher6")
    add_student(client, "Alice")
    sid = db.execute("SELECT id FROM students").fetchone()[0]
    headers = {"X-CSRF-Token": csrf(client)}
    client.post("/marks/add", json={"student_id": sid, "subject": "Math", "marks": 90}, headers=headers)

    r = client.delete(f"/api/students/{sid}", headers=headers)
    assert r.status_code == 200
    assert db.execute("SELECT COUNT(*) FROM marks").fetchone()[0] == 0


# ---------------------------------------------------------------- XSS / injection

def test_search_highlight_is_escaped(client):
    evil = "<img src=x onerror=alert(1)>"
    register_and_login(client, "teacher7")
    add_student(client, evil)
    r = client.get("/dashboard?q=" + urllib.parse.quote(evil))
    body = r.get_data(as_text=True)
    assert "<img src=x onerror=alert(1)>" not in body   # never raw
    assert "&lt;img" in body                              # rendered escaped, inside <mark>


def test_sql_injection_attempt_is_harmless(client, db):
    register_and_login(client, "teacher8")
    add_student(client, "Alice")
    client.get("/dashboard?q=' OR 1=1 --")
    assert db.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 1


# ---------------------------------------------------------------- pagination & exports

def test_dashboard_paginates(client):
    register_and_login(client, "teacher9")
    for i in range(30):
        add_student(client, f"Student {i:02d}")
    body = client.get("/dashboard").get_data(as_text=True)
    assert "Page 1 / 2" in body
    assert "Next" in body
    body2 = client.get("/dashboard?page=2").get_data(as_text=True)
    assert "Page 2 / 2" in body2


def test_export_students_csv(client):
    register_and_login(client, "teacher10")
    add_student(client, "CSV Student")
    r = client.get("/export/students")
    assert r.status_code == 200
    assert "CSV Student" in r.get_data(as_text=True)


# ---------------------------------------------------------------- models.py safety

def test_models_init_is_non_destructive(client):
    register_and_login(client, "keeper")
    add_student(client, "Survivor")
    init_db(client.db_path)  # simulates re-running setup
    count = db_of(client).execute("SELECT COUNT(*) FROM students").fetchone()[0]
    assert count == 1  # data survives re-running init (old code DROPped everything)


def test_no_demo_users_without_seed(tmp_path):
    path = str(tmp_path / "nodb-demo.db")
    init_db(path)
    assert sqlite3.connect(path).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_sqlite_fk_enforced_after_init(tmp_path):
    from flask import Flask  # not needed for connection; direct check via models.get_connection
    from models import get_connection
    path = str(tmp_path / "fk.db")
    init_db(path)
    conn = get_connection(path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO students (name, course_id, user_id) VALUES ('x', 1, 999)")
