"""
Student Management Portal - Flask application.

Run:
    python models.py          # create/upgrade the SQLite database (non-destructive)
    python app.py             # serve on http://127.0.0.1:5000 (debug: FLASK_DEBUG=1)

Configuration is done via environment variables (see README.md):
    SECRET_KEY, DATABASE_PATH, HOST, PORT, FLASK_DEBUG, SESSION_SECURE_COOKIES
"""

import csv
import hmac
import io
import logging
import os
import re
import secrets
import threading
import sqlite3
from collections import defaultdict, deque
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (
    Flask, Response, current_app, flash, g, jsonify, redirect,
    render_template, request, send_file, session, url_for,
)
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Application setup & security configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

DEFAULT_DB_PATH = os.path.join(app.root_path, "database.db")
SECRET_KEY_FILE = os.path.join(app.root_path, "secret_key")


def _load_secret_key():
    """Use SECRET_KEY from the environment; otherwise create a random key file.

    A predictable fallback secret lets attackers forge session cookies, so
    instead of shipping a default we generate a random key once and persist it
    outside of version control (gitignored). In production, set the SECRET_KEY
    environment variable explicitly.
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    try:
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as fh:
            key = fh.read().strip()
            if key:
                return key
    except FileNotFoundError:
        pass
    key = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, "x", encoding="utf-8") as fh:
            fh.write(key)
        os.chmod(SECRET_KEY_FILE, 0o600)
    except FileExistsError:
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as fh:
            key = fh.read().strip() or key
    return key


app.config.update(
    SECRET_KEY=_load_secret_key(),
    DATABASE=os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",          # blocks cross-site form posts from sending cookies
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_SECURE_COOKIES") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,     # 1 MiB body limit - no giant payload DoS
    JSON_SORT_KEYS=False,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


# ---------------------------------------------------------------------------
# Database helpers (one connection per request, transaction-safe)
# ---------------------------------------------------------------------------

def get_db():
    """Return the request-scoped SQLite connection, creating it if needed."""
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        # SQLite does not enforce FOREIGN KEY constraints unless asked. Without
        # this pragma every FK in the schema is decoration and cascade deletes
        # never fire, which lets orphaned rows pile up.
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def query_all(sql, params=()):
    return [dict(r) for r in get_db().execute(sql, params).fetchall()]


def query_one(sql, params=()):
    row = get_db().execute(sql, params).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

NAME_MAX = 100
SUBJECT_MAX = 60
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")


def clean_name(raw):
    """Strip and validate a student name; return None when invalid."""
    name = (raw or "").strip()
    if 1 <= len(name) <= NAME_MAX:
        return name
    return None


def clean_subject(raw):
    subject = (raw or "").strip()
    if 1 <= len(subject) <= SUBJECT_MAX:
        return subject
    return None


def clean_username(raw):
    username = (raw or "").strip()
    if USERNAME_RE.match(username):
        return username
    return None


def clean_date(raw):
    """Return the date as 'YYYY-MM-DD' if parseable, else None.

    Dates are stored as TEXT, so every insert must go through this gate or the
    table fills with unsortable junk and analytics silently break.
    """
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw.strip(), "%Y-%m-%d").date().isoformat()
    except ValueError:
        return None


def clean_present(raw):
    """Coerce JSON input to 0/1; reject anything ambiguous."""
    if raw is True or raw in (1, "1"):
        return 1
    if raw is False or raw in (0, "0"):
        return 0
    return None


def clean_marks(raw):
    """Return marks as float in [0, 100], or None.

    Without this check, non-numeric values were accepted and stored as TEXT in
    an INTEGER column, poisoning averages.
    """
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if value != value or value < 0 or value > 100:  # NaN / range check
        return None
    return value


def course_exists(course_id):
    try:
        cid = int(course_id)
    except (TypeError, ValueError):
        return None
    return query_one("SELECT id, name FROM courses WHERE id = ?", (cid,))


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------
# Flask sessions are cookie-based and carry no server-side token, so a
# cross-site form post could previously perform state changes as the logged-in
# user. This is a standard synchronizer-token double-submit: a random value is
# stored in the session, rendered into every form / meta tag, and required to
# match on every unsafe request.

@app.context_processor
def inject_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["csrf_token"]}


def _wants_json():
    return request.path.startswith("/api/") or request.is_json or request.accept_mimetypes.best == "application/json"


@app.before_request
def csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    session_token = session.get("csrf_token") or ""
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    if not session_token or not hmac.compare_digest(str(sent), str(session_token)):
        if _wants_json():
            return jsonify({"success": False, "error": "Missing or invalid CSRF token"}), 400
        return render_template("error.html",
                               error="Your session expired or the form was submitted from another site. Please reload and try again."), 400
    return None


@app.after_request
def security_headers(resp: Response) -> Response:
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


# ---------------------------------------------------------------------------
# Login rate limiting (in-process)
# ---------------------------------------------------------------------------
# Prevents unlimited password guessing. State lives in this process, so it
# resets on restart and does not span multiple workers - adequate for a
# single-instance app; use a shared store (e.g. Redis) when scaling out.

_login_failures = defaultdict(deque)
_login_lock = threading.Lock()
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60


def _login_locked_out(key):
    now = datetime.now()
    with _login_lock:
        attempts = _login_failures[key]
        while attempts and (now - attempts[0]).total_seconds() > LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        return len(attempts) >= LOGIN_MAX_FAILURES


def _record_login_failure(key):
    with _login_lock:
        _login_failures[key].append(datetime.now())


def _clear_login_failures(key):
    with _login_lock:
        _login_failures.pop(key, None)


# ---------------------------------------------------------------------------
# Auth decorators & user helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Authentication required"}), 401
            flash("Please log in to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def get_user(username):
    return query_one("SELECT * FROM users WHERE username = ?", (username,))


def create_user(username, password):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

STUDENTS_BASE_SQL = """
    SELECT students.*, courses.name AS course_name
    FROM students
    LEFT JOIN courses ON students.course_id = courses.id
    WHERE students.user_id = ?
"""


def get_students(user_id, search_query=None, course_id=None, page=None, per_page=25):
    """Return (students, total_count). page=None disables pagination."""
    sql = STUDENTS_BASE_SQL
    params = [user_id]
    if search_query:
        sql += " AND students.name LIKE ? ESCAPE '\\'"
        like = "%" + search_query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params.append(like)
    if course_id:
        sql += " AND students.course_id = ?"
        params.append(course_id)

    total = query_one(f"SELECT COUNT(*) AS c FROM ({sql})", tuple(params))["c"]

    sql += " ORDER BY students.name, students.id"
    if page is not None:
        offset = (max(page, 1) - 1) * per_page
        sql += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
    return query_all(sql, tuple(params)), total


def get_student(student_id, user_id):
    """Fetch a student ONLY if it belongs to user_id (tenant scoping)."""
    return query_one(
        "SELECT * FROM students WHERE id = ? AND user_id = ?",
        (student_id, user_id),
    )


def delete_student_cascade(student_id, user_id):
    """Delete a student and all dependent rows in one transaction.

    Children are removed explicitly (not only via FK cascade) so the behavior
    is identical for databases created with older schema versions.
    """
    db = get_db()
    student = db.execute(
        "SELECT name FROM students WHERE id = ? AND user_id = ?",
        (student_id, user_id),
    ).fetchone()
    if student is None:
        return None
    db.execute("DELETE FROM attendance WHERE student_id = ?", (student_id,))
    db.execute("DELETE FROM marks WHERE student_id = ?", (student_id,))
    db.execute("DELETE FROM students WHERE id = ? AND user_id = ?", (student_id, user_id))
    db.commit()
    return dict(student)


def get_attendance(student_id, start_date=None, end_date=None):
    sql = "SELECT * FROM attendance WHERE student_id = ?"
    params = [student_id]
    if start_date:
        sql += " AND date >= ?"
        params.append(start_date)
    if end_date:
        sql += " AND date <= ?"
        params.append(end_date)
    sql += " ORDER BY date DESC"
    return query_all(sql, tuple(params))


def mark_attendance(student_id, date_str, present):
    db = get_db()
    try:
        existing = db.execute(
            "SELECT id FROM attendance WHERE student_id = ? AND date = ?",
            (student_id, date_str),
        ).fetchone()
        if existing:
            db.execute(
                "UPDATE attendance SET present = ? WHERE id = ?",
                (present, existing["id"]),
            )
        else:
            db.execute(
                "INSERT INTO attendance (student_id, date, present) VALUES (?, ?, ?)",
                (student_id, date_str, present),
            )
        db.commit()
        return True
    except sqlite3.Error:
        logging.exception("Error marking attendance")
        db.rollback()
        return False


def get_marks(student_id, subject=None):
    sql = "SELECT * FROM marks WHERE student_id = ?"
    params = [student_id]
    if subject:
        sql += " AND subject = ?"
        params.append(subject)
    sql += " ORDER BY subject, id DESC"
    return query_all(sql, tuple(params))


def add_marks(student_id, subject, marks):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO marks (student_id, subject, marks) VALUES (?, ?, ?)",
            (student_id, subject, marks),
        )
        db.commit()
        return True
    except sqlite3.Error:
        logging.exception("Error adding marks")
        db.rollback()
        return False


def get_courses():
    return query_all("SELECT * FROM courses ORDER BY name")


def get_student_stats(user_id):
    thirty_days_ago = (date.today() - timedelta(days=30)).isoformat()
    total = query_one(
        "SELECT COUNT(*) AS count FROM students WHERE user_id = ?", (user_id,)
    )["count"]
    by_course = query_all(
        """SELECT courses.name, COUNT(*) AS count
           FROM students
           JOIN courses ON students.course_id = courses.id
           WHERE students.user_id = ?
           GROUP BY courses.name""",
        (user_id,),
    )
    attendance_stats = query_one(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN present = 1 THEN 1 ELSE 0 END) AS present
           FROM attendance
           WHERE student_id IN (SELECT id FROM students WHERE user_id = ?)
             AND date >= ?""",
        (user_id, thirty_days_ago),
    )
    rate = 0
    if attendance_stats and attendance_stats["total"]:
        rate = (attendance_stats["present"] / attendance_stats["total"]) * 100
    return {
        "total_students": total,
        "by_course": by_course,
        "attendance_rate": round(rate, 1),
    }


def highlight(name, needle):
    """Return `name` with case-sensitive `needle` occurrences wrapped in <mark>.

    Every piece is HTML-escaped individually, so a student whose name contains
    markup can never inject raw HTML (the old implementation used |safe on
    user-controlled strings - a stored/reflected XSS).
    """
    if not needle or needle not in name:
        return escape(name)
    marker = f"<mark>{escape(needle)}</mark>"
    return Markup(marker).join(escape(part) for part in name.split(needle))


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = clean_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username:
            flash("Username must be 3-32 characters (letters, digits, . _ -).", "error")
            return render_template("register.html")
        if len(password) < 8 or len(password) > 128:
            flash("Password must be between 8 and 128 characters.", "error")
            return render_template("register.html")
        if get_user(username):
            flash("Username already exists. Please choose another.", "error")
            return render_template("register.html")

        if create_user(username, password):
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        logging.info("Registration failed for username %r", username)
        flash("Registration failed. Please try again.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = (request.remote_addr or "?", username)

        if _login_locked_out(key):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html"), 429

        user = get_user(username)
        if user and check_password_hash(user["password"], password):
            _clear_login_failures(key)
            session.clear()
            session.permanent = True
            session["user"] = username
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_hex(32)  # rotate on privilege change
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        _record_login_failure(key)
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Student routes
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "").strip()[:NAME_MAX]
    course_filter = request.args.get("course", "")
    user_id = session["user_id"]
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    students, total = get_students(
        user_id,
        q if q else None,
        course_filter if course_filter else None,
        page=page,
    )
    for s in students:
        s["highlighted_name"] = highlight(s["name"], q)

    per_page = 25
    total_pages = max((total + per_page - 1) // per_page, 1)
    return render_template(
        "dashboard.html",
        students=students,
        total=total,
        q=q,
        courses=get_courses(),
        course_filter=course_filter,
        stats=get_student_stats(user_id),
        page=page,
        total_pages=total_pages,
    )


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_student():
    courses = get_courses()
    if request.method == "POST":
        name = clean_name(request.form.get("name", ""))
        course = course_exists(request.form.get("course_id"))

        if not name or not course:
            flash("Student name (max 100 chars) and a valid course are required.", "error")
            return render_template("add_student.html", courses=courses)

        db = get_db()
        db.execute(
            "INSERT INTO students (name, course_id, user_id) VALUES (?, ?, ?)",
            (name, course["id"], session["user_id"]),
        )
        db.commit()
        flash(f"Student '{name}' added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_student.html", courses=courses)


@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_student(id):
    user_id = session["user_id"]
    student = get_student(id, user_id)
    if not student:
        flash("Student not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    courses = get_courses()
    if request.method == "POST":
        name = clean_name(request.form.get("name", ""))
        course = course_exists(request.form.get("course_id"))

        if not name or not course:
            flash("Student name (max 100 chars) and a valid course are required.", "error")
            return render_template("edit_student.html", student=student, courses=courses)

        db = get_db()
        db.execute(
            "UPDATE students SET name = ?, course_id = ? WHERE id = ? AND user_id = ?",
            (name, course["id"], id, user_id),
        )
        db.commit()
        flash(f"Student '{name}' updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_student.html", student=student, courses=courses)


@app.route("/student/<int:id>")
@login_required
def student_profile(id):
    user_id = session["user_id"]
    student = get_student(id, user_id)
    if not student:
        flash("Student not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    attendance = get_attendance(id)
    attendance_summary = {
        "total": len(attendance),
        "present": sum(1 for a in attendance if a["present"] == 1),
        "absent": sum(1 for a in attendance if a["present"] == 0),
    }
    attendance_summary["percentage"] = (
        round(attendance_summary["present"] / attendance_summary["total"] * 100, 1)
        if attendance_summary["total"] else 0
    )

    marks = get_marks(id)
    marks_by_subject = defaultdict(list)
    for mark in marks:
        marks_by_subject[mark["subject"]].append(mark["marks"])
    marks_summary = {
        subject: {
            "average": round(sum(scores) / len(scores), 1),
            "highest": max(scores),
            "lowest": min(scores),
            "count": len(scores),
        }
        for subject, scores in marks_by_subject.items()
    }

    return render_template(
        "student_profile.html",
        student=student,
        attendance=attendance[:10],
        attendance_summary=attendance_summary,
        marks=marks[:10],
        marks_summary=marks_summary,
    )


@app.route("/delete/<int:id>", methods=["POST"])
@login_required
def delete_student(id):
    """Delete requires POST (plus CSRF token): GET deletables get crawled and
    hotlinked, and a single crafted link could previously wipe a student."""
    student = delete_student_cascade(id, session["user_id"])
    if student:
        flash(f"Student '{student['name']}' and all associated records deleted successfully!", "success")
    else:
        flash("Student not found or access denied.", "error")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Attendance routes
# ---------------------------------------------------------------------------

@app.route("/attendance")
@login_required
def attendance_page():
    user_id = session["user_id"]
    date_str = clean_date(request.args.get("date", "")) or date.today().isoformat()
    students = get_students(user_id)[0]

    # One LEFT JOIN instead of one query per student (was N+1).
    rows = query_all(
        """SELECT students.id AS student_id, attendance.present AS present
           FROM students
           LEFT JOIN attendance
             ON attendance.student_id = students.id AND attendance.date = ?
           WHERE students.user_id = ?""",
        (date_str, user_id),
    )
    attendance_records = {row["student_id"]: row["present"] for row in rows}

    return render_template(
        "attendance.html",
        students=students,
        date=date_str,
        attendance_records=attendance_records,
    )


@app.route("/attendance/mark", methods=["POST"])
@login_required
def mark_attendance_route():
    """Mark/unmark a single student for a date.

    The student must belong to the logged-in user: previously any authenticated
    user could write attendance for another year's students (IDOR).
    """
    data = request.get_json(silent=True) or {}
    student_id = data.get("student_id")
    date_str = clean_date(data.get("date"))
    present = clean_present(data.get("present"))

    if date_str is None or present is None:
        return jsonify({"success": False, "error": "Invalid date (YYYY-MM-DD) or present (0/1)"}), 400

    try:
        student_id = int(student_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid student_id"}), 400

    user_id = session["user_id"]
    if not get_student(student_id, user_id):
        return jsonify({"success": False, "error": "Student not found"}), 404

    if mark_attendance(student_id, date_str, present):
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Database error"}), 500


# ---------------------------------------------------------------------------
# Marks routes
# ---------------------------------------------------------------------------

@app.route("/marks")
@login_required
def marks_page():
    user_id = session["user_id"]
    students = get_students(user_id)[0]

    # One join for every student's marks, grouped in Python (was one query per
    # student).
    rows = query_all(
        """SELECT marks.* FROM marks
           JOIN students ON marks.student_id = students.id
           WHERE students.user_id = ?
           ORDER BY marks.student_id, marks.subject, marks.id DESC""",
        (user_id,),
    )
    student_marks = {s["id"]: [] for s in students}
    for row in rows:
        student_marks[row["student_id"]].append(row)

    return render_template("marks.html", students=students, student_marks=student_marks)


@app.route("/marks/add", methods=["POST"])
@login_required
def add_marks_route():
    data = request.get_json(silent=True) or {}
    student_id = data.get("student_id")
    subject = clean_subject(data.get("subject"))
    marks = clean_marks(data.get("marks"))

    if subject is None or marks is None:
        return jsonify({"success": False,
                        "error": "Subject (1-60 chars) and numeric marks (0-100) are required"}), 400

    try:
        student_id = int(student_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid student_id"}), 400

    user_id = session["user_id"]
    if not get_student(student_id, user_id):
        return jsonify({"success": False, "error": "Student not found"}), 404

    if add_marks(student_id, subject, marks):
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Database error"}), 500


# ---------------------------------------------------------------------------
# Analytics route
# ---------------------------------------------------------------------------

@app.route("/analytics")
@login_required
def analytics_page():
    user_id = session["user_id"]
    stats = get_student_stats(user_id)
    thirty_days_ago = (date.today() - timedelta(days=30)).isoformat()

    attendance_trend = query_all(
        """SELECT date,
                  COUNT(*) AS total,
                  SUM(CASE WHEN present = 1 THEN 1 ELSE 0 END) AS present
           FROM attendance
           WHERE student_id IN (SELECT id FROM students WHERE user_id = ?)
             AND date >= ?
           GROUP BY date
           ORDER BY date""",
        (user_id, thirty_days_ago),
    )
    top_performers = query_all(
        """SELECT students.name, courses.name AS course_name, AVG(marks.marks) AS avg_marks
           FROM students
           JOIN courses ON students.course_id = courses.id
           JOIN marks ON students.id = marks.student_id
           WHERE students.user_id = ?
           GROUP BY students.id
           ORDER BY avg_marks DESC
           LIMIT 10""",
        (user_id,),
    )
    subject_performance = query_all(
        """SELECT marks.subject, AVG(marks.marks) AS avg_marks, COUNT(*) AS count
           FROM marks
           JOIN students ON marks.student_id = students.id
           WHERE students.user_id = ?
           GROUP BY marks.subject
           ORDER BY avg_marks DESC""",
        (user_id,),
    )

    return render_template(
        "analytics.html",
        stats=stats,
        attendance_trend=attendance_trend,
        top_performers=top_performers,
        subject_performance=subject_performance,
    )


# ---------------------------------------------------------------------------
# Export routes
# ---------------------------------------------------------------------------

def _csv_response(rows, header, filename):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),  # BOM so Excel opens UTF-8 correctly
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/export/students")
@login_required
def export_students():
    students = get_students(session["user_id"])[0]
    rows = ([s["id"], s["name"], s["course_name"] or ""] for s in students)
    filename = f"students_{date.today().strftime('%Y%m%d')}.csv"
    return _csv_response(rows, ["ID", "Name", "Course"], filename)


@app.route("/export/attendance")
@login_required
def export_attendance():
    user_id = session["user_id"]
    rows_raw = query_all(
        """SELECT students.id AS sid, students.name AS sname, attendance.date, attendance.present
           FROM attendance
           JOIN students ON attendance.student_id = students.id
           WHERE students.user_id = ?
           ORDER BY students.name, attendance.date DESC""",
        (user_id,),
    )
    rows = (
        [r["sid"], r["sname"], r["date"], "Present" if r["present"] == 1 else "Absent"]
        for r in rows_raw
    )
    filename = f"attendance_{date.today().strftime('%Y%m%d')}.csv"
    return _csv_response(rows, ["Student ID", "Student Name", "Date", "Status"], filename)


# ---------------------------------------------------------------------------
# REST API endpoints (session-authenticated, CSRF-protected via X-CSRF-Token)
# ---------------------------------------------------------------------------

@app.route("/api/students", methods=["GET"])
@login_required
def api_get_students():
    q = request.args.get("q", "").strip()[:NAME_MAX]
    course = request.args.get("course", "")
    students, total = get_students(
        session["user_id"],
        q or None,
        course or None,
    )
    return jsonify({"success": True, "total": total, "data": students})


@app.route("/api/students", methods=["POST"])
@login_required
def api_create_student():
    data = request.get_json(silent=True) or {}
    name = clean_name(data.get("name", ""))
    course = course_exists(data.get("course_id"))
    if not name or not course:
        return jsonify({"success": False,
                        "error": "name (1-100 chars) and an existing course_id are required"}), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO students (name, course_id, user_id) VALUES (?, ?, ?)",
        (name, course["id"], session["user_id"]),
    )
    db.commit()
    return jsonify({
        "success": True,
        "data": {"id": cur.lastrowid, "name": name, "course_id": course["id"]},
    }), 201


@app.route("/api/students/<int:id>", methods=["PUT"])
@login_required
def api_update_student(id):
    data = request.get_json(silent=True) or {}
    name = clean_name(data.get("name", ""))
    course = course_exists(data.get("course_id"))
    if not name or not course:
        return jsonify({"success": False,
                        "error": "name (1-100 chars) and an existing course_id are required"}), 400

    user_id = session["user_id"]
    if not get_student(id, user_id):
        return jsonify({"success": False, "error": "Student not found"}), 404

    db = get_db()
    db.execute(
        "UPDATE students SET name = ?, course_id = ? WHERE id = ? AND user_id = ?",
        (name, course["id"], id, user_id),
    )
    db.commit()
    return jsonify({"success": True, "data": {"id": id, "name": name, "course_id": course["id"]}})


@app.route("/api/students/<int:id>", methods=["DELETE"])
@login_required
def api_delete_student(id):
    # Same cascade-safe helper as the UI delete; previously the API orphaned
    # attendance and marks rows of the deleted student.
    student = delete_student_cascade(id, session["user_id"])
    if student is None:
        return jsonify({"success": False, "error": "Student not found"}), 404
    return jsonify({"success": True, "message": "Student deleted"})


@app.route("/api/courses", methods=["GET"])
@login_required
def api_get_courses():
    return jsonify({"success": True, "data": get_courses()})


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    if _wants_json():
        return jsonify({"success": False, "error": "Not found"}), 404
    return render_template("error.html", error="Page not found"), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", error="Request body too large"), 413


@app.errorhandler(500)
def server_error(e):
    logging.exception("Unhandled server error")
    return render_template("error.html", error="Internal server error"), 500


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG") == "1"
    if debug:
        app.logger.warning(
            "FLASK_DEBUG=1: the interactive debugger allows arbitrary code "
            "execution. Only use this on localhost, never expose it."
        )
    # Never hard-code debug=True / 0.0.0.0: that used to expose the Werkzeug
    # debugger console to the whole network. Bind to localhost unless the
    # operator explicitly asks otherwise, and put a real WSGI server
    # (gunicorn) with HTTPS in front of this app in production.
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=debug,
    )
