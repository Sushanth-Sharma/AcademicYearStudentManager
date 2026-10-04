# 📚 Academic Year Student Manager (Student Management Portal)

A small self-contained Flask web app for teachers to manage students per
academic year: rosters, attendance, marks, analytics and CSV export. Each
logged-in account (e.g. academic year `2023`) only ever sees its own students.

- **Backend:** Flask 3 + SQLite (stdlib `sqlite3`, no ORM)
- **Frontend:** server-rendered Jinja2 templates + vanilla JS (no build step)
- **Auth:** session cookies, hashed passwords (Werkzeug scrypt)
- **Tests:** pytest suite covering auth, tenant isolation, validation, CSRF

---

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python models.py                   # create database.db (safe to re-run, never destroys data)
python app.py                      # serve on http://127.0.0.1:5000
```

Optional, for demos only — creates academic-year accounts
`2023` / `2024` / `2025` with passwords `2023pass` / `2024pass` / `2025pass`:

```bash
python models.py --seed
```

> These passwords are public. Only use `--seed` on a local demo database and
> delete it afterwards; never expose a seeded database to a network.

### Configuration (environment variables)

| Variable                | Default        | Purpose                                                  |
|-------------------------|----------------|----------------------------------------------------------|
| `SECRET_KEY`            | auto-generated | Signs session cookies. Required in production. If unset, a random key is persisted to `secret_key` (gitignored). |
| `DATABASE_PATH`         | `database.db`  | SQLite database file location.                           |
| `FLASK_DEBUG`           | unset          | Set to `1` for the dev server + reloader. **Never expose a debug server to a network.** |
| `HOST` / `PORT`         | `127.0.0.1` / `5000` | Dev-server bind address (change `HOST` deliberately). |
| `SESSION_SECURE_COOKIES`| unset          | Set to `1` behind HTTPS to mark cookies `Secure`.        |

## Features

- **Auth** — registration, login, logout (POST + CSRF), per-account data isolation
- **Students** — create / edit / search / filter / paginated list / delete (cascades)
- **Attendance** — one present/absent mark per student per day (upsert), date picker, bulk “mark all”
- **Marks** — per-subject scores, validated `0–100`, per-subject averages
- **Analytics** — 30-day attendance trend, top performers, subject performance
- **Export** — students & attendance as CSV (UTF-8 BOM for Excel)
- **REST API** — `/api/students` CRUD, `/api/courses` (session auth + `X-CSRF-Token` header)

## Project layout

```
app.py        Flask app: routes, auth, CSRF, validation, DB helpers
models.py     Non-destructive schema bootstrap + indexes + optional demo seed
templates/    Jinja2 templates (base.html layout, per-page children)
static/       style.css
tests/        pytest suite (security regressions + behavior)
```

## Database

SQLite is used with `PRAGMA foreign_keys = ON` on every connection, `CHECK`
constraints in the schema, `UNIQUE(student_id, date)` on attendance, and
`ON DELETE CASCADE` from `attendance`/`marks` → `students` (plus explicit
cascade deletes in code so older database files behave identically).

```
users      (id, username UNIQUE, password-hash)
courses    (id, name UNIQUE)
students   (id, name, course_id→courses, user_id→users)
attendance (id, student_id→students, date 'YYYY-MM-DD', present 0|1, UNIQUE(student_id,date))
marks      (id, student_id→students, subject, marks 0..100 REAL)
```

## Security notes

Implemented deliberately:

- All SQL is parameterized; LIKE wildcards in searches are escaped.
- Tenant scoping (`WHERE ... AND user_id = ?`) on every student read/write,
  including the JSON endpoints for attendance/marks.
- CSRF: synchronizer token required on every POST/PUT/DELETE (form field
  `csrf_token` or header `X-CSRF-Token` for `fetch`), session cookie `SameSite=Lax`, `HttpOnly`.
- Login rate limiting: 5 failures per IP+username per 15 min (in-process).
- No secrets in the repo: fallback `SECRET_KEY` is a random generated file, never a hardcoded string.
- Debug server defaults to `127.0.0.1` and `debug` off unless `FLASK_DEBUG=1`.
- Output escaping everywhere — including search-term highlighting, which is
  built from escaped fragments server-side (no `|safe`).
- Destructive actions (delete, logout) are POST-only.
- `MAX_CONTENT_LENGTH` = 1 MiB; basic security headers (`X-Frame-Options`, `nosniff`).

Known limitations (by design for a single-instance app): in-memory rate-limit
state and session cookies do not survive multi-worker deployments horizontally —
use a shared store if you scale out. Serve behind HTTPS with a real WSGI
server in production, e.g. `gunicorn -w 2 -b 127.0.0.1:8000 app:app`.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite includes regressions for previously fixed issues: the attendance
IDOR, the destructive `DROP TABLE` in setup, missing marks/date validation,
CSRF enforcement, cascade deletes, and XSS in search highlighting.

## License

MIT — see [LICENSE](LICENSE).
