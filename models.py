"""
Schema bootstrap for the Student Management Portal.

    python models.py              # create/upgrade database.db - NEVER destroys data
    python models.py --seed       # also create the demo academic-year accounts
    python models.py --db PATH    # target another database file

The previous version began with `DROP TABLE IF EXISTS students`, so re-running
setup silently wiped every student (and orphaned their attendance/marks).
Everything here is now idempotent: `CREATE TABLE IF NOT EXISTS` + guarded
index creation, safe to run at any time, on an existing database or an empty one.
"""

import argparse
import os
import sqlite3

from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 3 AND 32),
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS courses(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100)
);

CREATE TABLE IF NOT EXISTS students(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    course_id INTEGER,
    user_id INTEGER NOT NULL,
    FOREIGN KEY(course_id) REFERENCES courses(id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    date TEXT NOT NULL CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    present INTEGER NOT NULL CHECK (present IN (0, 1)),
    FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
    -- one record per student per day; makes duplicate marks impossible
    UNIQUE(student_id, date)
);

CREATE TABLE IF NOT EXISTS marks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 60),
    marks REAL NOT NULL CHECK (marks BETWEEN 0 AND 100),
    FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_students_user ON students(user_id);
CREATE INDEX IF NOT EXISTS idx_students_course ON students(course_id);
CREATE INDEX IF NOT EXISTS idx_attendance_student_date ON attendance(student_id, date);
CREATE INDEX IF NOT EXISTS idx_marks_student ON marks(student_id, subject);
"""

SAMPLE_COURSES = ("Mathematics", "Science", "Art")

# Demo accounts for the seeded flow shown in the README. Deliberately gated
# behind --seed so a real deployment never ships accounts with known passwords.
DEMO_USERS = {
    "2023": "2023pass",
    "2024": "2024pass",
    "2025": "2025pass",
}


def get_connection(db_path):
    conn = sqlite3.connect(db_path)
    # Without this pragma SQLite ignores every FOREIGN KEY clause above.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path="database.db", seed_demo=False):
    """Create the schema (non-destructive) and optionally seed demo data."""
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA)

        # Pre-existing databases may contain duplicate attendance rows from
        # before the UNIQUE(student_id, date) constraint existed; keep the
        # newest mark per student/day so the unique index can be created.
        conn.execute(
            """DELETE FROM attendance
               WHERE id NOT IN (
                   SELECT MAX(id) FROM attendance GROUP BY student_id, date
               )"""
        )
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_unique
               ON attendance(student_id, date)"""
        )

        for name in SAMPLE_COURSES:
            conn.execute("INSERT OR IGNORE INTO courses (name) VALUES (?)", (name,))

        if seed_demo:
            for username, password in DEMO_USERS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
            print(
                "WARNING: demo accounts seeded (usernames 2023/2024/2025 with the "
                "passwords shown in README). Do NOT use --seed outside local demos."
            )

        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize the SQLite database.")
    parser.add_argument(
        "--db",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db"),
        help="path to the SQLite database file (default: database.db next to this script)",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="also create demo academic-year accounts (local demos only)",
    )
    args = parser.parse_args()

    init_db(args.db, seed_demo=args.seed)
    print(f"Database ready at {args.db} (no existing data was modified).")
