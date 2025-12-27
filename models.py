import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("database.db")

# Drop old students table if exists (for migration)
conn.execute("DROP TABLE IF EXISTS students")
# Students table with user_id
conn.execute("""
CREATE TABLE IF NOT EXISTS students(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    course_id INTEGER,
    user_id INTEGER,
    FOREIGN KEY(course_id) REFERENCES courses(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

# Users table (for admin authentication)
conn.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")

# Courses table
conn.execute("""
CREATE TABLE IF NOT EXISTS courses(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
)
""")

# Attendance table
conn.execute("""
CREATE TABLE IF NOT EXISTS attendance(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    date TEXT,
    present INTEGER,
    FOREIGN KEY(student_id) REFERENCES students(id)
)
""")

# Marks table
conn.execute("""
CREATE TABLE IF NOT EXISTS marks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    subject TEXT,
    marks INTEGER,
    FOREIGN KEY(student_id) REFERENCES students(id)
)
""")

# Insert academic year users (2023, 2024, 2025) with hashed passwords
conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("2023", generate_password_hash("2023pass")))
conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("2024", generate_password_hash("2024pass")))
conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("2025", generate_password_hash("2025pass")))

# Insert sample courses if not exists
conn.execute("INSERT OR IGNORE INTO courses (id, name) VALUES (?, ?)", (1, "Mathematics"))
conn.execute("INSERT OR IGNORE INTO courses (name) VALUES (?)", ("Science",))
conn.execute("INSERT OR IGNORE INTO courses (name) VALUES (?)", ("Art",))

conn.commit()
conn.close()