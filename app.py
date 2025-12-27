from flask import Flask, render_template, request, redirect, session, jsonify, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "securekey"

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_courses():
    db = get_db()
    courses = db.execute("SELECT * FROM courses").fetchall()
    db.close()
    return [dict(c) for c in courses]

def get_students(user_id):
    db = get_db()
    students = db.execute("SELECT students.*, courses.name as course_name FROM students LEFT JOIN courses ON students.course_id = courses.id WHERE students.user_id=?", (user_id,)).fetchall()
    db.close()
    return [dict(s) for s in students]

def get_student(student_id, user_id):
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id=? AND user_id=?", (student_id, user_id)).fetchone()
    db.close()
    return dict(student) if student else None

def get_user(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    return user

def create_user(username, password):
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, generate_password_hash(password)))
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return False
    db.close()
    return True

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if not username or not password:
            error = "Username and password required."
        elif get_user(username):
            error = "Username already exists."
        else:
            if create_user(username, password):
                return redirect(url_for("login"))
            else:
                error = "Registration failed."
    return render_template("register.html", error=error)

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = get_user(username)
        if user and check_password_hash(user["password"], password):
            session["user"] = username
            session["user_id"] = user["id"]
            return redirect("/dashboard")
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    q = request.args.get("q", "")
    user_id = session["user_id"]
    if q:
        db = get_db()
        students = db.execute(
            "SELECT students.*, courses.name as course_name FROM students LEFT JOIN courses ON students.course_id = courses.id WHERE students.user_id=? AND students.name LIKE ?",
            (user_id, f"%{q}%")
        ).fetchall()
        students = [dict(s) for s in students]
        db.close()
    else:
        students = get_students(user_id)
    message = request.args.get("message")
    return render_template("dashboard.html", students=students, message=message, q=q)

@app.route("/add", methods=["GET", "POST"])
def add_student():
    if "user" not in session:
        return redirect("/")
    courses = get_courses()
    if request.method == "POST":
        name = request.form["name"]
        course_id = request.form["course_id"]
        user_id = session["user_id"]
        db = get_db()
        db.execute("INSERT INTO students (name, course_id, user_id) VALUES (?, ?, ?)", (name, course_id, user_id))
        db.commit()
        db.close()
        return redirect("/dashboard?message=Student+added+successfully")
    return render_template("add_student.html", courses=courses)

@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_student(id):
    if "user" not in session:
        return redirect("/")
    user_id = session["user_id"]
    student = get_student(id, user_id)
    courses = get_courses()
    if not student:
        return redirect("/dashboard")
    if request.method == "POST":
        name = request.form["name"]
        course_id = request.form["course_id"]
        db = get_db()
        db.execute("UPDATE students SET name=?, course_id=? WHERE id=? AND user_id=?", (name, course_id, id, user_id))
        db.commit()
        db.close()
        return redirect("/dashboard?message=Student+updated+successfully")
    return render_template("edit_student.html", student=student, courses=courses)

@app.route("/delete/<int:id>")
def delete_student(id):
    if "user" not in session:
        return redirect("/")
    user_id = session["user_id"]
    db = get_db()
    db.execute("DELETE FROM students WHERE id=? AND user_id=?", (id, user_id))
    db.commit()
    db.close()
    return redirect("/dashboard?message=Student+deleted+successfully")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# REST API endpoints
@app.route("/api/students", methods=["GET"])
def api_get_students():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_students(session["user_id"]))

@app.route("/api/students", methods=["POST"])
def api_create_student():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    name = data.get("name")
    course_id = data.get("course_id")
    user_id = session["user_id"]
    if not name or not course_id:
        return jsonify({"error": "Missing name or course_id"}), 400
    db = get_db()
    cur = db.execute("INSERT INTO students (name, course_id, user_id) VALUES (?, ?, ?)", (name, course_id, user_id))
    db.commit()
    student_id = cur.lastrowid
    db.close()
    return jsonify({"id": student_id, "name": name, "course_id": course_id, "user_id": user_id}), 201

@app.route("/api/students/<int:id>", methods=["PUT"])
def api_update_student(id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    name = data.get("name")
    course_id = data.get("course_id")
    user_id = session["user_id"]
    if not name or not course_id:
        return jsonify({"error": "Missing name or course_id"}), 400
    db = get_db()
    db.execute("UPDATE students SET name=?, course_id=? WHERE id=? AND user_id=?", (name, course_id, id, user_id))
    db.commit()
    db.close()
    return jsonify({"id": id, "name": name, "course_id": course_id, "user_id": user_id})

@app.route("/api/students/<int:id>", methods=["DELETE"])
def api_delete_student(id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = session["user_id"]
    db = get_db()
    db.execute("DELETE FROM students WHERE id=? AND user_id=?", (id, user_id))
    db.commit()
    db.close()
    return jsonify({"result": "deleted"})

@app.route("/api/courses", methods=["GET"])
def api_get_courses():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_courses())

@app.route("/api/courses", methods=["POST"])
def api_create_course():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    name = data.get("name")
    if not name:
        return jsonify({"error": "Missing course name"}), 400
    db = get_db()
    cur = db.execute("INSERT INTO courses (name) VALUES (?)", (name,))
    db.commit()
    course_id = cur.lastrowid
    db.close()
    return jsonify({"id": course_id, "name": name}), 201

@app.route("/api/courses/<int:id>", methods=["PUT"])
def api_update_course(id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    name = data.get("name")
    if not name:
        return jsonify({"error": "Missing course name"}), 400
    db = get_db()
    db.execute("UPDATE courses SET name=? WHERE id=?", (name, id))
    db.commit()
    db.close()
    return jsonify({"id": id, "name": name})

@app.route("/api/courses/<int:id>", methods=["DELETE"])
def api_delete_course(id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    db.execute("DELETE FROM courses WHERE id=?", (id,))
    db.commit()
    db.close()
    return jsonify({"result": "deleted"})

@app.route("/api/attendance", methods=["GET"])
def api_get_attendance():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    rows = db.execute("SELECT * FROM attendance").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/marks", methods=["GET"])
def api_get_marks():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    rows = db.execute("SELECT * FROM marks").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    app.run(debug=True)
