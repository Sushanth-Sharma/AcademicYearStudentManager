from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash, send_file
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import os
import csv
import io
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# Database helper functions
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def close_db(conn):
    if conn:
        conn.close()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Course management
def get_courses():
    db = get_db()
    try:
        courses = db.execute("SELECT * FROM courses ORDER BY name").fetchall()
        return [dict(c) for c in courses]
    finally:
        close_db(db)

# Student management
def get_students(user_id, search_query=None, course_id=None):
    db = get_db()
    try:
        query = """SELECT students.*, courses.name as course_name 
                   FROM students 
                   LEFT JOIN courses ON students.course_id = courses.id 
                   WHERE students.user_id=?"""
        params = [user_id]
        
        if search_query:
            query += " AND students.name LIKE ?"
            params.append(f"%{search_query}%")
        
        if course_id:
            query += " AND students.course_id=?"
            params.append(course_id)
        
        query += " ORDER BY students.name"
        
        students = db.execute(query, params).fetchall()
        return [dict(s) for s in students]
    finally:
        close_db(db)

def get_student(student_id, user_id):
    db = get_db()
    try:
        student = db.execute(
            "SELECT * FROM students WHERE id=? AND user_id=?",
            (student_id, user_id)
        ).fetchone()
        return dict(student) if student else None
    finally:
        close_db(db)

# Attendance management
def get_attendance(student_id, start_date=None, end_date=None):
    db = get_db()
    try:
        query = "SELECT * FROM attendance WHERE student_id=?"
        params = [student_id]
        
        if start_date:
            query += " AND date >= ?"
            params.append(start_date)
        if end_date:
            query += " AND date <= ?"
            params.append(end_date)
        
        query += " ORDER BY date DESC"
        
        records = db.execute(query, params).fetchall()
        return [dict(r) for r in records]
    finally:
        close_db(db)

def mark_attendance(student_id, date, present):
    db = get_db()
    try:
        # Check if attendance already exists for this date
        existing = db.execute(
            "SELECT id FROM attendance WHERE student_id=? AND date=?",
            (student_id, date)
        ).fetchone()
        
        if existing:
            db.execute(
                "UPDATE attendance SET present=? WHERE id=?",
                (present, existing['id'])
            )
        else:
            db.execute(
                "INSERT INTO attendance (student_id, date, present) VALUES (?, ?, ?)",
                (student_id, date, present)
            )
        db.commit()
        return True
    except Exception as e:
        print(f"Error marking attendance: {e}")
        return False
    finally:
        close_db(db)

# Marks management
def get_marks(student_id, subject=None):
    db = get_db()
    try:
        query = "SELECT * FROM marks WHERE student_id=?"
        params = [student_id]
        
        if subject:
            query += " AND subject=?"
            params.append(subject)
        
        query += " ORDER BY subject, id DESC"
        
        records = db.execute(query, params).fetchall()
        return [dict(r) for r in records]
    finally:
        close_db(db)

def add_marks(student_id, subject, marks):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO marks (student_id, subject, marks) VALUES (?, ?, ?)",
            (student_id, subject, marks)
        )
        db.commit()
        return True
    except Exception as e:
        print(f"Error adding marks: {e}")
        return False
    finally:
        close_db(db)

# Analytics functions
def get_student_stats(user_id):
    db = get_db()
    try:
        # Total students
        total = db.execute(
            "SELECT COUNT(*) as count FROM students WHERE user_id=?",
            (user_id,)
        ).fetchone()['count']
        
        # Students by course
        by_course = db.execute(
            """SELECT courses.name, COUNT(*) as count 
               FROM students 
               JOIN courses ON students.course_id = courses.id 
               WHERE students.user_id=? 
               GROUP BY courses.name""",
            (user_id,)
        ).fetchall()
        
        # Recent attendance rate (last 30 days)
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        attendance_stats = db.execute(
            """SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN present=1 THEN 1 ELSE 0 END) as present
               FROM attendance 
               WHERE student_id IN (SELECT id FROM students WHERE user_id=?)
               AND date >= ?""",
            (user_id, thirty_days_ago)
        ).fetchone()
        
        attendance_rate = 0
        if attendance_stats['total'] > 0:
            attendance_rate = (attendance_stats['present'] / attendance_stats['total']) * 100
        
        return {
            'total_students': total,
            'by_course': [dict(c) for c in by_course],
            'attendance_rate': round(attendance_rate, 1)
        }
    finally:
        close_db(db)

# User management
def get_user(username):
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(user) if user else None
    finally:
        close_db(db)

def create_user(username, password):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        close_db(db)

# Routes
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("register.html")
        
        if get_user(username):
            flash("Username already exists. Please choose another.", "error")
            return render_template("register.html")
        
        if create_user(username, password):
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Registration failed. Please try again.", "error")
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        user = get_user(username)
        if user and check_password_hash(user["password"], password):
            session["user"] = username
            session["user_id"] = user["id"]
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")
    
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "").strip()
    course_filter = request.args.get("course", "")
    user_id = session["user_id"]
    
    students = get_students(user_id, q if q else None, course_filter if course_filter else None)
    courses = get_courses()
    stats = get_student_stats(user_id)
    
    return render_template("dashboard.html", 
                         students=students, 
                         q=q, 
                         courses=courses,
                         course_filter=course_filter,
                         stats=stats)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_student():
    courses = get_courses()
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        course_id = request.form.get("course_id")
        user_id = session["user_id"]
        
        if not name or not course_id:
            flash("Student name and course are required.", "error")
            return render_template("add_student.html", courses=courses)
        
        db = get_db()
        try:
            db.execute(
                "INSERT INTO students (name, course_id, user_id) VALUES (?, ?, ?)",
                (name, course_id, user_id)
            )
            db.commit()
            flash(f"Student '{name}' added successfully!", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            flash("Error adding student. Please try again.", "error")
        finally:
            close_db(db)
    
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
        name = request.form.get("name", "").strip()
        course_id = request.form.get("course_id")
        
        if not name or not course_id:
            flash("Student name and course are required.", "error")
            return render_template("edit_student.html", student=student, courses=courses)
        
        db = get_db()
        try:
            db.execute(
                "UPDATE students SET name=?, course_id=? WHERE id=? AND user_id=?",
                (name, course_id, id, user_id)
            )
            db.commit()
            flash(f"Student '{name}' updated successfully!", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            flash("Error updating student. Please try again.", "error")
        finally:
            close_db(db)
    
    return render_template("edit_student.html", student=student, courses=courses)

@app.route("/student/<int:id>")
@login_required
def student_profile(id):
    user_id = session["user_id"]
    student = get_student(id, user_id)
    
    if not student:
        flash("Student not found or access denied.", "error")
        return redirect(url_for("dashboard"))
    
    # Get attendance records
    attendance = get_attendance(id)
    attendance_summary = {
        'total': len(attendance),
        'present': sum(1 for a in attendance if a['present'] == 1),
        'absent': sum(1 for a in attendance if a['present'] == 0)
    }
    if attendance_summary['total'] > 0:
        attendance_summary['percentage'] = round((attendance_summary['present'] / attendance_summary['total']) * 100, 1)
    else:
        attendance_summary['percentage'] = 0
    
    # Get marks
    marks = get_marks(id)
    marks_by_subject = defaultdict(list)
    for mark in marks:
        marks_by_subject[mark['subject']].append(mark['marks'])
    
    marks_summary = {}
    for subject, scores in marks_by_subject.items():
        marks_summary[subject] = {
            'average': round(sum(scores) / len(scores), 1),
            'highest': max(scores),
            'lowest': min(scores),
            'count': len(scores)
        }
    
    return render_template("student_profile.html", 
                         student=student,
                         attendance=attendance[:10],  # Last 10 records
                         attendance_summary=attendance_summary,
                         marks=marks[:10],  # Last 10 records
                         marks_summary=marks_summary)

@app.route("/delete/<int:id>")
@login_required
def delete_student(id):
    user_id = session["user_id"]
    db = get_db()
    try:
        # Get student name before deleting
        student = db.execute("SELECT name FROM students WHERE id=? AND user_id=?", (id, user_id)).fetchone()
        
        if student:
            # Delete associated records
            db.execute("DELETE FROM attendance WHERE student_id=?", (id,))
            db.execute("DELETE FROM marks WHERE student_id=?", (id,))
            db.execute("DELETE FROM students WHERE id=? AND user_id=?", (id, user_id))
            db.commit()
            flash(f"Student '{student['name']}' and all associated records deleted successfully!", "success")
        else:
            flash("Student not found or access denied.", "error")
    except Exception as e:
        flash("Error deleting student. Please try again.", "error")
    finally:
        close_db(db)
    
    return redirect(url_for("dashboard"))

# Attendance routes
@app.route("/attendance")
@login_required
def attendance_page():
    user_id = session["user_id"]
    date = request.args.get("date", datetime.now().strftime('%Y-%m-%d'))
    students = get_students(user_id)
    
    # Get attendance for the selected date
    db = get_db()
    attendance_records = {}
    try:
        for student in students:
            record = db.execute(
                "SELECT present FROM attendance WHERE student_id=? AND date=?",
                (student['id'], date)
            ).fetchone()
            attendance_records[student['id']] = record['present'] if record else None
    finally:
        close_db(db)
    
    return render_template("attendance.html", 
                         students=students, 
                         date=date,
                         attendance_records=attendance_records)

@app.route("/attendance/mark", methods=["POST"])
@login_required
def mark_attendance_route():
    data = request.get_json()
    student_id = data.get("student_id")
    date = data.get("date")
    present = data.get("present")
    
    if mark_attendance(student_id, date, present):
        return jsonify({"success": True})
    return jsonify({"success": False}), 500

# Marks routes
@app.route("/marks")
@login_required
def marks_page():
    user_id = session["user_id"]
    students = get_students(user_id)
    
    # Get all marks for each student
    student_marks = {}
    for student in students:
        student_marks[student['id']] = get_marks(student['id'])
    
    return render_template("marks.html", 
                         students=students,
                         student_marks=student_marks)

@app.route("/marks/add", methods=["POST"])
@login_required
def add_marks_route():
    data = request.get_json()
    student_id = data.get("student_id")
    subject = data.get("subject")
    marks = data.get("marks")
    
    if not student_id or not subject or marks is None:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    
    # Verify student belongs to user
    user_id = session["user_id"]
    student = get_student(student_id, user_id)
    if not student:
        return jsonify({"success": False, "error": "Student not found"}), 404
    
    if add_marks(student_id, subject, marks):
        return jsonify({"success": True})
    return jsonify({"success": False}), 500

# Analytics route
@app.route("/analytics")
@login_required
def analytics_page():
    user_id = session["user_id"]
    stats = get_student_stats(user_id)
    
    # Get detailed analytics
    db = get_db()
    try:
        # Attendance trends (last 30 days)
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        attendance_trend = db.execute(
            """SELECT date, 
                      COUNT(*) as total,
                      SUM(CASE WHEN present=1 THEN 1 ELSE 0 END) as present
               FROM attendance 
               WHERE student_id IN (SELECT id FROM students WHERE user_id=?)
               AND date >= ?
               GROUP BY date
               ORDER BY date""",
            (user_id, thirty_days_ago)
        ).fetchall()
        
        # Top performers by average marks
        top_performers = db.execute(
            """SELECT students.name, courses.name as course_name, AVG(marks.marks) as avg_marks
               FROM students
               JOIN courses ON students.course_id = courses.id
               LEFT JOIN marks ON students.id = marks.student_id
               WHERE students.user_id=?
               GROUP BY students.id
               HAVING avg_marks IS NOT NULL
               ORDER BY avg_marks DESC
               LIMIT 10""",
            (user_id,)
        ).fetchall()
        
        # Subject-wise performance
        subject_performance = db.execute(
            """SELECT marks.subject, AVG(marks.marks) as avg_marks, COUNT(*) as count
               FROM marks
               JOIN students ON marks.student_id = students.id
               WHERE students.user_id=?
               GROUP BY marks.subject
               ORDER BY avg_marks DESC""",
            (user_id,)
        ).fetchall()
        
    finally:
        close_db(db)
    
    return render_template("analytics.html",
                         stats=stats,
                         attendance_trend=[dict(a) for a in attendance_trend],
                         top_performers=[dict(t) for t in top_performers],
                         subject_performance=[dict(s) for s in subject_performance])

# Export routes
@app.route("/export/students")
@login_required
def export_students():
    user_id = session["user_id"]
    students = get_students(user_id)
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Course'])
    
    for student in students:
        writer.writerow([student['id'], student['name'], student['course_name']])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'students_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route("/export/attendance")
@login_required
def export_attendance():
    user_id = session["user_id"]
    students = get_students(user_id)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Student ID', 'Student Name', 'Date', 'Status'])
    
    for student in students:
        attendance = get_attendance(student['id'])
        for record in attendance:
            writer.writerow([
                student['id'],
                student['name'],
                record['date'],
                'Present' if record['present'] == 1 else 'Absent'
            ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'attendance_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))

# REST API endpoints
@app.route("/api/students", methods=["GET"])
@login_required
def api_get_students():
    try:
        students = get_students(session["user_id"])
        return jsonify({"success": True, "data": students})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/students", methods=["POST"])
@login_required
def api_create_student():
    try:
        data = request.get_json()
        name = data.get("name", "").strip()
        course_id = data.get("course_id")
        user_id = session["user_id"]
        
        if not name or not course_id:
            return jsonify({"success": False, "error": "Missing name or course_id"}), 400
        
        db = get_db()
        cur = db.execute(
            "INSERT INTO students (name, course_id, user_id) VALUES (?, ?, ?)",
            (name, course_id, user_id)
        )
        db.commit()
        student_id = cur.lastrowid
        close_db(db)
        
        return jsonify({
            "success": True,
            "data": {"id": student_id, "name": name, "course_id": course_id}
        }), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/students/<int:id>", methods=["PUT"])
@login_required
def api_update_student(id):
    try:
        data = request.get_json()
        name = data.get("name", "").strip()
        course_id = data.get("course_id")
        user_id = session["user_id"]
        
        if not name or not course_id:
            return jsonify({"success": False, "error": "Missing name or course_id"}), 400
        
        db = get_db()
        result = db.execute(
            "UPDATE students SET name=?, course_id=? WHERE id=? AND user_id=?",
            (name, course_id, id, user_id)
        )
        db.commit()
        close_db(db)
        
        if result.rowcount == 0:
            return jsonify({"success": False, "error": "Student not found"}), 404
        
        return jsonify({
            "success": True,
            "data": {"id": id, "name": name, "course_id": course_id}
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/students/<int:id>", methods=["DELETE"])
@login_required
def api_delete_student(id):
    try:
        user_id = session["user_id"]
        db = get_db()
        result = db.execute("DELETE FROM students WHERE id=? AND user_id=?", (id, user_id))
        db.commit()
        close_db(db)
        
        if result.rowcount == 0:
            return jsonify({"success": False, "error": "Student not found"}), 404
        
        return jsonify({"success": True, "message": "Student deleted"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/courses", methods=["GET"])
@login_required
def api_get_courses():
    try:
        courses = get_courses()
        return jsonify({"success": True, "data": courses})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", error="Internal server error"), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)