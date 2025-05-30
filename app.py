from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, Response, make_response
from werkzeug.utils import secure_filename
import os
from flask_mysqldb import MySQL

load_dotenv()  # Load environment variables from .env

app = Flask(__name__)

# TODO: consider wrapping repeated code in reusable helper functions
# TODO: replace with dynamic user id upon login
# user_id = 1  # student
user_id = 3  # educator
# user_id = 5  # admin

@app.route("/")
def index():
    return render_template("index.html", hide_header=True)

@app.route("/home")
def home():
    cur = mysql.connection.cursor()
    cur.execute("SELECT name, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    user_name, role = user

    announcements = []  

    if role == "student":
        cur.execute("""
            SELECT c.id, c.course_code, c.name
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            WHERE e.user_id = %s
        """, (user_id,))
        courses = cur.fetchall()

        cur.execute("""
            SELECT a.title, a.content, a.posted_at, c.name
            FROM announcements a
            JOIN courses c ON a.course_id = c.id
            JOIN enrollments e ON e.course_id = c.id
            WHERE e.user_id = %s
            ORDER BY a.posted_at DESC
            LIMIT 5
        """, (user_id,))
        announcements = cur.fetchall()

    elif role == "educator":
        # Get educator's courses
        cur.execute("""
            SELECT c.id, c.course_code, c.name
            FROM courses c
            WHERE c.educator_id = %s
        """, (user_id,))
        courses = cur.fetchall()
        announcements = []

    else:
        courses = []

    cur.close()
    return render_template("home.html", user_name=user_name, role=role,
                           courses=courses, announcements=announcements)


@app.route("/materials/<int:material_id>/download")
def download_material(material_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cur.fetchone()[0]

    if role == "student":
        cur.execute("""
            SELECT 1 FROM enrollments e
            JOIN materials m ON e.course_id = m.course_id
            WHERE e.user_id = %s AND m.id = %s
        """, (user_id, material_id))
    elif role == "educator":
        cur.execute("""
            SELECT 1 FROM materials m
            JOIN courses c ON m.course_id = c.id
            WHERE m.id = %s AND c.educator_id = %s
        """, (material_id, user_id))
    else:
        cur.close()
        return "Access denied", 403

    if not cur.fetchone():
        cur.close()
        return "Access denied", 403

    # Fetch file and metadata
    cur.execute("SELECT file_name, mime_type, file FROM materials WHERE id = %s", (material_id,))
    result = cur.fetchone()
    cur.close()

    if not result:
        return "Material not found", 404

    file_name, mime_type, file_data = result

    # Serve file with proper headers
    response = make_response(file_data)
    response.headers.set("Content-Type", mime_type or "application/octet-stream")
    response.headers.set("Content-Disposition", f"attachment; filename={file_name}")
    return response

@app.route("/courses/<int:course_id>/upload", methods=["GET", "POST"])
def upload_material(course_id):
    cur = mysql.connection.cursor()
    
    # Get current user info
    cur.execute("SELECT name, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close()
        return "User not found", 404

    user_name, role = user
    cur.close()

    if request.method == "POST":
        # Get uploaded file
        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return "No file selected", 400

        # Sanitize and extract file metadata
        title = request.form["title"]
        description = request.form["description"]
        filename = secure_filename(uploaded_file.filename)
        mime_type = uploaded_file.mimetype
        file_data = uploaded_file.read()

        # Verify user permission
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
        allowed = cur.fetchone()

        if not allowed:
            cur.close()
            return "Access denied", 403

        # Insert into database
        cur.execute("""
            INSERT INTO materials (course_id, uploader_id, title, description, file, mime_type, file_name)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (course_id, user_id, title, description, file_data, mime_type, filename))

        mysql.connection.commit()
        cur.close()

        return redirect(url_for("view_course", course_id=course_id))

    return render_template("upload.html", course_id=course_id, user_name=user_name)

@app.route("/courses/<int:course_id>")
def view_course(course_id):
    cur = mysql.connection.cursor()

    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]

    cur.execute("SELECT name, description FROM courses WHERE id = %s", (course_id,))
    course = cur.fetchone()

    cur.execute("""
    SELECT id, title, description, uploaded_at
    FROM materials
    WHERE course_id = %s
    ORDER BY uploaded_at DESC
    """, (course_id,))
    materials = cur.fetchall()

    cur.execute("SELECT title, content FROM announcements WHERE course_id = %s ORDER BY posted_at DESC", (course_id,))
    announcements = cur.fetchall()

    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cur.fetchone()[0]

    if role == "student":
        cur.execute("SELECT 1 FROM enrollments WHERE user_id = %s AND course_id = %s", (user_id, course_id))
    elif role == "educator":
        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
    else:
        allowed = None

    allowed = cur.fetchone()
    if not allowed:
        cur.close()
        return "Access denied", 403

    cur.close()
    return render_template("course_details.html", course=course, materials=materials,
                           announcements=announcements, role=role, course_id=course_id, user_name=user_name)

@app.route("/courses/<int:course_id>/forum", methods=["GET", "POST"])
def course_forum(course_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cur.fetchone()[0]

    if role == "student":
        cur.execute("SELECT 1 FROM enrollments WHERE user_id = %s AND course_id = %s", (user_id, course_id))
    elif role == "educator":
        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
    else:
        allowed = None

    allowed = cur.fetchone()
    if not allowed:
        cur.close()
        return "Access denied", 403

    if request.method == "POST":
        content = request.form["content"]
        parent_post_id = request.form.get("parent_post_id")
        cur.execute("""
            INSERT INTO forum_posts (course_id, author_id, parent_post_id, content)
            VALUES (%s, %s, %s, %s)
        """, (course_id, user_id, parent_post_id or None, content))
        mysql.connection.commit()

    cur.execute("""
    SELECT id, content, author_id, parent_post_id, thread_id FROM forum_posts
    WHERE thread_id IN (
        SELECT id FROM forum_threads WHERE course_id = %s
    )
    ORDER BY posted_at
    """, (course_id,))

    rows = cur.fetchall()
    columns = [col[0] for col in cur.description]
    posts = [dict(zip(columns, row)) for row in rows]
    cur.close()

    return render_template("forum.html", posts=posts, course_id=course_id, role=role, user_name=user_name)

@app.route("/courses/<int:course_id>/announcement", methods=["GET", "POST"])
def post_announcement(course_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cur.fetchone()[0]
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]

    if request.method == "POST" and role == "educator":
        title = request.form["title"]
        content = request.form["content"]

        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
        allowed = cur.fetchone()
        if not allowed:
            cur.close()
            return "Access denied", 403

        cur.execute("""
            INSERT INTO announcements (course_id, author_id, title, content)
            VALUES (%s, %s, %s, %s)
        """, (course_id, user_id, title, content))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for("view_course", course_id=course_id))

    cur.close()
    return render_template("announcement_form.html", course_id=course_id, role=role, user_name=user_name)

@app.route("/admin/users")
def manage_users():
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]
    cur.execute("SELECT id, name, email, role FROM users")
    users = cur.fetchall()
    cur.close()
    return render_template("user_management.html", users=users, user_name=user_name)

@app.route("/admin/users/add", methods=["GET", "POST"])
def add_user():
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        cur.execute("""
            INSERT INTO users (name, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
        """, (name, email, password, role))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for("manage_users"))

    cur.close()
    return render_template("user_form.html", action="Add", user_name=user_name)

@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
def edit_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        role = request.form["role"]

        cur.execute("""
            UPDATE users
            SET name = %s, email = %s, role = %s
            WHERE id = %s
        """, (name, email, role, user_id))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for("manage_users"))

    cur.execute("SELECT name, email, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    return render_template("user_form.html", action="Edit", user=user, user_id=user_id, user_name=user_name)

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for("manage_users"))

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)
