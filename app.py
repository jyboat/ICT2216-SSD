from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, Response, make_response, abort
from werkzeug.utils import secure_filename
from collections import defaultdict
import os
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
import bleach
import re
import logging
import time
import pyotp
import qrcode
import io
import base64

load_dotenv()  # Load environment variables from .env

app = Flask(__name__)

# bcrypt hashing
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

# session timeout
app.permanent_session_lifetime = timedelta(minutes=15)

# key: IP, value: list of timestamps
login_attempts = defaultdict(list)
BLOCK_THRESHOLD = 5
BLOCK_WINDOW = 600  # seconds

# function to check if session has expired
def is_session_expired():
    if 'user_id' not in session:
        return True
    last = session.get('last_active', 0)
    if time.time() - last > 900:  # 900 = 15 mins
        session.clear()
        return True
    session['last_active'] = time.time()
    return False

# TODO: consider wrapping repeated code in reusable helper functions
# TODO: replace with dynamic user id upon login

# Helper function to check if educator role
def is_educator(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cur.fetchone()[0]
    cur.close()
    return role == "educator"

# Helper function to repeatedly get user_id
def get_current_user_id():
    return session.get('user_id')

@app.route("/")
def index():
    success = request.args.get('success') == '1'
    return render_template("login.html", hide_header=True, success=success)

@app.route("/home")
def home():
    if is_session_expired():
        return redirect(url_for('index'))

    user_id = session['user_id']
    user_name = session['user_name']
    role = session['role']

    if role == "admin":
        return redirect(url_for("manage_users"))

    cur = mysql.connection.cursor()

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
    user_id = get_current_user_id()
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
        abort(403, description="Access denied")

    if not cur.fetchone():
        cur.close()
        abort(403, description="Access denied")

    # Fetch file and metadata
    cur.execute("SELECT file_name, mime_type, file FROM materials WHERE id = %s", (material_id,))
    result = cur.fetchone()
    cur.close()

    if not result:
        abort(404, description="Materials not found")

    file_name, mime_type, file_data = result

    # Serve file with proper headers
    response = make_response(file_data)
    response.headers.set("Content-Type", mime_type or "application/octet-stream")
    response.headers.set("Content-Disposition", f"attachment; filename={file_name}")
    return response

@app.route("/materials/<int:material_id>/edit", methods=["GET", "POST"])
def edit_material(material_id):
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Fetch existing data
    cur.execute("""
        SELECT course_id, title, description, file_name, mime_type
        FROM materials
        WHERE id = %s AND uploader_id = %s
    """, (material_id, user_id))
    material = cur.fetchone()

    if not material:
        cur.close()
        abort(403, description="Access denied or Materials not found")

    course_id, current_title, current_desc, current_filename, current_mime = material

    if request.method == "POST":
        new_title = request.form["title"]
        new_description = request.form["description"]

        uploaded_file = request.files.get("file")
        if uploaded_file and uploaded_file.filename:
            # File was uploaded, update it
            new_filename = secure_filename(uploaded_file.filename)
            new_mime = uploaded_file.mimetype
            new_file_data = uploaded_file.read()

            cur.execute("""
                UPDATE materials
                SET title = %s, description = %s, file = %s, file_name = %s, mime_type = %s
                WHERE id = %s AND uploader_id = %s
            """, (new_title, new_description, new_file_data, new_filename, new_mime, material_id, user_id))
        else:
            # No new file uploaded — only update text fields
            cur.execute("""
                UPDATE materials
                SET title = %s, description = %s
                WHERE id = %s AND uploader_id = %s
            """, (new_title, new_description, material_id, user_id))

        mysql.connection.commit()
        cur.close()

        return redirect(url_for("view_course", course_id=course_id))

    cur.close()
    return render_template(
        "edit_material.html",
        title=current_title,
        description=current_desc,
        material_id=material_id,
        course_id=course_id,
        file_name=current_filename
    )


@app.route("/materials/<int:material_id>/delete", methods=["POST"])
def delete_material(material_id):
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Confirm ownership and get course_id for redirect
    cur.execute("SELECT course_id FROM materials WHERE id = %s AND uploader_id = %s", (material_id, user_id))
    result = cur.fetchone()

    if not result:
        cur.close()
        abort(403, description="Access denied or Materials not found")

    course_id = result[0]

    cur.execute("DELETE FROM materials WHERE id = %s", (material_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for("view_course", course_id=course_id))


@app.route("/courses/<int:course_id>/announcement/<int:announcement_id>/edit", methods=["GET", "POST"])
def edit_announcement(course_id, announcement_id):
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Check if this user is the educator for the course
    cur.execute("""
        SELECT a.title, a.content
        FROM announcements a
        JOIN courses c ON a.course_id = c.id
        WHERE a.id = %s AND c.id = %s AND c.educator_id = %s
    """, (announcement_id, course_id, user_id))

    result = cur.fetchone()
    if not result:
        cur.close()
        abort(403, description="Access denied or announcement not found")

    current_title, current_content = result

    if request.method == "POST":
        new_title = request.form["title"].strip()
        new_content = request.form["content"].strip()

        cur.execute("""
            UPDATE announcements
            SET title = %s, content = %s
            WHERE id = %s
        """, (new_title, new_content, announcement_id))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for("view_course", course_id=course_id))

    cur.close()
    return render_template("edit_announcement.html", title=current_title, content=current_content,
                           course_id=course_id, announcement_id=announcement_id)


@app.route("/courses/<int:course_id>/upload", methods=["GET", "POST"])
def upload_material(course_id):
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()
    
    # Get current user info
    cur.execute("SELECT name, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close()
        abort(404, description="User not found")

    user_name, role = user

    # Only allow educators to upload
    if role != "educator":
        cur.close()
        abort(403, description="Access denied: only educators can upload materials")

    cur.close()

    if request.method == "POST":
        # Get uploaded file
        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            abort(400, description="No File Selected")

        # Sanitize and extract file metadata

        filename = secure_filename(uploaded_file.filename)
        mime_type = uploaded_file.mimetype

        if not filename.lower().endswith(".pdf") or mime_type != "application/pdf":
            abort(400, description="Only PDF files are allowed")


        title = request.form["title"]
        description = request.form["description"]
        file_data = uploaded_file.read()

        # Verify user permission
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
        allowed = cur.fetchone()

        if not allowed:
            cur.close()
            abort(403, description="Access denied")

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
    user_id = get_current_user_id()
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

    cur.execute("SELECT title, content, id, posted_at FROM announcements WHERE course_id = %s ORDER BY posted_at DESC", (course_id,))
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
        abort(403, description="Access denied")

    cur.close()
    return render_template("course_details.html", course=course, materials=materials,
                           announcements=announcements, role=role, course_id=course_id, user_name=user_name)


@app.route("/courses/<int:course_id>/announcement/<int:announcement_id>/delete", methods=["POST"])
def delete_announcement(course_id, announcement_id):
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Verify that this educator owns the course
    cur.execute("""
        SELECT 1
        FROM announcements a
        JOIN courses c ON a.course_id = c.id
        WHERE a.id = %s AND c.id = %s AND c.educator_id = %s
    """, (announcement_id, course_id, user_id))

    if not cur.fetchone():
        cur.close()
        abort(403, description="Access denied")

    cur.execute("DELETE FROM announcements WHERE id = %s", (announcement_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for("view_course", course_id=course_id))


@app.route("/courses/<int:course_id>/forum", methods=["GET", "POST"])
def course_forum(course_id):
    user_id = get_current_user_id()
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
        cur.close()
        abort(403, description="Access denied")

    if not cur.fetchone():
        cur.close()
        abort(403, description="Access denied")

    if request.method == "POST":
        content = request.form["content"].strip()

        # Validate length and reject patterns
        if not content or len(content) > 1000:
            abort(400, description="Invalid content")
        # simple regex to catch script injection attempts
        if re.search(r'<\s*script|on\w+\s*=|javascript:', content, re.IGNORECASE):
            abort(400, description="Malicious input blocked")
        # Sanitize
        content = bleach.clean(content, tags=[], attributes={}, strip=True)

        parent_post_id = request.form.get("parent_post_id")

        cur.execute("SELECT id FROM forum_threads WHERE course_id = %s LIMIT 1", (course_id,))
        thread = cur.fetchone()

        if not thread:
            cur.execute("""
                INSERT INTO forum_threads (course_id, author_id, title)
                VALUES (%s, %s, %s)
            """, (course_id, user_id, "General Discussion"))
            mysql.connection.commit()
            thread_id = cur.lastrowid
        else:
            thread_id = thread[0]

        cur.execute("""
            INSERT INTO forum_posts (thread_id, author_id, parent_post_id, content)
            VALUES (%s, %s, %s, %s)
        """, (thread_id, user_id, parent_post_id or None, content))
        mysql.connection.commit()

    # Fetch all posts for this course’s threads
    cur.execute("""
        SELECT fp.id, fp.content, fp.author_id, fp.parent_post_id, fp.thread_id, fp.posted_at, u.name AS author_name
        FROM forum_posts fp
        JOIN users u ON fp.author_id = u.id
        WHERE fp.thread_id IN (
            SELECT id FROM forum_threads WHERE course_id = %s
        )
        ORDER BY fp.posted_at
    """, (course_id,))

    rows = cur.fetchall()
    columns = [col[0] for col in cur.description]
    posts = [dict(zip(columns, row)) for row in rows]
    posts_dict = {post["id"]: post["author_id"] for post in posts}

    cur.close()

    return render_template("forum.html", posts=posts, course_id=course_id, role=role,
                           user_name=user_name, current_user_id=user_id, posts_dict=posts_dict)

@app.route("/forum/posts/<int:post_id>/edit", methods=["GET", "POST"])
def edit_post(post_id):
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    cur.execute("SELECT author_id, content, thread_id FROM forum_posts WHERE id = %s", (post_id,))
    result = cur.fetchone()
    if not result:
        cur.close()
        abort(404, description="Post not found")

    author_id, content, thread_id = result

    if author_id != user_id and not is_educator(user_id):
        cur.close()
        abort(403, description="Access denied")

    if request.method == "POST":
        new_content = request.form["content"]
        cur.execute("UPDATE forum_posts SET content = %s WHERE id = %s", (new_content, post_id))
        mysql.connection.commit()

        cur.execute("SELECT course_id FROM forum_threads WHERE id = %s", (thread_id,))
        course_result = cur.fetchone()
        cur.close()

        if not course_result:
            abort(404, description="Course not found")

        course_id = course_result[0]
        return redirect(url_for("course_forum", course_id=course_id))

    cur.close()
    return render_template("edit_post.html", content=content, post_id=post_id)

@app.route("/forum/posts/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT author_id FROM forum_posts WHERE id = %s", (post_id,))
    result = cur.fetchone()
    if not result:
        cur.close()
        abort(404, description="Post not found")

    author_id = result[0]
    if user_id != author_id and not is_educator(user_id):
        cur.close()
        abort(403, description="Access denied")

    cur.execute("DELETE FROM forum_posts WHERE id = %s", (post_id,))
    mysql.connection.commit()
    cur.close()
    return redirect(request.referrer or url_for("home"))


@app.route("/courses/<int:course_id>/announcement", methods=["GET", "POST"])
def post_announcement(course_id):
    user_id = get_current_user_id()
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
            abort(403, description="Access denied")

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
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]
    cur.execute("SELECT id, name, email, role FROM users")
    users = cur.fetchall()
    cur.close()
    return render_template("user_management.html", users=users, user_name=user_name)

@app.route("/admin/users/add", methods=["GET", "POST"])
def add_user():
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    user_id = get_current_user_id()
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
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    user_id = get_current_user_id()
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
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for("manage_users"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        now = time.time()

        # Clean old attempts
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < BLOCK_WINDOW]

        # Append the current attempt *before* checking threshold
        login_attempts[ip].append(now)

        # Block if too many attempts
        if len(login_attempts[ip]) >= BLOCK_THRESHOLD:
            suspicious_logger.warning(f"Blocked login - too many attempts - IP: {ip}")
            log_to_database("WARNING", 429, 'Unauthenticated', ip, "/login", "Blocked login - too many attempts")
            return render_template("login.html", error="Too many failed attempts. Try again later.", hide_header=True)

        # Otherwise, Continue with login attempt
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            stored_hash = user[3]
            if bcrypt.check_password_hash(stored_hash, password):
                session['temp_user_id'] = user[0]
                login_attempts[ip] = [] 
                return redirect(url_for('verify_2fa'))
            else:
                suspicious_logger.warning(f"Failed login (wrong password) - email: {email}, IP: {request.remote_addr}")
                log_to_database("WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                                f"Failed login (wrong password) - email: {email}")
        else:
            suspicious_logger.warning(f"Failed login (no such user) - email: {email}, IP: {request.remote_addr}")
            log_to_database("WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                            f"Failed login (no such user) - email: {email}")

    return render_template("login.html", error="Invalid email or password", hide_header=True)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        user_id = session['temp_user_id']
        cur = mysql.connection.cursor()
        cur.execute("SELECT name, role, totp_secret FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()
        cur.close()

        if result:
            user_name, role, totp_secret = result
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(otp):
                # Finalize login
                session['user_id'] = user_id
                session['user_name'] = user_name
                session['role'] = role
                session['last_active'] = time.time()
                session.pop('temp_user_id', None)
                return redirect(url_for('home'))

        return render_template("verify_2fa.html", error="Invalid OTP code")

    return render_template("verify_2fa.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']


        if not name or not email or not password or not confirm_password:
            return render_template("register.html", error="All fields are required", hide_header=True)


        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match", hide_header=True)


        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()
        if existing_user:
            return render_template("register.html", error="An account with that email already exists", hide_header=True)

        if len(password) < 8:
            return render_template("register.html", error="Password must be at least 8 characters", hide_header=True)

        #password hasing
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        totp_secret = pyotp.random_base32()
        cur.execute("""
            INSERT INTO users (name, email, password_hash, totp_secret)
            VALUES (%s, %s, %s, %s)
        """, (name, email, hashed_pw, totp_secret))
        mysql.connection.commit()
        cur.close()

        session['temp_new_user_email'] = email 
        return redirect(url_for('setup_2fa'))

    return render_template("register.html", hide_header=True)

@app.route('/setup-2fa')
def setup_2fa():
    email = session.get('temp_new_user_email')
    if not email:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT totp_secret FROM users WHERE email = %s", (email,))
    result = cur.fetchone()
    cur.close()

    if not result:
        abort(404)

    totp_secret = result[0]
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=email, issuer_name="MyFlaskApp")
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template("setup_2fa.html", qr_code_b64=qr_code_b64)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(403)
def forbidden(e):
    user_id = session.get('user_id', 'Unauthenticated')
    ip = request.remote_addr
    path = request.path
    msg = "403 Forbidden"
    suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
    log_to_database("WARNING", 403, user_id, ip, path, msg)
    return render_template("error.html", error=e), 403

@app.errorhandler(404)
def not_found(e):
    user_id = session.get('user_id', 'Unauthenticated')
    ip = request.remote_addr
    path = request.path
    msg = "404 Not Found"
    suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
    log_to_database("WARNING", 404, user_id, ip, path, msg)
    return render_template("error.html", error=e), 404

@app.errorhandler(400)
def bad_request(e):
    user_id = session.get('user_id', 'Unauthenticated')
    ip = request.remote_addr
    path = request.path
    msg = "400 Bad Request"
    suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
    log_to_database("WARNING", 400, user_id, ip, path, msg)
    return render_template("error.html", error=e), 400

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

# Create a custom logger for suspicious activity
suspicious_logger = logging.getLogger("suspicious")
suspicious_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("logs.txt")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
suspicious_logger.addHandler(file_handler)

mysql = MySQL(app)

def log_to_database(type, status_code, user_id, ip_address, path, message):
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO logs (timestamp, type, status_code, user_id, ip_address, path, message)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (datetime.now(), type, status_code, str(user_id), ip_address, path, message))
    mysql.connection.commit()
    cur.close()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)
