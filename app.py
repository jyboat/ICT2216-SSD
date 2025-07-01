from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, Response, make_response, abort, flash
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from collections import defaultdict
import os
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.middleware.proxy_fix import ProxyFix
from sendgrid.helpers.mail import Mail as SGMail
from sendgrid.helpers.mail import TrackingSettings, ClickTracking, OpenTracking
from sendgrid import SendGridAPIClient
import bleach
import re
import logging
import time
import pyotp
import qrcode
import io
import base64
import requests
import hashlib

load_dotenv()  # Load environment variables from .env

app = Flask(__name__)

#Make flask trust proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# bcrypt hashing
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.secret_key)


MAIL_USERNAME = os.getenv('MAIL_USERNAME')


# cf key.
cf_secret_key = os.getenv("CF_SECRET_KEY")
# session timeout
app.permanent_session_lifetime = timedelta(minutes=15)

# key: IP, value: list of timestamps
login_attempts = defaultdict(list)
BLOCK_THRESHOLD = 5
BLOCK_WINDOW = 600  # seconds


app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Controls cross-site requests



# function to check if session has expired
def is_session_expired():
    if 'user_id' not in session or 'session_token' not in session:
        session.clear()
        return True
    
    # check if token matches
    cur = mysql.connection.cursor()
    cur.execute("SELECT session_token FROM users WHERE id = %s", (session['user_id'],))
    db_token = cur.fetchone()
    cur.close()

    if not db_token or db_token[0] != session.get('session_token'):
        session.clear()
        return True

    last = session.get('last_active', 0)
    if time.time() - last > 900:
        session.clear()
        return True

    session['last_active'] = time.time()
    return False

def is_valid_session():
    if 'user_id' not in session or 'session_token' not in session or 'fingerprint' not in session:
        return False

    # Check if fingerprint matches
    current_fingerprint = generate_fingerprint(request)
    if session.get('fingerprint') != current_fingerprint:
        suspicious_logger.warning(f"Session fingerprint mismatch - user_id: {session['user_id']}, IP: {request.remote_addr}")
        return False

    # Check if token matches in database
    cur = mysql.connection.cursor()
    cur.execute("SELECT session_token FROM users WHERE id = %s", (session['user_id'],))
    result = cur.fetchone()
    cur.close()

    return result and result[0] == session.get('session_token')

def generate_fingerprint(request):
    """Generate a fingerprint that works with Nginx"""
    # Get browser information
    user_agent = request.headers.get('User-Agent', '')
    
    # Get the real client IP from Nginx headers
    real_ip = request.headers.get('X-Real-IP') or request.remote_addr
    
    # Log the IPs for debugging
    if app.debug:
        print(f"Remote addr: {request.remote_addr}, X-Real-IP: {real_ip}")
    
    # Use partial IP for some flexibility
    ip_parts = real_ip.split('.')
    if len(ip_parts) >= 3:  # IPv4
        ip_partial = '.'.join(ip_parts[:3]) + '.0'
    else:
        ip_partial = real_ip  # Handle IPv6 or unusual formats
    
    # Create fingerprint
    fingerprint_str = f"{user_agent}|{ip_partial}"
    
    fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    return fingerprint

def is_logged_in():
    if is_valid_session():
        if time.time() - session.get('last_active', 0) < 900:
            session['last_active'] = time.time()
            return True
    return False

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

def generate_qr(secret, email):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="MyFlaskApp")
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

@app.before_request
def security_check():
    """Check for session hijacking on every request"""
    # Skip for non-authenticated routes
    if request.endpoint in ['login', 'register', 'static', 'verify_2fa', 'setup_2fa', 'index', 'logout', 'forget_password', 'reset_password']:
        return
    
    # Check if user is logged in
    if 'user_id' not in session or 'session_token' not in session:
        return redirect(url_for('login'))
    
    # Check fingerprint if present
    if 'fingerprint' in session:
        current_fingerprint = generate_fingerprint(request)
        stored_fingerprint = session['fingerprint']
        
        if current_fingerprint != stored_fingerprint:
            # Log potential session hijacking attempt
            suspicious_logger.warning(
                f"Session hijacking detected! User-ID: {session['user_id']}, "
                f"IP: {request.headers.get('X-Real-IP', request.remote_addr)}, "
                f"UA: {request.headers.get('User-Agent', '')[:50]}"
            )
            
            # Log to database
            log_to_database(
                "WARNING", 
                403, 
                session['user_id'], 
                request.headers.get('X-Real-IP', request.remote_addr), 
                request.path, 
                "Session hijacking attempt - fingerprint mismatch"
            )
            
            # Invalidate session
            session.clear()
            return redirect(url_for('login', error='security_violation'))
    
    # Also check for session expiration
    if is_session_expired():
        return redirect(url_for('login', error='session_expired'))



@app.route("/")
def index():
    success = request.args.get('success') == '1'
    return render_template("login.html", hide_header=True, success=success)

@app.route("/home")
def home():
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))

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
    if 'user_id' not in session:
        return redirect(url_for('login'))
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))
    
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
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
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
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
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


from flask import abort, redirect, render_template, request, session, url_for
import bleach

@app.route("/courses/<int:course_id>/announcement/<int:announcement_id>/edit", methods=["GET", "POST"])
def edit_announcement(course_id, announcement_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 

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
        new_title = bleach.clean(new_title, tags=[], strip=True)
        new_content = bleach.clean(new_content, tags=['b', 'i', 'u', 'strong', 'em', 'ul', 'ol', 'li', 'p', 'br'], strip=True)

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
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))  

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
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
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
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
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
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 

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
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
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
        safe_content = bleach.clean(new_content, tags=[], attributes={}, strip=True)

        cur.execute("UPDATE forum_posts SET content = %s WHERE id = %s", (safe_content, post_id))
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
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
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

    # Secure redirect: only allow known paths
    referrer = request.referrer or ""
    safe_paths = ["/forum", "/home"]
    parsed = urlparse(referrer.replace('\\', ''))

    if parsed.path in safe_paths and not parsed.netloc and not parsed.scheme:
        return redirect(parsed.path)

    return redirect(url_for("home"))

@app.route("/courses/<int:course_id>/announcement", methods=["GET", "POST"])
def post_announcement(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))  
    
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Fetch user role and name
    cur.execute("SELECT role, name FROM users WHERE id = %s", (user_id,))
    result = cur.fetchone()
    if not result:
        cur.close()
        abort(403, description="User not found")

    role, user_name = result

    if request.method == "POST" and role == "educator":
        title = bleach.clean(request.form["title"], tags=[], attributes={}, strip=True)
        content = bleach.clean(
            request.form["content"],
            tags=["b", "i", "u", "strong", "em", "br", "p"],  
            attributes={},
            strip=True
        )

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
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    admin_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (admin_id,))
    user_name = cur.fetchone()[0]
    cur.execute("""
        SELECT
          u.id,
          u.name,
          u.email,
          u.role,
          IFNULL(
            CONCAT_WS(', ',
              sc.student_courses,
              tc.teaching_courses
            ),
            ''
          ) AS courses
        FROM users u
        /* sub-query: student enrollments */
        LEFT JOIN (
          SELECT
            e.user_id,
            GROUP_CONCAT(c.course_code
                         ORDER BY c.course_code
                         SEPARATOR ', '
                        ) AS student_courses
          FROM enrollments e
          JOIN courses c ON c.id = e.course_id
          GROUP BY e.user_id
        ) sc ON sc.user_id = u.id
        /* sub-query: courses they teach */
        LEFT JOIN (
          SELECT
            c.educator_id AS user_id,
            GROUP_CONCAT(DISTINCT c.course_code
                         ORDER BY c.course_code
                         SEPARATOR ', '
                        ) AS teaching_courses
          FROM courses c
          GROUP BY c.educator_id
        ) tc ON tc.user_id = u.id

        GROUP BY u.id, u.name, u.email, u.role
        ORDER BY u.name
    """)
    users = cur.fetchall()
    cur.close()
    return render_template("user_management.html", users=users, user_name=user_name)

@app.route("/admin/users/add", methods=["GET", "POST"])
def add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]
    cur.execute("SELECT course_code FROM courses ORDER BY course_code")
    course_codes = [r[0] for r in cur.fetchall()]


    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]
        selected_codes = request.form.getlist("course_codes")

        cur.execute("""
            INSERT INTO users (name, email, password_hash, role, totp_secret)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, password, role, ""))
        mysql.connection.commit()
        new_user_id = cur.lastrowid
        for code in selected_codes:
            cur.execute("""
                INSERT INTO enrollments (user_id, course_id)
                VALUES (
                  %s,
                  (SELECT id FROM courses WHERE course_code = %s)
                )
            """, (new_user_id, code))
        mysql.connection.commit()

        cur.close()

        return redirect(url_for("manage_users"))

    cur.close()
    return render_template("user_form.html", action="Add", user_name=user_name,course_codes=course_codes, assigned_codes=[])

@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
def edit_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    admin_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id = %s", (admin_id,))
    user_name = cur.fetchone()[0]

    cur.execute("SELECT course_code FROM courses ORDER BY course_code")
    course_codes = [row[0] for row in cur.fetchall()]

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        role = request.form["role"]
        selected_codes = request.form.getlist("course_codes")

        cur.execute("""
            UPDATE users
            SET name = %s, email = %s, role = %s
            WHERE id = %s
        """, (name, email, role, user_id))

        cur.execute(
            "DELETE FROM enrollments WHERE user_id = %s",
            (user_id,)
        )

        for code in selected_codes:
            cur.execute("""
                INSERT INTO enrollments (user_id, course_id)
                VALUES (
                  %s,
                  (SELECT id FROM courses WHERE course_code = %s)
                )
            """, (user_id, code))

        mysql.connection.commit()
        cur.close()

        return redirect(url_for("manage_users"))

    cur.execute("SELECT name, email, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    cur.execute("""
      SELECT c.course_code
        FROM courses c
        JOIN enrollments e ON e.course_id = c.id
       WHERE e.user_id = %s
    """, (user_id,))
    assigned_codes = [row[0] for row in cur.fetchall()]
    cur.close()

    return render_template("user_form.html", action="Edit", user=user, user_id=user_id, user_name=user_name,
        course_codes=course_codes,
        assigned_codes=assigned_codes)

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))

    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for("manage_users"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('home'))
    
    error_param = request.args.get('error')
    error_message = None
    if error_param == 'session_expired':
        error_message = "Your session has expired. Please log in again."

    if request.method == 'POST':
        ip = request.remote_addr
        now = time.time()

        # Get the Cloudflare Turnstile token
        cf_turnstile_response = request.form.get('cf-turnstile-response')
        
        # If no token was provided, return an error
        if not cf_turnstile_response:
            suspicious_logger.warning(f"Login attempt without Cloudflare verification - IP: {ip}")
            log_to_database("WARNING", 400, 'Unauthenticated', ip, "/login", "Login attempt without Cloudflare verification")
            return render_template("login.html", error="Please complete the security check", hide_header=True)
            
        # Verify the token with Cloudflare
        verification_data = {
            'secret': cf_secret_key,  
            'response': cf_turnstile_response,
            'remoteip': ip
        }
        try:
            verification_response = requests.post(
                'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                data=verification_data
            ).json()
            
            # If verification failed, return an error
            if not verification_response.get('success'):
                suspicious_logger.warning(f"Failed Cloudflare verification - IP: {ip}")
                log_to_database("WARNING", 400, 'Unauthenticated', ip, "/login", "Failed Cloudflare verification")
                return render_template("login.html", error="Security check failed. Please try again.", hide_header=True)
        except Exception as e:
            # Handle request exceptions
            suspicious_logger.error(f"Cloudflare verification error: {str(e)} - IP: {ip}")
            log_to_database("ERROR", 500, 'Unauthenticated', ip, "/login", f"Cloudflare verification error: {str(e)}")
            return render_template("login.html", error="An error occurred during verification. Please try again.", hide_header=True)

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

                if request.form.get('remember_me') == 'on':
                    session.permanent = True
                else:
                    session.permanent = False

                login_attempts[ip] = [] 
                if user[6] is None:
                    session['temp_new_user_email'] = email
                    return redirect(url_for('setup_2fa'))   # Route for first-time TOTP setup
                else:
                    return redirect(url_for('verify_2fa'))  # Normal 2FA flow
            else:
                suspicious_logger.warning(f"Failed login (wrong password) - email: {email}, IP: {request.remote_addr}")
                log_to_database("WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                                f"Failed login (wrong password) - email: {email}")
        else:
            suspicious_logger.warning(f"Failed login (no such user) - email: {email}, IP: {request.remote_addr}")
            log_to_database("WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                            f"Failed login (no such user) - email: {email}")

    if request.method == 'POST':
        return render_template("login.html", error="Invalid email or password", hide_header=True)
    else:
        return render_template("login.html", hide_header=True, error=error_message)

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
                cur = mysql.connection.cursor()
                new_token = os.urandom(32).hex()
                cur.execute("UPDATE users SET session_token = %s WHERE id = %s", (new_token, user_id))
                mysql.connection.commit()
                cur.close()

                # Finalize login
                session['user_id'] = user_id
                session['user_name'] = user_name
                session['role'] = role
                session['last_active'] = time.time()
                session['session_token'] = new_token
                session['fingerprint'] = generate_fingerprint(request)
                session.pop('temp_user_id', None)
                return redirect(url_for('home'))

        cur.close()
        return render_template("verify_2fa.html", error="Invalid OTP code")

    return render_template("verify_2fa.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('home'))
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
        
        if len(password) < 8 or \
            not re.search(r'[A-Z]', password) or \
            not re.search(r'[a-z]', password) or \
            not re.search(r'[0-9]', password) or \
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return render_template("register.html", error="Password must be at least 8 characters and include uppercase, lowercase, digit, and special character.", hide_header=True)

        #password hashing
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

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    email = session.get('temp_new_user_email')
    if not email:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, role, totp_secret FROM users WHERE email = %s", (email,))
    result = cur.fetchone()
    cur.close()

    if not result:
        abort(404)

    user_id, user_name, role, totp_secret = result

    # If no secret exists, generate a new one
    if totp_secret is None:
        totp_secret = pyotp.random_base32()
        session['pending_totp_secret'] = totp_secret  # Save it temporarily

    else:
        # Secret exists for some reason (in case of edge case)
        session['pending_totp_secret'] = totp_secret

    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(session['pending_totp_secret'])

        if totp.verify(otp):
            # Finalize login and save the new TOTP secret
            cur = mysql.connection.cursor()
            new_token = os.urandom(32).hex()
            cur.execute("UPDATE users SET session_token = %s, totp_secret = %s WHERE id = %s",
                        (new_token, session['pending_totp_secret'], user_id))
            mysql.connection.commit()
            cur.close()

            # Login session
            session['user_id'] = user_id
            session['user_name'] = user_name
            session['role'] = role
            session['last_active'] = time.time()
            session['session_token'] = new_token
            session['fingerprint'] = generate_fingerprint(request)

            # Clean temp session values
            session.pop('temp_new_user_email', None)
            session.pop('pending_totp_secret', None)

            return redirect(url_for('home'))

        return render_template("setup_2fa.html", qr_code_b64=generate_qr(session['pending_totp_secret'], email), error="Invalid OTP")

    return render_template("setup_2fa.html", qr_code_b64=generate_qr(session['pending_totp_secret'], email))




@app.route("/admin/courses", methods=["GET", "POST"])
def manage_courses():

    if 'user_id' not in session:
        return redirect(url_for('login'))
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")

    admin_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name FROM users WHERE role = 'educator' ORDER BY name")
    educators = cur.fetchall() 

    if request.method == "POST" and request.form.get("course_code"):
        code        = request.form["course_code"].strip()
        name        = request.form["name"].strip()
        description = request.form["description"].strip()
        educator_id = request.form.get("educator_id")
        if code and name:
            cur.execute(
                """
                INSERT INTO courses
                  (course_code, name, description, educator_id)
                VALUES (%s, %s, %s, %s)
                """,
                (code, name, description, educator_id)
            )
            mysql.connection.commit()


    cur.execute("SELECT name FROM users WHERE id = %s", (admin_id,))
    user_name = cur.fetchone()[0]

    cur.execute("""
      SELECT id, course_code, name, description, educator_id
        FROM courses
       ORDER BY course_code
    """)
    courses = cur.fetchall()
    cur.close()

    return render_template(
        "course_management.html",
        courses=courses,
        user_name=user_name,
        educators = educators
    )

@app.route("/admin/courses/<int:course_id>/edit", methods=["GET", "POST"])
def edit_course(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name FROM users WHERE role = 'educator' ORDER BY name")
    educators = cur.fetchall()

    if request.method == "POST":
        code = bleach.clean(request.form["course_code"].strip(), tags=[], strip=True)
        name = bleach.clean(request.form["name"].strip(), tags=[], strip=True)
        description = bleach.clean(request.form["description"].strip(), tags=[], strip=True)
        educator_id = request.form.get("educator_id", type=int)

        if code and name and len(code) <= 10 and len(name) <= 100:
            cur.execute("""
                UPDATE courses
                   SET course_code = %s,
                       name = %s,
                       description = %s,
                       educator_id   = %s
                 WHERE id = %s
            """, (code, name, description, educator_id, course_id))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('manage_courses'))

    cur.execute("SELECT course_code, name, description, educator_id FROM courses WHERE id = %s", (course_id,))
    row = cur.fetchone()
    cur.close()

    if not row:
        abort(404)

    course_code, course_name, course_desc, current_educator_id = row
    return render_template(
        "course_edit.html",
        course_id=course_id,
        course_code=course_code,
        course_name=course_name,
        course_desc= course_desc,
        educators = educators,
        current_educator_id = current_educator_id
    )

@app.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
def delete_course(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))
    if session.get('role') != 'admin':
        abort(403, description="Admin access required")

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM courses WHERE id=%s", (course_id,))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('manage_courses'))

@app.route("/logout")
def logout():
    user_id = session.get('user_id')
    if user_id:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET session_token = NULL WHERE id = %s", (user_id,))
        mysql.connection.commit()
        cur.close()
    session.clear()
    return redirect(url_for('index'))

#Sendgrid API for mail
def send_reset_email_via_sendgrid(to_email: str, reset_url: str):
    message = SGMail(
        from_email=MAIL_USERNAME,
        to_emails=to_email,
        subject="Password Reset Request",
        html_content=(
            "<p>Hi,</p>"
            f"<p>To reset your password, click <a href='{reset_url}'>here</a>.</p>"
            "<p>If you did not request this, you can ignore this email.</p>"
        )
    )
     
    message.tracking_settings = TrackingSettings(
        click_tracking=ClickTracking(enable=False, enable_text=False),
        open_tracking=OpenTracking(enable=False)
    )

    sg = SendGridAPIClient(os.environ["SENDGRID_API_KEY"])
    resp = sg.send(message)
    if resp.status_code >= 400:
        raise Exception(f"SendGrid error {resp.status_code}")

class ForgetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

@app.route("/forget-password", methods=["GET", "POST"])
def forget_password():
    form = ForgetPasswordForm()
    if form.validate_on_submit():  
        email = form.email.data.strip().lower()
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        exists = cur.fetchone() is not None
        cur.close()
        
        if exists:
            token = serializer.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)
            
            send_reset_email_via_sendgrid(email, reset_url)

        return render_template("forget_password_sent.html")

    return render_template("forget_password.html", form=form)


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired("Please enter a password"),
            Length(min=8, message="Password must be at least 8 characters"),
            Regexp(r'.*[A-Z].*', message="Must include at least one uppercase letter"),
            Regexp(r'.*[a-z].*', message="Must include at least one lowercase letter"),
            Regexp(r'.*[0-9].*', message="Must include at least one digit"),
            Regexp(r'.*[!@#$%^&*(),.?\":{}|<>].*', message="Must include at least one special character")
        ]
    )
    confirm = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired("Please confirm your password"),
            EqualTo("password", message="Passwords must match")
        ]
    )
    submit = SubmitField("Reset Password")

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt="password-reset-salt",
            max_age=300             
        )
    except SignatureExpired:
        flash("That link has expired. Please request a new one.", "warning")
        return redirect(url_for("forget_password"))
    except BadSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("forget_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        
        hashed_pw = bcrypt.generate_password_hash(
            form.password.data
        ).decode("utf-8")

        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s",
            (hashed_pw, email)
        )
        mysql.connection.commit()
        cur.close()

        session.clear()

        flash("Your password has been reset. Please login with your new password", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", form=form)

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

    # Get the real IP address dued to proxy
    real_ip = request.headers.get('X-Real-IP', ip_address)

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO logs (timestamp, type, status_code, user_id, ip_address, path, message)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (datetime.now(), type, status_code, str(user_id), real_ip, path, message))
    mysql.connection.commit()
    cur.close()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=443)
