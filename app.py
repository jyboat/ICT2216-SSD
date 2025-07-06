from dotenv import load_dotenv
from flask import Flask, make_response, flash, abort, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename
from collections import defaultdict
import os
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from datetime import timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import time
import pyotp
import qrcode
import io
import base64
import session_utils
from log import log_to_database
from session_utils import is_session_expired, is_logged_in, get_current_user_id, generate_fingerprint
from error import register_error_handlers
from email_utils import send_reset_email_via_sendgrid
from forum import register_forum_routes
from announcement import register_announcement_routes
from course import register_course_routes

load_dotenv()  # Load environment variables from .env

app = Flask(__name__)

# Make flask trust proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# bcrypt hashing
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# cf key.
cf_secret_key = os.getenv("CF_SECRET_KEY")
# session timeout
app.permanent_session_lifetime = timedelta(minutes=15)

# key: IP, value: list of timestamps
login_attempts = defaultdict(list)
BLOCK_THRESHOLD = 5
BLOCK_WINDOW = 600  # seconds

app.config['SESSION_TYPE'] = 'redis' 
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1) 
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Controls cross-site requests


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
            session_utils.suspicious_logger.warning(
                f"Session hijacking detected! User-ID: {session['user_id']}, "
                f"IP: {request.headers.get('X-Real-IP', request.remote_addr)}, "
                f"UA: {request.headers.get('User-Agent', '')[:50]}"
            )
            
            # Log to database
            log_to_database(
                mysql,
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
    if is_session_expired(mysql):
        return redirect(url_for('login', error='session_expired'))


@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    success = request.args.get('success') == '1'
    return render_template("login.html", hide_header=True, success=success)


@app.route("/home")
def home():
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired(mysql):
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
    elif is_session_expired(mysql):
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
        return redirect(url_for('home'))

    if not cur.fetchone():
        cur.close()
        return redirect(url_for('home'))

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
    elif is_session_expired(mysql):
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

        return redirect(url_for("course.view_course", course_id=course_id))

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
    elif is_session_expired(mysql):
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

    return redirect(url_for("course.view_course", course_id=course_id))


@app.route("/courses/<int:course_id>/upload", methods=["GET", "POST"])
def upload_material(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired(mysql):
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
            return redirect(url_for('home'))

        # Insert into database
        cur.execute("""
            INSERT INTO materials (course_id, uploader_id, title, description, file, mime_type, file_name)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (course_id, user_id, title, description, file_data, mime_type, filename))

        mysql.connection.commit()
        cur.close()

        return redirect(url_for("course.view_course", course_id=course_id))

    return render_template("upload.html", course_id=course_id, user_name=user_name)


@app.route("/admin/users")
def manage_users():
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired(mysql):
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
        GROUP_CONCAT(
          DISTINCT ec.course_code
          ORDER BY ec.course_code
          SEPARATOR ', '
        ),
        ''
      ) AS courses
    FROM
      users u
    LEFT JOIN (
      -- combine enrollments and teaching assignments into one set
      SELECT
        e.user_id,
        c.course_code
      FROM
        enrollments e
        JOIN courses c ON c.id = e.course_id

      UNION

      SELECT
        c.educator_id AS user_id,
        c.course_code
      FROM
        courses c
    ) ec
      ON ec.user_id = u.id
    GROUP BY
      u.id,
      u.name,
      u.email,
      u.role
    ORDER BY
      u.name
""")
    users = cur.fetchall()

    cur.close()
    return render_template("user_management.html", users=users, user_name=user_name)


@app.route("/admin/users/add", methods=["GET", "POST"])
def add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired(mysql):
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

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute("""
            INSERT INTO users (name, email, password_hash, role, totp_secret)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, hashed_pw, role, ""))
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
    return render_template("user_form.html", action="Add", user_name=user_name, course_codes=course_codes, assigned_codes=[])


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
def edit_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired(mysql):
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
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        new_role = request.form.get("role", "")
        selected_codes = request.form.getlist("course_codes")
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        old_role = cur.fetchone()[0]
        # validation
        if not name or len(name) > 100:
            abort(400, "Name is required (max 100 chars)")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            abort(400, "Invalid email address")
        if new_role not in ("student", "educator", "admin"):
            abort(400, "Invalid role")

        cur.execute("""
            UPDATE users
            SET name = %s, email = %s, role = %s
            WHERE id = %s
        """, (name, email, new_role, user_id))

        if old_role == 'educator' and new_role != 'educator':
            cur.execute("DELETE FROM courses WHERE educator_id = %s", (user_id,))
        
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

    return render_template("user_form.html", action="Edit", user=user, user_id=user_id, user_name=user_name, course_codes=course_codes, assigned_codes=assigned_codes)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired(mysql):
        return redirect(url_for('login', error='session_expired'))

    if session.get('role') != 'admin':
        abort(403, description="Admin access required")
    cur = mysql.connection.cursor()
    cur.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
    if not cur.fetchone():
        cur.close()
        abort(404, "User not found")
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for("manage_users"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in(mysql):
        return redirect(url_for('home'))
    
    error_param = request.args.get('error')
    error_message = None
    if error_param == 'session_expired':
        error_message = "Your session has expired. Please log in again."

    if request.method == 'POST':
        ip = request.remote_addr
        now = time.time()

        # # Get the Cloudflare Turnstile token
        # cf_turnstile_response = request.form.get('cf-turnstile-response')
        
        # # If no token was provided, return an error
        # if not cf_turnstile_response:
        #     suspicious_logger.warning(f"Login attempt without Cloudflare verification - IP: {ip}")
        #     log_to_database("WARNING", 400, 'Unauthenticated', ip, "/login", "Login attempt without Cloudflare verification")
        #     return render_template("login.html", error="Please complete the security check", hide_header=True)
            
        # # Verify the token with Cloudflare
        # verification_data = {
        #     'secret': cf_secret_key,  
        #     'response': cf_turnstile_response,
        #     'remoteip': ip
        # }
        # try:
        #     verification_response = requests.post(
        #         'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        #         data=verification_data
        #     ).json()
            
        #     # If verification failed, return an error
        #     if not verification_response.get('success'):
        #         suspicious_logger.warning(f"Failed Cloudflare verification - IP: {ip}")
        #         log_to_database("WARNING", 400, 'Unauthenticated', ip, "/login", "Failed Cloudflare verification")
        #         return render_template("login.html", error="Security check failed. Please try again.", hide_header=True)
        # except Exception as e:
        #     # Handle request exceptions
        #     suspicious_logger.error(f"Cloudflare verification error: {str(e)} - IP: {ip}")
        #     log_to_database("ERROR", 500, 'Unauthenticated', ip, "/login", f"Cloudflare verification error: {str(e)}")
        #     return render_template("login.html", error="An error occurred during verification. Please try again.", hide_header=True)

        # Clean old attempts
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < BLOCK_WINDOW]

        # Append the current attempt *before* checking threshold
        login_attempts[ip].append(now)

        # Block if too many attempts
        if len(login_attempts[ip]) >= BLOCK_THRESHOLD:
            session_utils.suspicious_logger.warning(f"Blocked login - too many attempts - IP: {ip}")
            log_to_database(mysql, "WARNING", 429, 'Unauthenticated', ip, "/login", "Blocked login - too many attempts")
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
                if not user[6]:  
                    session['temp_new_user_email'] = email
                    return redirect(url_for('setup_2fa'))
                else:
                    return redirect(url_for('verify_2fa'))
            else:
                session_utils.suspicious_logger.warning(f"Failed login (wrong password) - email: {email}, IP: {request.remote_addr}")
                log_to_database(mysql, "WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                                f"Failed login (wrong password) - email: {email}")
        else:
            session_utils.suspicious_logger.warning(f"Failed login (no such user) - email: {email}, IP: {request.remote_addr}")
            log_to_database(mysql, "WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
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
    if is_logged_in(mysql):
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

        # password hashing
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
        log_to_database(mysql, "ERROR", 404, 'Unauthenticated', request.remote_addr, "/setup-2fa", f"User not found for email: {email}")
        abort(404)

    user_id, user_name, role, totp_secret = result

    # Generate a new TOTP secret if not already assigned
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        # Save it to database immediately
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET totp_secret = %s WHERE id = %s", (totp_secret, user_id))
        mysql.connection.commit()
        cur.close()
        session['pending_totp_secret'] = totp_secret
    else:
        session['pending_totp_secret'] = totp_secret

    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(session.get('pending_totp_secret'))

        if totp.verify(otp):
            try:
                cur = mysql.connection.cursor()
                new_token = os.urandom(32).hex()
                cur.execute("UPDATE users SET session_token = %s, totp_secret = %s WHERE id = %s",
                            (new_token, session['pending_totp_secret'], user_id))
                mysql.connection.commit()
                cur.close()

                # Finalize login session
                session['user_id'] = user_id
                session['user_name'] = user_name
                session['role'] = role
                session['last_active'] = time.time()
                session['session_token'] = new_token
                session['fingerprint'] = generate_fingerprint(request)

                # Cleanup
                session.pop('temp_new_user_email', None)
                session.pop('pending_totp_secret', None)

                log_to_database(mysql, "INFO", 200, user_id, request.remote_addr, "/setup-2fa", "2FA setup completed successfully")
                return redirect(url_for('home'))

            except Exception as e:
                log_to_database(mysql, "ERROR", 500, user_id, request.remote_addr, "/setup-2fa", f"Failed to save TOTP: {str(e)}")
                return render_template("setup_2fa.html", qr_code_b64=generate_qr(session['pending_totp_secret'], email),
                                       error="Failed to save 2FA. Please try again.")
        else:
            log_to_database(mysql, "WARNING", 401, user_id, request.remote_addr, "/setup-2fa", "Invalid OTP during 2FA setup")
            return render_template("setup_2fa.html", qr_code_b64=generate_qr(session['pending_totp_secret'], email),
                                   error="Invalid OTP")

    return render_template("setup_2fa.html", qr_code_b64=generate_qr(session['pending_totp_secret'], email))


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


class ForgetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')


@app.route("/forget-password", methods=["GET", "POST"])
def forget_password():
    form = ForgetPasswordForm()
    if form.validate_on_submit():  
        email = form.email.data.strip().lower()
        
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT role FROM users WHERE email = %s",
            (email,)
        )
        row = cur.fetchone()
        cur.close()

        if not row or row[0].lower() == "admin":
            return render_template("forget_password_sent.html")

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


app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)
register_error_handlers(app, mysql)
register_forum_routes(app, mysql)
register_announcement_routes(app, mysql)
register_course_routes(app, mysql)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=443)
