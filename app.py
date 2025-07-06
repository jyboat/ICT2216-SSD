from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
import os
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from modules.log import log_to_database
from modules.session_utils import is_session_expired, generate_fingerprint, suspicious_logger
from modules.error import register_error_handlers
from modules.forum import register_forum_routes
from modules.announcement import register_announcement_routes
from modules.course import register_course_routes
from modules.materials import register_material_routes
from modules.user import register_user_routes
from modules.auth import register_auth_routes

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

app.config['SESSION_TYPE'] = 'redis' 
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1) 
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Controls cross-site requests


@app.before_request
def security_check():
    """Check for session hijacking on every request"""
    # Skip for non-authenticated routes
    if request.endpoint in ['auth.login', 'auth.register', 'static', 'auth.verify_2fa', 'auth.setup_2fa', 'index', 'auth.logout', 'auth.forget_password', 'auth.reset_password']:
        return
    
    # Check if user is logged in
    if 'user_id' not in session or 'session_token' not in session:
        return redirect(url_for('auth.login'))
    
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
            return redirect(url_for('auth.login', error='security_violation'))
    
    # Also check for session expiration
    if is_session_expired(mysql):
        return redirect(url_for('auth.login', error='session_expired'))


@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    success = request.args.get('success') == '1'
    return render_template("login.html", hide_header=True, success=success)


@app.route("/home")
def home():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    elif is_session_expired(mysql):
        return redirect(url_for('auth.login', error='session_expired'))

    user_id = session['user_id']
    user_name = session['user_name']
    role = session['role']

    if role == "admin":
        return redirect(url_for("user.manage_users"))

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


app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)
register_error_handlers(app, mysql)
register_forum_routes(app, mysql)
register_announcement_routes(app, mysql)
register_course_routes(app, mysql)
register_material_routes(app, mysql)
register_user_routes(app, mysql, bcrypt)
register_auth_routes(app, mysql, bcrypt, serializer)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=443)
