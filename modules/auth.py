from flask import Blueprint, render_template, request, session, redirect, url_for, abort, flash
import requests
import re
import time
import pyotp
import base64
import io
import os
import qrcode
from itsdangerous import SignatureExpired, BadSignature
from modules.session_utils import is_logged_in, generate_fingerprint, suspicious_logger
from modules.email_utils import send_reset_email_via_sendgrid
from modules.log import *
from collections import defaultdict
import hashlib
from flask import current_app
from dotenv import load_dotenv

auth_bp = Blueprint("auth", __name__)

load_dotenv()  # Load environment variables from .env

# key: IP, value: list of timestamps
login_attempts = defaultdict(list)
forget_attempts = defaultdict(list)
BLOCK_THRESHOLD = 5
BLOCK_WINDOW = 600  # seconds
cf_secret_key = os.getenv("CF_SECRET_KEY")

def generate_qr(secret, email):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="MyFlaskApp")
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')


# Regular expressions for email and password validation
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

def validate_email_field(email):
    errors = []
    if not email:
        errors.append("Email is required.")
    elif not EMAIL_REGEX.fullmatch(email):
        errors.append("Invalid email address.")
    return errors

def validate_password_fields(pw, confirm_pw):
    errors = []
    if not pw:
        errors.append("Please enter a password.")
    else:
        if len(pw) < 8:
            errors.append("Password must be at least 8 characters.")
        if not any(c.isupper() for c in pw):
            errors.append("Must include at least one uppercase letter.")
        if not any(c.islower() for c in pw):
            errors.append("Must include at least one lowercase letter.")
        if not any(c.isdigit() for c in pw):
            errors.append("Must include at least one digit.")
        
        specials = '!@#$%^&*(),.?":{}|<>'
        if not any(c in specials for c in pw):
            errors.append("Must include at least one special character.")
    if pw and not confirm_pw:
        errors.append("Please confirm your password.")
    elif pw and confirm_pw and pw != confirm_pw:
        errors.append("Passwords must match.")
    return errors


def register_auth_routes(app, mysql, bcrypt, serializer):
    global login_attempts

    @auth_bp.route('/login', methods=['GET', 'POST'])
    def login():
        #if is_logged_in(mysql):
        #    return redirect(url_for('home'))
        print('LOGIN PAGE REACHED')
        error_param = request.args.get('error')
        error_message = None
        if error_param == 'session_expired':
            error_message = "Your session has expired. Please log in again."

        if request.method == 'POST':
            
            now = time.time()

            # Skip Cloudflare check if running in test mode
        if current_app.config.get("TESTING"):
            pass  # Skip verification for unit tests
        else:
            ip = request.remote_addr
            # Get the Cloudflare Turnstile token
            cf_turnstile_response = request.form.get('cf-turnstile-response')

            # If no token was provided, return an error
            if not cf_turnstile_response:
                suspicious_logger.warning(f"Login attempt without Cloudflare verification - IP: {ip}")
                log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/login", "Login attempt without Cloudflare verification")
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
                    log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/login", "Failed Cloudflare verification")
                    return render_template("login.html", error="Security check failed. Please try again.", hide_header=True)
            except Exception as e:
                # Handle request exceptions
                suspicious_logger.error(f"Cloudflare verification error: {str(e)} - IP: {ip}")
                log_to_database(mysql,"ERROR", 500, 'Unauthenticated', ip, "/login", f"Cloudflare verification error: {str(e)}")
                return render_template("login.html", error="An error occurred during verification. Please try again.", hide_header=True)

            # Clean old attempts
            login_attempts[ip] = [t for t in login_attempts[ip] if now - t < BLOCK_WINDOW]

            # Append the current attempt *before* checking threshold
            login_attempts[ip].append(now)

            # Block if too many attempts
            if len(login_attempts[ip]) >= BLOCK_THRESHOLD:
                suspicious_logger.warning(f"Blocked login - too many attempts - IP: {ip}")
                log_to_database(mysql, "WARNING", 429, 'Unauthenticated', ip, "/login",
                                "Blocked login - too many attempts")
                #Log to splunk
                log_to_splunk({
                    "event": "Blocked login - too many attempts",
                    "ip_address": ip,
                    "timestamp": datetime.now().isoformat(),
                    "status_code": 429,
                    "path": "/login"
                })
                return render_template("login.html", error="Too many failed attempts. Try again later.",
                                       hide_header=True)

            # Otherwise, Continue with login attempt
            email = request.form['email']
            password = request.form['password']

            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

            if user:
                stored_hash = user[3]
                if bcrypt.check_password_hash(stored_hash, password):
                    cur.execute("SELECT session_token FROM users WHERE id = %s", (user[0],))
                    existing_session = cur.fetchone()[0]

                    if existing_session:
                        cur.close()
                        session['pending_login'] = {
                            'email': email,
                            'password': password,
                            'remember_me': request.form.get('remember_me')
                        }
                        
                        print('LOGIN SESSION:', dict(session))
                        return render_template("login_warning.html",
                                                email=email,
                                                password=password,
                                                remember_me=request.form.get('remember_me'))
                    
                    session['temp_user_id'] = user[0]

                    if request.form.get('remember_me') == 'on':
                        session.permanent = True
                    else:
                        session.permanent = False

                    login_attempts[ip] = []
                    if not user[6]:
                        session['temp_new_user_email'] = email
                        return redirect(url_for('auth.setup_2fa'))
                    else:
                        return redirect(url_for('auth.verify_2fa'))
                else:
                    suspicious_logger.warning(
                        f"Failed login (wrong password) - email: {email}, IP: {request.remote_addr}")
                    log_to_database(mysql, "WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                                    f"Failed login (wrong password) - email: {email}")
                    # Log to splunk
                    log_to_splunk({
                        "event": "Failed login (wrong password)",
                        "email": email,
                        "ip_address": request.remote_addr,
                        "timestamp": datetime.now().isoformat(),
                        "status_code": 401,
                        "path": "/login"
                    })
            else:
                suspicious_logger.warning(
                    f"Failed login (no such user) - email: {email}, IP: {request.remote_addr}")
                log_to_database(mysql, "WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                                f"Failed login (no such user) - email: {email}")
                # Log to splunk
                log_to_splunk({
                    "event": "Failed login (no such user)",
                    "email": email,
                    "ip_address": request.remote_addr,
                    "timestamp": datetime.now().isoformat(),
                    "status_code": 401,
                    "path": "/login"
                })

        if request.method == 'POST':
            return render_template("login.html", error="Invalid email or password", hide_header=True)
        else:
            return render_template("login.html", hide_header=True, error=error_message)

    @auth_bp.route("/logout")
    def logout():
        user_id = session.get('user_id')
        if user_id:
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET session_token = NULL WHERE id = %s", (user_id,))
            mysql.connection.commit()
            cur.close()
        session.clear()
        return redirect(url_for('index'))

    @auth_bp.route('/register', methods=['GET', 'POST'])
    def register():
        
        if is_logged_in(mysql):
            return redirect(url_for('home'))
        if request.method == 'POST':
            
            # Skip Cloudflare check if running in test mode
            if current_app.config.get("TESTING"):
                pass  # Skip verification for unit tests
            else:
                ip = request.remote_addr
             # Get the Cloudflare Turnstile token
                cf_turnstile_response = request.form.get('cf-turnstile-response')

                # If no token was provided, return an error
                if not cf_turnstile_response:
                    suspicious_logger.warning(f"register attempt without Cloudflare verification - IP: {ip}")
                    log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/register", "Login attempt without Cloudflare verification")
                    return render_template("register.html", error="Please complete the security check", hide_header=True)

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
                        log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/register", "Failed Cloudflare verification")
                        return render_template("register.html", error="Security check failed. Please try again.", hide_header=True)
                except Exception as e:
                    # Handle request exceptions
                    suspicious_logger.error(f"Cloudflare verification error: {str(e)} - IP: {ip}")
                    log_to_database(mysql,"ERROR", 500, 'Unauthenticated', ip, "/register", f"Cloudflare verification error: {str(e)}")
                    return render_template("register.html", error="An error occurred during verification. Please try again.", hide_header=True)
            

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
                return render_template("register.html", error="An account with that email already exists",
                                       hide_header=True)

            if len(password) < 8 or \
                    not re.search(r'[A-Z]', password) or \
                    not re.search(r'[a-z]', password) or \
                    not re.search(r'[0-9]', password) or \
                    not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                return render_template("register.html",
                                       error="Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.",
                                       hide_header=True)

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
            return redirect(url_for('auth.setup_2fa'))

        return render_template("register.html", hide_header=True)

    @auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
    def verify_2fa():
        if 'temp_user_id' not in session:
            return redirect(url_for('auth.login'))

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

    @auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
    def setup_2fa():
        email = session.get('temp_new_user_email')
        if not email:
            return redirect(url_for('auth.login'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name, role, totp_secret FROM users WHERE email = %s", (email,))
        result = cur.fetchone()
        cur.close()

        if not result:
            log_to_database(mysql, "ERROR", 404, 'Unauthenticated', request.remote_addr, "/setup-2fa",
                            f"User not found for email: {email}")
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

                    log_to_database(mysql, "INFO", 200, user_id, request.remote_addr, "/setup-2fa",
                                    "2FA setup completed successfully")
                    return redirect(url_for('home'))

                except Exception as e:
                    log_to_database(mysql, "ERROR", 500, user_id, request.remote_addr, "/setup-2fa",
                                    f"Failed to save TOTP: {str(e)}")
                    return render_template("setup_2fa.html",
                                           qr_code_b64=generate_qr(session['pending_totp_secret'], email),
                                           error="Failed to save 2FA. Please try again.")
            else:
                log_to_database(mysql, "WARNING", 401, user_id, request.remote_addr, "/setup-2fa",
                                "Invalid OTP during 2FA setup")
                return render_template("setup_2fa.html", qr_code_b64=generate_qr(session['pending_totp_secret'], email),
                                       error="Invalid OTP")

        return render_template("setup_2fa.html", qr_code_b64=generate_qr(session['pending_totp_secret'], email))
    
    # login warning handler
    @auth_bp.route('/handle-login-warning', methods=['POST'])
    def handle_login_warning():
        print('WARNING SESSION:', dict(session))
        
        action = request.form['action']

        if current_app.config.get("TESTING"):
            pass
        else:
            ip = request.remote_addr
            # Get the Cloudflare Turnstile token
            cf_turnstile_response = request.form.get('cf-turnstile-response')

            # If no token was provided, return an error
            if not cf_turnstile_response:
                suspicious_logger.warning(f"Login attempt without Cloudflare verification - IP: {ip}")
                log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/login_warning", "Login attempt without Cloudflare verification")
                return render_template("login_warning.html", error="Please complete the security check", hide_header=True)

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
                    log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/login_warning", "Failed Cloudflare verification")
                    return render_template("login_warning.html", error="Security check failed. Please try again.", hide_header=True)
            except Exception as e:
                # Handle request exceptions
                suspicious_logger.error(f"Cloudflare verification error: {str(e)} - IP: {ip}")
                log_to_database(mysql,"ERROR", 500, 'Unauthenticated', ip, "/login_warning", f"Cloudflare verification error: {str(e)}")
                return render_template("login_warning.html", error="An error occurred during verification. Please try again.", hide_header=True)

        pending = session.get('pending_login')

        if pending and action == "continue":
            # Proceed with login and invalidate other session
            email = pending['email']
            password = pending['password']
            remember_me = pending['remember_me']
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

            if user and bcrypt.check_password_hash(user[3], password):
                # Set temporary session data for 2FA verification
                session['temp_user_id'] = user[0]

                if remember_me == 'on':
                    session.permanent = True
                else:
                    session.permanent = False

                # Nullify the existing session token
                cur.execute("UPDATE users SET session_token = NULL WHERE id = %s", (user[0],))
                mysql.connection.commit()
                cur.close()

                # Clear the pending login session
                session.pop('pending_login', None)
                # Check if user needs to set up 2FA
                # if not user[6]:  # Assuming index 6 is totp_secret
                # session['temp_new_user_email'] = email
                # return redirect(url_for('setup_2fa'))
                # else:
                return redirect(url_for('auth.verify_2fa'))

        # If action is 'cancel' or any other value, just redirect to home
        return redirect(url_for('auth.login'))

    @auth_bp.route("/forget-password", methods=["GET", "POST"])
    def forget_password():
        errors = []
        email = ""

        if request.method == "POST":

            #For rate limiting 
            ip  = request.remote_addr
            now = time.time()

            forget_attempts[ip] = [t for t in forget_attempts[ip] if now - t < BLOCK_WINDOW]

            forget_attempts[ip].append(now)

            if len(forget_attempts[ip]) > BLOCK_THRESHOLD:
                flash("Too many password reset requests.","warning")
                suspicious_logger.warning(f"Blocked login - too many attempts - IP: {ip}")
                log_to_database(mysql, "WARNING", 429, 'Unauthenticated', ip, "/login",
                                "Blocked forgot password - too many attempts")
            
                return render_template("forget_password.html",errors=errors,email=email)

        
            form = request.form
            email = (form.get("email") or "").strip().lower()
            cf_turnstile_response = request.form.get('cf-turnstile-response')
        if current_app.config.get("TESTING"):
            pass  

        # If no token was provided, return an error
        if not cf_turnstile_response:
            suspicious_logger.warning(f"reset password attempt without Cloudflare verification - IP: {ip}")
            log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/reset_password", "Login attempt without Cloudflare verification")
            return render_template("reset_password.html", error="Please complete the security check", hide_header=True)

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
                log_to_database(mysql,"WARNING", 400, 'Unauthenticated', ip, "/forget_password", "Failed Cloudflare verification")
                return render_template("forget_password.html", error="Security check failed. Please try again.", hide_header=True)
        except Exception as e:
            # Handle request exceptions
            suspicious_logger.error(f"Cloudflare verification error: {str(e)} - IP: {ip}")
            log_to_database(mysql,"ERROR", 500, 'Unauthenticated', ip, "/forget_password", f"Cloudflare verification error: {str(e)}")
            return render_template("forget_password.html", error="An error occurred during verification. Please try again.", hide_header=True)
        
        errors = validate_email_field(email)

        if not errors:
            with mysql.connection.cursor() as cur:
                cur.execute("SELECT role FROM users WHERE email = %s",(email,))
                row = cur.fetchone()
        
                if not row or row[0].lower() == "admin":
                    return render_template("forget_password_sent.html")

                token = serializer.dumps(email, salt="password-reset-salt")
                token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
                cur.execute(
                    "UPDATE users SET password_token = %s WHERE email = %s",
                (token_hash, email)
                )
            mysql.connection.commit()
        
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            send_reset_email_via_sendgrid(email, reset_url)

            return render_template("forget_password_sent.html", hide_header=True)

        return render_template("forget_password.html",errors=errors,email=email, hide_header=True)

    @auth_bp.route("/reset/<token>", methods=["GET", "POST"])
    def reset_password(token):
        error = request.args.get('error')  
        try:
            email = serializer.loads(
                token,
                salt="password-reset-salt",
                max_age=300
            )
        except SignatureExpired:
            flash("This reset link has expired.", "danger")
            return redirect(url_for("auth.forget_password"))
        except BadSignature:
            flash("This reset link is invalid.", "danger")
            return redirect(url_for("auth.forget_password"))
        
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with mysql.connection.cursor() as cur:
            cur.execute(
                "SELECT id FROM users WHERE email = %s AND password_token = %s",
                (email, token_hash)
            )
            row = cur.fetchone()

        if not row:
            flash("Invalid or expired token", "danger")
            return redirect(url_for("auth.forget_password"))

        user_id = row[0]

        errors = []
        if request.method == "POST":
            form = request.form
            pw = form.get("password", "")
            confirm_pw = form.get("confirm", "")
            errors = validate_password_fields(pw, confirm_pw)
        
            if not errors:
                new_pw_hash = bcrypt.generate_password_hash(pw).decode("utf-8")
                with mysql.connection.cursor() as cur:
                    cur.execute(
                    """
                    UPDATE users
                    SET password_hash = %s,
                    password_token = NULL
                    WHERE id = %s
                    """,
                    (new_pw_hash, user_id)
                    )
                mysql.connection.commit()

                session.clear()
                flash("Your password has been reset. Please log in with your new password.", "success")
                return redirect(url_for("auth.login",hide_header=True))

        return render_template("reset_password.html",hide_header=True)

    app.register_blueprint(auth_bp)
