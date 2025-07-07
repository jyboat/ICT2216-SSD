from flask import Blueprint, render_template, request, session, redirect, url_for, abort, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
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
from modules.log import log_to_database
from collections import defaultdict

auth_bp = Blueprint("auth", __name__)

# key: IP, value: list of timestamps
login_attempts = defaultdict(list)
BLOCK_THRESHOLD = 5
BLOCK_WINDOW = 600  # seconds


def generate_qr(secret, email):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="MyFlaskApp")
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')


class ForgetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired("Please enter a password"),
            Length(min=8, message="Password must be at least 8 characters"),
            Regexp(r'.*[A-Z].*', message="Must include at least one uppercase letter"),
            Regexp(r'.*[a-z].*', message="Must include at least one lowercase letter"),
            Regexp(r'.*[0-9].*', message="Must include at least one digit"),
            Regexp(r'.*[!@#$%^&*(),.?":{}|<>].*',message="Must include at least one special character")
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


def register_auth_routes(app, mysql, bcrypt, serializer):
    global login_attempts

    @auth_bp.route('/login', methods=['GET', 'POST'])
    def login():
        #if is_logged_in(mysql):
        #    return redirect(url_for('home'))

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
                suspicious_logger.warning(f"Blocked login - too many attempts - IP: {ip}")
                log_to_database(mysql, "WARNING", 429, 'Unauthenticated', ip, "/login",
                                "Blocked login - too many attempts")
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
            else:
                suspicious_logger.warning(
                    f"Failed login (no such user) - email: {email}, IP: {request.remote_addr}")
                log_to_database(mysql, "WARNING", 401, 'Unauthenticated', request.remote_addr, "/login",
                                f"Failed login (no such user) - email: {email}")

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
                                       error="Password must be at least 8 characters and include uppercase, lowercase, digit, and special character.",
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
        action = request.form.get('action')
        email = request.form['email']
        password = request.form['password']
        remember_me = request.form.get('remember_me')

        if action == "continue":
            # Proceed with login and invalidate other session
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
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            send_reset_email_via_sendgrid(email, reset_url)

            return render_template("forget_password_sent.html")

        return render_template("forget_password.html", form=form)

    @auth_bp.route("/reset/<token>", methods=["GET", "POST"])
    def reset_password(token):
        try:
            email = serializer.loads(
                token,
                salt="password-reset-salt",
                max_age=300
            )
        except SignatureExpired:
            flash("That link has expired. Please request a new one.", "warning")
            return redirect(url_for("auth.forget_password"))
        except BadSignature:
            flash("Invalid reset link.", "danger")
            return redirect(url_for("auth.forget_password"))

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
            return redirect(url_for("auth.login"))

        return render_template("reset_password.html", form=form)

    app.register_blueprint(auth_bp)
