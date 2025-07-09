from flask import Blueprint, request, render_template, redirect, url_for, session, abort
import re
from modules.session_utils import is_session_expired, get_current_user_id

user_bp = Blueprint("user", __name__)


def register_user_routes(app, mysql, bcrypt):
    @user_bp.route("/admin/users")
    def manage_users():
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

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

    @user_bp.route("/admin/users/add", methods=["GET", "POST"])
    def add_user():
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

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

            # Check if email already exists
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                error = "Email already exists. Please choose a different email."
                cur.close()
                return render_template("user_form.html", action="Add", user_name=user_name,
                                    course_codes=course_codes, assigned_codes=[], error=error)
            
            if len(password) < 8 or \
                not re.search(r'[A-Z]', password) or \
                not re.search(r'[a-z]', password) or \
                not re.search(r'[0-9]', password) or \
                not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                error = "Password must be at least 8 characters and include uppercase, lowercase, digit, and special character."
                cur.close()
                return render_template("user_form.html", action="Add", user_name=user_name,
                                    course_codes=course_codes, assigned_codes=[], error=error)

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

            return redirect(url_for("user.manage_users"))

        cur.close()
        return render_template("user_form.html", action="Add", user_name=user_name, course_codes=course_codes,
                               assigned_codes=[])

    @user_bp.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
    def edit_user(user_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

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

            return redirect(url_for("user.manage_users"))

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
                               course_codes=course_codes, assigned_codes=assigned_codes)

    @user_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    def delete_user(user_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

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
        return redirect(url_for("user.manage_users"))

    app.register_blueprint(user_bp)
