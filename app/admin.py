from flask import render_template, request, redirect, url_for, session, abort, Blueprint
import re
admin_bp = Blueprint("auth", __name__)

@admin_bp.route("/admin/users")
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

@admin_bp.route("/admin/users/add", methods=["GET", "POST"])
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
    return render_template("user_form.html", action="Add", user_name=user_name,course_codes=course_codes, assigned_codes=[])

@admin_bp.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
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
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip().lower()
        new_role = request.form.get("role", "")
        selected_codes = request.form.getlist("course_codes")
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        old_role = cur.fetchone()[0]
        #validation
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

    return render_template("user_form.html", action="Edit", user=user, user_id=user_id, user_name=user_name,
        course_codes=course_codes,
        assigned_codes=assigned_codes)

@admin_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
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


@admin_bp.route("/admin/courses", methods=["GET", "POST"])
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
        if not code or not name:
            flash("Course code and name are required.", "warning")
        else:
            # 1) check for an existing code
            cur.execute("SELECT 1 FROM courses WHERE course_code = %s", (code,))
            if cur.fetchone():
                flash(f"Course code “{code}” already exists.", "warning")
            else:
                # 2) safe to insert
                cur.execute(
                    """
                    INSERT INTO courses
                      (course_code, name, description, educator_id)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (code, name, description, educator_id)
                )
                mysql.connection.commit()
                flash(f"Course “{code}” added successfully.", "success")

        # redirect so a page‐reload won’t re‐POST
        cur.close()
        return redirect(url_for("manage_courses"))


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

@admin_bp.route("/admin/courses/<int:course_id>/edit", methods=["GET", "POST"])
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

@admin_bp.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
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