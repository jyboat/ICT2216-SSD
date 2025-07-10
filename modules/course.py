from flask import Blueprint, render_template, redirect, url_for, session, request, abort, flash
from modules.session_utils import is_session_expired, get_current_user_id
import bleach

course_bp = Blueprint("course", __name__)


def register_course_routes(app, mysql):
    @course_bp.route("/courses/<int:course_id>")
    def view_course(course_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

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

        allowed = cur.fetchone()
        if not allowed:
            cur.close()
            return redirect(url_for('home'))

        cur.execute("SELECT name, description FROM courses WHERE id = %s", (course_id,))
        course = cur.fetchone()

        cur.execute("""
        SELECT id, title, description, uploaded_at
        FROM materials
        WHERE course_id = %s
        ORDER BY uploaded_at DESC
        """, (course_id,))
        materials = cur.fetchall()

        cur.execute(
            "SELECT title, content, id, posted_at FROM announcements WHERE course_id = %s ORDER BY posted_at DESC",
            (course_id,))
        announcements = cur.fetchall()

        cur.close()
        return render_template("course_details.html", course=course, materials=materials,
                               announcements=announcements, role=role, course_id=course_id, user_name=user_name)

    @course_bp.route("/admin/courses", methods=["GET", "POST"])
    def manage_courses():

        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))
        if session.get('role') != 'admin':
            return redirect(url_for('home'))

        admin_id = get_current_user_id()
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name FROM users WHERE role = 'educator' ORDER BY name")
        educators = cur.fetchall()

        if request.method == "POST" and request.form.get("course_code"):
            code = request.form.get("course_code", "").strip()
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            raw_edu = request.form.get("educator_id", "")
            if not code or len(code) > 20:
                abort(400, "Course code is required (max 20 characters)")
            if not name or len(name) > 255:
                abort(400, "Course name is required (max 255 characters)")
            if len(description) > 2000:
                abort(400, "Description too long (max 2000 characters)")
            try:
                educator_id = int(raw_edu)
            except ValueError:
                abort(400, "Access denied")
            if educator_id not in {e[0] for e in educators}:
                abort(400, "Access denied")
            cur.execute("SELECT 1 FROM courses WHERE course_code = %s", (code,))
            if cur.fetchone():
                flash(f"Course code “{code}” already exists.", "warning")
            else:
                # 5) Final sanitize & insert
                safe_code = bleach.clean(code, tags=[], strip=True)
                safe_name = bleach.clean(name, tags=[], strip=True)
                safe_desc = bleach.clean(description, tags=[], strip=True)

                cur.execute("""
                    INSERT INTO courses
                      (course_code, name, description, educator_id)
                    VALUES (%s, %s, %s, %s)
                """, (safe_code, safe_name, safe_desc, educator_id))
                mysql.connection.commit()
                flash(f"Course “{safe_code}” added successfully.", "success")

            cur.close()
            return redirect(url_for("course.manage_courses"))

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
            educators=educators
        )

    @course_bp.route("/admin/courses/<int:course_id>/edit", methods=["GET", "POST"])
    def edit_course(course_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))
        if session.get('role') != 'admin':
            return redirect(url_for('home'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name FROM users WHERE role = 'educator' ORDER BY name")
        educators = cur.fetchall()

        if request.method == "POST":
            code = request.form.get("course_code", "").strip()
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            educator_raw = request.form.get("educator_id", "")
            if not code or len(code) > 20:
                abort(400, "Course code is required (max 20 chars)")
            if not name or len(name) > 255:
                abort(400, "Course name is required (max 255 chars)")
            if len(description) > 2000:
                abort(400, "Description too long (max 2000 chars)")

            try:
                educator_id = int(educator_raw)
            except ValueError:
                abort(400, "Access denied")

            if educator_id not in {e[0] for e in educators}:
                abort(400, "Access denied")
            cur.execute(
                "SELECT 1 FROM courses WHERE course_code = %s AND id != %s",
                (code, course_id)
            )
            if cur.fetchone():
                flash(f"Another course is already using code “{code}”.", "warning")
            else:
                # 5) sanitize & update
                safe_code = bleach.clean(code, tags=[], strip=True)
                safe_name = bleach.clean(name, tags=[], strip=True)
                safe_desc = bleach.clean(description, tags=[], strip=True)

            if code and name and len(code) <= 10 and len(name) <= 100:
                cur.execute("""
                    UPDATE courses
                       SET course_code = %s,
                           name = %s,
                           description = %s,
                           educator_id   = %s
                     WHERE id = %s
                """, (safe_code, safe_name, safe_desc, educator_id, course_id))
                mysql.connection.commit()
                cur.close()
                return redirect(url_for('course.manage_courses'))

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
            course_desc=course_desc,
            educators=educators,
            current_educator_id=current_educator_id
        )

    @course_bp.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
    def delete_course(course_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))
        if session.get('role') != 'admin':
            return redirect(url_for('home'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT 1 FROM courses WHERE id = %s", (course_id,))
        if not cur.fetchone():
            cur.close()
            abort(404, "Course not found")

        cur.execute("DELETE FROM courses WHERE id=%s", (course_id,))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('course.manage_courses'))

    app.register_blueprint(course_bp)
