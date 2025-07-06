from flask import Blueprint, render_template, redirect, url_for, session, request, abort
from session_utils import is_session_expired, get_current_user_id, is_educator
import bleach

course_bp = Blueprint("course", __name__)


def register_course_routes(app, mysql):

    @course_bp.route("/courses/<int:course_id>")
    def view_course(course_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        elif is_session_expired(mysql):
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

        cur.execute("""
            SELECT title, content, id, posted_at
            FROM announcements
            WHERE course_id = %s
            ORDER BY posted_at DESC
        """, (course_id,))
        announcements = cur.fetchall()

        cur.close()

        return render_template(
            "course_details.html",
            course=course,
            materials=materials,
            announcements=announcements,
            role=role,
            course_id=course_id,
            user_name=user_name
        )

    @course_bp.route("/manage-courses", methods=["GET", "POST"])
    def manage_courses():
        if 'user_id' not in session:
            return redirect(url_for("login"))
        elif is_session_expired(mysql):
            return redirect(url_for("login", error="session_expired"))

        user_id = get_current_user_id()

        if not is_educator(mysql, user_id):
            abort(403)

        cur = mysql.connection.cursor()

        if request.method == "POST":
            name = bleach.clean(request.form["name"], tags=[], strip=True)
            description = bleach.clean(request.form["description"], tags=[], strip=True)

            cur.execute("""
                    INSERT INTO courses (name, description, educator_id)
                    VALUES (%s, %s, %s)
                """, (name, description, user_id))
            mysql.connection.commit()

        cur.execute("SELECT id, name, description FROM courses WHERE educator_id = %s", (user_id,))
        courses = cur.fetchall()
        cur.close()

        return render_template("manage_courses.html", courses=courses)

    @course_bp.route("/courses/<int:course_id>/edit", methods=["GET", "POST"])
    def edit_course(course_id):
        if 'user_id' not in session:
            return redirect(url_for("login"))
        elif is_session_expired(mysql):
            return redirect(url_for("login", error="session_expired"))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

        cur.execute("SELECT name, description FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
        course = cur.fetchone()

        if not course:
            cur.close()
            abort(403)

        if request.method == "POST":
            new_name = bleach.clean(request.form["name"], tags=[], strip=True)
            new_description = bleach.clean(request.form["description"], tags=[], strip=True)

            cur.execute("""
                    UPDATE courses SET name = %s, description = %s
                    WHERE id = %s AND educator_id = %s
                """, (new_name, new_description, course_id, user_id))
            mysql.connection.commit()
            cur.close()

            return redirect(url_for("course.view_course", course_id=course_id))

        cur.close()
        return render_template("edit_course.html", course_id=course_id, name=course[0], description=course[1])

    @course_bp.route("/courses/<int:course_id>/delete", methods=["POST"])
    def delete_course(course_id):
        if 'user_id' not in session:
            return redirect(url_for("login"))
        elif is_session_expired(mysql):
            return redirect(url_for("login", error="session_expired"))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
        if not cur.fetchone():
            cur.close()
            abort(403)

        cur.execute("DELETE FROM courses WHERE id = %s", (course_id,))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for("manage_courses"))

    app.register_blueprint(course_bp)
