from flask import Blueprint, request, session, redirect, url_for, render_template, abort
import bleach
from modules.session_utils import is_session_expired, get_current_user_id

announcement_bp = Blueprint("announcement", __name__)


def register_announcement_routes(app, mysql):
    @announcement_bp.route("/courses/<int:course_id>/announcement", methods=["GET", "POST"])
    def post_announcement(course_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        elif is_session_expired(mysql):
            return redirect(url_for('login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()
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
                return redirect(url_for('home'))

            cur.execute("""
                    INSERT INTO announcements (course_id, author_id, title, content)
                    VALUES (%s, %s, %s, %s)
                """, (course_id, user_id, title, content))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for("view_course", course_id=course_id))

        cur.close()
        return render_template("announcement_form.html", course_id=course_id, role=role, user_name=user_name)

    @announcement_bp.route("/courses/<int:course_id>/announcement/<int:announcement_id>/edit", methods=["GET", "POST"])
    def edit_announcement(course_id, announcement_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        elif is_session_expired(mysql):
            return redirect(url_for('login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

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
            new_title = bleach.clean(request.form["title"].strip(), tags=[], strip=True)
            new_content = bleach.clean(request.form["content"].strip(),
                                       tags=['b', 'i', 'u', 'strong', 'em', 'ul', 'ol', 'li', 'p', 'br'], strip=True)

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

    @announcement_bp.route("/courses/<int:course_id>/announcement/<int:announcement_id>/delete", methods=["POST"])
    def delete_announcement(course_id, announcement_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        elif is_session_expired(mysql):
            return redirect(url_for('login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

        cur.execute("""
                SELECT 1
                FROM announcements a
                JOIN courses c ON a.course_id = c.id
                WHERE a.id = %s AND c.id = %s AND c.educator_id = %s
            """, (announcement_id, course_id, user_id))

        if not cur.fetchone():
            cur.close()
            return redirect(url_for('home'))

        cur.execute("DELETE FROM announcements WHERE id = %s", (announcement_id,))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for("view_course", course_id=course_id))

    app.register_blueprint(announcement_bp)
