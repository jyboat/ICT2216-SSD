from flask import Blueprint, render_template, request, redirect, url_for, abort, session
import bleach
from urllib.parse import urlparse

from modules.session_utils import is_session_expired, get_current_user_id, is_educator

forum_bp = Blueprint('forum', __name__)


def register_forum_routes(app, mysql):
    @forum_bp.route("/courses/<int:course_id>/forum", methods=["GET", "POST"])
    def course_forum(course_id):
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
        else:
            cur.close()
            return redirect(url_for('home'))

        if not cur.fetchone():
            cur.close()
            return redirect(url_for('home'))

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

    @forum_bp.route("/courses/<int:course_id>/forum/posts/<int:post_id>/edit", methods=["GET", "POST"])
    def edit_post(post_id, course_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

        cur.execute("SELECT author_id, content, thread_id FROM forum_posts WHERE id = %s", (post_id,))
        result = cur.fetchone()
        if not result:
            cur.close()
            abort(404, description="Access denied")

        author_id, content, thread_id = result

        cur.execute("""
            SELECT course_id
              FROM forum_threads
             WHERE id = %s
        """, (thread_id,))
        tc = cur.fetchone()
        if not tc or tc[0] != course_id:
            cur.close()
            abort(404, "Access denied")
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        role_row = cur.fetchone()
        cur.close()
        if not role_row:
            abort(403, "Access denied")
        role = role_row[0]
        if author_id != user_id or role == 'educator':
            cur.execute("""
                SELECT 1
                  FROM courses
                 WHERE id = %s
                   AND educator_id = %s
            """, (course_id, user_id))
            if not cur.fetchone():
                cur.close()
                return redirect(url_for('home'))

        if request.method == "POST":
            new_content = request.form["content"]
            safe_content = bleach.clean(new_content, tags=[], attributes={}, strip=True)

            cur.execute("UPDATE forum_posts SET content = %s WHERE id = %s", (safe_content, post_id))
            mysql.connection.commit()

            cur.execute("SELECT course_id FROM forum_threads WHERE id = %s", (thread_id,))
            course_result = cur.fetchone()
            cur.close()

            if not course_result:
                abort(404, description="Access denied")

            course_id = course_result[0]
            return redirect(url_for("forum.course_forum", course_id=course_id))

        cur.close()
        return render_template("edit_post.html", content=content, post_id=post_id)

    @forum_bp.route("/forum/posts/<int:post_id>/delete", methods=["POST"])
    def delete_post(post_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()
        
        cur.execute("""
            SELECT t.course_id, c.educator_id
            FROM forum_posts   AS p
            JOIN forum_threads AS t ON p.thread_id = t.id
            JOIN courses       AS c ON t.course_id = c.id
            WHERE p.id = %s
            """, (post_id,))
        results = cur.fetchone()
        if not results:
            cur.close()
            abort(404, description="Access denied")
        course_id, educator_id = results

  
        if user_id != educator_id:
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

        return redirect(url_for("forum.course_forum", course_id=course_id))

    app.register_blueprint(forum_bp)
