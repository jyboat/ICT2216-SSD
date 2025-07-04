from flask import render_template, request, redirect, url_for, session, abort, Blueprint
from urllib.parse import urlparse
import bleach

forum_bp = Blueprint("auth", __name__)

@forum_bp.route("/forum/posts/<int:post_id>/edit", methods=["GET", "POST"])
def edit_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    cur.execute("SELECT author_id, content, thread_id FROM forum_posts WHERE id = %s", (post_id,))
    result = cur.fetchone()
    if not result:
        cur.close()
        abort(404, description="Post not found")

    author_id, content, thread_id = result

    if author_id != user_id and not is_educator(user_id):
        cur.close()
        redirect(url_for('home'))

    if request.method == "POST":
        new_content = request.form["content"]
        safe_content = bleach.clean(new_content, tags=[], attributes={}, strip=True)

        cur.execute("UPDATE forum_posts SET content = %s WHERE id = %s", (safe_content, post_id))
        mysql.connection.commit()

        cur.execute("SELECT course_id FROM forum_threads WHERE id = %s", (thread_id,))
        course_result = cur.fetchone()
        cur.close()

        if not course_result:
            abort(404, description="Course not found")

        course_id = course_result[0]
        return redirect(url_for("course_forum", course_id=course_id))

    cur.close()
    return render_template("edit_post.html", content=content, post_id=post_id)

@forum_bp.route("/forum/posts/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT author_id FROM forum_posts WHERE id = %s", (post_id,))
    result = cur.fetchone()
    if not result:
        cur.close()
        abort(404, description="Post not found")

    author_id = result[0]
    if user_id != author_id and not is_educator(user_id):
        cur.close()
        redirect(url_for('home'))

    cur.execute("DELETE FROM forum_posts WHERE id = %s", (post_id,))
    mysql.connection.commit()
    cur.close()

    # Secure redirect: only allow known paths
    referrer = request.referrer or ""
    safe_paths = ["/forum", "/home"]
    parsed = urlparse(referrer.replace('\\', ''))

    if parsed.path in safe_paths and not parsed.netloc and not parsed.scheme:
        return redirect(parsed.path)

    return redirect(url_for("course_forum", course_id=course_id))