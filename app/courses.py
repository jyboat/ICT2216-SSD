from flask import render_template, request, redirect, url_for, session, abort, Blueprint
from werkzeug.utils import secure_filename
import bleach

courses_bp = Blueprint("auth", __name__)

@courses_bp.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    success = request.args.get('success') == '1'
    return render_template("login.html", hide_header=True, success=success)

@courses_bp.route("/home")
def home():
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))

    user_id = session['user_id']
    user_name = session['user_name']
    role = session['role']

    if role == "admin":
        return redirect(url_for("manage_users"))

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
    

@courses_bp.route("/courses/<int:course_id>/announcement/<int:announcement_id>/edit", methods=["GET", "POST"])
def edit_announcement(course_id, announcement_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 

    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Check if this user is the educator for the course
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
        new_title = request.form["title"].strip()
        new_content = request.form["content"].strip()
        new_title = bleach.clean(new_title, tags=[], strip=True)
        new_content = bleach.clean(new_content, tags=['b', 'i', 'u', 'strong', 'em', 'ul', 'ol', 'li', 'p', 'br'], strip=True)

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

@courses_bp.route("/courses/<int:course_id>/upload", methods=["GET", "POST"])
def upload_material(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))  

    user_id = get_current_user_id()
    cur = mysql.connection.cursor()
    
    # Get current user info
    cur.execute("SELECT name, role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close()
        abort(404, description="User not found")

    user_name, role = user

    # Only allow educators to upload
    if role != "educator":
        cur.close()
        abort(403, description="Access denied: only educators can upload materials")

    cur.close()

    if request.method == "POST":
        # Get uploaded file
        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            abort(400, description="No File Selected")

        # Sanitize and extract file metadata

        filename = secure_filename(uploaded_file.filename)
        mime_type = uploaded_file.mimetype

        if not filename.lower().endswith(".pdf") or mime_type != "application/pdf":
            abort(400, description="Only PDF files are allowed")


        title = request.form["title"]
        description = request.form["description"]
        file_data = uploaded_file.read()

        # Verify user permission
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
        allowed = cur.fetchone()

        if not allowed:
            cur.close()
            redirect(url_for('home'))

        # Insert into database
        cur.execute("""
            INSERT INTO materials (course_id, uploader_id, title, description, file, mime_type, file_name)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (course_id, user_id, title, description, file_data, mime_type, filename))

        mysql.connection.commit()
        cur.close()

        return redirect(url_for("view_course", course_id=course_id))

    return render_template("upload.html", course_id=course_id, user_name=user_name)

@courses_bp.route("/courses/<int:course_id>")
def view_course(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    user_name = cur.fetchone()[0]

    cur.execute("SELECT name, description FROM courses WHERE id = %s", (course_id,))
    course = cur.fetchone()

    cur.execute("""
    SELECT id, title, description, uploaded_at
    FROM materials
    WHERE course_id = %s
    ORDER BY uploaded_at DESC
    """, (course_id,))
    materials = cur.fetchall()

    cur.execute("SELECT title, content, id, posted_at FROM announcements WHERE course_id = %s ORDER BY posted_at DESC", (course_id,))
    announcements = cur.fetchall()

    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cur.fetchone()[0]

    if role == "student":
        cur.execute("SELECT 1 FROM enrollments WHERE user_id = %s AND course_id = %s", (user_id, course_id))
    elif role == "educator":
        cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
    else:
        allowed = None

    allowed = cur.fetchone()
    if not allowed:
        cur.close()
        redirect(url_for('home'))

    cur.close()
    return render_template("course_details.html", course=course, materials=materials,
                           announcements=announcements, role=role, course_id=course_id, user_name=user_name)


@courses_bp.route("/courses/<int:course_id>/announcement/<int:announcement_id>/delete", methods=["POST"])
def delete_announcement(course_id, announcement_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Verify that this educator owns the course
    cur.execute("""
        SELECT 1
        FROM announcements a
        JOIN courses c ON a.course_id = c.id
        WHERE a.id = %s AND c.id = %s AND c.educator_id = %s
    """, (announcement_id, course_id, user_id))

    if not cur.fetchone():
        cur.close()
        redirect(url_for('home'))

    cur.execute("DELETE FROM announcements WHERE id = %s", (announcement_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for("view_course", course_id=course_id))


@courses_bp.route("/courses/<int:course_id>/forum", methods=["GET", "POST"])
def course_forum(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
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
    else:
        cur.close()
        redirect(url_for('home'))

    if not cur.fetchone():
        cur.close()
        redirect(url_for('home'))

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