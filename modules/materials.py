from flask import Blueprint, request, session, redirect, url_for, render_template, abort, make_response
from werkzeug.utils import secure_filename
from modules.session_utils import is_session_expired, get_current_user_id

material_bp = Blueprint("material", __name__)


def register_material_routes(app, mysql):
    @material_bp.route("/materials/<int:material_id>/download")
    def download_material(material_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        role = cur.fetchone()[0]

        if role == "student":
            cur.execute("""
                SELECT 1 FROM enrollments e
                JOIN materials m ON e.course_id = m.course_id
                WHERE e.user_id = %s AND m.id = %s
            """, (user_id, material_id))
        elif role == "educator":
            cur.execute("""
                SELECT 1 FROM materials m
                JOIN courses c ON m.course_id = c.id
                WHERE m.id = %s AND c.educator_id = %s
            """, (material_id, user_id))
        else:
            cur.close()
            return redirect(url_for('home'))

        if not cur.fetchone():
            cur.close()
            return redirect(url_for('home'))

        # Fetch file and metadata
        cur.execute("SELECT file_name, mime_type, file FROM materials WHERE id = %s", (material_id,))
        result = cur.fetchone()
        cur.close()

        if not result:
            abort(404, description="Access denied")

        file_name, mime_type, file_data = result

        # Serve file with proper headers
        response = make_response(file_data)
        response.headers.set("Content-Type", mime_type or "application/octet-stream")
        response.headers.set("Content-Disposition", f"attachment; filename={file_name}")
        return response

    @material_bp.route("/materials/<int:material_id>/edit", methods=["GET", "POST"])
    def edit_material(material_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

        # Fetch existing data
        cur.execute("""
        SELECT m.course_id,
               m.title,
               m.description,
               m.file_name,
               m.mime_type
            FROM materials AS m
            JOIN courses   AS c ON m.course_id = c.id
        WHERE m.id = %s
            AND c.educator_id = %s
        """, (material_id, user_id))
        material = cur.fetchone()

        if not material:
            cur.close()
            abort(403, description="Access denied or Materials not found")

        course_id, current_title, current_desc, current_filename, current_mime = material

        if request.method == "POST":
            new_title = request.form["title"]
            new_description = request.form["description"]
            uploaded_file = request.files.get("file")
            
            if uploaded_file and uploaded_file.filename:
                # File was uploaded, update it
                new_filename = secure_filename(uploaded_file.filename)
                new_mime = uploaded_file.mimetype
                new_file_data = uploaded_file.read()

                cur.execute("""
                    UPDATE materials
                    SET title = %s, description = %s, file = %s, file_name = %s, mime_type = %s
                    WHERE id = %s 
                """, (new_title, new_description, new_file_data, new_filename, new_mime, material_id))
            else:
                # No new file uploaded — only update text fields
                cur.execute("""
                    UPDATE materials
                    SET title = %s, description = %s
                    WHERE id = %s 
                """, (new_title, new_description, material_id))

            mysql.connection.commit()
            cur.close()

            return redirect(url_for("course.view_course", course_id=course_id))

        cur.close()
        return render_template(
            "edit_material.html",
            title=current_title,
            description=current_desc,
            material_id=material_id,
            course_id=course_id,
            file_name=current_filename
        )

    @material_bp.route("/materials/<int:material_id>/delete", methods=["POST"])
    def delete_material(material_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

        # Confirm ownership and get course_id for redirect
        cur.execute("""
            SELECT m.course_id
            FROM materials AS m
            JOIN courses   AS c ON m.course_id = c.id
            WHERE m.id = %s
            AND c.educator_id = %s
            """, (material_id, user_id))
        result = cur.fetchone()

        if not result:
            cur.close()
            abort(403, description="Access denied or Materials not found")

        course_id = result[0]

        cur.execute("DELETE FROM materials WHERE id = %s", (material_id,))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for("course.view_course", course_id=course_id))

    @material_bp.route("/courses/<int:course_id>/upload", methods=["GET", "POST"])
    def upload_material(course_id):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        elif is_session_expired(mysql):
            return redirect(url_for('auth.login', error='session_expired'))

        user_id = get_current_user_id()
        cur = mysql.connection.cursor()

        # Get current user info
        cur.execute("SELECT name, role FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            cur.close()
            abort(404, description="Access denied")

        user_name, role = user

        # Only allow educators to upload
        if role != "educator":
            cur.close()
            abort(403, description="Access denied")

        cur.close()

        if request.method == "POST":
            # Get uploaded file
            uploaded_file = request.files["file"]
            if not uploaded_file or uploaded_file.filename == "":
                abort(400, description="Access denied")

            # Sanitize and extract file metadata

            filename = secure_filename(uploaded_file.filename)
            mime_type = uploaded_file.mimetype
            file_data = uploaded_file.read()

            # 🔐 Check file signature (magic number)
            if not file_data.startswith(b'%PDF-'):
                abort(400, description="Access denied")

            # limit size
            if len(file_data) > 10 * 1024 * 1024:  # 10 MB limit
                abort(400, description="Access denied")

            if not filename.lower().endswith(".pdf") or mime_type != "application/pdf":
                abort(400, description="Access denied")

            title = request.form["title"]
            description = request.form["description"]
            

            # Verify user permission
            cur = mysql.connection.cursor()
            cur.execute("SELECT 1 FROM courses WHERE id = %s AND educator_id = %s", (course_id, user_id))
            allowed = cur.fetchone()

            if not allowed:
                cur.close()
                return redirect(url_for('home'))

            # Insert into database
            cur.execute("""
                INSERT INTO materials (course_id, uploader_id, title, description, file, mime_type, file_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (course_id, user_id, title, description, file_data, mime_type, filename))

            mysql.connection.commit()
            cur.close()

            return redirect(url_for("course.view_course", course_id=course_id))

        return render_template("upload.html", course_id=course_id, user_name=user_name)

    app.register_blueprint(material_bp)
