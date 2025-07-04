from flask import render_template, request, redirect, url_for, session, make_response, abort, Blueprint
from werkzeug.utils import secure_filename

materials_bp = Blueprint("materials", __name__)

@materials_bp.route("/materials/<int:material_id>/download")
def download_material(material_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired'))
    
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
        redirect(url_for('home'))

    if not cur.fetchone():
        cur.close()
        redirect(url_for('home'))

    # Fetch file and metadata
    cur.execute("SELECT file_name, mime_type, file FROM materials WHERE id = %s", (material_id,))
    result = cur.fetchone()
    cur.close()

    if not result:
        abort(404, description="Materials not found")

    file_name, mime_type, file_data = result

    # Serve file with proper headers
    response = make_response(file_data)
    response.headers.set("Content-Type", mime_type or "application/octet-stream")
    response.headers.set("Content-Disposition", f"attachment; filename={file_name}")
    return response

@materials_bp.route("/materials/<int:material_id>/edit", methods=["GET", "POST"])
def edit_material(material_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Fetch existing data
    cur.execute("""
        SELECT course_id, title, description, file_name, mime_type
        FROM materials
        WHERE id = %s AND uploader_id = %s
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
                WHERE id = %s AND uploader_id = %s
            """, (new_title, new_description, new_file_data, new_filename, new_mime, material_id, user_id))
        else:
            # No new file uploaded — only update text fields
            cur.execute("""
                UPDATE materials
                SET title = %s, description = %s
                WHERE id = %s AND uploader_id = %s
            """, (new_title, new_description, material_id, user_id))

        mysql.connection.commit()
        cur.close()

        return redirect(url_for("view_course", course_id=course_id))

    cur.close()
    return render_template(
        "edit_material.html",
        title=current_title,
        description=current_desc,
        material_id=material_id,
        course_id=course_id,
        file_name=current_filename
    )


@materials_bp.route("/materials/<int:material_id>/delete", methods=["POST"])
def delete_material(material_id):
    if 'user_id' not in session:
        return redirect(url_for('login')) 
    elif is_session_expired():
        return redirect(url_for('login', error='session_expired')) 
    
    user_id = get_current_user_id()
    cur = mysql.connection.cursor()

    # Confirm ownership and get course_id for redirect
    cur.execute("SELECT course_id FROM materials WHERE id = %s AND uploader_id = %s", (material_id, user_id))
    result = cur.fetchone()

    if not result:
        cur.close()
        abort(403, description="Access denied or Materials not found")

    course_id = result[0]

    cur.execute("DELETE FROM materials WHERE id = %s", (material_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for("view_course", course_id=course_id))