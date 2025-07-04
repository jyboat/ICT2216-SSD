from flask import render_template, request, session, Blueprint

errors_bp = Blueprint("auth", __name__)

@errors_bp.errorhandler(403)
def forbidden(e):
    user_id = session.get('user_id', 'Unauthenticated')
    ip = request.remote_addr
    path = request.path
    msg = "403 Forbidden"
    suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
    log_to_database("WARNING", 403, user_id, ip, path, msg)
    return render_template("error.html", error=e), 403

@errors_bp.errorhandler(404)
def not_found(e):
    user_id = session.get('user_id', 'Unauthenticated')
    ip = request.remote_addr
    path = request.path
    msg = "404 Not Found"
    suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
    log_to_database("WARNING", 404, user_id, ip, path, msg)
    return render_template("error.html", error=e), 404

@errors_bp.errorhandler(400)
def bad_request(e):
    user_id = session.get('user_id', 'Unauthenticated')
    ip = request.remote_addr
    path = request.path
    msg = "400 Bad Request"
    suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
    log_to_database("WARNING", 400, user_id, ip, path, msg)
    return render_template("error.html", error=e), 400