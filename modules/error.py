from flask import render_template, request, session
from modules.log import log_to_database
from modules.session_utils import suspicious_logger


def register_error_handlers(app, mysql):
    @app.errorhandler(403)
    def forbidden(e):
        user_id = session.get('user_id', 'Unauthenticated')
        ip = request.remote_addr
        path = request.path
        msg = "403 Forbidden"
        suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
        log_to_database(mysql, "WARNING", 403, user_id, ip, path, msg)
        return render_template("error.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e):
        user_id = session.get('user_id', 'Unauthenticated')
        ip = request.remote_addr
        path = request.path
        msg = "404 Not Found"
        suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
        log_to_database(mysql, "WARNING", 404, user_id, ip, path, msg)
        return render_template("error.html", error=e), 404

    @app.errorhandler(400)
    def bad_request(e):
        user_id = session.get('user_id', 'Unauthenticated')
        ip = request.remote_addr
        path = request.path
        msg = "400 Bad Request"
        suspicious_logger.warning(f"{msg} - user_id: {user_id}, IP: {ip}, path: {path}")
        log_to_database(mysql, "WARNING", 400, user_id, ip, path, msg)
        return render_template("error.html", error=e), 400
