from flask import request, redirect, url_for, session
from .utils import generate_fingerprint, log_to_database, is_session_expired, suspicious_logger

def setup_security(app):

    @app.before_request
    def security_check():
        """Check for session hijacking on every request"""
        # Skip for non-authenticated routes
        if request.endpoint in ['login', 'register', 'static', 'verify_2fa', 'setup_2fa', 'index', 'logout', 'forget_password', 'reset_password']:
            return
        
        # Check if user is logged in
        if 'user_id' not in session or 'session_token' not in session:
            return redirect(url_for('login'))
        
        # Check fingerprint if present
        if 'fingerprint' in session:
            current_fingerprint = generate_fingerprint(request)
            stored_fingerprint = session['fingerprint']
            
            if current_fingerprint != stored_fingerprint:
                # Log potential session hijacking attempt
                suspicious_logger.warning(
                    f"Session hijacking detected! User-ID: {session['user_id']}, "
                    f"IP: {request.headers.get('X-Real-IP', request.remote_addr)}, "
                    f"UA: {request.headers.get('User-Agent', '')[:50]}"
                )
                
                # Log to database
                log_to_database(
                    "WARNING", 
                    403, 
                    session['user_id'], 
                    request.headers.get('X-Real-IP', request.remote_addr), 
                    request.path, 
                    "Session hijacking attempt - fingerprint mismatch"
                )
                
                # Invalidate session
                session.clear()
                return redirect(url_for('login', error='security_violation'))
        
        # Also check for session expiration
        if is_session_expired():
            return redirect(url_for('login', error='session_expired'))
