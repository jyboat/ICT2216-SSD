from flask import request, session
import time
import pyotp
import qrcode
import io
import base64
import hashlib
import logging

suspicious_logger = logging.getLogger("suspicious")
suspicious_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("logs.txt")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
suspicious_logger.addHandler(file_handler)

# function to check if session has expired
def is_session_expired():
    if 'user_id' not in session or 'session_token' not in session:
        session.clear()
        return True
    
    # check if token matches
    cur = mysql.connection.cursor()
    cur.execute("SELECT session_token FROM users WHERE id = %s", (session['user_id'],))
    db_token = cur.fetchone()
    cur.close()

    if not db_token or db_token[0] != session.get('session_token'):
        session.clear()
        return True

    last = session.get('last_active', 0)
    if time.time() - last > 900:
        session.clear()
        return True

    session['last_active'] = time.time()
    return False

def is_valid_session():
    if 'user_id' not in session or 'session_token' not in session or 'fingerprint' not in session:
        return False

    # Check if fingerprint matches
    current_fingerprint = generate_fingerprint(request)
    if session.get('fingerprint') != current_fingerprint:
        suspicious_logger.warning(f"Session fingerprint mismatch - user_id: {session['user_id']}, IP: {request.remote_addr}")
        return False

    # Check if token matches in database
    cur = mysql.connection.cursor()
    cur.execute("SELECT session_token FROM users WHERE id = %s", (session['user_id'],))
    result = cur.fetchone()
    cur.close()

    return result and result[0] == session.get('session_token')

def generate_fingerprint(request):
    """Generate a fingerprint that works with Nginx"""
    # Get browser information
    user_agent = request.headers.get('User-Agent', '')
    
    # Get the real client IP from Nginx headers
    real_ip = request.headers.get('X-Real-IP') or request.remote_addr
    
    # Log the IPs for debugging
    if app.debug:
        print(f"Remote addr: {request.remote_addr}, X-Real-IP: {real_ip}")
    
    # Use partial IP for some flexibility
    ip_parts = real_ip.split('.')
    if len(ip_parts) >= 3:  # IPv4
        ip_partial = '.'.join(ip_parts[:3]) + '.0'
    else:
        ip_partial = real_ip  # Handle IPv6 or unusual formats
    
    # Create fingerprint WITH server secret
    server_secret = app.config['SECRET_KEY']  # Use your Flask secret key
    fingerprint_str = f"{user_agent}|{ip_partial}|{server_secret}"
    
    fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    return fingerprint

def is_logged_in():
    if is_valid_session():
        if time.time() - session.get('last_active', 0) < 900:
            session['last_active'] = time.time()
            return True
    return False

# Helper function to check if educator role
def is_educator(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cur.fetchone()[0]
    cur.close()
    return role == "educator"

# Helper function to repeatedly get user_id
def get_current_user_id():
    return session.get('user_id')

def generate_qr(secret, email):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="MyFlaskApp")
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def log_to_database(type, status_code, user_id, ip_address, path, message):

    # Get the real IP address dued to proxy
    real_ip = request.headers.get('X-Real-IP', ip_address)

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO logs (timestamp, type, status_code, user_id, ip_address, path, message)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (datetime.now(), type, status_code, str(user_id), real_ip, path, message))
    mysql.connection.commit()
    cur.close()