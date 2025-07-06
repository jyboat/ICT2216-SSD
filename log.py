from flask import request
from datetime import datetime

def log_to_database(mysql,type, status_code, user_id, ip_address, path, message):

    # Get the real IP address dued to proxy
    real_ip = request.headers.get('X-Real-IP', ip_address)

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO logs (timestamp, type, status_code, user_id, ip_address, path, message)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (datetime.now(), type, status_code, str(user_id), real_ip, path, message))
    mysql.connection.commit()
    cur.close()