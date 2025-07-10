from flask import request
from datetime import datetime
import requests

SPLUNK_HOST = "test_splunk_1"
SPLUNK_HEC_PORT = "8088"
SPLUNK_HEC_TOKEN = "e01244bd-6b33-44be-b270-f1a5d12d9871"

def log_to_database(mysql, type, status_code, user_id, ip_address, path, message):

    # Get the real IP address dued to proxy
    real_ip = request.headers.get('X-Real-IP', ip_address)

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO logs (timestamp, type, status_code, user_id, ip_address, path, message)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (datetime.now(), type, status_code, str(user_id), real_ip, path, message))
    mysql.connection.commit()
    cur.close()

def log_to_splunk(event_data):

    # get real ip
    if 'ip_address' in event_data:
        event_data['ip_address'] = request.headers.get('X-Real-IP', event_data['ip_address'])
        
    url = f"https://{SPLUNK_HOST}:{SPLUNK_HEC_PORT}/services/collector"
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "event": event_data,
        "sourcetype": "login_attempts",
    }
    try:
        requests.post(url, headers=headers, json=payload, verify=False)
    except Exception as e:
        print(f"Failed to log to Splunk: {e}")
