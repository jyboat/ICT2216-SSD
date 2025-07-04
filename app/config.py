import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    MYSQL_HOST = os.getenv('MYSQL_HOST')
    MYSQL_USER = os.getenv('MYSQL_USER')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
    MYSQL_DB = os.getenv('MYSQL_DB')
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    CF_SECRET_KEY = os.getenv("CF_SECRET_KEY")

    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')

    # cf key.
    cf_secret_key = os.getenv("CF_SECRET_KEY")
