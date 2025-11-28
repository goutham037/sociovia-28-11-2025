import os, json
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

SERVICE_ACCOUNT_JSON = json.loads(os.getenv("SERVICE_ACCOUNT_JSON"))

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS") == "True"
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    MAIL_FROM = os.getenv("MAIL_FROM")
    ADMIN_EMAILS = os.getenv("ADMIN_EMAILS").split(",")
    APP_BASE_URL = os.getenv("APP_BASE_URL")
    FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN")
    VERIFY_TTL_MIN = int(os.getenv("VERIFY_TTL_MIN", 15))
    ADMIN_LINK_TTL_HOURS = int(os.getenv("ADMIN_LINK_TTL_HOURS", 48))
    PERMANENT_SESSION_LIFETIME = timedelta(days=int(os.getenv("PERMANENT_SESSION_LIFETIME_DAYS", 7)))
