import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Union

from flask import Flask, request, jsonify, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from sqlalchemy.orm import DeclarativeBase

from config import Config
from models import db, User, Admin  # make sure your models.py exports these
from mailer import send_mail
from tokens import make_action_token, load_action_token
from utils import log_action, valid_password, generate_code, load_email_template

# ---------------- Setup ----------------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sociovia")

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = os.environ.get("SESSION_SECRET", app.config.get("SECRET_KEY", "dev-secret"))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:8080")

# after app = Flask(__name__) and app.config.from_object(Config)
from datetime import timedelta

# IMPORTANT for dev cross-origin cookies:
app.config.update(
    SESSION_COOKIE_SAMESITE="None",   # allow cross-site
    SESSION_COOKIE_SECURE=False,      # dev: False if not using HTTPS; set True in prod with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)

# CORS: use exact frontend origin(s) and supports_credentials=True
from flask_cors import CORS

FRONTEND_ORIGINS = [
    app.config.get("FRONTEND_ORIGIN", "http://localhost:8080"),
    "http://127.0.0.1:8080"   # include this if you sometimes use 127.0.0.1
]

CORS(app,
     supports_credentials=True,
     resources={
         r"/api/*": {"origins": FRONTEND_ORIGINS},
         r"/admin/*": {"origins": FRONTEND_ORIGINS}
     })

# Initialize DB
db.init_app(app)
with app.app_context():
    db.create_all()
    # Create default admin if none exists (override with env vars in production)
    if not Admin.query.first():
        admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@sociovia.com")
        admin_pass = os.getenv("DEFAULT_ADMIN_PASS", "admin123")
        admin = Admin(email=admin_email, password_hash=generate_password_hash(admin_pass), is_superadmin=True)
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Created default admin: {admin_email} / {admin_pass}")

# ---------------- Helpers ----------------
def parse_admin_emails(value: Union[str, List[str], None]) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [e.strip() for e in value if e and e.strip()]
    return [e.strip() for e in str(value).split(",") if e.strip()]

def send_mail_to(recipient: Union[str, List[str]], subject: str, body: str) -> None:
    """
    Safe wrapper to send mail to single or multiple recipients.
    send_mail(recipient, subject, body) should be implemented in mailer.py
    """
    if isinstance(recipient, (list, tuple)):
        for r in recipient:
            try:
                send_mail(r, subject, body)
            except Exception:
                logger.exception("Failed to send mail to %s", r)
    else:
        try:
            send_mail(recipient, subject, body)
        except Exception:
            logger.exception("Failed to send mail to %s", recipient)

def serialize_user(u: User) -> Dict[str, Any]:
    """Return a JSON-safe representation of a User model (MVP fields)."""
    return {
        "id": u.id,
        "name": u.name,
        "email": u.email,
        "phone": u.phone,
        "business_name": u.business_name,
        "industry": u.industry,
        "status": u.status,
        "email_verified": bool(u.email_verified),
        "created_at": u.created_at.isoformat() if hasattr(u, "created_at") and u.created_at else None,
        "rejection_reason": getattr(u, "rejection_reason", None),
    }

def require_admin_session():
    admin_id = session.get("admin_id")
    if not admin_id:
        abort(401, description="admin_not_authenticated")
    admin = Admin.query.get(admin_id)
    if not admin:
        abort(401, description="admin_not_found")
    return admin

# Config helpers
VERIFY_TTL_MIN = int(app.config.get("VERIFY_TTL_MIN", os.getenv("VERIFY_TTL_MIN", 15)))
ADMIN_LINK_TTL_HOURS = int(app.config.get("ADMIN_LINK_TTL_HOURS", os.getenv("ADMIN_LINK_TTL_HOURS", 48)))
APP_BASE_URL = app.config.get("APP_BASE_URL", os.getenv("APP_BASE_URL", ""))

# ---------------- Public JSON APIs ----------------

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    business_name = (data.get("business_name") or "").strip()
    industry = (data.get("industry") or "").strip()
    password = data.get("password") or ""

    errors = []
    if not name:
        errors.append("Name is required")
    if not email:
        errors.append("Email is required")
    else:
        try:
            validate_email(email)
        except EmailNotValidError:
            errors.append("Invalid email format")
    if not valid_password(password):
        errors.append("Password must be at least 8 characters")
    if not business_name:
        errors.append("Business name is required")
    if email and User.query.filter_by(email=email).first():
        errors.append("Email already registered")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    verification_code = generate_code()
    user = User(
        name=name,
        email=email,
        phone=phone,
        business_name=business_name,
        industry=industry,
        password_hash=generate_password_hash(password),
        verification_code_hash=generate_password_hash(verification_code),
        verification_expires_at=datetime.utcnow() + timedelta(minutes=VERIFY_TTL_MIN),
        status="pending_verification",
    )
    db.session.add(user)
    db.session.commit()
    log_action("system", "user_signup", user.id, {"email": email})

    # Send verification email
    try:
        email_body = load_email_template("user_verify.txt", {"name": name, "code": verification_code})
        send_mail_to(email, "Verify your Sociovia account", email_body)
    except Exception:
        logger.exception("Failed to send verification email")

    return jsonify({"success": True, "message": "Signup successful. Check your email for verification code."}), 201

@app.route("/api/verify-email", methods=["POST"])
def api_verify_email():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    if not email or not code:
        return jsonify({"success": False, "error": "Email and code required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    if user.email_verified:
        return jsonify({"success": True, "message": "Already verified", "status": user.status}), 200

    if not user.verification_code_hash or user.verification_expires_at < datetime.utcnow():
        return jsonify({"success": False, "error": "Verification expired"}), 400

    if not check_password_hash(user.verification_code_hash, code):
        return jsonify({"success": False, "error": "Invalid code"}), 400

    user.email_verified = True
    user.status = "under_review"
    user.verification_code_hash = None
    user.verification_expires_at = None
    db.session.commit()
    log_action("system", "email_verified", user.id)
    log_action("system", "moved_to_review", user.id)

    # Notify admins
    try:
        admin_list = parse_admin_emails(app.config.get("ADMIN_EMAILS", os.getenv("ADMIN_EMAILS", "")))
        if admin_list:
            approve_token = make_action_token({"user_id": user.id, "action": "approve", "issued_at": datetime.utcnow().isoformat()})
            reject_token = make_action_token({"user_id": user.id, "action": "reject", "issued_at": datetime.utcnow().isoformat()})
            email_body = load_email_template("admin_notify.txt", {
                "name": user.name,
                "email": user.email,
                "business_name": user.business_name,
                "industry": user.industry,
                "approve_url": f"{APP_BASE_URL}/admin/action?token={approve_token}",
                "reject_url": f"{APP_BASE_URL}/admin/action?token={reject_token}"
            })
            send_mail_to(admin_list, f"New account to review – {user.business_name}", email_body)
    except Exception:
        logger.exception("Failed to notify admins")

    return jsonify({"success": True, "message": "Email verified. Account under review.", "status": user.status}), 200

@app.route("/api/resend-code", methods=["POST"])
def api_resend_code():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "email_required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "error": "user_not_found"}), 404
    if user.email_verified:
        return jsonify({"success": True, "message": "already_verified"}), 200

    verification_code = generate_code()
    user.verification_code_hash = generate_password_hash(verification_code)
    user.verification_expires_at = datetime.utcnow() + timedelta(minutes=VERIFY_TTL_MIN)
    db.session.commit()

    try:
        email_body = load_email_template("user_verify.txt", {"name": user.name, "code": verification_code})
        send_mail_to(user.email, "Verify your Sociovia account", email_body)
    except Exception:
        logger.exception("Failed to send verification email")
        return jsonify({"success": False, "error": "email_failed"}), 500

    return jsonify({"success": True, "message": "code_sent"}), 200

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
    if user.status == "pending_verification":
        return jsonify({"success": False, "status": user.status, "error": "pending_verification"}), 403
    if user.status == "under_review":
        return jsonify({"success": False, "status": user.status, "error": "under_review"}), 403
    if user.status == "rejected":
        return jsonify({"success": False, "status": user.status, "error": "rejected", "reason": user.rejection_reason}), 403

    # session-based for now (MVP). Consider JWT for production + cross-origin auth.
    session['user_id'] = user.id
    return jsonify({"success": True, "message": "Login successful", "user": {"id": user.id, "name": user.name}}), 200

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop('user_id', None)
    return jsonify({"success": True, "message": "Logged out"}), 200

@app.route("/api/status")
def api_status():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"status": user.status}), 200

# ---------------- Admin JSON APIs ----------------

@app.route("/api/admin/login", methods=["POST"])
def api_admin_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"success": False, "error": "email_and_password_required"}), 400
    admin = Admin.query.filter_by(email=email).first()
    if not admin or not check_password_hash(admin.password_hash, password):
        return jsonify({"success": False, "error": "invalid_credentials"}), 401
    session['admin_id'] = admin.id
    return jsonify({"success": True, "message": "admin_authenticated"}), 200

@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    session.pop('admin_id', None)
    return jsonify({"success": True, "message": "admin_logged_out"}), 200

@app.route("/api/admin/review", methods=["GET"])
def api_admin_review():
    try:
        admin = require_admin_session()
    except Exception as e:
        return jsonify({"success": False, "error": "admin_not_authenticated"}), 401

    users = User.query.filter_by(status="under_review").order_by(User.created_at.desc()).all()
    return jsonify({"success": True, "users": [serialize_user(u) for u in users]}), 200

@app.route("/api/admin/approve/<int:user_id>", methods=["POST"])
def api_admin_approve(user_id: int):
    try:
        admin = require_admin_session()
    except Exception:
        return jsonify({"success": False, "error": "admin_not_authenticated"}), 401

    user = User.query.get_or_404(user_id)
    if user.status != "under_review":
        return jsonify({"success": False, "error": "user_not_in_review"}), 400

    user.status = "approved"
    db.session.commit()
    log_action(admin.email, "approved", user.id)

    try:
        email_body = load_email_template("user_approved.txt", {"name": user.name})
        send_mail_to(user.email, "Your Sociovia account is approved", email_body)
    except Exception:
        logger.exception("Failed to send approval email")

    return jsonify({"success": True, "message": f"user_{user.id}_approved"}), 200

@app.route("/api/admin/reject/<int:user_id>", methods=["POST"])
def api_admin_reject(user_id: int):
    try:
        admin = require_admin_session()
    except Exception:
        return jsonify({"success": False, "error": "admin_not_authenticated"}), 401

    data = request.get_json() or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify({"success": False, "error": "rejection_reason_required"}), 400

    user = User.query.get_or_404(user_id)
    if user.status != "under_review":
        return jsonify({"success": False, "error": "user_not_in_review"}), 400

    user.status = "rejected"
    user.rejection_reason = reason
    db.session.commit()
    log_action(admin.email, "rejected", user.id, {"reason": reason})

    try:
        email_body = load_email_template("user_rejected.txt", {"name": user.name, "reason": reason})
        send_mail_to(user.email, "Update on your Sociovia account", email_body)
    except Exception:
        logger.exception("Failed to send rejection email")

    return jsonify({"success": True, "message": f"user_{user.id}_rejected"}), 200

@app.route("/api/admin/action", methods=["GET"])
def api_admin_action():
    token = request.args.get("token")
    if not token:
        return jsonify({"success": False, "error": "token_required"}), 400

    try:
        payload = load_action_token(token, ADMIN_LINK_TTL_HOURS * 3600)
        user_id = payload.get("user_id")
        action = payload.get("action")
        reason = payload.get("reason", "Rejected via admin link")

        user = User.query.get_or_404(user_id)
        if user.status != "under_review":
            return jsonify({"success": False, "error": "user_not_in_review"}), 400

        if action == "approve":
            user.status = "approved"
            db.session.commit()
            log_action("admin_link", "approved", user.id)
            try:
                email_body = load_email_template("user_approved.txt", {"name": user.name})
                send_mail_to(user.email, "Your Sociovia account is approved", email_body)
            except Exception:
                logger.exception("Failed to send approval email (admin link)")
            return jsonify({"success": True, "message": f"user_{user.id}_approved"}), 200

        if action == "reject":
            user.status = "rejected"
            user.rejection_reason = reason
            db.session.commit()
            log_action("admin_link", "rejected", user.id, {"reason": reason})
            try:
                email_body = load_email_template("user_rejected.txt", {"name": user.name, "reason": reason})
                send_mail_to(user.email, "Update on your Sociovia account", email_body)
            except Exception:
                logger.exception("Failed to send rejection email (admin link)")
            return jsonify({"success": True, "message": f"user_{user.id}_rejected"}), 200

        return jsonify({"success": False, "error": "invalid_action"}), 400

    except Exception:
        logger.exception("Token validation failed")
        return jsonify({"success": False, "error": "invalid_or_expired_token"}), 400

# ---------------- Run (dev) ----------------
if __name__ == "__main__":
    debug_flag = os.getenv("FLASK_ENV", "development") != "production"
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug_flag)
