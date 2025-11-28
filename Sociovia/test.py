import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Union
from flask import Flask, current_app, request, jsonify, session, abort, url_for
from sqlalchemy import DateTime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from sqlalchemy.orm import DeclarativeBase
from flask_session import Session
from flask_cors import CORS, cross_origin
from config import Config
from models import db, User, Admin,SocialAccount ,AIUsage,AIUsageDailySummary,AssistantThread, AssistantMessage
from mailer import send_mail
from tokens import make_action_token, load_action_token
from utils import log_action, valid_password, generate_code, load_email_template
import os
import json
import re
import smtplib
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import request, jsonify

# ---------------- Setup ----------------
load_dotenv()
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',level=logging.DEBUG)
logger = logging.getLogger("sociovia")

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config.from_object(Config)

# Security key for sessions
app.secret_key = os.environ.get("SESSION_SECRET", app.config.get("SECRET_KEY", "dev-secret"))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["ALLOW_REQUEST_USER_ID_FALLBACK"] = True  # [fix this in after session validation]

# ---------------- Session + CORS ----------------
FRONTEND_ORIGINS = [
    "https://sociovia-c9473.web.app",
    "https://sociovia.com",
    "http://127.0.0.1:8080",
    "http://localhost:3000",
    "https://6136l5dn-8080.inc1.devtunnels.ms",
    "http://192.168.0.102:8080"
]


app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_SAMESITE="None",   
    SESSION_COOKIE_SECURE=True,      
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)


# OAuth / Facebook config — override with environment in production
FB_APP_ID = os.getenv("FB_APP_ID", "")
FB_APP_SECRET = os.getenv("FB_APP_SECRET", "")
FB_API_VERSION = os.getenv("FB_API_VERSION", "v16.0")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://sociovia-py.onrender.com")
OAUTH_REDIRECT_BASE = os.getenv("OAUTH_REDIRECT_BASE", APP_BASE_URL)
# default scopes for facebook-first flow; instagram scopes will be requested later when linking IG
OAUTH_SCOPES = os.getenv("OAUTH_SCOPES", "pages_show_list,pages_read_engagement,ads_management")
Session(app)

app.config.setdefault("CORS_HEADERS", "Content-Type,Authorization,X-Requested-With,X-User-Id,X-User-Email")
CORS(
    app,
    origins=FRONTEND_ORIGINS,         # exact allowed origins list
    supports_credentials=True,        # important to allow cookies
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-User-Id", "X-User-Email"],
    expose_headers=["Content-Type"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
)
@app.after_request
def add_vary_origin(resp):
    resp.headers["Vary"] = "Origin"
    return resp
# ---------------- DB Init ----------------
db.init_app(app)
with app.app_context():
    db.create_all()
    
    if not Admin.query.first():
        admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@sociovia.com")
        admin_pass = os.getenv("DEFAULT_ADMIN_PASS", "admin123")
        admin = Admin(
            email=admin_email,
            password_hash=generate_password_hash(admin_pass),
            is_superadmin=True
        )
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
APP_BASE_URL = "https://sociovia-py.onrender.com"

# ---------------- Public APIs ----------------
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

    try:
        email_body = load_email_template("user_verify.txt", {"name": name, "code": verification_code})
        send_mail_to(email, "Verify your Sociovia account", email_body)
    except Exception:
        logger.exception("Failed to send verification email")

    return jsonify({"success": True, "message": "Signup successful. Check your email for verification code."}), 201
from flask import make_response

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "email_password_required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        logger.info("login_failed email=%s ip=%s", email, request.remote_addr)
        return jsonify({"success": False, "error": "invalid_credentials"}), 401

    # Account review / verification states
    if user.status in ["pending_verification", "under_review", "rejected"]:
        # return status so frontend can route user appropriately
        logger.info("login_blocked email=%s status=%s", email, user.status)
        return jsonify({"success": False, "status": user.status, "error": "not_approved"}), 403

    # Create server-side session (filesystem session via Flask-Session)
    session.permanent = True
    session["user_id"] = user.id
    session.modified = True

    # Debug log the session contents (remove or lower level in production)
    logger.debug("api_login: session after set -> %s", dict(session))

    # Return minimal user info (frontend should call /api/me for authoritative data)
    resp = make_response(jsonify({
        "success": True,
        "message": "Login successful",
        "user": {"id": user.id, "name": user.name, "email": user.email}
    }), 200)

    # Optionally: if you want to set an explicit test cookie for debugging (remove in prod)
    if os.getenv("DEBUG_SET_TEST_COOKIE", "false").lower() in ("1", "true"):
        resp.set_cookie("sv_test", "ok", httponly=True, secure=False, samesite="Lax", max_age=3600)

    return resp


@app.route("/api/me", methods=["GET"])
def api_me():
    # Return 401 when no session is present (client should then redirect to login)
    user_id = session.get("user_id")
    logger.debug("api_me: incoming session -> %s", dict(session))

    if not user_id:
        # no session
        return jsonify({"success": False, "error": "unauthenticated"}), 401

    user = User.query.get(user_id)
    if not user:
        # invalid/expired session — clear it
        session.pop("user_id", None)
        return jsonify({"success": False, "error": "unauthenticated"}), 401

    return jsonify({"success": True, "user": serialize_user(user)}), 200

    
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

# ---------------- Admin APIs ----------------
ADMIN_EMAIL = "admin@sociovia.com"
ADMIN_PASSWORD = "admin123"


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


@app.route("/api/admin/review", methods=["POST"])
def admin_review():
    """Fetch pending users - requires admin credentials in body"""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if email != ADMIN_EMAIL or password != ADMIN_PASSWORD:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    users = (
        User.query.filter_by(status="under_review")
        .order_by(User.created_at.desc())
        .all()
    )

    user_list = [
        {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "phone": u.phone,
            "business_name": u.business_name,
            "industry": u.industry,
            "created_at": u.created_at.isoformat(),
            "status": u.status,
        }
        for u in users
    ]

    return jsonify({"success": True, "users": user_list})



@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    session.pop('admin_id', None)
    return jsonify({"success": True, "message": "admin_logged_out"}), 200
    """_summary_

    Returns:
        _type_: _description_
        
        @app.route("/api/admin/review", methods=["GET"])
def api_admin_review():
    try:
        admin = require_admin_session()
    except Exception:
        return jsonify({"success": False, "error": "admin_not_authenticated"}), 401

    users = User.query.filter_by(status="under_review").order_by(User.created_at.desc()).all()
    return jsonify({"success": True, "users": [serialize_user(u) for u in users]}), 200

    """
 
""
 

@app.route("/api/admin/approve/<int:user_id>", methods=["POST"])
def api_admin_approve(user_id: int):
    

    user = User.query.get_or_404(user_id)
    if user.status != "under_review":
        return jsonify({"success": False, "error": "user_not_in_review"}), 400

    user.status = "approved"
    db.session.commit()
    log_action("sharan1114411@gmail.com", "approved", user.id)

    try:
        email_body = load_email_template("user_approved.txt", {"name": user.name})
        send_mail_to(user.email, "Your Sociovia account is approved", email_body)
    except Exception:
        logger.exception("Failed to send approval email")

    return jsonify({"success": True, "message": f"user_{user.id}_approved"}), 200


@app.route("/api/admin/reject/<int:user_id>", methods=["POST"])
def api_admin_reject(user_id: int):
   

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


from flask import redirect, render_template_string

from urllib.parse import unquote, urlencode
from flask import redirect, render_template_string

@app.route("/admin/action", methods=["GET"])
def api_admin_action():
    token = request.args.get("token")
    if not token:
        logger.warning("admin action hit with no token")
        return jsonify({"success": False, "error": "token_required"}), 400

    # Log origin + DB URI for debugging (remove in prod)
    logger.info("admin action request from=%s db=%s", request.remote_addr, app.config.get("SQLALCHEMY_DATABASE_URI"))

    try:
        # Try unquoting if email client double-encoded
        try:
            payload = load_action_token(unquote(token), ADMIN_LINK_TTL_HOURS * 3600)
        except Exception:
            payload = load_action_token(token, ADMIN_LINK_TTL_HOURS * 3600)

        logger.info("admin link payload: %s", payload)
        user_id = payload.get("user_id")
        action = payload.get("action")
        reason = payload.get("reason", "Rejected via admin link")

        # Safer lookup (no immediate abort)
        user = User.query.filter_by(id=user_id).first()
        if not user:
            # log all known user ids to help debug
            try:
                ids = [u.id for u in User.query.with_entities(User.id).all()]
            except Exception:
                ids = "<couldn't fetch ids>"
            logger.warning("admin link: user id %s not found. existing_user_ids=%s", user_id, ids)
            return render_template_string(
                "<h3>Invalid admin link</h3><p>User not found. Contact support.</p>"
            ), 400

        if user.status != "under_review":
            return render_template_string(
                "<h3>Action not allowed</h3><p>User status: {{status}}</p>",
                status=user.status
            ), 400

        if action == "approve":
            user.status = "approved"
            db.session.commit()
            log_action("admin_link", "approved", user.id)
            try:
                email_body = load_email_template("user_approved.txt", {"name": user.name})
                send_mail_to(user.email, "Your Sociovia account is approved", email_body)
            except Exception:
                logger.exception("Failed to send approval email (admin link)")
            return redirect(f"{APP_BASE_URL.rstrip('/')}/admin/complete?status=approved&uid={user.id}")

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
            return redirect(f"{APP_BASE_URL.rstrip('/')}/admin/complete?status=rejected&uid={user.id}")

        return render_template_string("<h3>Invalid action</h3>"), 400

    except Exception as e:
        logger.exception("Token validation failed: %s", e)
        return render_template_string("<h3>Invalid or expired admin link</h3><p>Please contact support.</p>"), 400
# ---------------- Workspace Model + Routes ----------------
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

# Allowed file extensions for uploads
ALLOWED_IMAGE_EXTS = {"png", "jpg", "jpeg", "svg", "webp", "gif"}
UPLOAD_BASE = os.path.join(os.getcwd(), "uploads", "workspaces")  # e.g. ./uploads/workspaces/<user_id>/

# Create uploads base directory if missing
os.makedirs(UPLOAD_BASE, exist_ok=True)
class Workspace(db.Model):
    __tablename__ = "workspaces"
    __table_args__ = {"extend_existing": True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    business_name = db.Column(db.String(255))
    business_type = db.Column(db.String(100))
    registered_address = db.Column(db.String(255))
    b2b_b2c = db.Column(db.String(50))
    industry = db.Column(db.String(100))
    describe_business = db.Column(db.Text)
    describe_audience = db.Column(db.Text)
    website = db.Column(db.String(255))
    direct_competitors = db.Column(db.Text)
    indirect_competitors = db.Column(db.Text)
    social_links = db.Column(db.Text)
    usp = db.Column(db.String(255))
    logo_path = db.Column(db.String(255))
    creatives_paths = db.Column(db.Text)
    additional_remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())  # this is missing in DB




def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTS


@app.route("/uploads/workspaces/<int:user_id>/<path:filename>")
def serve_workspace_upload(user_id: int, filename: str):
    """
    Serve uploaded workspace files. In production use a proper static file server.
    """
    directory = os.path.join(UPLOAD_BASE, str(user_id))
    return send_from_directory(directory, filename, as_attachment=False)
# ---------------- Helpers (add this helper) ----------------
def get_user_from_request(require: bool = True):
    """
    Resolve a User from the incoming request.
    Resolution order:
      1) session['user_id']
      2) X-User-Id header
      3) user_id query param or form field
      4) X-User-Email header
      5) email query param or form field
    Returns User instance or None.
    """
    def _get_user_by_id_safe(uid):
        try:
            if uid is None:
                return None
            # ensure int
            uid_int = int(uid)
        except Exception:
            return None
        # prefer db.session.get for SQLAlchemy 1.4+/2.0
        try:
            return db.session.get(User, uid_int)
        except Exception:
            # fallback for older SQLAlchemy versions
            try:
                return User.query.get(uid_int)
            except Exception:
                return None

    # 1) session
    user_id = session.get("user_id")
    u = _get_user_by_id_safe(user_id)
    if u:
        return u

    # 2) X-User-Id header
    uid = request.headers.get("X-User-Id")
    u = _get_user_by_id_safe(uid)
    if u:
        return u

    # 3) user_id param/form
    uid = request.args.get("user_id") or (request.form.get("user_id") if request.form else None)
    u = _get_user_by_id_safe(uid)
    if u:
        return u

    # 4) X-User-Email header
    email = request.headers.get("X-User-Email")
    if email:
        try:
            norm = str(email).strip().lower()
            u = User.query.filter_by(email=norm).first()
            if u:
                return u
        except Exception:
            pass

    # 5) email query/form
    email = request.args.get("email") or (request.form.get("email") if request.form else None)
    if email:
        try:
            norm = str(email).strip().lower()
            u = User.query.filter_by(email=norm).first()
            if u:
                return u
        except Exception:
            pass

    return None if require else None

from flask import request, jsonify
import os, json
from botocore.exceptions import BotoCoreError, ClientError
import time
import uuid
import json as _json
from werkzeug.utils import secure_filename

@app.route("/api/workspace/setup", methods=["POST"])
def api_workspace_setup_create():
    """
    Create a new workspace (multipart/form-data). Always creates a NEW workspace record.
    """
    try:
        user = get_user_from_request(require=True)
        print(user)
        if not user:
            return jsonify({"success": False, "error": "not_authenticated"}), 401
        user_id = user.id

        if not request.content_type or "multipart/form-data" not in request.content_type:
            return jsonify({"success": False, "error": "content_type_must_be_multipart"}), 415

        form = request.form
        # Accept either shape for descriptions (compatibility)
        description = (form.get("describe_business") or form.get("description") or "").strip()
        audience_description = (form.get("describe_audience") or form.get("audience_description") or "").strip()

        business_name = (form.get("business_name") or "").strip()
        business_type = (form.get("business_type") or "").strip()
        registered_address = (form.get("registered_address") or "").strip()
        b2b_b2c = (form.get("b2b_b2c") or "").strip().upper()
        industry = (form.get("industry") or "").strip()
        website = (form.get("website") or "").strip()
        direct_competitors_raw = (form.get("direct_competitors") or "").strip()
        indirect_competitors_raw = (form.get("indirect_competitors") or "").strip()
        social_links_raw = (form.get("social_links") or "").strip()
        usp = (form.get("usp") or "").strip()
        additional_remarks = (form.get("additional_remarks") or "").strip()

        logo_file = request.files.get("logo")
        creatives_files = request.files.getlist("creatives")

        # --- parsing helpers (preserve name + website) ---
        def parse_competitors(raw: str):
            raw = (raw or "").strip()
            if not raw:
                return []
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    out = []
                    for item in parsed:
                        if isinstance(item, dict):
                            name = str(item.get("name") or "").strip()
                            # accept website or url keys
                            website = (item.get("website") or item.get("url") or "").strip() or None
                            if name:
                                out.append({"name": name, "website": website})
                        else:
                            s = str(item).strip()
                            if s:
                                out.append({"name": s, "website": None})
                    return out
            except Exception:
                pass
            # fallback: comma separated names (no websites)
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            return [{"name": p, "website": None} for p in parts]

        def parse_social_links(raw: str):
            raw = (raw or "").strip()
            if not raw:
                return []
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    out = []
                    for item in parsed:
                        if isinstance(item, dict):
                            platform = (item.get("platform") or item.get("name") or "").strip() or None
                            url = (item.get("url") or item.get("link") or "").strip() or None
                            if platform or url:
                                out.append({"platform": platform, "url": url})
                        else:
                            s = str(item).strip()
                            if s:
                                out.append({"platform": None, "url": s})
                    return out
            except Exception:
                pass
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            return [{"platform": None, "url": p} for p in parts]

        direct_competitors = parse_competitors(direct_competitors_raw)
        indirect_competitors = parse_competitors(indirect_competitors_raw)
        social_links = parse_social_links(social_links_raw)

        # --- validation ---
        errors = []
        if not business_name:
            errors.append("business_name_required")
        if business_type not in ["Pvt Ltd", "Sole Proprietorship", "Partnership", "Public"]:
            errors.append("invalid_business_type")
        if not registered_address:
            errors.append("registered_address_required")
        if b2b_b2c not in ["B2B", "B2C"]:
            errors.append("invalid_b2b_b2c")
        if not industry:
            errors.append("industry_required")
        if len(description) < 100:
            errors.append("describe_business_min_100")
        if len(audience_description) < 100:
            errors.append("describe_audience_min_100")
        if not usp:
            errors.append("usp_required")
        if not logo_file:
            errors.append("logo_required")
        elif not allowed_file(logo_file.filename):
            errors.append("logo_invalid_file_type")
        if len(direct_competitors) < 2:
            errors.append("direct_competitors_min_2")
        if len(indirect_competitors) < 2:
            errors.append("indirect_competitors_min_2")

        if errors:
            return jsonify({"success": False, "errors": errors}), 400

        # --- Upload to DigitalOcean Spaces using existing `s3` client ---
        SPACE_NAME = os.environ.get("SPACE_NAME") or os.environ.get("DO_SPACES_BUCKET") or os.environ.get("DO_SPACES_NAME")
        SPACE_REGION = os.environ.get("SPACE_REGION") or os.environ.get("DO_SPACES_REGION")
        # endpoint is optional; public URL constructed below uses {bucket}.{region}.digitaloceanspaces.com
        SPACE_ENDPOINT = os.environ.get("SPACE_ENDPOINT")

        if s3 is None or not SPACE_NAME:
            app.logger.exception("S3 client not configured or SPACE_NAME missing")
            return jsonify({"success": False, "error": "storage_not_configured"}), 500

        def spaces_public_url(bucket: str, key: str, region: str = SPACE_REGION):
            # Default DO Spaces public URL pattern:
            return f"https://{bucket}.{region}.digitaloceanspaces.com/{key}"

        def upload_fileobj_to_spaces(fileobj, bucket, key, content_type=None, acl="public-read"):
            try:
                extra_args = {}
                if acl:
                    extra_args["ACL"] = acl
                if content_type:
                    extra_args["ContentType"] = content_type
                try:
                    fileobj.seek(0)
                except Exception:
                    pass
                s3.upload_fileobj(fileobj, bucket, key, ExtraArgs=extra_args)
                return True, None
            except (BotoCoreError, ClientError) as exc:
                return False, str(exc)

        # upload logo
        uploaded_logo_key = None
        uploaded_creative_keys = []
        ts = int(time.time())

        if logo_file and logo_file.filename:
            if not allowed_file(logo_file.filename):
                return jsonify({"success": False, "error": "logo_invalid_file_type"}), 400
            safe_logo = secure_filename(logo_file.filename)
            unique = f"{ts}_{uuid.uuid4().hex[:8]}"
            uploaded_logo_key = f"workspaces/{user_id}/logo_{unique}_{safe_logo}"
            ok, err = upload_fileobj_to_spaces(logo_file.stream, SPACE_NAME, uploaded_logo_key, content_type=logo_file.mimetype)
            if not ok:
                app.logger.exception("Spaces upload failed for logo: %s", err)
                return jsonify({"success": False, "error": "upload_failed", "details": err}), 500

        # upload creatives
        for idx, f in enumerate(creatives_files or []):
            if not f or not f.filename:
                continue
            if not allowed_file(f.filename):
                app.logger.warning("Skipping creative due to invalid file type: %s", f.filename)
                continue
            safe = secure_filename(f.filename)
            unique = f"{ts}_{uuid.uuid4().hex[:6]}_{idx}"
            key = f"workspaces/{user_id}/creative_{unique}_{safe}"
            ok, err = upload_fileobj_to_spaces(f.stream, SPACE_NAME, key, content_type=f.mimetype)
            if not ok:
                app.logger.exception("Spaces upload failed for creative %s: %s", f.filename, err)
                return jsonify({"success": False, "error": "upload_failed", "details": err}), 500
            uploaded_creative_keys.append(key)

        # --- CREATE a NEW workspace (do NOT override existing) ---
        workspace = Workspace(user_id=user_id)  # ALWAYS new
        workspace.business_name = business_name
        workspace.business_type = business_type
        workspace.registered_address = registered_address
        workspace.b2b_b2c = b2b_b2c
        workspace.industry = industry
        # map to DB columns used in your snapshot
        workspace.description = description
        workspace.audience_description = audience_description
        workspace.website = website or None
        workspace.direct_competitors = _json.dumps(direct_competitors)  # structured JSON with website preserved
        workspace.indirect_competitors = _json.dumps(indirect_competitors)
        workspace.social_links = _json.dumps(social_links)
        workspace.usp = usp

        # store the PUBLIC URL(s) in DB (you asked to save the URL)
        logo_url = spaces_public_url(SPACE_NAME, uploaded_logo_key) if uploaded_logo_key else None
        creative_urls = [spaces_public_url(SPACE_NAME, k) for k in uploaded_creative_keys]

        workspace.logo_path = logo_url  # store full public URL
        workspace.creatives_paths = _json.dumps(creative_urls)  # JSON list of public URLs

        workspace.additional_remarks = additional_remarks or None

        db.session.add(workspace)
        db.session.commit()

        log_action(user.email or "system", "workspace_create", user.id, {"workspace_id": workspace.id})

        return jsonify({
            "success": True,
            "message": "workspace_created",
            "workspace": {
                "id": workspace.id,
                "user_id": workspace.user_id,
                "business_name": workspace.business_name,
                "description": workspace.description,
                "audience_description": workspace.audience_description,
                "website": workspace.website,
                "direct_competitors": direct_competitors,
                "indirect_competitors": indirect_competitors,
                "social_links": social_links,
                "usp": workspace.usp,
                "logo_url": logo_url,
                "creative_urls": creative_urls,
            }
        }), 201

    except Exception as e:
        logger.exception("Workspace create failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500

def allowed_file(filename):
    """Check if file extension is allowed."""
    allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif'}
    return os.path.splitext(filename)[1].lower() in allowed_extensions
# put near top of file for consistent usage
UPLOAD_BASE = os.getenv("UPLOAD_BASE", "uploads")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://sociovia-py.onrender.com").rstrip('/')

# update endpoint
class Generation(db.Model):
    __tablename__ = 'conversationss'
    __table_args__ = {'extend_existing': True} 
    
    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=True)
    prompt = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Generation {self.id}>'

from flask import jsonify, request
from flask_cors import cross_origin
from datetime import datetime
import os
import json
from werkzeug.utils import secure_filename
import logging

from flask import jsonify, request
from flask_cors import cross_origin
from datetime import datetime
import os
import json
from werkzeug.utils import secure_filename
import logging

logger = logging.getLogger(__name__)


@app.route('/api/workspace/<int:workspace_id>', methods=['PUT','GET','OPTIONS'])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['GET','PUT','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_workspace(workspace_id):
    logger.info(f"Request to /api/workspace/{workspace_id} with method {request.method}")
    try:
        user = get_user_from_request(require=True)
        if not user:
            logger.warning("Authentication failed")
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        # Use authenticated user.id — don't trust user_id query param
        workspace = Workspace.query.filter_by(id=workspace_id, user_id=user.id).first()
        if not workspace:
            logger.warning(f"Workspace {workspace_id} not found or forbidden for user {user.id}")
            # either not found or not owned by this user
            return jsonify({"success": False, "error": "not_found_or_forbidden"}), 404

        if request.method == 'GET':
            # Fetch generations (conversations)
            generations = Generation.query.filter_by(workspace_id=workspace_id).order_by(Generation.created_at.desc()).all()
            generations_data = [
                {
                    "id": g.id,
                    "prompt": g.prompt,
                    "response": g.response,
                    "created_at": g.created_at.isoformat() if g.created_at else None
                } for g in generations
            ]
            logger.info(f"Fetched {len(generations_data)} generations for workspace {workspace_id}")

            # Fetch creatives
            creatives = Creative.query.filter_by(workspace_id=workspace_id).order_by(Creative.created_at.desc()).all()
            creatives_data = [
                {
                    "id": c.id,
                    "filename": c.filename,
                    "url": c.url,
                    "type": c.type,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "user_id": c.user_id,
                    "workspace_id": c.workspace_id
                } for c in creatives
            ]
            logger.info(f"Fetched {len(creatives_data)} creatives for workspace {workspace_id}")

            logo_url = None
            if workspace.logo_path:
                logo_url = f"{APP_BASE_URL}/uploads/{workspace.logo_path}"

            return jsonify({
                "success": True,
                "workspace": {
                    "id": workspace.id,
                    "user_id": workspace.user_id,
                    "business_name": workspace.business_name,
                    "business_type": workspace.business_type,
                    "registered_address": workspace.registered_address,
                    "b2b_b2c": workspace.b2b_b2c,
                    "industry": workspace.industry,
                    "description": workspace.description,
                    "audience_description": workspace.audience_description,
                    "website": workspace.website,
                    "competitor_direct_1": workspace.competitor_direct_1,
                    "competitor_direct_2": workspace.competitor_direct_2,
                    "competitor_indirect_1": workspace.competitor_indirect_1,
                    "competitor_indirect_2": workspace.competitor_indirect_2,
                    "social_links": workspace.social_links,
                    "usp": workspace.usp,
                    "logo_path": logo_url,
                    "creatives_path": workspace.creatives_path,
                    "remarks": workspace.remarks,
                    "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
                    "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None
                },
                "creatives": creatives_data,
                "conversations": generations_data
            }), 200

        # Only owner may update (we already filtered by user.id)
        # Handle multipart/form-data
        # request.mimetype is safer for checking
        if request.mimetype and "multipart/form-data" in request.mimetype:
            form = request.form.to_dict()
            logo_file = request.files.get("logo")
        else:
            logger.warning("Invalid content type for update")
            return jsonify({"success": False, "error": "invalid_content_type", "details": "Expected multipart/form-data"}), 400

        fields = [
            'business_name', 'business_type', 'registered_address', 'b2b_b2c',
            'industry', 'description', 'audience_description', 'website',
            'competitor_direct_1', 'competitor_direct_2', 'competitor_indirect_1',
            'competitor_indirect_2', 'social_links', 'usp', 'creatives_path', 'remarks'
        ]
        for field in fields:
            if field in form and form[field] is not None:
                if field == 'social_links':
                    try:
                        json.loads(form[field])
                        setattr(workspace, field, form[field])
                    except json.JSONDecodeError:
                        logger.warning("Invalid social_links format")
                        return jsonify({"success": False, "error": "invalid_social_links_format"}), 400
                else:
                    setattr(workspace, field, form[field].strip())

        # Normalize old logo path handling. store relative path WITHOUT leading "uploads/"
        old_logo_rel = workspace.logo_path  # keep as relative like "2/logo_xxx.png"

        if logo_file and logo_file.filename:
            if not allowed_file(logo_file.filename):
                logger.warning("Invalid logo file type")
                return jsonify({"success": False, "error": "invalid_logo_file_type", "details": "Allowed types: png, jpg, jpeg, gif"}), 400

            # User-specific dir under UPLOAD_BASE
            user_upload_dir = os.path.join(UPLOAD_BASE, str(user.id))
            os.makedirs(user_upload_dir, exist_ok=True)

            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            safe_name = secure_filename(logo_file.filename)
            ext = os.path.splitext(safe_name)[1]
            logo_filename = f"logo_{workspace_id}_{timestamp}{ext}"
            logo_abs_path = os.path.join(user_upload_dir, logo_filename)

            try:
                logo_file.save(logo_abs_path)
                # store relative path (no leading uploads/)
                workspace.logo_path = os.path.join(str(user.id), logo_filename).replace('\\','/')
                logger.info(f"Uploaded new logo for workspace {workspace_id}: {workspace.logo_path}")
            except Exception as e:
                logger.warning("Failed to save logo file %s: %s", logo_abs_path, e)
                return jsonify({"success": False, "error": "logo_upload_failed", "details": str(e)}), 500

            # best-effort cleanup of old logo (old_logo_rel is relative)
            if old_logo_rel:
                try:
                    old_abs = os.path.join(UPLOAD_BASE, old_logo_rel)
                    if os.path.exists(old_abs):
                        os.remove(old_abs)
                        logger.info(f"Removed old logo {old_logo_rel} for workspace {workspace_id}")
                except Exception as e:
                    logger.warning("Could not remove old logo file %s: %s", old_logo_rel, e)

        workspace.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            logger.info(f"Workspace {workspace_id} updated successfully")
        except Exception as e:
            db.session.rollback()
            logger.exception("DB update failed for workspace %s", workspace_id)
            return jsonify({"success": False, "error": "db_update_failed", "details": str(e)}), 500

        log_action(user.email or "system", "workspace_update", user.id, {"workspace_id": workspace_id})

        logo_url = f"{APP_BASE_URL}/uploads/{workspace.logo_path}" if workspace.logo_path else None

        return jsonify({
            "success": True,
            "message": "workspace_updated",
            "workspace": {
                "id": workspace.id,
                "user_id": workspace.user_id,
                "business_name": workspace.business_name,
                "business_type": workspace.business_type,
                "registered_address": workspace.registered_address,
                "b2b_b2c": workspace.b2b_b2c,
                "industry": workspace.industry,
                "description": workspace.description,
                "audience_description": workspace.audience_description,
                "website": workspace.website,
                "competitor_direct_1": workspace.competitor_direct_1,
                "competitor_direct_2": workspace.competitor_direct_2,
                "competitor_indirect_1": workspace.competitor_indirect_1,
                "competitor_indirect_2": workspace.competitor_indirect_2,
                "social_links": workspace.social_links,
                "usp": workspace.usp,
                "logo_path": logo_url,
                "creatives_path": workspace.creatives_path,
                "remarks": workspace.remarks,
                "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
                "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None
            }
        }), 200

    except Exception as e:
        logger.exception("Workspace update failed for workspace_id %s", workspace_id)
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500

@app.route('/api/generations', methods=['GET', 'OPTIONS'])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['GET','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_generations():
    logger.info("Request to /api/generations")
    try:
        user = get_user_from_request(require=True)
        if not user:
            logger.warning("Authentication failed for generations")
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        workspace_id = request.args.get('workspace_id', type=int)
        if not workspace_id:
            logger.warning("Missing workspace_id")
            return jsonify({"success": False, "error": "missing_workspace_id"}), 400

        # Ensure workspace belongs to user
        workspace = Workspace.query.filter_by(id=workspace_id, user_id=user.id).first()
        if not workspace:
            logger.warning(f"Workspace {workspace_id} not found or forbidden for user {user.id}")
            return jsonify({"success": False, "error": "not_found_or_forbidden"}), 404

        generations = Generation.query.filter(Generation.workspace_id == str(workspace_id)).order_by(Generation.created_at.desc()) .all()

        generations_data = [
            {
                "id": g.id,
                "prompt": g.prompt,
                "response": g.response,
                "created_at": g.created_at.isoformat() if g.created_at else None
            } for g in generations
        ]
        logger.info(f"Fetched {len(generations_data)} generations for workspace {workspace_id}")

        return jsonify({
            "success": True,
            "generations": generations_data
        }), 200

    except Exception as e:
        logger.exception("Generations fetch failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500

@app.route('/api/generations/me', methods=['GET', 'OPTIONS'])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['GET','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_generations_me():
    logger.info("Request to /api/generations/me")
    try:
        user = get_user_from_request(require=True)
        if not user:
            logger.warning("Authentication failed for generations/me")
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        # For non-workspace mode, fetch generations without workspace_id
        generations = Generation.query.filter_by(user_id=user.id, workspace_id=None).order_by(Generation.created_at.desc()).all()
        generations_data = [
            {
                "id": g.id,
                "prompt": g.prompt,
                "response": g.response,
                "created_at": g.created_at.isoformat() if g.created_at else None
            } for g in generations
        ]
        logger.info(f"Fetched {len(generations_data)} generations for user {user.id} (non-workspace)")

        return jsonify({
            "success": True,
            "generations": generations_data
        }), 200

    except Exception as e:
        logger.exception("Generations me fetch failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500
@app.route("/api/workspace/<int:workspace_id>", methods=["DELETE", "OPTIONS"])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['DELETE','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_workspace_delete(workspace_id):
    """
    Delete a workspace.
    - Authenticated route (get_user_from_request(require=True))
    - Only owner can delete (or admins if your app supports that)
    - Cleans up uploaded files (logo + creatives) stored under UPLOAD_BASE
    """
    try:
        user = get_user_from_request(require=True)
        if not user:
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        # Fetch workspace
        workspace = Workspace.query.filter_by(id=workspace_id).first()
        if not workspace:
            return jsonify({"success": False, "error": "not_found"}), 404

        # Authorization: only owner may delete
        if workspace.user_id != user.id:
            # Optional: allow admins to delete
            # if not getattr(user, "is_admin", False):
            return jsonify({"success": False, "error": "forbidden"}), 403

        # File cleanup (best-effort; never fail the whole operation because of missing file)
        try:
            # workspace.logo_path is expected to be something like "2/logo_xxx.png"
            if workspace.logo_path:
                logo_abs = os.path.join(UPLOAD_BASE, workspace.logo_path)
                if os.path.exists(logo_abs):
                    try:
                        os.remove(logo_abs)
                    except Exception as e:
                        logger.warning("Could not remove logo file %s: %s", logo_abs, e)

            # creatives_paths stored as JSON array of relative paths (or None)
            if workspace.creatives_paths:
                try:
                    creatives_list = json.loads(workspace.creatives_paths)
                except Exception:
                    creatives_list = workspace.creatives_paths if isinstance(workspace.creatives_paths, list) else []

                for p in creatives_list or []:
                    try:
                        abs_path = os.path.join(UPLOAD_BASE, p)
                        if os.path.exists(abs_path):
                            os.remove(abs_path)
                    except Exception as e:
                        logger.warning("Could not remove creative file %s: %s", p, e)
        except Exception as e:
            # don't abort on file cleanup failure; just log
            logger.exception("File cleanup error while deleting workspace %s: %s", workspace_id, e)

        # Delete DB row (hard delete). If you want soft-delete, set a flag instead.
        try:
            db.session.delete(workspace)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.exception("DB delete failed for workspace %s", workspace_id)
            return jsonify({"success": False, "error": "db_delete_failed", "details": str(e)}), 500

        # Optional: filesystem-level cleanup for user's directory if empty
        try:
            user_dir = os.path.join(UPLOAD_BASE, str(user.id))
            if os.path.isdir(user_dir) and not os.listdir(user_dir):
                try:
                    os.rmdir(user_dir)
                except Exception as e:
                    logger.debug("Could not remove empty user upload dir %s: %s", user_dir, e)
        except Exception:
            pass

        log_action(user.email or "system", "workspace_delete", user.id, {"workspace_id": workspace_id})

        return jsonify({"success": True, "message": "workspace_deleted", "workspace_id": workspace_id}), 200

    except Exception as e:
        logger.exception("Workspace delete failed")
        # In dev you can include details; in prod avoid leaking internal details
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500
    
from flask import request, jsonify
from app import db
from models import Workspace
import json
from datetime import datetime
import logging
from flask import jsonify, request


# Define Creative model
class Creative(db.Model):
    __tablename__ = 'creatives'
    __table_args__ = {"extend_existing": True}
    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.String(128), nullable=False)
    workspace_id = db.Column(db.String(128), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    filename = db.Column(db.String(256))
    type = db.Column(db.String(32))  # 'generated' or 'saved'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
from app import db
from models import Workspace
import json
from datetime import datetime
import logging
from flask import jsonify, request


@app.route("/api/workspace", methods=["GET"])
def api_workspace_get():
    """
    GET /api/workspace
    Query params:
      - user_id (optional): numeric id of user whose workspaces to fetch
      - workspace_id (optional): specific workspace id to fetch
    If user is authenticated and no user_id is provided, returns the requesting user's workspace(s).
    """
    from sqlalchemy import cast, Integer
    import json

    def _safe_json(v, default):
        if v is None:
            return default
        if isinstance(v, (list, dict)):
            return v
        try:
            return json.loads(v)
        except Exception:
            return default

    def _logo_url(path):
        if not path:
            return None
        p = str(path)
        return p if p.startswith("http://") or p.startswith("https://") else f"{APP_BASE_URL}/uploads/{p}"

    try:
        # Parse query params
        q_user_id = request.args.get("user_id")
        q_workspace_id = request.args.get("workspace_id")

        # Coerce to int if present
        if q_user_id is not None:
            try:
                q_user_id_int = int(q_user_id)
            except ValueError:
                return jsonify({"success": False, "error": "invalid_user_id"}), 400
        else:
            q_user_id_int = None

        if q_workspace_id is not None:
            try:
                q_workspace_id_int = int(q_workspace_id)
            except ValueError:
                return jsonify({"success": False, "error": "invalid_workspace_id"}), 400
        else:
            q_workspace_id_int = None

        # Optional auth (public fetch allowed)
        try:
            user = get_user_from_request(require=False)
        except Exception:
            user = None

        # Decide which user_id to use
        if q_user_id_int is not None:
            use_user_id = q_user_id_int
        elif user:
            try:
                use_user_id = int(getattr(user, "id", user))
            except Exception:
                return jsonify({"success": False, "error": "could_not_resolve_user_id"}), 500
        else:
            return jsonify({"success": False, "error": "user_id_required"}), 400

        # ---------- Single workspace ----------
        if q_workspace_id_int is not None:
            workspace = Workspace.query.filter_by(id=q_workspace_id_int, user_id=use_user_id).first()
            if not workspace:
                return jsonify({"success": False, "error": "not_found"}), 404

            # Cast column to int to avoid varchar=int mismatch
            creatives = (
                Creative.query
                .filter(cast(Creative.workspace_id, Integer) == int(q_workspace_id_int))
                .order_by(Creative.created_at.desc())
                .all()
            )
            creatives_out = [{
                "id": c.id,
                "user_id": c.user_id,
                "workspace_id": c.workspace_id,
                "url": getattr(c, "url", None),
                "filename": getattr(c, "filename", None),
                "type": getattr(c, "type", None),
                "created_at": c.created_at.isoformat() if c.created_at else None
            } for c in creatives]

            direct_competitors = [workspace.competitor_direct_1, workspace.competitor_direct_2]
            indirect_competitors = [workspace.competitor_indirect_1, workspace.competitor_indirect_2]

            return jsonify({
                "success": True,
                "workspace": {
                    "id": workspace.id,
                    "user_id": workspace.user_id,
                    "business_name": workspace.business_name,
                    "description": workspace.description,
                    "audience_description": workspace.audience_description,
                    "website": workspace.website,
                    "direct_competitors": [c for c in direct_competitors if c],
                    "indirect_competitors": [c for c in indirect_competitors if c],
                    "social_links": _safe_json(workspace.social_links, []),
                    "usp": workspace.usp,
                    "logo_path": _logo_url(workspace.logo_path),
                    "creatives_path": _safe_json(workspace.creatives_path, []),
                    "created_at": workspace.created_at.isoformat() if getattr(workspace, "created_at", None) else None,
                    "updated_at": workspace.updated_at.isoformat() if getattr(workspace, "updated_at", None) else None,
                },
                "creatives": creatives_out
            }), 200

        # ---------- All workspaces for the user ----------
        workspaces = (
            Workspace.query
            .filter_by(user_id=use_user_id)
            .order_by(Workspace.id.desc())
            .all()
        )

        out = []
        for w in workspaces:
            direct_competitors = [getattr(w, "competitor_direct_1", None), getattr(w, "competitor_direct_2", None)]
            indirect_competitors = [getattr(w, "competitor_indirect_1", None), getattr(w, "competitor_indirect_2", None)]
            socials = _safe_json(getattr(w, "social_links", None), [])
            creatives_path = _safe_json(getattr(w, "creatives_path", None), [])

            # Count with cast to int (works even if column is varchar)
            creatives_count = Creative.query.filter(cast(Creative.workspace_id, Integer) == int(w.id)).count()

            out.append({
                "id": w.id,
                "user_id": w.user_id,
                "business_name": w.business_name,
                "description": w.description,
                "audience_description": w.audience_description,
                "website": w.website,
                "direct_competitors": [c for c in direct_competitors if c],
                "indirect_competitors": [c for c in indirect_competitors if c],
                "social_links": socials,
                "usp": w.usp,
                "logo_path": _logo_url(w.logo_path),
                "creatives_path": creatives_path,
                "creatives_count": creatives_count,
                "created_at": w.created_at.isoformat() if getattr(w, "created_at", None) else None,
                "updated_at": w.updated_at.isoformat() if getattr(w, "updated_at", None) else None,
            })

        return jsonify({"success": True, "workspaces": out}), 200

    except Exception as e:
        logger.exception("Workspace fetch failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500
 
@app.after_request
def _add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in FRONTEND_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type,Authorization,X-Requested-With,X-User-Id,X-User-Email"
        )
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    return response


@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:8080")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    return response
from flask import request, jsonify
from models import Workspace  # adjust import if needed
 # your SQLAlchemy db instance
USER_WORKSPACES = {
    "9": {"id": 9, "name": "Shiva's Workspace", "role": "Owner"},
    "10": {"id": 10, "name": "Team Workspace", "role": "Member"}
}


import json
import os
from datetime import datetime

@app.route("/api/workspace/me", methods=["GET"])
def get_workspace_me():
    # Resolve user_id from query param first, otherwise try session/header via helper
    user_id = request.args.get("user_id")
    if not user_id:
        user = get_user_from_request(require=False)
        user_id = getattr(user, "id", None)

    try:
        user_id = int(user_id)
    except Exception:
        return jsonify({"success": False, "error": "missing_or_invalid_user_id"}), 400

    # Attempt to fetch workspace
    try:
        workspace = Workspace.query.filter_by(user_id=user_id).first()
    except Exception as e:
        logger.exception("DB error fetching workspace")
        return jsonify({"success": False, "error": "db_error", "details": str(e)}), 500

    # No workspace row
    if not workspace:
        return jsonify({"success": True, "workspace": None}), 200

    # If the route somehow returns the mock dict (old code), return normalized shape
    if isinstance(workspace, dict):
        # mock -> map to expected shape
        result = {
            "id": workspace.get("id"),
            "user_id": workspace.get("id"),
            "business_name": workspace.get("name") or "",
            "business_type": "",
            "registered_address": "",
            "b2b_b2c": "",
            "industry": "",
            "describe_business": "",
            "describe_audience": "",
            "website": "",
            "direct_competitors": [],
            "indirect_competitors": [],
            "social_links": [],
            "usp": "",
            "logo_path": None,
            "logo_url": None,
            "creative_urls": [],
            "additional_remarks": None,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        return jsonify({"success": True, "workspace": result}), 200

    # At this point we expect a SQLAlchemy Workspace object — read attributes defensively
    def g(name, default=None):
        try:
            return getattr(workspace, name, default)
        except Exception:
            return default

    # Debug: log available attribute names (helpful to see what's missing)
    try:
        logger.debug("Workspace object dir(): %s", [a for a in dir(workspace) if not a.startswith("_")][:200])
    except Exception:
        pass

    # Safe JSON loads helper
    def safe_load(text_or_none):
        if not text_or_none:
            return []
        try:
            return json.loads(text_or_none)
        except Exception:
            return []

    created_at = g("created_at")
    updated_at = g("updated_at")

    def iso_or_none(dt):
        try:
            return dt.isoformat()
        except Exception:
            return None

    creatives = safe_load(g("creatives_paths") or "[]")
    direct_competitors = safe_load(g("direct_competitors") or "[]")
    indirect_competitors = safe_load(g("indirect_competitors") or "[]")
    social_links = safe_load(g("social_links") or "[]")

    logo_path = g("logo_path")
    logo_url = None
    if logo_path:
        logo_url = f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{g('user_id')}/{os.path.basename(logo_path)}"

    result = {
        "id": g("id"),
        "user_id": g("user_id"),
        "business_name": g("business_name") or "",
        "business_type": g("business_type") or "",
        "registered_address": g("registered_address") or "",
        "b2b_b2c": g("b2b_b2c") or "",
        "industry": g("industry") or "",
        "describe_business": g("describe_business") or "",
        "describe_audience": g("describe_audience") or "",
        "website": g("website") or "",
        "direct_competitors": direct_competitors,
        "indirect_competitors": indirect_competitors,
        "social_links": social_links,
        "usp": g("usp") or "",
        "logo_path": logo_path,
        "logo_url": logo_url,
        "creative_urls": [f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{g('user_id')}/{os.path.basename(p)}" for p in creatives],
        "additional_remarks": g("additional_remarks"),
        "created_at": iso_or_none(created_at),
        "updated_at": iso_or_none(updated_at),
    }

    return jsonify({"success": True, "workspace": result}), 200

@app.route("/api/workspace/caps", methods=["GET"])
def api_workspace_caps():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Missing user_id"}), 400

    # Example caps (replace with DB logic if needed)
    caps = [
        {"name": "Campaigns", "used": 3, "limit": 10},
        {"name": "Team Members", "used": 2, "limit": 5},
        {"name": "Storage (GB)", "used": 1, "limit": 5},
    ]

    return jsonify({"success": True, "caps": caps})


# ---------------- metaa - marketingg  ----------------

def get_facebook_token_for_user(user_id):
    sa = SocialAccount.query.filter_by(provider="facebook", user_id=user_id).first()
    if not sa or not sa.access_token:
        return None
    return sa.access_token


import requests

@app.route("/api/meta/adaccounts", methods=["GET"])
def list_ad_accounts():
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    if not token:
        return jsonify({"success": False, "error": "no_facebook_token"}), 403

    url = f"https://graph.facebook.com/v16.0/me/adaccounts"
    params = {"access_token": token, "fields": "account_id,name,currency,timezone_id"}
    r = requests.get(url, params=params, timeout=10)
    if r.status_code != 200:
        return jsonify({"success": False, "error": "fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "ad_accounts": r.json().get("data", [])}), 200

@app.route("/api/meta/adaccounts/<account_id>/campaigns", methods=["POST"])
def create_campaign(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    if not token:
        return jsonify({"success": False, "error": "no_facebook_token"}), 403

    data = request.json or {}
    name = data.get("name", "New Campaign")
    objective = data.get("objective", "LINK_CLICKS")  # choose valid objective
    status = data.get("status", "PAUSED")

    url = f"https://graph.facebook.com/v16.0/act_{account_id}/campaigns"
    params = {"access_token": token}
    payload = {"name": name, "objective": objective, "status": status}
    r = requests.post(url, params=params, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error": "fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "campaign": r.json()}), 201

@app.route("/api/meta/adaccounts/<account_id>/adsets", methods=["POST"])
def create_adset(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    body = request.json or {}

    payload = {
      "name": body.get("name","My AdSet"),
      "campaign_id": body["campaign_id"],
      "daily_budget": body.get("daily_budget", 1000),  # in minor units (e.g., cents)
      "billing_event": body.get("billing_event","IMPRESSIONS"),
      "optimization_goal": body.get("optimization_goal","LINK_CLICKS"),
      "bid_strategy": body.get("bid_strategy","LOWEST_COST_WITHOUT_CAP"),
      "targeting": json.dumps(body.get("targeting", {"geo_locations":{"countries":["US"]}})),
      "start_time": body.get("start_time"),  # ISO8601 or timestamp
      "end_time": body.get("end_time"),
      "status": body.get("status","PAUSED")
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/adsets"
    r = requests.post(url, params={"access_token": token}, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error":"fb_error","details": r.json()}), r.status_code
    return jsonify({"success": True,"adset": r.json()}), 201


@app.route("/api/meta/adaccounts/<account_id>/creatives", methods=["POST"])
def create_creative(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    body = request.json or {}

    # Example: link ad creative
    object_story_spec = {
        "page_id": body["page_id"],
        "link_data": {
            "message": body.get("message", "Try it!"),
            "link": body["link"],
            "caption": body.get("caption",""),
        }
    }

    payload = {
        "name": body.get("name","Creative"),
        "object_story_spec": json.dumps(object_story_spec)
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/adcreatives"
    r = requests.post(url, params={"access_token": token}, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error":"fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "creative": r.json()}), 201

@app.route("/api/meta/adaccounts/<account_id>/ads", methods=["POST"])
def create_ad(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    body = request.json or {}
    payload = {
        "name": body.get("name","My Ad"),
        "adset_id": body["adset_id"],
        "creative": json.dumps({"creative_id": body["creative_id"]}),
        "status": body.get("status","PAUSED")
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/ads"
    r = requests.post(url, params={"access_token": token}, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error":"fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "ad": r.json()}), 201


@app.route("/api/meta/adaccounts/<account_id>/insights", methods=["GET"])
def ad_account_insights(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    params = {
        "access_token": token,
        "level": request.args.get("level","ad"),
        "time_range": json.dumps({"since": request.args.get("since"), "until": request.args.get("until")}),
        "fields": request.args.get("fields","impressions,clicks,spend,ctr")
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/insights"
    r = requests.get(url, params=params, timeout=20)
    return jsonify({"success": r.status_code == 200, "data": r.json()}), r.status_code


@app.route("/api/social/accounts", methods=["GET", "OPTIONS"])
def api_social_accounts():
    if request.method == "OPTIONS":
        # Preflight
        return jsonify({}), 200
    # Normal GET
    accounts = SocialAccount.query.all()
    return jsonify({"accounts": [a.serialize() for a in accounts]})


@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        headers = resp.headers

        headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-User-Id, X-User-Email"
        headers["Access-Control-Allow-Credentials"] = "true"

        return resp

@app.route('/')
def index():
    return "SOCIOVIA running. POST credentials to endpoints to fetch data."


# Add to your Flask app.py

@app.route("/api/workspaces", methods=["GET"])
def api_workspaces():
    """Return all workspaces for the current user"""
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    
    # Get all workspaces for this user
    workspaces = Workspace.query.filter_by(user_id=user.id).all()
    
    result = []
    for workspace in workspaces:
        # Format each workspace to match the expected frontend structure
        result.append({
            "id": workspace.id,
            "name": workspace.business_name,
            "sector": workspace.industry,
            "role": "Owner",  # Default role
            "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
            "logo": workspace.logo_path if hasattr(workspace, 'logo_path') else None
        })
    
    return jsonify({"success": True, "workspaces": result}), 200

@app.route("/api/workspace/list", methods=["GET"])
def api_workspace_list():
    """Alternative endpoint for workspace list"""
    return api_workspaces()  # Reuse the same implementation

@app.route("/api/workspace/metrics", methods=["GET"])
def api_workspace_metrics():
    """Return metrics for workspaces"""
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    
    workspaces = Workspace.query.filter_by(user_id=user.id).all()
    metrics = {}
    
    for workspace in workspaces:
        # Create mock metrics for each workspace (replace with real data)
        metrics[workspace.id] = {
            "workspace_id": workspace.id,
            "total_spend": 10000 + workspace.id * 100,
            "leads": 500 + workspace.id * 50,
            "active_campaigns": (workspace.id % 5) + 1,
            "reach": 10000 + workspace.id * 1000,
            "impressions": 50000 + workspace.id * 5000,
            "clicks": 3000 + workspace.id * 300,
            "ctr": 6.0 - (workspace.id % 5) * 0.2,
            "cpm": 15.0 + (workspace.id % 5) * 0.5,
            "last_updated": datetime.utcnow().isoformat()
        }
    
    return jsonify({"success": True, "metrics": metrics}), 200

# ---------------- Password reset endpoints ----------------
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

# TTL for password reset tokens (hours)
RESET_TTL_HOURS = int(app.config.get("RESET_TTL_HOURS", os.getenv("RESET_TTL_HOURS", 2)))
# Constants (near other config constants)
RESET_TTL_SECONDS = int(os.getenv("RESET_TTL_SECONDS", 3600))  # 1 hour by default

# ---------------- Password reset endpoints (consolidated) ----------------
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

# TTL for password reset tokens (seconds). Can be overridden via env/config.
RESET_TTL_SECONDS = int(app.config.get("RESET_TTL_SECONDS", os.getenv("RESET_TTL_SECONDS", 3600)))
# Also provide hours for human messaging if needed
RESET_TTL_HOURS = max(1, int(RESET_TTL_SECONDS // 3600))

# FRONTEND base used for reset link (point to your frontend site)
FRONTEND_BASE_URL = app.config.get("FRONTEND_BASE_URL", os.getenv("FRONTEND_BASE_URL", "https://sociovia.com"))

def _build_reset_url(token: str) -> str:
    return f"{FRONTEND_BASE_URL.rstrip('/')}/reset-password?token={token}"

@app.route("/api/password/forgot", methods=["POST"])
def api_password_forgot():
    """
    Request a password reset. Body: { "email": "<email>" }.
    Sends a single-use token link to the user's email (token TTL controlled by RESET_TTL_SECONDS).
    """
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "email_required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Do NOT reveal that the email is missing: return generic success
        logger.info("Password reset requested for unknown email: %s", email)
        return jsonify({"success": True, "message": "If the email exists, a reset link has been sent."}), 200

    try:
        # Create signed reset token (stateless). Uses your existing make_action_token function.
        token = make_action_token({
            "user_id": user.id,
            "action": "reset_password",
            "issued_at": datetime.utcnow().isoformat()
        })

        reset_url = _build_reset_url(token)

        # Try to render your template; pass both reset_url and reset_link names
        try:
            email_body = load_email_template(
                "password_reset.txt",
                {"name": user.name or user.email, "reset_url": reset_url, "reset_link": reset_url, "ttl_hours": RESET_TTL_HOURS}
            )
        except Exception:
            # Fallback to simple text if template missing or rendering fails
            email_body = (
                f"Hi {user.name or user.email},\n\n"
                f"We received a request to reset your password.\n\n"
                f"Click the link below to reset your password (valid for {RESET_TTL_HOURS} hour(s)):\n\n"
                f"{reset_url}\n\n"
                "If you didn't request this, please ignore this email.\n\n"
                "Thanks,\nSociovia Team\nhttps://sociovia.com"
            )

        send_mail_to(user.email, "Sociovia — Password reset instructions", email_body)
        log_action("system", "password_reset_requested", user.id)
    except Exception as e:
        logger.exception("Failed to process forgot-password for %s", email)
        # Keep response generic for security
        return jsonify({"success": False, "error": "internal_error"}), 500

    return jsonify({"success": True, "message": "If the email exists, a reset link has been sent."}), 200


# Compatibility alias (optional) - forwards to canonical endpoint
@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password_alias():
    return api_password_forgot()


@app.route("/api/password/forgot/validate", methods=["GET"])
def api_password_reset_validate():
    """
    Validate a reset token -> returns {"valid": True, "user_id": ...} or {"valid": False, "error": "..."}.
    Accepts token as query param: ?token=...
    """
    token = request.args.get("token") or ""
    if not token:
        return jsonify({"valid": False, "error": "token_required"}), 400
    try:
        payload = load_action_token(token, RESET_TTL_SECONDS)
        if payload.get("action") != "reset_password":
            return jsonify({"valid": False, "error": "invalid_action"}), 400
        user_id = payload.get("user_id")
        user = User.query.get(user_id)
        if not user:
            return jsonify({"valid": False, "error": "user_not_found"}), 404
        return jsonify({"valid": True, "user_id": user_id, "email": user.email}), 200
    except Exception as e:
        logger.exception("Reset token validate failed: %s", e)
        return jsonify({"valid": False, "error": "invalid_or_expired_token"}), 400


@app.route("/api/password/reset", methods=["POST"])
def api_password_reset():
    """
    Reset the password. Body: { token: string, password: string }
    """
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("password") or ""

    if not token or not new_password:
        return jsonify({"success": False, "error": "token_and_password_required"}), 400

    # Basic password policy check (reuse valid_password from utils)
    if not valid_password(new_password):
        return jsonify({"success": False, "error": "password_policy_failed"}), 400

    try:
        payload = load_action_token(token, RESET_TTL_SECONDS)
    except Exception as e:
        logger.warning("Invalid/expired reset token: %s", e)
        return jsonify({"success": False, "error": "invalid_or_expired_token"}), 400

    if payload.get("action") != "reset_password":
        return jsonify({"success": False, "error": "invalid_action"}), 400

    user_id = payload.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "user_not_found"}), 404

    # All good: update password
    try:
        user.password_hash = generate_password_hash(new_password)
        db.session.add(user)
        db.session.commit()
        log_action("system", "password_reset_completed", user.id)

        # Try to send confirmation email (non-fatal if it fails)
        try:
            email_body = load_email_template("password_reset_confirm.txt", {"name": user.name or user.email})
        except Exception:
            email_body = f"Hi {user.name or user.email},\n\nYour password was successfully changed.\n\nIf you did not request this, please contact support.\n\nSociovia Team"
        send_mail_to(user.email, "Your Sociovia password has been changed", email_body)

        return jsonify({"success": True, "message": "password_reset_success"}), 200
    except Exception as e:
        logger.exception("Failed to update password for user %s: %s", user_id, e)
        return jsonify({"success": False, "error": "internal_server_error"}), 500

# ---------------- FastAPI microservice for Facebook Graph API proxy ----------------

# ---------------- CORS preflight handler ----------------
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        headers = resp.headers
        headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-User-Id, X-User-Email"
        headers["Access-Control-Allow-Credentials"] = "true"
        return resp

from flask import request, make_response

# canonical list of allowed origins (dev + prod)
ALLOWED_ORIGINS = {
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://127.0.0.1",
    "https://localhost:3000",
    "https://sociovia.com",
    "https://sociovia-c9473.web.app",
    "https://6136l5dn-5000.inc1.devtunnels.ms",
}

@app.after_request
def after_request(response):
    origin = request.headers.get("Origin")
    # only echo back allowed origins (do NOT echo arbitrary origins when using credentials)
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS,PATCH"
        # include any custom headers your frontend sends
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Requested-With, "
            "X-User-Id, X-User-Email"
        )
        # tell caches that the response varies by Origin
        response.headers["Vary"] = "Origin"
    return response

# handle preflight quickly (optional but recommended)
@app.route("/api/<path:_>", methods=["OPTIONS"])
def handle_preflight(_):
    # empty 200 response — after_request will add the CORS headers
    return make_response("", 200)

# ---------------- Facebook-first OAuth routes (compatibility) ----------------
def _build_fb_oauth_url(state: str, scopes: str = None):
    client_id = FB_APP_ID
    redirect_uri = f"{OAUTH_REDIRECT_BASE.rstrip('/')}/api/oauth/facebook/callback"
    use_scopes = scopes or OAUTH_SCOPES
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': use_scopes,
        'response_type': 'code',
        'state': state,
    }
    return f"https://www.facebook.com/{FB_API_VERSION}/dialog/oauth?{urlencode(params)}"

# Support legacy /api/oauth/instagram/connect by routing to FB connect for now (compat)
@app.route('/api/oauth/facebook/connect', methods=['GET'])
@app.route('/api/oauth/instagram/connect', methods=['GET'])
def oauth_facebook_connect():
    # Read incoming state (may already be JSON or a plain string)
    incoming_state = request.args.get('state') or ''
    raw_user_id = request.args.get('user_id')

    # Build a JSON state object so we can carry user_id through the FB OAuth dance.
    # If incoming_state is JSON, merge; otherwise keep it under "s".
    state_payload = {}
    if incoming_state:
        try:
            parsed = json.loads(incoming_state)
            if isinstance(parsed, dict):
                state_payload.update(parsed)
            else:
                state_payload['s'] = incoming_state
        except Exception:
            state_payload['s'] = incoming_state

    # Add user_id if provided on the connect request
    if raw_user_id:
        try:
            state_payload['user_id'] = int(raw_user_id)
        except Exception:
            state_payload['user_id'] = raw_user_id

    # Final state string passed to FB (empty string if nothing)
    state_to_send = json.dumps(state_payload) if state_payload else ''

    current_app.logger.info('Starting Facebook connect (state=%s)', state_to_send)
    auth_url = _build_fb_oauth_url(state=state_to_send)
    return redirect(auth_url)

# Add this at the top of your Flask config or constants
OAUTH_SCOPES = [
    # Pages
    "pages_show_list",            # List all Pages the user manages
    "pages_read_engagement",      # Read Page insights and engagement
    "pages_manage_posts",         # Create, edit, delete Page posts
    "pages_manage_engagement",    # Moderate comments, respond to messages
    "pages_read_user_content",    # Read user-generated content on the Page
    "pages_manage_metadata",      # Read Page settings, roles, metadata
    "pages_manage_ads",           # Manage ads linked to Pages

    # Ads & Business
    "ads_management",             # Create/update/delete ad campaigns, sets, and ads
    "ads_read",                   # Read ads and insights
    "business_management",        # Access Business Manager assets and roles

    # Instagram
    "instagram_basic",            # Read Instagram account profile info
    "instagram_content_publish"   # Publish content to Instagram business accounts
]


OAUTH_SCOPES_STR = ",".join(OAUTH_SCOPES)
@app.route('/api/oauth/facebook/callback', methods=['GET'])
@app.route('/api/oauth/instagram/callback', methods=['GET'])
def oauth_facebook_callback():
    code = request.args.get('code')
    state = request.args.get('state') or ''
    error = request.args.get('error')
    frontend = FRONTEND_BASE_URL.rstrip('/')

    def render_response(payload):
        payload_json = json.dumps(payload)
        return render_template_string("""
<!doctype html><html><head><meta charset="utf-8"/></head><body>
<script>
(function(){
  var payload = {{payload|safe}};
  var targetOrigin = "{{frontend}}";
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(payload, targetOrigin);
      window.close();
    } else {
      var frag = "data=" + encodeURIComponent(JSON.stringify(payload));
      window.location.href = "{{frontend}}/oauth-complete#" + frag;
    }
  } catch(e) {
    var frag = "data=" + encodeURIComponent(JSON.stringify(payload));
    window.location.href = "{{frontend}}/oauth-complete#" + frag;
  }
})();
</script>
</body></html>
        """, payload=payload_json, frontend=frontend)

    # 1) validate
    if error or not code:
        payload = {"type": "sociovia_oauth_complete", "success": False, "state": state,
                   "fb_error": {"message": error or "no_code"}}
        return render_response(payload)

    # 2) exchange code -> short token
    token_url = f"https://graph.facebook.com/{FB_API_VERSION}/oauth/access_token"
    params = {
        'client_id': FB_APP_ID,
        'client_secret': FB_APP_SECRET,
        'redirect_uri': f"{OAUTH_REDIRECT_BASE.rstrip('/')}/api/oauth/facebook/callback",
        'code': code
    }
    try:
        r = requests.get(token_url, params=params, timeout=10)
        data = r.json()
        if 'error' in data:
            raise ValueError(data['error'])
        short_token = data.get('access_token')
    except Exception as exc:
        payload = {"type": "sociovia_oauth_complete", "success": False, "state": state,
                   "fb_error": {"message": "token_exchange_failed", "details": str(exc)}}
        return render_response(payload)

    # 3) exchange short -> long (best-effort)
    exch_url = f"https://graph.facebook.com/{FB_API_VERSION}/oauth/access_token"
    exch_params = {
        'grant_type': 'fb_exchange_token',
        'client_id': FB_APP_ID,
        'client_secret': FB_APP_SECRET,
        'fb_exchange_token': short_token
    }
    try:
        r2 = requests.get(exch_url, params=exch_params, timeout=10)
        long_token = r2.json().get('access_token', short_token)
    except Exception:
        long_token = short_token

    # 4) fetch pages
    try:
        pages_url = f"https://graph.facebook.com/{FB_API_VERSION}/me/accounts"
        pages_r = requests.get(pages_url, params={
            'access_token': long_token,
            'fields': 'id,name,access_token,instagram_business_account'
        }, timeout=10)
        pages = pages_r.json().get('data', [])
    except Exception as exc:
        payload = {"type": "sociovia_oauth_complete", "success": False, "state": state,
                   "fb_error": {"message": "fetch_pages_failed", "details": str(exc)}}
        return render_response(payload)

    # 5) resolve user - PRIORITIZE explicit request user_id (from query param), then session, then state fallback
    user = None
    user_id = None

    # 5.a check query param first (you asked user_id will be in request)
    raw_q_uid = request.args.get("user_id")
    print("DEBUG: callback raw user_id (query param):", raw_q_uid, flush=True)
    if raw_q_uid:
        try:
            parsed_uid = int(raw_q_uid)
            maybe_user = User.query.get(parsed_uid)
            if maybe_user:
                user = maybe_user
                user_id = maybe_user.id
                current_app.logger.info(f"oauth callback: using user_id from query param: {user_id}")
            else:
                current_app.logger.warning(f"oauth callback: user_id {parsed_uid} provided but user not found")
        except Exception as e:
            current_app.logger.warning(f"oauth callback: invalid user_id query param: {raw_q_uid} ({e})")

    # 5.b fallback to session if query param not present / invalid
    if not user:
        session_user = get_user_from_request(require=False)
        if session_user:
            user = session_user
            user_id = getattr(session_user, "id", None)
            current_app.logger.info(f"oauth callback: resolved session user_id={user_id}")

    # 5.c final fallback: parse state JSON or simple substring (kept but lower priority)
    if not user and state:
        try:
            parsed_state = json.loads(state)
            if isinstance(parsed_state, dict) and parsed_state.get("user_id"):
                try:
                    parsed_uid = int(parsed_state.get("user_id"))
                    maybe_user = User.query.get(parsed_uid)
                    if maybe_user:
                        user = maybe_user
                        user_id = maybe_user.id
                        current_app.logger.info(f"oauth callback: resolved user_id from state JSON: {user_id}")
                except Exception:
                    current_app.logger.warning("oauth callback: invalid user_id in state JSON")
        except Exception:
            # not JSON — attempt simple "user_id=NN" substring extraction
            if "user_id=" in state:
                try:
                    tail = state.split("user_id=")[1].split("&")[0]
                    parsed_uid = int(tail)
                    maybe_user = User.query.get(parsed_uid)
                    if maybe_user:
                        user = maybe_user
                        user_id = maybe_user.id
                        current_app.logger.info(f"oauth callback: resolved user_id from state substring: {user_id}")
                except Exception:
                    current_app.logger.warning("oauth callback: failed to parse user_id from state substring")

    # 6) save/update social accounts
    saved = []
    db_error = None
    try:
        for p in pages:
            page_id = str(p.get('id'))
            page_name = p.get('name') or ""
            page_token = p.get('access_token') or long_token
            ig = p.get('instagram_business_account')
            ig_id = str(ig.get('id')) if ig else None

            # DEBUG log
            current_app.logger.info(f"Saving page id={page_id}, name={page_name}, attaching user_id={user_id}")
            print("DEBUG: saving page, attaching user_id=", user_id, " page_id=", page_id, flush=True)

            try:
                existing = SocialAccount.query.filter_by(provider='facebook', provider_user_id=page_id).first()

                if existing:
                    # normalize existing.user_id if stored as empty string (or string "None")
                    try:
                        if existing.user_id == "" or existing.user_id is None:
                            existing.user_id = None
                    except Exception:
                        existing.user_id = None

                    existing.access_token = page_token
                    existing.scopes = ",".join(OAUTH_SCOPES) if isinstance(OAUTH_SCOPES, (list, tuple)) else str(OAUTH_SCOPES)
                    existing.instagram_business_id = ig_id

                    # only overwrite/attach owner if we have a resolved user_id
                    if user_id:
                        try:
                            existing.user_id = int(user_id)
                        except Exception:
                            existing.user_id = user_id
                        current_app.logger.info(f"Updated existing SocialAccount {page_id} owner -> {existing.user_id}")
                    db.session.add(existing)
                    db.session.flush()
                    saved.append(existing.serialize())
                else:
                    sa = SocialAccount(
                        provider='facebook',
                        provider_user_id=page_id,
                        account_name=page_name,
                        access_token=page_token,
                        user_id=(int(user_id) if user_id else None),
                        scopes=",".join(OAUTH_SCOPES) if isinstance(OAUTH_SCOPES, (list, tuple)) else str(OAUTH_SCOPES),
                        instagram_business_id=ig_id
                    )
                    db.session.add(sa)
                    db.session.flush()
                    current_app.logger.info(f"Created SocialAccount {page_id} owner -> {sa.user_id}")
                    print("DEBUG: created SocialAccount", sa.serialize(), flush=True)
                    saved.append(sa.serialize())
            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("Failed to save social account")
                db_error = str(e)
                # break early on per-account DB error to avoid partial inconsistent state
                break
    except Exception as e:
        db_error = str(e)

    # final commit (if no earlier DB error)
    try:
        if db_error is None:
            db.session.commit()
    except Exception as e:
        current_app.logger.exception("Final commit failed in oauth callback")
        db.session.rollback()
        db_error = str(e)

    resp_payload = {
        "type": "sociovia_oauth_complete",
        "success": (len(saved) > 0 and db_error is None),
        "state": state,
        "saved": saved,
        "fb_pages_count": len(pages),
        "user_attached": bool(user_id)
    }
    if db_error:
        resp_payload["db_error"] = db_error

    return render_response(resp_payload)


@app.route('/api/oauth/facebook/save-selection', methods=['POST'])
@cross_origin(origins=["https://sociovia.com","https://6136l5dn-5000.inc1.devtunnels.ms"], supports_credentials=True)
def oauth_save_selection():
    """
    Request body:
    {
      "user_id": 2,
      "accounts": [
         { "provider":"facebook", "provider_user_id":"123", "name":"My Page", "access_token":"...", "instagram_business_id":"..." },
         ...
      ],
      "features": { "pages_manage_posts": true, "ads_management": false }  # optional
    }
    """
    try:
        data = request.get_json(force=True, silent=True)
    except Exception as e:
        current_app.logger.warning("oauth_save_selection invalid json: %s", e)
        return jsonify({'success': False, 'error': 'invalid_json'}), 400

    if not data:
        return jsonify({'success': False, 'error': 'invalid_json'}), 400

    raw_user_id = data.get('user_id')
    print("DEBUG: oauth_save_selection raw_user_id:", raw_user_id, flush=True)
    if raw_user_id is None or raw_user_id == "":
        return jsonify({'success': False, 'error': 'missing_user_id'}), 400

    try:
        user_id = int(raw_user_id)
    except Exception:
        return jsonify({'success': False, 'error': 'invalid_user_id'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'user_not_found'}), 404

    accounts = data.get('accounts', [])
    features = data.get('features', {}) or {}
    saved = []

    try:
        for a in accounts:
            provider = a.get('provider') or 'facebook'
            pid = str(a.get('provider_user_id') or "").strip()
            if not pid:
                current_app.logger.warning("Skipping account with empty provider_user_id: %s", a)
                continue

            name = a.get('name') or a.get('account_name') or ""
            access_token = a.get('access_token') or None
            instagram_business_id = a.get('instagram_business_id') or a.get('instagram_business_account') or None

            # compute scopes_list
            if isinstance(a.get('scopes'), (list, tuple)):
                scopes_list = [s for s in a.get('scopes') if s]
            elif isinstance(a.get('scopes'), str) and a.get('scopes').strip():
                scopes_list = [s.strip() for s in a.get('scopes').replace("{","").replace("}","").split(",") if s.strip()]
            else:
                scopes_list = [k for k, v in (features or {}).items() if v]

            existing = SocialAccount.query.filter_by(provider=provider, provider_user_id=pid).first()
            if existing:
                # normalize user_id empty-string -> None
                if existing.user_id == "" or existing.user_id is None:
                    existing.user_id = None

                if name:
                    existing.account_name = name
                if access_token:
                    existing.access_token = access_token
                if instagram_business_id:
                    existing.instagram_business_id = instagram_business_id

                # Only set user_id if existing has no owner or owner == same user
                try:
                    if not existing.user_id:
                        existing.user_id = user.id
                    elif int(existing.user_id) == user.id:
                        existing.user_id = user.id
                    # else leave as-is (do not override another user's ownership)
                except Exception:
                    existing.user_id = user.id

                # merge scopes if provided
                if scopes_list:
                    existing_scopes = []
                    if existing.scopes:
                        if isinstance(existing.scopes, str):
                            existing_scopes = [s.strip() for s in existing.scopes.replace("{","").replace("}","").split(",") if s.strip()]
                        elif isinstance(existing.scopes, (list, tuple)):
                            existing_scopes = list(existing.scopes)
                    merged = list(dict.fromkeys(existing_scopes + scopes_list))
                    existing.scopes = ",".join(merged)

                db.session.add(existing)
                db.session.flush()
                saved.append(existing.serialize())
            else:
                new_scopes = ",".join(scopes_list) if scopes_list else ""
                sa = SocialAccount(
                    user_id=user.id,
                    provider=provider,
                    provider_user_id=pid,
                    account_name=name,
                    access_token=access_token,
                    instagram_business_id=instagram_business_id,
                    scopes=new_scopes
                )
                db.session.add(sa)
                db.session.flush()
                saved.append(sa.serialize())

        db.session.commit()
        return jsonify({'success': True, 'connected': saved}), 200

    except Exception as e:
        current_app.logger.exception("oauth_save_selection failed")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'db_error', 'message': str(e)}), 500



@app.route('/api/oauth/facebook/revoke', methods=['POST'])
@app.route('/api/oauth/instagram/revoke', methods=['POST'])
def oauth_revoke():
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'missing_user_id'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'user_not_found'}), 404

    provider = data.get('provider')
    provider_user_id = str(data.get('provider_user_id'))
    sa = SocialAccount.query.filter_by(
        provider=provider,
        provider_user_id=provider_user_id,
        user_id=user.id
    ).first()

    if not sa:
        return jsonify({'success': False, 'error': 'not_found'}), 404

    try:
        if sa.access_token:
            revoke_url = f"https://graph.facebook.com/{FB_API_VERSION}/me/permissions"
            requests.delete(revoke_url, params={'access_token': sa.access_token}, timeout=5)
    except Exception:
        logger.exception('Failed to call fb revoke')

    db.session.delete(sa)
    db.session.commit()
    return jsonify({'success': True}), 200

# Deauthorize & Data Deletion endpoints (hook into FB App settings)
@app.route('/api/oauth/deauthorize', methods=['POST'])
def fb_deauthorize():
    # FB sends a signed_request form param on deauth — you must verify it with your app secret.
    # For now accept and mark accounts disconnected (dev skeleton).
    payload = request.form or request.json or {}
    logger.info("FB deauthorize payload: %s", payload)
    # TODO: validate signed_request here
    # Example behavior: find user by facebook id in payload and remove tokens
    return jsonify({'success': True}), 200

@app.route('/api/data-deletion', methods=['POST'])
def fb_data_deletion():
    # Data deletion flow: FB will POST a request. You should start deletion and return a JSON with a status URL.
    body = request.get_json() or {}
    logger.info("FB data deletion request: %s", body)
    # TODO: implement actual deletion and return a reachable status/url per FB spec
    status_url = f"{APP_BASE_URL.rstrip('/')}/data-deletion-status?request_id={int(datetime.utcnow().timestamp())}"
    return jsonify({"url": status_url}), 200

# ---------------- Facebook Meta endpoints (ads, campaigns, insights) ----------------
def get_facebook_token_for_user(user_id):
    if not user_id:
        return None
    sa = SocialAccount.query.filter_by(provider="facebook", user_id=user_id).first()
    if not sa:
        return None
    # prefer the stored access_token
    token = getattr(sa, "access_token", None)
    return token

import os
import json
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from dotenv import load_dotenv  

BASE_DIR = Path(__file__).resolve().parent
STORAGE_FILE =BASE_DIR = Path(__file__).resolve().parent/ "tokens.json" 
    # ----- Storage helpers (file-backed demo) -----
async def read_storage() -> Dict[str, Any]:
    if not STORAGE_FILE.exists():
        await asyncio.to_thread(STORAGE_FILE.write_text, json.dumps({"pages": {}, "workspace_map": {}}))
    raw = await asyncio.to_thread(STORAGE_FILE.read_text)
    try:
        return json.loads(raw)
    except Exception:
        return {"pages": {}, "workspace_map": {}}

async def write_storage(payload: Dict[str, Any]):
    await asyncio.to_thread(STORAGE_FILE.write_text, json.dumps(payload, indent=2))

# ----- WebSocket connection manager (simple broadcast) -----
class ConnectionManager:
    def __init__(self):
        self.connections: List[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.connections.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self.lock:
            if ws in self.connections:
                self.connections.remove(ws)

    async def broadcast(self, message: Dict[str, Any]):
        text = json.dumps(message)
        async with self.lock:
            to_remove: List[WebSocket] = []
            for ws in list(self.connections):
                try:
                    await ws.send_text(text)
                except Exception:
                    to_remove.append(ws)
            for ws in to_remove:
                if ws in self.connections:
                    self.connections.remove(ws)

manager = ConnectionManager()

# ----- HTTP helper for Facebook Graph calls -----
async def fb_get(path: str, params: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/v17.0/{path}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.get(url, params=params)
        try:
            return r.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Invalid response from Facebook")

async def fb_post(path: str, params: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/v17.0/{path}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(url, data=params)
        try:
            return r.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Invalid response from Facebook")

# ----- Parse Insights -> WorkspaceMetrics (best-effort) -----
def parse_facebook_insights_to_metrics(page_id: str, insights_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Graph API insights response into a metrics dict frontend expects.
    The Graph API returns `data` array where each item has `name`, `period`, `values`.
    We try to extract: impressions, clicks (if available), reach, ctr, cpm estimate, leads (not usually on page insights).
    This function returns a dict containing keys: workspace_id (placeholder), page_id, impressions, clicks, reach, ctr, cpm, total_spend (unknown), leads (unknown), last_updated
    Adjust mapping per your Graph API calls (ads insights vs page insights differ).
    """
    metrics: Dict[str, Any] = {
        "workspace_id": None,
        "page_id": page_id,
        "impressions": 0,
        "clicks": 0,
        "reach": 0,
        "ctr": 0.0,
        "cpm": 0.0,
        "total_spend": 0.0,
        "leads": 0,
        "active_campaigns": 0,
        "last_updated": int(asyncio.get_event_loop().time()) if asyncio.get_event_loop().is_running() else 0,
        "insights_raw": insights_response,
    }

    data = insights_response.get("data") or []
    # Common names: page_impressions, page_impressions_unique, page_engaged_users, page_fans, etc.
    for item in data:
        name = item.get("name")
        values = item.get("values") or []
        # try last value numeric
        last_value = None
        if values:
            last = values[-1]
            # `value` could be number or dict
            last_value = last.get("value") if isinstance(last, dict) else last

        if name in ("page_impressions", "page_impressions_unique"):
            try:
                metrics["impressions"] = int(last_value or 0)
            except Exception:
                pass
        elif name in ("page_engaged_users",):
            try:
                metrics["reach"] = int(last_value or 0)
            except Exception:
                pass
        elif name in ("page_fan_adds", "page_fan_removes"):
            # ignore for now
            pass
        # Add other mapping rules as needed

    # Ads-level metrics (if you call /act_{ad_account}/insights) would include 'impressions', 'clicks', 'spend', 'ctr', 'cpm'
    # Check if insights_response already has totals in a different shape (some endpoints return a single object with fields)
    # Try to extract ads-like fields if present:
    if isinstance(insights_response, dict):
        # sometimes metrics are top-level keys
        for k in ("impressions", "clicks", "spend", "ctr", "cpm"):
            if k in insights_response:
                try:
                    if k == "spend":
                        metrics["total_spend"] = float(insights_response[k])
                    elif k == "impressions":
                        metrics["impressions"] = int(insights_response[k])
                    elif k == "clicks":
                        metrics["clicks"] = int(insights_response[k])
                    elif k == "ctr":
                        metrics["ctr"] = float(insights_response[k])
                    elif k == "cpm":
                        metrics["cpm"] = float(insights_response[k])
                except Exception:
                    pass

    # heuristics: compute ctr if impressions and clicks available
    try:
        imps = metrics.get("impressions", 0)
        clicks = metrics.get("clicks", 0)
        if imps and clicks:
            metrics["ctr"] = round((clicks / imps) * 100, 2)
    except Exception:
        metrics["ctr"] = 0.0

    # attempt approximate CPM if we have spend and impressions
    try:
        if metrics.get("impressions") and metrics.get("total_spend"):
            metrics["cpm"] = round((metrics["total_spend"] / (metrics["impressions"] / 1000 or 1)), 2)
    except Exception:
        metrics["cpm"] = 0.0

    # active_campaigns & leads require Ads API / conversion tracking; leave defaults
    return metrics

# ----- ROUTES -----

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/facebook/pages")
    async def list_pages():
        """
        Return pages we have stored (linked) with their metadata.
        """
        store = await read_storage()
        pages = list(store.get("pages", {}).values())
        return JSONResponse({"success": True, "pages": pages})

    @app.post("/api/facebook/unlink")
    async def unlink_page(req: Request):
        """
        Body: { pageId: '12345' }
        Removes stored page token and associated workspace mapping.
        """
        body = await req.json()
        page_id = str(body.get("pageId") or "")
        if not page_id:
            raise HTTPException(400, "pageId required")

        store = await read_storage()
        pages = store.get("pages", {})
        if page_id in pages:
            pages.pop(page_id, None)
            # remove mappings to workspace
            wsmap = store.get("workspace_map", {})
            to_delete = [k for k, v in wsmap.items() if str(v) == page_id]
            for k in to_delete:
                wsmap.pop(k, None)
            store["workspace_map"] = wsmap
            store["pages"] = pages
            await write_storage(store)
            # broadcast unlink event
            await manager.broadcast({"type": "page_unlinked", "payload": {"pageId": page_id}})
            return {"success": True, "message": "Page unlinked"}
        return {"success": False, "message": "Page not found"}

    @app.post("/api/facebook/switch")
    async def switch_account(req: Request):
        """
        Body: { workspaceId: 123, pageId: '67890' }
        Map workspace -> pageId so future refreshes attribute metrics to workspace.
        """
        body = await req.json()
        workspace_id = body.get("workspaceId")
        page_id = str(body.get("pageId") or "")
        if not workspace_id or not page_id:
            raise HTTPException(400, "workspaceId and pageId required")

        store = await read_storage()
        store.setdefault("workspace_map", {})[str(workspace_id)] = page_id
        await write_storage(store)
        await manager.broadcast({"type": "page_switched", "payload": {"workspaceId": workspace_id, "pageId": page_id}})
        return {"success": True}

    @app.post("/api/facebook/refresh")
    async def refresh_insights(req: Request):
        """
        Trigger server to fetch latest insights for a given page or all pages.
        Body: { pageId?: '123' }
        The server will fetch Graph API insights and broadcast messages to WS clients:
        - message type: 'metrics_update' with payload equal to parsed metrics (see parse_facebook_insights_to_metrics).
        """
        body = await req.json()
        page_id = body.get("pageId")

        store = await read_storage()
        pages = store.get("pages", {})
        targets: List[str] = [page_id] if page_id else list(pages.keys())
        if not targets:
            return {"success": False, "message": "No pages linked to refresh"}

        async def fetch_and_broadcast(pid: str):
            page = pages.get(pid)
            token = page.get("access_token") if page else None
            if not token:
                return False
            # Choose which insights to request. Adjust metrics list to your needs.
            metric = "page_impressions,page_engaged_users"
            params = {"access_token": token, "metric": metric, "period": "days_7"}
            try:
                data = await fb_get(f"{pid}/insights", params)
                metrics = parse_facebook_insights_to_metrics(pid, data)
                # attach workspace_id if mapped
                workspace_map = store.get("workspace_map", {})
                mapped_ws = None
                for wsid, p in (workspace_map.items() if isinstance(workspace_map, dict) else []):
                    if str(p) == str(pid):
                        mapped_ws = int(wsid) if str(wsid).isdigit() else wsid
                        break
                metrics["workspace_id"] = mapped_ws or metrics.get("workspace_id")
                # broadcast
                await manager.broadcast({"type": "metrics_update", "payload": metrics})
                return True
            except Exception as e:
                print("refresh error for", pid, e)
                return False

        results = await asyncio.gather(*(fetch_and_broadcast(pid) for pid in targets))
        ok = all(results)
        return {"success": ok}

    @app.post("/api/facebook/exchange_code")
    async def exchange_code(req: Request):
        """
        Exchanges an OAuth code for a user access token and fetches pages & page access tokens.
        Body: { code: string, redirect_uri: string }
        Returns: pages list with page access tokens (and stores them).
        IMPORTANT: In production you must validate state and associate tokens with the authenticated user (not shown here).
        """
        body = await req.json()
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")
        if not code or not redirect_uri:
            raise HTTPException(400, "code and redirect_uri required")

        # Step 1: exchange code -> user access token
        exchange_params = {
            "client_id": FB_APP_ID,
            "redirect_uri": redirect_uri,
            "client_secret": FB_APP_SECRET,
            "code": code,
        }
        token_resp = await fb_get("oauth/access_token", exchange_params)
        user_token = token_resp.get("access_token")
        if not user_token:
            raise HTTPException(status_code=400, detail={"message": "Failed to exchange code", "details": token_resp})

        # Step 2: get pages (with page access tokens)
        # Request /me/accounts with user access token
        pages_resp = await fb_get("me/accounts", {"access_token": user_token})
        pages_data = pages_resp.get("data", [])
        stored = await read_storage()
        pages_store = stored.get("pages", {})
        for p in pages_data:
            pid = str(p.get("id"))
            # Graph returns `access_token` for page if user has sufficient permissions
            page_token = p.get("access_token")
            pages_store[pid] = {
                "id": pid,
                "name": p.get("name"),
                "category": p.get("category"),
                "access_token": page_token,
                # extra fields
            }
        stored["pages"] = pages_store
        await write_storage(stored)

        # return the pages list
        return {"success": True, "pages": list(pages_store.values()), "user_token": bool(user_token)}

    # ----- WebSocket endpoint -----
    @app.websocket("/ws/metrics")
    async def websocket_metrics(ws: WebSocket):
        """
        WebSocket for broadcasting metric updates.
        Message format:
        { type: 'metrics_update', payload: { workspace_id, page_id, impressions, clicks, ctr, cpm, total_spend, last_updated, insights_raw } }
        Clients can simply listen and merge payload into their metricsMap.
        """
        await manager.connect(ws)
        try:
            while True:
                # optionally, the client may send messages to subscribe; we currently ignore client messages
                try:
                    msg = await ws.receive_text()
                    # ignore; optionally parse subscription messages here
                except Exception:
                    # idle loop to keep alive; allow server to send broadcasts
                    await asyncio.sleep(0.1)
        except WebSocketDisconnect:
            await manager.disconnect(ws)
        except Exception:
            await manager.disconnect(ws)
            

from flask import jsonify, request
import requests
import json
from typing import Optional

# --- Helper: call Graph API with a token (safe wrapper) ---
def _graph_get(path: str, token: str, params: dict = None, timeout: int = 10):
    """
    GET to Graph API path (path may be like 'me' or '12345' or '12345/insights').
    Returns tuple (ok: bool, status_code: int, json_or_text)
    """
    params = params.copy() if params else {}
    params["access_token"] = token
    url = f"https://graph.facebook.com/{FB_API_VERSION}/{path}"
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        # try parse json but return raw text if parse fails
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return (resp.status_code == 200, resp.status_code, body)
    except Exception as exc:
        logger.exception("Graph GET failed for %s: %s", path, exc)
        return (False, 500, {"error": "exception", "details": str(exc)})

# --- 1) /api/social/accounts/db  (list DB accounts; alias for your existing route) ---
@app.route("/api/social/accounts/db", methods=["GET", "OPTIONS"])
def api_social_accounts_db():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    user = get_user_from_request(require=False)
    if user:
        accounts = SocialAccount.query.filter((SocialAccount.user_id == None) | (SocialAccount.user_id == user.id)).all()
    else:
        accounts = SocialAccount.query.filter_by(user_id=None).all()
    return jsonify({"success": True, "accounts": [a.serialize() for a in accounts]}), 200

# --- 2) /api/social/accounts/raw  (fetch current DB accounts + try to refresh Graph data for each) ---
@app.route("/api/social/accounts/raw", methods=["GET"])
def api_social_accounts_raw():
    """
    Returns an array of objects: { db: <serialized DB row>, fb_raw: <graph response or null>, error: <optional> }
    This helps the frontend show both DB state and the latest data from FB for each connected page.
    """
    user = get_user_from_request(require=False)
    accounts = SocialAccount.query.all()
    result = []
    for a in accounts:
        entry = {"db": a.serialize(), "fb_raw": None, "error": None}
        token = a.access_token or (get_facebook_token_for_user(user.id) if user else None)
        if token:
            ok, status, body = _graph_get(f"{a.provider_user_id}", token, params={"fields":"id,name,link,fan_count,category,instagram_business_account"})
            if ok:
                entry["fb_raw"] = body
            else:
                entry["error"] = {"status": status, "body": body}
        else:
            entry["error"] = {"message":"no_token_available"}
        result.append(entry)
    return jsonify({"success": True, "rows": result}), 200

# --- 3) /api/facebook/page-details?page_id=...&fields=...  (fetch FB page details/insights for a page) ---
@app.route("/api/facebook/page-details", methods=["GET"])
def api_facebook_page_details():
    """
    Query params:
      - page_id (required)
      - fields (optional, comma separated) default: id,name,link,fan_count,category,insights.metric(page_impressions,page_engaged_users).period(days_7)
      - since / until (optional) for insights time_range
    """
    page_id = request.args.get("page_id")
    if not page_id:
        return jsonify({"success": False, "error": "missing_page_id"}), 400

    # Try to find a DB SocialAccount for this page
    sa = SocialAccount.query.filter_by(provider="facebook", provider_user_id=str(page_id)).first()
    token = None
    if sa and sa.access_token:
        token = sa.access_token
    else:
        # fallback: current user's token
        user = get_user_from_request(require=False)
        if user:
            token = get_facebook_token_for_user(user.id)

    if not token:
        return jsonify({"success": False, "error": "no_token_available"}), 403

    # fields default
    fields = request.args.get("fields") or "id,name,link,fan_count,category,instagram_business_account"
    extra_params = {}
    # support insights query if user requested insights via fields param using Graph shorthand (frontend can pass)
    # but to make it easier: accept `insights=true` and since/until for insights
    if request.args.get("insights") == "true":
        since = request.args.get("since")
        until = request.args.get("until")
        if since and until:
            extra_params["time_range"] = json.dumps({"since": since, "until": until})
        # get some common metrics if not explicitly provided
        fields = fields + ",insights.metric(page_impressions,page_engaged_users,page_fans).period(days_7)"

    ok, status, body = _graph_get(f"{page_id}", token, params={"fields": fields, **extra_params}, timeout=20)
    if not ok:
        return jsonify({"success": False, "error": "fb_error", "details": body}), status
    return jsonify({"success": True, "page": body}), 200
 
# Add / paste into your Flask app file (below other imports & existing helpers)
from flask import request, jsonify
import json
import requests
from datetime import datetime

# ensure _graph_get exists (if not, add this helper)
def _graph_get(path: str, token: str, params: dict = None, timeout: int = 10):
    params = params.copy() if params else {}
    params["access_token"] = token
    url = f"https://graph.facebook.com/{FB_API_VERSION}/{path}"
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return (resp.status_code == 200, resp.status_code, body)
    except Exception as exc:
        logger.exception("Graph GET failed for %s: %s", path, exc)
        return (False, 500, {"error": "exception", "details": str(exc)})

# --- 1) Full social management endpoint (list accounts + optionally live fb data) ---
@app.route("/api/social/management", methods=["GET", "OPTIONS"])
def api_social_management():
    """
    Return linked social accounts for the resolved user.

    Resolution order:
      1) get_user_from_request(require=False)   (session or bearer token)
      2) optional fallback: request.args['user_id'] or JSON['user_id'] when
         current_app.config['ALLOW_REQUEST_USER_ID_FALLBACK'] is True (dev-only)

    Returns 401 when no user could be resolved.
    """
    DEFAULT_USER_ID = None  # legacy default removed; require explicit user or explicit fallback

    # read JSON if present (silent to avoid parse errors)
    data = request.get_json(silent=True) or {}

    # 1) try normal resolution (session / token)
    user = get_user_from_request(require=False)

    # 2) optional dev fallback: explicit user_id in query or body
    if not user:
        fallback_uid = request.args.get("user_id") or data.get("user_id")
        if fallback_uid and current_app.config.get("ALLOW_REQUEST_USER_ID_FALLBACK"):
            try:
                fallback_uid = int(fallback_uid)
                user = User.query.get(fallback_uid)
                if user:
                    current_app.logger.warning(
                        f"api_social_management used fallback user_id={fallback_uid} from request. "
                        "Enable fallback only for development."
                    )
            except Exception as e:
                current_app.logger.warning(f"Invalid fallback user_id provided to api_social_management: {fallback_uid} ({e})")
                user = None

    # If still no user, return 401
    if not user:
        return jsonify({"success": False, "error": "unauthorized", "message": "user not authenticated"}), 401

    # Only return accounts for this user
    accounts = SocialAccount.query.filter_by(user_id=user.id).order_by(SocialAccount.id.desc()).all()

    rows = []
    active = None

    for a in accounts:
        item = {"db": a.serialize(), "fb_raw": None, "error": None}

        # Prefer account access_token; otherwise try to fetch a token for this user
        token = a.access_token or get_facebook_token_for_user(user.id)

        if token:
            ok, status, body = _graph_get(
                f"{a.provider_user_id}",
                token,
                params={"fields": "id,name,link,fan_count,category,picture.width(200).height(200),instagram_business_account"},
            )
            if ok:
                item["fb_raw"] = body
            else:
                item["error"] = {"status": status, "body": body}
        else:
            item["error"] = {"message": "no_token_available"}

        rows.append(item)

        try:
            if getattr(user, "active_social_account_id", None) == a.id:
                active = a.serialize()
        except Exception:
            pass

    # If no active and rows exist, optionally set first as active (keeping previous behavior)
    if active is None and rows:
        active = rows[0]["db"]

    return jsonify({"success": True, "accounts": rows, "active_account": active}), 200


from flask import g, session, request, jsonify

@app.before_request
def load_user():
    user_id = session.get("user_id")
    if user_id:
        g.user = User.query.get(user_id)
    else:
        g.user = None

# --- 2) Update permissions / scopes for a social account ---

# Fix permissions endpoint to always save under user 1
@app.route("/api/social/permissions", methods=["POST"])
def api_social_permissions():
    """
    Update social account permissions.

    Behavior:
      1. Resolve user via get_user_from_request(require=False).
      2. If not found and app.config["ALLOW_REQUEST_USER_ID_FALLBACK"] is True,
         attempt to use `user_id` from request JSON or query as a fallback (dev-only).
      3. Validate provider/provider_user_id and update `scopes`.
      4. Assign the account to the resolved user (account.user_id = user.id).
    Notes:
      - Accepting user_id from requests is insecure for production; enable only for dev/debug.
      - If you prefer not to reassign account ownership, add a check preventing reassignment.
    """
    data = request.get_json(silent=True) or {}

    # Resolve user (session / token)
    user = get_user_from_request(require=False)

    # Optional fallback: accept explicit user_id in request (dev-only)
    if not user:
        fallback_uid = data.get("user_id") or request.args.get("user_id")
        if fallback_uid and current_app.config.get("ALLOW_REQUEST_USER_ID_FALLBACK"):
            try:
                fallback_uid = int(fallback_uid)
                user = User.query.get(fallback_uid)
                if user:
                    current_app.logger.warning(
                        f"api_social_permissions used fallback user_id={fallback_uid} from request. "
                        "Enable fallback only for development."
                    )
            except Exception as e:
                current_app.logger.warning(f"Invalid fallback user_id provided: {fallback_uid} ({e})")
                user = None

    if not user:
        return jsonify({"success": False, "error": "unauthorized"}), 401

    provider = data.get("provider")
    provider_user_id = str(data.get("provider_user_id") or "")

    if not provider or not provider_user_id:
        return jsonify({"success": False, "error": "missing_required_fields"}), 400

    # Normalize scopes input: accept list or comma-separated string
    scopes = data.get("scopes", [])
    if isinstance(scopes, str):
        # allow either "a,b,c" or "a, b, c"
        scopes = [s.strip() for s in scopes.split(",") if s.strip()]
    elif isinstance(scopes, (list, tuple)):
        scopes = [str(s).strip() for s in scopes if str(s).strip()]
    else:
        scopes = []

    account = SocialAccount.query.filter_by(
        provider=provider,
        provider_user_id=provider_user_id
    ).first()

    if not account:
        return jsonify({"success": False, "error": "account_not_found"}), 404

    try:
        account.scopes = ",".join(scopes)
        # assign/ensure this account is associated with the resolved user
        account.user_id = user.id

        db.session.add(account)
        db.session.commit()

        return jsonify({
            "success": True,
            "account": account.serialize() if hasattr(account, "serialize") else {
                "id": account.id,
                "provider": account.provider,
                "provider_user_id": account.provider_user_id,
                "scopes": account.scopes,
                "user_id": account.user_id
            }
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to update social permissions")
        return jsonify({
            "success": False,
            "error": "db_error",
            "message": str(e)
        }), 500

@app.route("/api/social/unlink", methods=["POST"])
def api_social_unlink():
    """Unlink social account.

    Behavior:
      1. Try to resolve user via get_user_from_request(require=False).
      2. If not found, look for user_id in request JSON or query parameters
         and try to load that user (fallback).
      3. If still not found -> 401.
    NOTE: Accepting user_id from requests is a fallback for testing/dev only;
    don't rely on it in production unless you have additional safeguards.
    """
    # read JSON early (silent=True to avoid exceptions on non-json bodies)
    data = request.get_json(silent=True) or {}

    # 1) try normal resolution (session / token helpers)
    user = get_user_from_request(require=False)

    # 2) fallback: if no user, check for explicit user_id in payload or query
    if not user:
        fallback_uid = data.get("user_id") or request.args.get("user_id")
        if fallback_uid:
            try:
                fallback_uid = int(fallback_uid)
                # attempt to fetch the User by id
                user = User.query.get(fallback_uid)
                if user:
                    # warn in logs so you can detect fallback usage
                    current_app.logger.warning(
                        f"api_social_unlink used fallback user_id={fallback_uid} from request. "
                        "Ensure this is intended (dev-only)."
                    )
            except Exception as e:
                current_app.logger.warning(f"Invalid fallback user_id provided: {fallback_uid} ({e})")
                user = None

    if not user:
        return jsonify({"success": False, "error": "unauthorized"}), 401

    # validate request body after user resolution
    provider = data.get("provider")
    provider_user_id = str(data.get("provider_user_id") or "")

    if not provider or not provider_user_id:
        return jsonify({"success": False, "error": "missing_required_fields"}), 400

    account = SocialAccount.query.filter_by(
        provider=provider,
        provider_user_id=provider_user_id,
        user_id=user.id
    ).first()

    if not account:
        return jsonify({"success": False, "error": "account_not_found"}), 404

    try:
        # Try to revoke at Facebook if we have token
        if account.access_token:
            try:
                revoke_url = f"https://graph.facebook.com/{FB_API_VERSION}/me/permissions"
                requests.delete(
                    revoke_url,
                    params={"access_token": account.access_token},
                    timeout=10
                )
            except Exception as e:
                current_app.logger.warning(f"Failed to revoke FB token: {e}")

        db.session.delete(account)
        db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to unlink social account")
        return jsonify({
            "success": False,
            "error": "db_error",
            "message": str(e)
        }), 500

       
        # --- 5) Current active profile summary for UI (picture/name/fan_count etc) ---
@app.route("/api/social/active-profile", methods=["GET"])
def api_social_active_profile():
    user = get_user_from_request(require=True)
    active_id = getattr(user, "active_social_account_id", None)
    if not active_id:
        return jsonify({"success": False, "error": "no_active_account"}), 404
    sa = SocialAccount.query.get(active_id)
    if not sa:
        return jsonify({"success": False, "error": "active_account_not_found"}), 404
    token = sa.access_token or get_facebook_token_for_user(user.id)
    if not token:
        return jsonify({"success": False, "error": "no_token_available"}), 403
    ok, status, body = _graph_get(f"{sa.provider_user_id}", token, params={"fields":"id,name,link,fan_count,picture.width(200).height(200),category,instagram_business_account"})
    if not ok:
        return jsonify({"success": False, "error": "fb_error", "details": body}), status
    return jsonify({"success": True, "profile": body, "db": sa.serialize()}), 200


# --- facebook_insights_routes.py ---
import requests
import json
from datetime import datetime, timedelta
from flask import request, jsonify

# Helpers: _graph_get
def _graph_get(path_or_node: str, access_token: str, params: dict = None, timeout: int = 10):
    """
    Simple helper to call the Facebook Graph API GET endpoint.
    path_or_node: "12345" or "12345/posts" etc.
    access_token: token string
    returns: (ok: bool, status_code: int, body: dict or text)
    """
    params = params or {}
    params["access_token"] = access_token
    url = f"https://graph.facebook.com/{FB_API_VERSION}/{path_or_node.lstrip('/')}"
    try:
        r = requests.get(url, params=params, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = r.text
        ok = (r.status_code == 200)
        return ok, r.status_code, body
    except Exception as exc:
        logger.exception("_graph_get exception for %s: %s", path_or_node, exc)
        return False, 0, {"error": "request_exception", "details": str(exc)}

# Helper: attempt to find a SocialAccount for user 1 (or find first)
def _choose_account_for_default_user(default_uid=1, provider="facebook", provider_user_id: str = None):
    """
    If provider_user_id provided, look that up first.
    Otherwise prefer accounts for user_id == default_uid, else first account.
    Returns (SocialAccount instance or None)
    """
    if provider_user_id:
        sa = SocialAccount.query.filter_by(provider=provider, provider_user_id=str(provider_user_id)).first()
        if sa:
            return sa
    # try user default
    sa = SocialAccount.query.filter_by(provider=provider, user_id=default_uid).order_by(SocialAccount.id.desc()).first()
    if sa:
        return sa
    # fallback: any account
    sa = SocialAccount.query.filter_by(provider=provider).order_by(SocialAccount.id.desc()).first()
    return sa

# Route: page details (used by FacebookManager.refreshRow)
@app.route("/api/facebook/page-details2", methods=["GET"])
def api_facebook_page_details2():
    """
    GET params:
      page_id (provider_user_id) - optional; if not provided we try to pick user 1's account
      insights (bool) - if true, also include basic insights (not used heavily)
    Returns:
      { success: true, page: {...} } or error
    """
    page_id = request.args.get("page_id") or request.args.get("provider_user_id")
    include_insights = request.args.get("insights", "false").lower() in ("1", "true", "yes")

    # Choose SocialAccount (prefer provided id > user 1 > first)
    sa = _choose_account_for_default_user(default_uid=1, provider="facebook", provider_user_id=page_id)
    if not sa:
        return jsonify({"success": False, "error": "no_social_account_found"}), 404

    token = sa.access_token or None
    if not token:
        # if you have a function to fetch app token, use it as a last resort
        token = f"{FB_APP_ID}|{FB_APP_SECRET}"

    # get page basic fields
    ok, status, body = _graph_get(f"{sa.provider_user_id}", token, params={"fields": "id,name,link,fan_count,category,picture.width(200).height(200)"})
    if not ok:
        return jsonify({"success": False, "error": "graph_error", "status": status, "body": body}), status if status else 500

    page_obj = body if isinstance(body, dict) else {"raw": body}

    # optional: add a few lightweight insights (page impressions last 7 days)
    if include_insights:
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        until = datetime.utcnow().strftime("%Y-%m-%d")
        metrics = "page_impressions,page_engaged_users"
        ok_i, s_i, b_i = _graph_get(f"{sa.provider_user_id}/insights", token, params={"metric": metrics, "since": since, "until": until})
        if ok_i and isinstance(b_i, dict):
            page_obj["insights"] = b_i.get("data", b_i)
        else:
            page_obj["insights_error"] = {"status": s_i, "body": b_i}

    return jsonify({"success": True, "page": page_obj})

# Route: insights (page metrics + posts summary) used by FacebookInsights.tsx
@app.route("/api/facebook/insights2", methods=["GET"])
def api_facebook_insights2():
    """
    Query params:
      provider_user_id (page id) optional -> if missing, pick first account for user 1
      limit (optional) number of posts to fetch (default 10)
    Returns:
      { success: true, page_insights: {...}, posts: [...] }
    """
    provider_user_id = request.args.get("provider_user_id")
    limit = int(request.args.get("limit") or 10)

    # pick account
    sa = _choose_account_for_default_user(default_uid=1, provider="facebook", provider_user_id=provider_user_id)
    if not sa:
        return jsonify({"success": False, "error": "no_social_account_found"}), 404

    token = sa.access_token or None
    if not token:
        token = f"{FB_APP_ID}|{FB_APP_SECRET}"  # fall back to app token (may have limited access)

    page_id = sa.provider_user_id

    # 1) Basic page fields
    ok_page, status_page, page_body = _graph_get(f"{page_id}", token, params={"fields":"id,name,link,fan_count,category,picture.width(200).height(200)"})
    if not ok_page:
        return jsonify({"success": False, "error": "page_fetch_failed", "details": {"status": status_page, "body": page_body}}), status_page if status_page else 500

    # 2) Fetch recent insights (last 30 days)
    try:
        since_date = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
        until_date = datetime.utcnow().strftime("%Y-%m-%d")
        # request some common page-level metrics
        metrics = "page_impressions,page_engaged_users,page_consumptions,page_views_total"
        ok_i, status_i, insights_body = _graph_get(f"{page_id}/insights", token, params={"metric": metrics, "since": since_date, "until": until_date})
    except Exception as e:
        ok_i, status_i, insights_body = False, 0, {"error": str(e)}

    page_insights = {}
    if ok_i and isinstance(insights_body, dict):
        try:
            # Graph returns data array where each element has 'name' and 'values'
            for item in insights_body.get("data", []):
                name = item.get("name")
                values = item.get("values") or []
                # pick last value numeric
                if values:
                    last_val = values[-1].get("value")
                    page_insights[name] = last_val
            # Normalize into the fields frontend expects
            page_insights_normalized = {
                "fan_count": page_body.get("fan_count"),
                "talking_about_count": page_insights.get("page_engaged_users") or 0,
                "page_views": page_insights.get("page_views_total") or 0,
                "page_impressions": page_insights.get("page_impressions") or 0,
                "engagement_rate": 0.0,
            }
            # compute engagement_rate if possible
            try:
                impressions = float(page_insights_normalized.get("page_impressions") or 0) or 1
                engaged = float(page_insights_normalized.get("talking_about_count") or 0)
                page_insights_normalized["engagement_rate"] = round((engaged / impressions) * 100, 2) if impressions else 0.0
            except Exception:
                page_insights_normalized["engagement_rate"] = 0.0
        except Exception as exc:
            logger.exception("Failed to normalize insights: %s", exc)
            page_insights_normalized = {
                "fan_count": page_body.get("fan_count"),
                "talking_about_count": None,
                "page_views": None,
                "page_impressions": None,
                "engagement_rate": None,
            }
    else:
        # graph insights failed; return basic placeholders
        page_insights_normalized = {
            "fan_count": page_body.get("fan_count"),
            "talking_about_count": None,
            "page_views": None,
            "page_impressions": None,
            "engagement_rate": None,
            "insights_error": {"status": status_i, "body": insights_body}
        }

    # 3) Fetch recent posts and simple metrics (likes/comments/shares)
    posts_result = []
    try:
        # request posts with comment & reaction counts and shares
        fields = "id,message,created_time,shares,comments.limit(0).summary(true),reactions.limit(0).summary(true)"
        ok_p, status_p, posts_body = _graph_get(f"{page_id}/posts", token, params={"fields": fields, "limit": limit})
        if ok_p and isinstance(posts_body, dict):
            for p in posts_body.get("data", []):
                pid = p.get("id")
                message = p.get("message")
                created_time = p.get("created_time")
                shares = (p.get("shares") or {}).get("count", 0)
                comments = (p.get("comments") or {}).get("summary", {}).get("total_count", 0)
                reactions = (p.get("reactions") or {}).get("summary", {}).get("total_count", 0)
                posts_result.append({
                    "id": pid,
                    "message": message,
                    "created_time": created_time,
                    "likes": reactions,
                    "comments": comments,
                    "shares": shares,
                    "raw": p
                })
        else:
            # try older "feed" endpoint fallback
            posts_result = []
    except Exception as exc:
        logger.exception("Failed to fetch posts for %s: %s", page_id, exc)
        posts_result = []

    response = {
        "success": True,
        "page": page_body,
        "page_insights": page_insights_normalized,
        "posts": posts_result,
    }
    return jsonify(response)
@app.route("/api/workspace/assets", methods=["GET"])
def api_workspace_assets():
    try:
        workspace_id = request.args.get("workspace_id") or request.args.get("id")
        if not workspace_id:
            return jsonify({"success": False, "error": "bad_request", "details": "workspace_id required"}), 400
        try:
            wid = int(workspace_id)
        except Exception:
            return jsonify({"success": False, "error": "bad_request", "details": "workspace_id must be integer"}), 400

        ws = Workspace.query.filter_by(id=wid).first()
        if not ws:
            return jsonify({"success": True, "assets": []}), 200

        def _parse_paths_field(field_value):
            if not field_value:
                return []
            if isinstance(field_value, list):
                return [str(x) for x in field_value if x]
            if isinstance(field_value, dict):
                return []
            if isinstance(field_value, str):
                s = field_value.strip()
                try:
                    parsed = json.loads(s)
                    if isinstance(parsed, list):
                        return [str(x) for x in parsed if x]
                except Exception:
                    pass
                parts = [p.strip() for p in s.split(",") if p.strip()]
                if parts:
                    return parts
                return [s]
            return []

        # try multiple attribute names safely
        creatives_field = (
            getattr(ws, "creatives_paths", None)
            or getattr(ws, "creatives_path", None)
            or getattr(ws, "creatives", None)
            or getattr(ws, "creatives_list", None)
        )
        cp = _parse_paths_field(creatives_field)

        assets_out = []
        for p in cp:
            url = p
            if not (p.startswith("http://") or p.startswith("https://")):
                try:
                    url = url_for("uploaded_workspace_file", user_id=ws.user_id, filename=os.path.basename(p), _external=True)
                except Exception:
                    url = p
            ext = os.path.splitext(p)[1].lower()
            atype = "image" if ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp"] else "file"
            assets_out.append({"name": os.path.basename(p) or p, "url": url, "type": atype})

        # if still empty, try a JSON 'creatives' structure (objects)
        if not assets_out and getattr(ws, "creatives", None):
            raw_creatives = getattr(ws, "creatives")
            try:
                parsed = json.loads(raw_creatives) if isinstance(raw_creatives, str) else raw_creatives
                if isinstance(parsed, list):
                    for c in parsed:
                        u = c.get("url") or c.get("path") or c.get("src")
                        if u and not (u.startswith("http://") or u.startswith("https://")):
                            try:
                                u = url_for("uploaded_workspace_file", user_id=ws.user_id, filename=os.path.basename(u), _external=True)
                            except Exception:
                                pass
                        assets_out.append({"name": c.get("name") or os.path.basename(u or ""), "url": u, "type": c.get("type") or "file"})
            except Exception:
                current_app.logger.exception("parsing creatives JSON failed")

        return jsonify({"success": True, "assets": assets_out}), 200

    except Exception as e:
        current_app.logger.exception("api_workspace_assets failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500
# ---------- Helper: safe parse creatives list ----------
def _parse_paths_field(field_value):
    """
    Accepts:
      - None -> []
      - JSON string -> parsed list
      - list -> list
      - comma-separated string -> split
    Returns list of strings.
    """
    if not field_value:
        return []
    if isinstance(field_value, list):
        return [str(x) for x in field_value if x]
    if isinstance(field_value, (dict, int, float)):
        # unexpected types -> empty
        return []
    if isinstance(field_value, str):
        s = field_value.strip()
        # try JSON parse
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(x) for x in parsed if x]
        except Exception:
            pass
        # fallback comma-split
        parts = [p.strip() for p in s.split(",") if p.strip()]
        return parts
    return []
#------------------------creatiives pipeline merge--------------------------

# ai_image_backend.py
# Full backend with:
#  - theme generation and per-theme social content (caption/hashtags/cta/alt_text)
#  - image generation (single & multi-image)
#  - edit endpoint supporting both models.generate_content and chat-based edit (client.chats.create)
#  - ImageConfig shim fallback for older google-genai SDKs
#  - Modified to save assets to DigitalOcean Spaces (S3-compatible) in an organized manner (outputs/ for generated, saved/ for saved)
#  - Added background cleanup for outputs/ objects older than 24 hours
#  - Added SQLAlchemy integration to store generated and saved URLs in 'creatives' table with user_id and workspace_id
#  - Added Conversation model to save each prompt/response as a conversation in 'conversations' table, including image URLs

# -*- coding: utf-8 -*-
import os
import sys
import uuid
import mimetypes
import base64
import json
import re
import textwrap
import threading
import urllib.request
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from urllib.parse import urljoin 

import boto3
from botocore.exceptions import ClientError

from flask import Flask, render_template, request, jsonify, send_from_directory, abort, make_response, redirect
from flask_cors import CORS


# google-genai SDK imports (may vary by SDK version)
from google import genai
from google.genai.types import HttpOptions, Part, GenerateContentConfig

# ImageConfig may not exist in older SDKs — provide a robust fallback
try :
    from google.genai.types import ImageConfig  # type: ignore
    IMAGE_CONFIG_IS_CLASS = True
except Exception:
    # fallback builder — returns a plain dict or simple object usable by GenerateContentConfig
    def ImageConfig(**kwargs):
        # return a plain dict — many SDK wrappers accept dicts for nested config on older versions
        return kwargs
    IMAGE_CONFIG_IS_CLASS = False

# --- Configuration ---
MODEL_ID = os.environ.get("MODEL_ID", "")  # image-capable model
TEXT_MODEL = os.environ.get("TEXT_MODEL", "")        # text-capable model

# DigitalOcean Spaces configuration
SPACE_NAME = os.environ.get("SPACE_NAME", "")
print("[env] SPACE_NAME:", SPACE_NAME)
SPACE_REGION = os.environ.get("SPACE_REGION")
SPACE_ENDPOINT = f'https://{SPACE_REGION}.digitaloceanspaces.com'
SPACE_CDN = f'https://{SPACE_NAME}.{SPACE_REGION}.cdn.digitaloceanspaces.com'
ACCESS_KEY = os.environ.get("ACCESS_KEY")
SECRET_KEY = os.environ.get("SECRET_KEY")

# Initialize S3 client
if ACCESS_KEY and SECRET_KEY:
    s3 = boto3.client('s3',
                      aws_access_key_id=ACCESS_KEY,
                      aws_secret_access_key=SECRET_KEY,
                      endpoint_url=SPACE_ENDPOINT)
    print("[startup] S3 client initialized for DigitalOcean Spaces.")
else:
    s3 = None
    print("[startup] Warning: DO_ACCESS_KEY_ID or DO_SECRET_ACCESS_KEY not set. Cannot use Spaces storage.", file=sys.stderr)

# Local index for saved images (consider moving to DB for production)
OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "outputs"))  # Local temp if needed, but not used for storage
SAVED_INDEX_PATH = os.path.join(OUTPUT_DIR, "saved_index.json")
os.makedirs(OUTPUT_DIR, exist_ok=True)  # For index only
_saved_index_lock = threading.Lock()

EXTERNAL_BASE_URL = os.environ.get("EXTERNAL_BASE_URL")  # e.g. "https://ai.example.com"
if not EXTERNAL_BASE_URL:
    EXTERNAL_BASE_URL = "http://127.0.0.1:5000"
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 10_485_760))  # 10 MB default
DOWNLOAD_TIMEOUT = int(os.environ.get("DOWNLOAD_TIMEOUT", 15))  # seconds for external downloads


# --- Init GenAI client (Vertex mode) ---
def init_client():
    project = os.environ.get("GCP_PROJECT") or os.environ.get("PROJECT_ID") or "angular-sorter-473216-k8"
    location = os.environ.get("GOOGLE_CLOUD_LOCATION") or "global"
    adc_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    print("[env] GCP_PROJECT:", project)
    print("[env] LOCATION:", location)
    print("[env] ADC PATH SET:", bool(adc_path))
    try:
        client = genai.Client(
            http_options=HttpOptions(api_version="v1"),
            project=project,
            location=location,
            vertexai=True,
        )
        print("[startup] genai.Client initialized (Vertex mode).")
        return client
    except Exception as e:
        print("[startup] genai.Client init FAILED:", e)
        return None

GENAI_CLIENT = init_client()
if not GENAI_CLIENT:
    print("Warning: GENAI_CLIENT not initialized. Ensure google-genai is installed and ADC is configured.", file=sys.stderr)

# --- Saved-index utilities (local for now) ---
def _load_saved_index() -> Dict[str, Any]:
    with _saved_index_lock:
        if not os.path.exists(SAVED_INDEX_PATH):
            return {}
        try:
            with open(SAVED_INDEX_PATH, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception as e:
            print("[saved_index] failed to load index:", e)
            return {}

def _save_saved_index(index: Dict[str, Any]):
    with _saved_index_lock:
        tmp = SAVED_INDEX_PATH + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(index, f, indent=2, ensure_ascii=False)
            os.replace(tmp, SAVED_INDEX_PATH)
        except Exception as e:
            print("[saved_index] failed to write index:", e)

# ensure index loaded on startup (lazy)
_SAVED_INDEX = _load_saved_index()

def _register_saved(id: str, meta: Dict[str, Any]):
    global _SAVED_INDEX
    _SAVED_INDEX = _SAVED_INDEX or {}
    _SAVED_INDEX[id] = meta
    _save_saved_index(_SAVED_INDEX)

# --- Helpers to save binary/image parts from GenAI response to Spaces ---
def _save_inline_part(inline, prefix="img"):
    data = getattr(inline, "data", None)
    if not data:
        return None
    if isinstance(data, str):
        try:
            data = base64.b64decode(data)
        except Exception as e:
            print("[save] inline base64 decode failed:", e)
            return None
    if not isinstance(data, (bytes, bytearray)):
        print("[save] inline data not bytes, skipping")
        return None
    mime = getattr(inline, "mime_type", "image/png") or "image/png"
    ext = mimetypes.guess_extension(mime) or ".png"
    fname = f"{prefix}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}_{uuid.uuid4().hex}{ext}"
    key = f"outputs/{fname}"  # Organized under outputs/
    if not s3:
        print("[save] S3 client not available")
        return None
    try:
        s3.put_object(Bucket=SPACE_NAME, Key=key, Body=data, ContentType=mime, ACL='public-read')
        print(f"[save] uploaded {key} to {SPACE_NAME}")
        return fname
    except Exception as e:
        print("[save] upload failed:", e)
        return None

def save_images_from_response(response, prefix="img"):
    saved = []
    for ci, cand in enumerate(getattr(response, "candidates", []) or []):
        content = getattr(cand, "content", None)
        if not content:
            continue
        for pi, part in enumerate(getattr(content, "parts", []) or []):
            inline = getattr(part, "inline_data", None)
            if inline and getattr(inline, "data", None):
                fname = _save_inline_part(inline, prefix=f"{prefix}_c{ci}_p{pi}")
                if fname:
                    saved.append(fname)
    return saved
# put this near your other helpers
import base64, re, datetime

import base64, re, time, requests, os, json

def save_images_from_response_robust(resp_obj, prefix="gen", max_files=6, verbose=True):
    """
    Robust extraction of images from a generator response object.
    Uses `time` to build a timestamp (avoids datetime.datetime name collisions).
    Saves files to outputs/, uploads to Spaces if s3 client exists.
    Returns list of saved filenames (may be empty).
    """
    os.makedirs("outputs", exist_ok=True)
    os.makedirs("outputs/debug", exist_ok=True)
    # timestamp using time (UTC)
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"{int(time.time()*1e6) % 1000000:06d}"
    debug_dump = os.path.join("outputs", "debug", f"gen_resp_{prefix}_{ts}.json")
    saved_files = []

    # Dump raw response for inspection
    try:
        with open(debug_dump, "w", encoding="utf-8") as f:
            try:
                json.dump(resp_obj, f, default=str, ensure_ascii=False, indent=2)
            except Exception:
                f.write(repr(resp_obj))
        if verbose:
            print("[debug] wrote raw generator response to", debug_dump, flush=True)
    except Exception as e:
        if verbose:
            print("[debug] failed to write generator dump:", e, flush=True)

    def _write_bytes(data_bytes, ext=".png"):
        safe_prefix = re.sub(r"[^A-Za-z0-9_.-]", "_", prefix)[:40]
        fname = f"{safe_prefix}_{ts}_{len(saved_files)}{ext}"
        path = os.path.join("outputs", fname)
        try:
            with open(path, "wb") as wf:
                wf.write(data_bytes)
            if verbose:
                print("[save] wrote", path, flush=True)
            # attempt upload if s3 configured
            try:
                s3_client = globals().get("s3") or globals().get("spaces_client")
                bucket = globals().get("SPACE_BUCKET") or globals().get("SPACES_BUCKET")
                if s3_client and bucket:
                    try:
                        s3_client.upload_file(path, bucket, f"outputs/{fname}", ExtraArgs={"ACL": "public-read"})
                        if verbose:
                            print("[save] uploaded", fname, "to spaces", flush=True)
                    except Exception:
                        with open(path, "rb") as fobj:
                            s3_client.put_object(Bucket=bucket, Key=f"outputs/{fname}", Body=fobj, ACL="public-read")
                        if verbose:
                            print("[save] uploaded (put_object) ", fname, "to spaces", flush=True)
            except Exception as e:
                if verbose:
                    print("[save] upload attempt failed:", e, flush=True)
            saved_files.append(fname)
            return True
        except Exception as e:
            if verbose:
                print("[save] write failed:", e, flush=True)
            return False

    def try_b64_decode(s):
        try:
            return base64.b64decode(s)
        except Exception:
            if "," in s:
                try:
                    return base64.b64decode(s.split(",", 1)[1])
                except Exception:
                    return None
            return None

    # Strategy A: inspect common attributes (.candidates / .artifacts / .output)
    try:
        candidates = getattr(resp_obj, "candidates", None)
        if candidates:
            for c in candidates:
                content = getattr(c, "content", None) or getattr(c, "outputs", None) or getattr(c, "output", None)
                parts = content if isinstance(content, (list, tuple)) else (getattr(content, "parts", None) or [content])
                for p in parts:
                    # check common fields
                    for attr in ("image", "binary", "data", "image_bytes", "content", "b64", "base64"):
                        val = None
                        if isinstance(p, dict) and attr in p:
                            val = p[attr]
                        else:
                            val = getattr(p, attr, None) if hasattr(p, attr) else None
                        if val:
                            if isinstance(val, (bytes, bytearray)):
                                if _write_bytes(bytes(val)):
                                    if len(saved_files) >= max_files: 
                                        return saved_files
                            elif isinstance(val, str):
                                decoded = try_b64_decode(val)
                                if decoded:
                                    if _write_bytes(decoded):
                                        if len(saved_files) >= max_files:
                                            return saved_files
                    # check for uri/url fields in part
                    uri = (p.get("uri") if isinstance(p, dict) else None) or getattr(p, "uri", None) or getattr(p, "image_uri", None) or getattr(p, "url", None)
                    if uri:
                        try:
                            r = requests.get(uri, stream=True, timeout=20)
                            if r.status_code == 200:
                                if _write_bytes(r.content):
                                    if len(saved_files) >= max_files:
                                        return saved_files
                        except Exception as e:
                            if verbose:
                                print("[save] failed to download uri:", uri, e, flush=True)

        # top-level artifacts / output / outputs
        for top_attr in ("artifacts", "output", "outputs", "artifacts_list"):
            outv = getattr(resp_obj, top_attr, None)
            if outv:
                items = outv if isinstance(outv, (list, tuple)) else [outv]
                for item in items:
                    if isinstance(item, dict):
                        for k in ("uri", "image_uri", "url", "download_uri", "gcs_uri"):
                            if k in item and item[k]:
                                try:
                                    r = requests.get(item[k], stream=True, timeout=20)
                                    if r.status_code == 200:
                                        if _write_bytes(r.content):
                                            if len(saved_files) >= max_files:
                                                return saved_files
                                except Exception as e:
                                    if verbose:
                                        print("[save] download failed for", item[k], e, flush=True)
                        for k in ("binary", "data", "b64", "base64", "image_base64", "image"):
                            if k in item and item[k]:
                                val = item[k]
                                if isinstance(val, (bytes, bytearray)):
                                    if _write_bytes(bytes(val)): 
                                        if len(saved_files) >= max_files:
                                            return saved_files
                                elif isinstance(val, str):
                                    dec = try_b64_decode(val)
                                    if dec and _write_bytes(dec):
                                        if len(saved_files) >= max_files:
                                            return saved_files
                    else:
                        uri = getattr(item, "uri", None) or getattr(item, "image_uri", None) or getattr(item, "url", None)
                        if uri:
                            try:
                                r = requests.get(uri, stream=True, timeout=20)
                                if r.status_code == 200:
                                    if _write_bytes(r.content):
                                        if len(saved_files) >= max_files:
                                            return saved_files
                            except Exception as e:
                                if verbose:
                                    print("[save] failed to download uri:", uri, e, flush=True)
                        for attr in ("binary", "data", "image", "b64", "base64"):
                            v = getattr(item, attr, None)
                            if v:
                                if isinstance(v, (bytes, bytearray)):
                                    if _write_bytes(bytes(v)): 
                                        if len(saved_files) >= max_files:
                                            return saved_files
                                elif isinstance(v, str):
                                    dec = try_b64_decode(v)
                                    if dec and _write_bytes(dec):
                                        if len(saved_files) >= max_files:
                                            return saved_files
    except Exception as e:
        if verbose:
            print("[save] strategy A failed:", e, flush=True)

    # Strategy B: scan repr for data URIs or long base64 blocks
    try:
        rep = repr(resp_obj)
        for m in re.finditer(r"data:image/(?:png|jpeg|jpg);base64,([A-Za-z0-9+/=]+)", rep):
            b64 = m.group(1)
            dec = try_b64_decode(b64)
            if dec and _write_bytes(dec):
                if len(saved_files) >= max_files:
                    return saved_files
        for m in re.finditer(r"([A-Za-z0-9+/=]{200,})", rep):
            b64 = m.group(1)
            dec = try_b64_decode(b64)
            if dec and (dec[:8] == b'\x89PNG\r\n\x1a\n' or dec[:3] == b'\xff\xd8\xff'):
                if _write_bytes(dec):
                    if len(saved_files) >= max_files:
                        return saved_files
    except Exception as e:
        if verbose:
            print("[save] strategy B failed:", e, flush=True)

    if not saved_files and verbose:
        print("[save] no images extracted; inspect", debug_dump, flush=True)
    return saved_files

import os, re

def save_images_from_genai_content(resp_obj, prefix="gen", max_files=3, verbose=True):
    """
    Extract images from Vertex genai response objects that have:
      resp_obj.content.parts -> Part.inline_data.data (bytes) with mime_type.
    Writes files to outputs/ and returns list of filenames.
    """
    os.makedirs("outputs", exist_ok=True)
    saved = []
    # safe timestamp
    import time
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"{int(time.time()*1e6) % 1000000:06d}"

    def write_bytes(bts: bytes, mime="image/png"):
        # choose extension from mime
        ext = ".png"
        if "jpeg" in (mime or "").lower() or "jpg" in (mime or "").lower():
            ext = ".jpg"
        safe_prefix = re.sub(r"[^A-Za-z0-9_.-]", "_", prefix)[:40]
        fname = f"{safe_prefix}_{ts}_{len(saved)}{ext}"
        out = os.path.join("outputs", fname)
        with open(out, "wb") as f:
            f.write(bts)
        if verbose: print("[save_genai] wrote", out, flush=True)
        saved.append(fname)
        return fname

    # 1) Try the exact path: resp_obj.content.parts -> inline_data.data with mime_type
    try:
        content = getattr(resp_obj, "content", None) or getattr(resp_obj, "contents", None) or None
        if content:
            parts = getattr(content, "parts", None) or (content if isinstance(content, (list,tuple)) else None)
            if parts:
                for p in parts:
                    if len(saved) >= max_files:
                        break
                    # p may be an object with attributes inline_data (Blob)
                    inline = getattr(p, "inline_data", None) or getattr(p, "blob", None) or None
                    if inline:
                        data = getattr(inline, "data", None)
                        mime = getattr(inline, "mime_type", None) or getattr(inline, "mime", None) or None
                        if isinstance(data, (bytes, bytearray)):
                            write_bytes(bytes(data), mime=mime)
                            continue
                        # sometimes data is a memoryview
                        try:
                            # try to get buffer
                            mv = bytes(data)
                            write_bytes(mv, mime=mime)
                            continue
                        except Exception:
                            pass
    except Exception as e:
        if verbose: print("[save_genai] primary extraction failed:", e, flush=True)

    # 2) Fallback: attempt the generic robust saver (if you added it earlier)
    try:
        # call previous robust saver if available
        if 'save_images_from_response_robust' in globals() and save_images_from_response_robust is not save_images_from_genai_content:
            more = save_images_from_response_robust(resp_obj, prefix=prefix, max_files=max_files, verbose=verbose)
            for f in more:
                if len(saved) >= max_files:
                    break
                if f not in saved:
                    saved.append(f)
    except Exception as e:
        if verbose: print("[save_genai] fallback robust saver failed:", e, flush=True)

    # 3) If nothing saved, write debug repr to outputs/debug for inspection
    if not saved:
        os.makedirs("outputs/debug", exist_ok=True)
        dbg_path = os.path.join("outputs", "debug", f"gen_resp_{prefix}_{ts}.txt")
        try:
            with open(dbg_path, "w", encoding="utf-8") as wf:
                wf.write(repr(resp_obj))
            if verbose: print("[save_genai] no images found; dumped repr to", dbg_path, flush=True)
        except Exception as e:
            if verbose: print("[save_genai] failed to write debug dump:", e, flush=True)

    return saved


# --- Background cleanup for outputs/ (24hr expiry) ---
def cleanup_outputs():
    while True:
        time.sleep(3600)  # Run every hour
        if not s3:
            continue
        try:
            now = datetime.now(timezone.utc)
            continuation_token = None
            while True:
                kwargs = {
                    'Bucket': SPACE_NAME,
                    'Prefix': 'outputs/',
                    'MaxKeys': 1000
                }
                if continuation_token:
                    kwargs['ContinuationToken'] = continuation_token
                response = s3.list_objects_v2(**kwargs)
                for obj in response.get('Contents', []):
                    if now - obj['LastModified'] > timedelta(hours=24):
                        s3.delete_object(Bucket=SPACE_NAME, Key=obj['Key'])
                        print(f"[cleanup] Deleted expired object: {obj['Key']}")
                if response.get('IsTruncated'):
                    continuation_token = response.get('NextContinuationToken')
                else:
                    break
        except Exception as e:
            print("[cleanup] Failed to clean outputs:", e)

# Start cleanup thread if s3 is available
if s3:
    cleanup_thread = threading.Thread(target=cleanup_outputs, daemon=True)
    cleanup_thread.start()
    print("[startup] Started background cleanup thread for outputs/")

# --- Flask app ---

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://dbuser:StrongPasswordHere@34.10.193.3:5432/postgres"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Define Creative model


# Define Conversation model
class Conversation(db.Model):
    __tablename__ = 'conversationss'
    __table_args__ = {'extend_existing': True} 
    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.String(128), nullable=False)
    workspace_id = db.Column(db.String(128), nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Create tables if not exist and test connection




def _build_base_url():
    return EXTERNAL_BASE_URL.rstrip("/")

def escape_for_inline(s: str) -> str:
    if s is None:
        return ""
    return s.replace("\\", "\\\\").replace('"', '\\"')


import json
import textwrap
from typing import Optional, List

# This function assumes `escape_for_inline` exists in the calling module (as in your codebase).
# If not available, a safe fallback is provided.
def _escape_for_inline_fallback(s: Optional[str]) -> str:
    if s is None:
        return ""
    return str(s).replace("\\", "\\\\").replace('"', '\\"')

def advanced_master_ad_creative_prompt(user_input: str, *, has_image: bool = False,
                                       image_hint: Optional[str] = None,
                                       num_variants: int = 3,
                                       target_platforms: List[str] = ["facebook", "instagram", "tiktok"],
                                       include_example: bool = True) -> str:
    """
    Produces an advanced "master" instruction prompt for ad creative planning.
    Returns a single string containing the instruction to be sent to a text-model prompt generator.
    This version injects:
      - theme context (Trust & Innovation)
      - realism-weighted keywords
      - dynamic negative prompt composition (attempts to load recent feedback negatives)
      - ranking hint for downstream reranker (CLIP + realism model)
      - theme planner metadata for downstream systems
    """

    # Try to use your existing escape_for_inline if available, otherwise fallback
    try:
        escape = globals().get("escape_for_inline", None) or globals().get("_escape_for_inline_fallback")
        if not escape:
            escape = _escape_for_inline_fallback
    except Exception:
        escape = _escape_for_inline_fallback

    ui_raw = (user_input or "").strip()
    ui = escape(ui_raw)
    if num_variants < 1:
        num_variants = 1
    platforms_str = ", ".join(target_platforms)

    # --- Theme + realism boosters (to be injected into visual prompts) ---
    theme_context = (
        "Theme: Trust & Innovation — emphasize realism, human warmth, professionalism, and authenticity "
        "in AI-assisted legal environments."
    )
    # Weighted tokens for generation systems that support weighting (e.g. '(token:1.2)')
    realism_boost = "(realistic skin texture:1.25), (natural lighting:1.15), (professional composition:1.2)"

    # --- Try to fetch recent feedback-driven negatives from NegativeBank if available ---
    feedback_negatives = []
    try:
        # attempt to import and query your negatives bank if present in project
        from lib.negatives import NegativeBank  # type: ignore
        nb = NegativeBank()
        # get top global negatives (fallback safe)
        feedback_negatives = nb.get_prio_negatives(category="global", top_n=8) or []
    except Exception:
        # fallback: keep empty list; the base negatives will still be used
        feedback_negatives = []

    # --- Base negative prompt (comprehensive) ---
    base_negatives = [
        "cartoon", "anime", "3D render", "CGI", "low resolution", "fake human faces",
        "distorted hands", "deformed fingers", "missing limbs", "extra limbs",
        "overexposed lighting", "plastic skin", "unrealistic reflections",
        "blurry", "pixelated", "bad anatomy", "text watermark", "oversaturated colors",
        "neon backgrounds", "robotic faces", "poor typography", "grainy textures",
        "disfigured proportions", "duplicate people", "messy papers", "unnatural smile",
        "incorrect hand gestures", "floating objects", "jpeg artifacts", "low quality"
    ]

    # Merge feedback negatives (dedupe, keep order)
    merged_negatives = []
    seen = set()
    for n in base_negatives + list(feedback_negatives):
        t = (n or "").strip()
        if not t:
            continue
        if t.lower() in seen:
            continue
        merged_negatives.append(t)
        seen.add(t.lower())

    neg_prompt_combined = ", ".join(merged_negatives)

    # Example payload (keeps structure similar to previous examples)
    example = ""
    if include_example:
        example_obj = {
            "ad_title": "⚖️ Digital Advocate — Trust & Innovation",
            "research_insights": "2025 simulated insight: AI-assisted legal tools increase workflow efficiency and perceived trust when visuals are human-forward and authenticity is emphasized.",
            "components": [
                {
                    "component": "Visual/Video",
                    "content": "**Option 1 (UGC-style short video - TikTok):** Start with a stressed lawyer surrounded by paperwork; cut to the same lawyer relaxed while a subtle holographic UI organizes files. Keep edits fast (15s), include close-ups of hands and UI.",
                    "notes": "Optimize for mobile: 9:16 aspect ratio, strong opening frame in first 1.5s. Prioritize natural facial expressions and real human texture; avoid sci-fi/excessive CGI.",
                    "visual_options": [
                        {
                            "type": "video",
                            "description": "UGC-to-professional transformation clip (15s).",
                            "visual_prompt": (
                                f"Photorealistic, cinematic 15s ad sequence: {theme_context} {realism_boost}. "
                                "Start: chaotic desk, dim light; Transition: calm desk with AI holographic document sorting in soft blue glow. "
                                "Closeups on hands interacting with UI, natural expressions, editorial color grade, shot on Canon EOS R5, 50mm lens, 60fps slow motion, 9:16 aspect ratio, mobile-first composition."
                            ),
                            "negative_prompt": neg_prompt_combined
                        },
                        {
                            "type": "static",
                            "description": "Hero image for LinkedIn/Instagram.",
                            "visual_prompt": (
                                f"Ultra-realistic cinematic advertisement photo of a confident professional lawyer in a modern sunlit office, "
                                f"AI holographic legal interface organizing digital documents beside the person, soft natural light through large windows, "
                                f"subtle blue holographic glow representing AI assistance, calm and confident facial expression, neat desk with open legal files, "
                                f"shot on Canon EOS R5, 50mm lens, f/1.8, depth of field, corporate branding aesthetic, editorial ad photography, {realism_boost}, "
                                "realistic skin texture, elegant business attire, premium office interiors, minimalist color palette (beige, navy blue, white, silver accents), "
                                "tagline elegantly displayed: “Digital Advocate – Simplifying Legal Work with Trust and Innovation.”"
                            ),
                            "negative_prompt": neg_prompt_combined
                        }
                    ]
                },
                {
                    "component": "Primary Text",
                    "content": (
                        "Concise, human-centered copy that emphasizes trust and time-savings. Example: "
                        "\"Stop drowning in paperwork. Let Digital Advocate organize your caseload so you can focus on clients.\""
                    ),
                    "notes": "Keep <= 125 characters for headlines; personalize where possible (e.g., 'For small firms', 'For corporate counsel')."
                },
                {
                    "component": "CTA Button",
                    "content": "Primary CTA: 'Try Digital Advocate' / Secondary CTA: 'See a demo'",
                    "notes": "Use strong command verbs and small friction (demo, try)."
                }
            ],
            "why_this_works": (
                "- Trend alignment: human-first visuals increase trust for legal audiences.\n"
                "- Conversion focus: clear pain → solution → CTA structure.\n"
                "- Platform optimization: mobile-first shorts + high-res feed creatives."
            ),
            "ab_testing_ideas": "Test 'human-first' warm visuals vs 'tech-first' cool visuals; 15s vs 30s videos on TikTok.",
            "scaling_tips": "Generate 20 variants per theme, personalize headline copy using user metadata.",
            "closing_question": "Which platform and tone do you want to prioritize for launch?",
            "attached_prompt": ui_raw
        }
        example = json.dumps(example_obj, ensure_ascii=False)

    # Build instruction string (single JSON output required)
    instruction = textwrap.dedent(f"""
    You are an expert AI-driven creative marketing team in 2025 producing high-converting ad creatives.
    Simulate research, pick audience pain points, craft emotionally resonant hooks, and produce scalable ad variants tailored for platforms: {platforms_str}.
    Use best practices: prioritize authenticity, photorealism, A/B testing readiness, and fast-loading formats on mobile platforms.
    Produce EXACTLY one JSON object as output (valid JSON only, no surrounding prose).
    The top-level key must be "ad_variants" and contain exactly {num_variants} plan objects.

    REQUIRED keys per plan:
      - ad_title (<=15 words)
      - research_insights
      - components (array; includes at least one "Visual/Video" object with 2-4 visual_options)
      - why_this_works
      - ab_testing_ideas
      - scaling_tips
      - closing_question
      - attached_prompt

    Additional plan-level fields added for integration:
      - ranking_hint: short string describing reranker usage (CLIP + realism model)
      - theme_meta: metadata object describing theme id, palette, tone, and planner flags

    ADVANCED RULES:
      - Always include realism boosters (lighting, lens, composition) in visual prompts.
      - Append the NEGATIVE PROMPT below to every visual_option as its 'negative_prompt' value.
      - Include platform-specific aspect notes (9:16 for TikTok, 1:1 for Instagram feed, 16:9 for wide placements).
      - If has_image is True, suggest explicit logo placement per guidelines and mention that the uploaded image is treated as a branding asset (do not overwrite user instruction).
      - No hallucinated brand names or unverifiable claims.
      - If validation fails, return: {{ "error": "validation_failed", "reason": "<reason>" }}.

    NEGATIVE PROMPT (apply to all visual options):
    "{neg_prompt_combined}"

    RANKING HINT (apply to each plan): "After generation, score realism and relevance using CLIP similarity (prompt→image) and a realism classifier trained on previous human feedback. Rerank top candidates before human review."

    THEME_META (apply to each plan):
    {json.dumps({
        "theme_id": "digital_advocate_trust_innovation",
        "primary_palette": ["#F5F2EE", "#0B2153", "#C0C6CC", "#FFFFFF"],
        "emotional_tone": "trustworthy, intelligent, confident",
        "visual_style": "ultra-realistic corporate photography",
        "neg_prompt_weight": "adaptive",
        "feedback_integration": True
    }, ensure_ascii=False)}

    EXAMPLE (for format only): {example}

    User request (verbatim): "{ui}"
    """).strip()

    return instruction

def master_prompt_json(user_input: str, *, has_image: bool = False,
                       image_hint: Optional[str] = None,
                       num_themes: int = 3,
                       include_example: bool = True) -> str:
    """
    Build an instruction string for the text model to generate theme JSON objects.
    Updated requirement: visual_prompt MUST be a **detailed multi-line A–Z checklist**
    (NOT a single-line paragraph). Each visual_prompt must include labeled entries
    from A through Z covering a complete A→Z creative & production checklist
    (composition, lighting, camera, lenses, color, wardrobe, props, logo placement,
    typography clear area, motion, post-processing, deliverables, negative hints, etc.)
    and then finish with the literal token END_PROMPT on its own line.

    This enforces highly descriptive prompts (A–Z) rather than compact one-liners.
    """
    # prefer existing escape_for_inline if present; otherwise fallback
    try:
        escape = globals().get("escape_for_inline") or globals().get("_escape_for_inline_fallback")
        if not escape:
            raise NameError()
    except Exception:
        def escape(s: Optional[str]) -> str:
            if s is None:
                return ""
            return str(s).replace("\\", "\\\\").replace('"', '\\"')

    ui_raw = (user_input or "").strip()
    ui = escape(ui_raw)
    if num_themes < 1:
        num_themes = 1

    # If an image/logo is provided, instruct model how to treat it
    img_note = ""
    if has_image:
        img_note = (
            "If an image/logo is provided, treat it primarily as a branding/logo asset and prioritize "
            "the user's textual prompt for message, tone and content. Do NOT let the image content "
            "override the user's explicit instructions. Suggest logo placement (e.g., bottom-right, ~8-10% width) "
            "and mention 'logo_area_reserved' in visual_prompt where caption overlay is expected."
        )
        if image_hint:
            img_note += f" Image hint: {escape(image_hint)}."

    # realism & camera cues to be injected / required in visual_prompt
    realism_boost = "(realistic skin texture:1.25), (natural lighting:1.15), (professional composition:1.2)"
    camera_template = "Include camera cues: e.g., 'shot on Canon EOS R5, 50mm, f/1.8' or 'Sony A7R IV, 35mm, shallow DOF'."

    # platform aspect guidance (model should reflect this in aspect_ratio field)
    platform_aspect_guide = {
        "tiktok": "9:16 (vertical, mobile-first; close framing; strong first-frame hook)",
        "instagram_post": "4:5 (portrait feed; shallow DOF for subject)",
        "instagram_square": "1:1 (centered composition)",
        "instagram_story": "9:16 (full-bleed vertical)",
        "facebook": "16:9 (wide landscape hero)",
        "linkedin": "1.91:1 (professional landscape)",
        "default": "16:9"
    }

    # comprehensive avoid-list phrased as inline guidance (so visual_prompt contains explicit negatives per letter)
    avoid_list = [
        "cartoon", "anime", "CGI", "3D render", "low resolution", "fake human faces",
        "distorted hands", "deformed fingers", "extra limbs", "missing limbs",
        "plastic skin", "unrealistic reflections", "blurry", "pixelated", "text watermark",
        "oversaturated colors", "neon backgrounds", "robotic faces", "poor typography",
        "jpeg artifacts", "duplicate objects", "floating objects"
    ]
    avoid_hint = "Avoid: " + ", ".join(avoid_list) + "."

    example = ""
    if include_example:
        # Example visual_prompt now demonstrates A–D as sample; real output must have A..Z
        example_obj = {
            "title": "Sunlit Alley (sample partial A–D)",
            "one_line": "A quiet narrow alley at golden hour with scattered leaves.",
            "visual_prompt": (
                "A: Composition - wide-angle leading lines toward a vanishing point; subject offset 1/3 from left.\n"
                "B: Lighting - golden hour backlight, soft fill from right, subtle rim light.\n"
                "C: Camera/Lens - shot on 35mm, f/2.8, low angle, slight tilt down.\n"
                "D: Color/Palette - warm ambers + cool shadows, muted highlights.\n"
                "... (continue through to Z, fully detailed) ...\n"
                f"{camera_template} {realism_boost}\n"
                f"{avoid_hint}\n"
                "END_PROMPT"
            ),
            "keywords": ["alley", "golden_hour", "wet_cobblestone", "long_shadows", "backlight", "photorealistic"],
            "aspect_ratio": "16:9; centered vertical leading lines",
            "attached_prompt": ui_raw
        }
        example = json.dumps(example_obj, ensure_ascii=False)

    instruction = textwrap.dedent(f"""
    You are a prompt-engineering assistant for an IMAGE generation model focused on creating
    ultra-detailed ad-ready themes. Produce EXACTLY one JSON object as output (only valid JSON, no leading/trailing text).
    The JSON must contain a single key "themes" which is an array of exactly {num_themes} theme objects.
    Do NOT output any explanatory prose outside of the JSON.

    REQUIRED keys for each theme object (exactly these six keys, no extras):
      - title: short string (<= 8 words)
      - one_line: one short sentence describing the concept
      - visual_prompt: MULTI-LINE descriptive A–Z checklist. **MUST include labeled entries from "A:" through "Z:" (26 items).**
                       Each letter entry should be 1-3 sentences (concise but descriptive) covering distinct aspects of the creative:
                       (composition, subject placement, camera/lens, aperture, shutter, lighting types, color palette, materials/textures,
                       wardrobe, styling, props, logo placement, typography safe area, caption area, motion cues, background treatment,
                       reflections, skin/retouch guidance, depth cues, bokeh, contrast, post-processing, color grading, resolution,
                       deliverables, negative hints). After the "Z:" entry include the literal line 'END_PROMPT' on its own line.
                       Do NOT put the A–Z list in an embedded JSON array—visual_prompt must be a single multiline string value.
      - keywords: array of 5-10 short tokens (use underscores, e.g., 'legal_ai', no commas inside elements)
      - aspect_ratio: a ratio (e.g., '16:9', '4:5', '9:16') AND a short platform composition hint from the recommended mappings:
                      {json.dumps(platform_aspect_guide, ensure_ascii=False)}
      - attached_prompt: the exact original user input (verbatim). This MUST match exactly.

    ADDITIONAL GUIDANCE:
      - Visual prompts must be very descriptive from A→Z; avoid generic one-line prompts. The goal is an A→Z creative & production checklist.
      - Each visual_prompt MUST mention at least one camera cue and one realism-weighted token such as {realism_boost}.
      - Include one explicit line within the A–Z text that reserves logo area when has_image is True (e.g. 'logo_area_reserved: bottom-right ~8% width').
      - Include inline negative guidance (avoid list) as one of the lettered entries (preferably near the end).
      - Do NOT invent brand names or real person names.
      - All text must be in English.

    VALIDATION CHECKS the model must satisfy before returning:
      1) Top-level object is valid JSON with a single "themes" key.
      2) "themes" is an array of length {num_themes}.
      3) Each theme contains exactly these keys: ["title","one_line","visual_prompt","keywords","aspect_ratio","attached_prompt"].
      4) attached_prompt equals the user's raw input verbatim.
      5) keywords length is between 5 and 10.
      6) title <= 8 words and safe for filenames.
      7) visual_prompt contains labeled entries A: through Z: (26 distinct labeled lines), is multi-line, contains at least one camera cue and one realism-weighted token, contains 'logo_area_reserved' if has_image is True, and ends with a line 'END_PROMPT'.
      If any check fails, output a single JSON object: {{ "error": "validation_failed", "reason": "<short reason>" }}.

    RETURN FORMAT:
      {{ "themes": [ theme1, theme2, ... ] }}

    EXAMPLE (partial A–D shown for format guidance, NOT to be repeated verbatim):
    {example}

    User request (raw): "{ui}"
    """).strip()

    return instruction


def build_content_prompt_from_theme(user_prompt: str, theme: Dict[str, Any], workspace_ctx: Optional[Dict[str, Any]] = None) -> str:
    """
    Build an advanced instruction for the text model to produce a full AD CREATIVE plan
    that matches the table/example layout you provided.

    Output requirement:
      - Produce EXACTLY one JSON object (no surrounding prose).
      - Top-level key: "ad_plan"
      - ad_plan must include:
          - ad_title (string)
          - ad_creative (array of component rows). Each row must be an object:
              { "component": "<Component Name>",
                "content": "<Detailed content / copy / visual directions>",
                "notes": "<Short notes / optimization tips>" }
            The ad_creative array must include at minimum these components (in any order):
              "Visual/Video", "Primary Text", "Headline", "Description", "Call to Action (CTA) Button", "Target Audience"
          - why_this_works (string or array)
          - ab_testing_ideas (string)
          - workspace_context (the provided workspace_ctx JSON serialized) -- optional but include if present
          - attached_prompt (the original user prompt verbatim)
    Validation rules:
      - The returned JSON must contain only the required keys listed above (extra top-level keys allowed only if they are clearly useful: e.g., 'tracking_tags').
      - Strings must be concise where requested (headline <= 10 words).
      - ad_creative must include at least two Visual/Video options in the content (Video and Static).
    """
    # Prefer existing escape function if present
    try:
        escape = globals().get("escape_for_inline") or globals().get("_escape_for_inline_fallback")
        if not escape:
            raise NameError()
    except Exception:
        def escape(s: Optional[str]) -> str:
            if s is None:
                return ""
            return str(s).replace("\\", "\\\\").replace('"', '\\"')

    theme_title = theme.get("title", "")
    theme_one_line = theme.get("one_line", "")
    attached = theme.get("attached_prompt", "") or ""
    ui = escape(user_prompt or "")

    # Prepare a short example block that mirrors the user's requested table (keeps format but short)
    example_table = {
        "ad_title": "⚖️ Stop Drowning in Legal Paperwork! Meet Your AI Advocate.",
        "ad_creative": [
            {
                "component": "Visual/Video",
                "content": (
                    "Option 1 (Video): Start with fast-paced montage of 'legal stress' shots (stacks of paper, rubbing temples, zoom on confusing document). "
                    "Slam cut to a hand placing a sleek phone/tablet showing the AI Advocate app. Person smiles and scrolls. "
                    "Option 2 (Static/Carousel): Split-image - Left: chaotic desk at late hour; Right: clean desk with app UI and calm person sipping coffee."
                ),
                "notes": "Visuals must convey speed, simplicity, and relief quickly."
            },
            {
                "component": "Primary Text",
                "content": "Tired of legal fees and confusing documents? 🤯 Get clarity and support without the hourly bill. [App Name] simplifies contracts, researches cases, drafts documents instantly.",
                "notes": "Keep punchy, problem→solution. Use emojis to break up copy."
            },
            {
                "component": "Headline",
                "content": "AI Advocate: Legal Work, Simplified. 🚀",
                "notes": "Short, action-oriented, clear value prop (<=10 words)."
            },
            {
                "component": "Description",
                "content": "From startups to personal docs—expert-level legal assistance 24/7. Try it Free!",
                "notes": "Reinforce availability and low barrier entry."
            },
            {
                "component": "Call to Action (CTA) Button",
                "content": "Learn More (or Try Now)",
                "notes": "'Learn More' typically lower friction for complex products."
            },
            {
                "component": "Target Audience",
                "content": "SMBs, Entrepreneurs, Freelancers; Interests: Legal tech, startup tools, business automation, contract management.",
                "notes": "Use for Meta targeting; suggest lookalike audiences from existing CRM lists."
            }
        ],
        "why_this_works": (
            "- Pain Point Focus: addresses cost & complexity.\n"
            "- Clear Value: shows capability (contract review, drafting, research) and benefit (focus on business).\n"
            "- A/B Ready: video vs static to test engagement."
        ),
        "ab_testing_ideas": "Test video (15s) vs static carousel; test 'Try Free' vs 'See Demo' CTAs; test human-first vs product-demo visuals.",
        "attached_prompt": attached
    }

    # Build the instruction string we will send to the text model
    workspace_snippet = ""
    if workspace_ctx:
        try:
            workspace_snippet = json.dumps(workspace_ctx, ensure_ascii=False)
        except Exception:
            workspace_snippet = str(workspace_ctx)

    inst = textwrap.dedent(f"""
    You are a senior social-media copywriter and ad strategist. Produce EXACTLY one JSON object as output (no surrounding prose).
    The top-level key must be "ad_plan".
    
    You should not make any spelling mistakes and gramatical mistakes 

    REQUIRED structure for "ad_plan":
      - ad_title: short, hooky title (string).
      - ad_creative: array of component objects. Each component object MUST contain:
          - component: e.g., "Visual/Video", "Primary Text", "Headline", "Description", "Call to Action (CTA) Button", "Target Audience"
          - content: detailed content (for Visual/Video include at least two options: one Video, one Static)
          - notes: concise optimization or platform notes
      - why_this_works: concise rationale (string or array)
      - ab_testing_ideas: 2-3 testable hypotheses (string)
      - workspace_context: (optional) include the provided workspace JSON if available
      - attached_prompt: the exact original user prompt (verbatim) - this must match the user's input.

    STRICT RULES:
      - Output ONLY valid JSON and nothing else.
      - ad_creative must include the "Visual/Video" component and that component's content must include both:
          (a) "Option 1 (Video):" with a short video storyboard, and
          (b) "Option 2 (Static Image/Carousel):" with split-image or carousel instructions.
      - Headlines should be <= 10 words.
      - Primary Text (copy) should be natural and problem→solution focused and <= 220 chars for caption use.
      - Include platform optimization notes in component.notes (e.g., mobile-first 9:16 for TikTok, 4:5 for IG feed).
      - Do NOT hallucinate product features or make unverifiable legal claims. Use language like 'assist', 'simplify', 'help', not 'legal advice'.
      - If any validation fails, return: {{ "error": "validation_failed", "reason": "<short reason>" }}.

    USE THE FOLLOWING INPUTS:
      - USER_PROMPT (verbatim): "{ui}"
      - THEME_TITLE: "{escape(theme_title)}"
      - THEME_ONE_LINE: "{escape(theme_one_line)}"
      - ATTACHED_PROMPT: "{escape(attached)}"
      {"WORKSPACE_CONTEXT: " + workspace_snippet if workspace_snippet else ""}

    EXAMPLE (format only; follow structure, content should be tailored to the inputs):
    {json.dumps(example_table, ensure_ascii=False)}

    Now produce the JSON ad_plan for the user input above.
    """).strip()

    return inst



# Replace _generate_image_from_prompt with this (uses contents=[prompt_text] simple shape)
def _generate_image_from_prompt(
    prompt_text: str,
    model_id: str = MODEL_ID,
    candidate_count: int = 1,
    guidance_scale: float | None = None,
    max_output_tokens: int = 2048,
) -> Any:
    """
    Uses GENAI_CLIENT.models.generate_content with contents=[prompt_text].
    - Tries a single multi-candidate call first (candidate_count may work).
    - If that fails, falls back to repeated single-candidate calls (which works with your SDK).
    Returns:
      - If multi-call succeeded -> the SDK response object (may contain .candidates)
      - If fallback used -> list of response objects (one per candidate)
    """
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")

    full_prompt = f"Generate an image of: {prompt_text}"

    # Build simple config (prefer typed config; fallback to dict)
    try:
        cfg = types.GenerateContentConfig(
            response_modalities=["TEXT", "IMAGE"],
            candidate_count=candidate_count,
            max_output_tokens=max_output_tokens,
        )
        if guidance_scale is not None:
            try:
                setattr(cfg, "guidance_scale", guidance_scale)
            except Exception:
                pass
    except Exception:
        cfg = {
            "response_modalities": ["TEXT", "IMAGE"],
            "candidate_count": candidate_count,
            "max_output_tokens": max_output_tokens,
        }
        if guidance_scale is not None:
            cfg["guidance_scale"] = guidance_scale

    # 1) Try one multi-candidate call using the simple contents shape the SDK expects
    try:
        resp = GENAI_CLIENT.models.generate_content(model=model_id, contents=[full_prompt], config=cfg)
        # If candidate_count == 1, return the resp directly (backwards compat)
        if candidate_count == 1:
            return resp
        # Otherwise return resp (caller can inspect resp.candidates)
        return resp
    except Exception as e:
        print(f"[_generate_image_from_prompt] multi-candidate call failed: {e}. Falling back to repeated single-candidate calls.", flush=True)

    # 2) Fallback: call single-candidate generation candidate_count times (works with this SDK)
    responses = []
    for i in range(candidate_count):
        try:
            try:
                single_cfg = types.GenerateContentConfig(
                    response_modalities=["TEXT", "IMAGE"],
                    candidate_count=1,
                    max_output_tokens=max_output_tokens,
                )
                if guidance_scale is not None:
                    try:
                        setattr(single_cfg, "guidance_scale", guidance_scale)
                    except Exception:
                        pass
            except Exception:
                single_cfg = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1, "max_output_tokens": max_output_tokens}
                if guidance_scale is not None:
                    single_cfg["guidance_scale"] = guidance_scale

            r = GENAI_CLIENT.models.generate_content(model=model_id, contents=[full_prompt], config=single_cfg)
            responses.append(r)
        except Exception as e2:
            print(f"[_generate_image_from_prompt] candidate call {i} failed: {e2}", flush=True)
            # continue to collect other candidates if possible
    return responses


# Convenience: always return a normalized list of candidate-response-like objects
def generate_image_candidates(prompt_text: str, model_id: str = MODEL_ID, n: int = 3, guidance_scale: float | None = None):
    """
    Returns a list of response objects or candidate-like objects so calling code can treat uniformly.
    """
    resp = _generate_image_from_prompt(prompt_text, model_id=model_id, candidate_count=n, guidance_scale=guidance_scale)
    normalized = []

    # If fallback returned a list of full response objects, return them
    if isinstance(resp, list):
        normalized.extend(resp)
        return normalized

    # If SDK returned a single response object with .candidates, extract each candidate as a pseudo-response
    if getattr(resp, "candidates", None):
        # resp.candidates likely contains candidate objects; return them directly
        for cand in resp.candidates:
            normalized.append(cand)
        return normalized

    # Otherwise return the single response as a single-item list for uniformity
    normalized.append(resp)
    return normalized


    
def _generate_image_with_input_image(prompt_text: str, file_bytes: Optional[bytes], mime_type: Optional[str], file_uri: Optional[str] = None, model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    contents = []
    if file_bytes is not None:
        contents.append(Part.from_bytes(data=file_bytes, mime_type=mime_type or "image/jpeg"))
    elif file_uri:
        if mime_type:
            contents.append(Part.from_uri(file_uri=file_uri, mime_type=mime_type))
        else:
            contents.append(Part.from_uri(file_uri=file_uri))
    else:
        raise ValueError("file_bytes or file_uri required for image-guided generation")

    # Prefix prompt to explicitly request image generation
    prompt_text = f"Generate an image based on the following: {prompt_text}"
    contents.append(prompt_text)
    print("Contents for image gen:", contents)

    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)

    resp = GENAI_CLIENT.models.generate_content(
        model=model_id,
        contents=contents,
        config=cfg,
    )
    return resp

# Additional helpers for multi-image and edit flows
def _generate_image_with_input_images(prompt_text: str, parts: List[Part], model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)

    # Prefix prompt to explicitly request image generation
    prompt_text = f"Generate an image based on the following: {prompt_text}"
    contents = parts + [prompt_text]
    resp = GENAI_CLIENT.models.generate_content(model=model_id, contents=contents, config=cfg)
    return resp

def _generate_image_edit_with_instruction(prompt_text: str, part: Part, model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    # A single-image edit: send image part then instruction text using models.generate_content
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)
    contents = [part, prompt_text]
    resp = GENAI_CLIENT.models.generate_content(model=model_id, contents=contents, config=cfg)
    return resp

def _chat_image_edit_with_instruction(prompt_text: str, part: Part, model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    # Chat-style edit: create a chat and send message (mirrors the snippet you pasted)
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    try:
        chat = GENAI_CLIENT.chats.create(model=model_id)
    except Exception as e:
        print("[chat_edit] chats.create failed:", e)
        raise

    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)

    # send_message takes `message` list: [Part, "instruction"]
    response = chat.send_message(
        message=[part, prompt_text],
        config=cfg,
    )
    return response

# --- Utilities to extract text from a response (concatenate parts) ---
def extract_text_from_response(response: Any) -> str:
    texts = []
    for cand in getattr(response, "candidates", []) or []:
        content = getattr(cand, "content", None)
        if not content:
            continue
        for part in getattr(content, "parts", []) or []:
            t = getattr(part, "text", None)
            if t:
                texts.append(t)
    return "\n".join(texts)

# --- Robust JSON extraction helpers ---
def _extract_json_from_fenced(text: str) -> Optional[str]:
    m = re.search(r"```json\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"```(?:[\w+-]*)\s*(.*?)```", text, flags=re.DOTALL)
    if m:
        return m.group(1).strip()
    return None

def _extract_balanced_json_candidates(text: str) -> List[str]:
    candidates = []
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        stack = []
        for j in range(i, len(text)):
            if text[j] == "{":
                stack.append("{")
            elif text[j] == "}":
                if stack:
                    stack.pop()
                if not stack:
                    candidate = text[i:j+1]
                    candidates.append(candidate)
                    break
    return candidates

def parse_json_from_model_text(raw_text: str, *, retry_forced: bool = True) -> Dict[str, Any]:
    if not raw_text or not raw_text.strip():
        raise ValueError("empty model text")

    fenced = _extract_json_from_fenced(raw_text)
    if fenced:
        try:
            return json.loads(fenced)
        except Exception as e:
            print("[parse_json] fenced block parse failed:", e)

    candidates = _extract_balanced_json_candidates(raw_text)
    if candidates:
        candidates = sorted(candidates, key=len, reverse=True)
        for cand in candidates:
            try:
                parsed = json.loads(cand)
                return parsed
            except Exception as e:
                print("[parse_json] candidate parse failed:", e)
        print("[parse_json] no balanced candidate parsed successfully")

    if retry_forced:
        try:
            reformat_prompt = (
                "The model returned the following text. Extract and return ONLY a valid JSON object "
                "that preserves the original structure. Do not add explanation or text. "
                "Input:\n\n"
                + raw_text
            )
            resp = _generate_text_from_prompt(reformat_prompt, model_id=TEXT_MODEL, response_modalities=["TEXT"], candidate_count=1)
            reformatted = extract_text_from_response(resp)
            fenced2 = _extract_json_from_fenced(reformatted) or reformatted
            try:
                return json.loads(fenced2)
            except Exception as e:
                candidates2 = _extract_balanced_json_candidates(reformatted)
                for cand in sorted(candidates2, key=len, reverse=True):
                    try:
                        return json.loads(cand)
                    except:
                        continue
                raise ValueError(f"reformat attempt failed to yield parseable JSON: {e}; reformatted raw: {reformatted}")
        except Exception as e:
            raise ValueError(f"failed to auto-reformat model output to JSON: {e}") from e

    raise ValueError("no parseable JSON found in model text")


# Platform -> default aspect ratio map (common social sizes)
PLATFORM_ASPECT_MAP = {
    "instagram_post": "4:5",
    "instagram_square": "1:1",
    "instagram_story": "9:16",
    "tiktok": "9:16",
    "twitter_post": "16:9",
    "facebook_post": "1.91:1",
    "linkedin_post": "1.91:1",
}

# --- New helper: resolve local outputs path from a URL or path ---
def _extract_output_filename_from_url(url: str) -> Optional[str]:
    """
    If url references our outputs (either a path '/outputs/...' or full EXTERNAL_BASE_URL + /outputs/...),
    return the filename (basename) so it can be copied locally.
    """
    if not url:
        return None
    try:
        # Normalize
        if url.startswith(_build_base_url()):
            # http(s)://host/outputs/<fname>
            path = url[len(_build_base_url()):]
            if path.startswith("/"):
                # find /outputs/<...>
                idx = path.find("/outputs/")
                if idx >= 0:
                    rel = path[idx + 1:]  # outputs/...
                else:
                    rel = path.lstrip("/")
            else:
                rel = path
            # If rel begins with outputs/, strip it
            if rel.startswith("outputs/"):
                fname = os.path.basename(rel)
                return fname
        # direct absolute path like /outputs/<fname>
        if "/outputs/" in url:
            return os.path.basename(url)
        # else maybe just a filename
        if url.startswith("http://") or url.startswith("https://"):
            # fallback: parse name from URL path
            from urllib.parse import urlparse
            parsed = urlparse(url)
            fname = os.path.basename(parsed.path)
            if fname:
                return fname
        # last resort: if it's a plain filename
        if os.path.basename(url) == url:
            return url
    except Exception:
        pass
    return None

# --- Helper to download external URL to memory ---
def _download_external_to_bytes(url: str) -> Optional[tuple[bytes, str]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ai-image-backend/1.0"})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as r:
            # If content-length present, check
            cl = r.getheader("Content-Length")
            if cl:
                try:
                    if int(cl) > MAX_UPLOAD_BYTES:
                        print("[download] remote file too large", cl)
                        return None
                except Exception:
                    pass
            data = r.read(MAX_UPLOAD_BYTES + 1)
            if len(data) > MAX_UPLOAD_BYTES:
                print("[download] remote file exceeded MAX_UPLOAD_BYTES")
                return None
            mime = r.getheader("Content-Type") or "image/png"
        return data, mime
    except Exception as e:
        print("[download] failed to fetch external url:", e)
        return None

# --- Helper to check if object exists in Spaces ---
def _object_exists(key: str) -> bool:
    if not s3:
        return False
    try:
        s3.head_object(Bucket=SPACE_NAME, Key=key)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == "404":
            return False
        raise

# --- Endpoints for saving / posting images ---

@app.route("/api/v1/save-image", methods=["POST"])
def save_image_endpoint():
    """
    Save a generated or external image into the workspace 'saved' folder in Spaces.
    Accepts application/json { "url": "<image url>" }
    or form-encoded 'url' parameter.
    Returns: { success: true, id: "<saved-id>", url: "<cdn url>" }
    """
    try:
        data = request.get_json(force=False, silent=True) or {}
        if not data:
            data = request.form.to_dict() or {}
        url = data.get("url")
        user_id = data.get("user_id") or request.headers.get("X-User-Id")
        workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
        if not url:
            return jsonify({"success": False, "error": "url_required"}), 400

        # if url is local outputs path or points to our base, copy from Spaces
        filename_hint = _extract_output_filename_from_url(url)
        ext = ".png"
        if filename_hint:
            ext = os.path.splitext(filename_hint)[1] or ext

        saved_id = uuid.uuid4().hex
        saved_fname = f"{saved_id}{ext}"
        saved_key = f"saved/{saved_fname}"  # Organized under saved/

        # 1) If filename_hint references our outputs: copy object in Spaces
        copied = False
        if filename_hint:
            source_key = f"outputs/{filename_hint}"
            if _object_exists(source_key):
                try:
                    s3.copy_object(
                        Bucket=SPACE_NAME,
                        CopySource={'Bucket': SPACE_NAME, 'Key': source_key},
                        Key=saved_key,
                        ACL='public-read'
                    )
                    copied = True
                    print(f"[save-image] copied {source_key} to {saved_key} in Spaces")
                except Exception as e:
                    print("[save-image] failed to copy from outputs in Spaces:", e)
                    # fallthrough to try download if url is full http(s)

        # 2) If not copied and url is http(s), attempt to download and upload
        if not copied and (url.startswith("http://") or url.startswith("https://")):
            download_result = _download_external_to_bytes(url)
            if download_result:
                data, mime = download_result
                try:
                    s3.put_object(Bucket=SPACE_NAME, Key=saved_key, Body=data, ContentType=mime, ACL='public-read')
                    copied = True
                    print(f"[save-image] uploaded external {url} to {saved_key} in Spaces")
                except Exception as e:
                    print("[save-image] failed to upload external to Spaces:", e)

        # 3) If not copied and not http, maybe client passed a fname in outputs/
        if not copied and not (url.startswith("http://") or url.startswith("https://")):
            # treat as possible key name under outputs/
            source_key = f"outputs/{url}"
            if _object_exists(source_key):
                try:
                    s3.copy_object(
                        Bucket=SPACE_NAME,
                        CopySource={'Bucket': SPACE_NAME, 'Key': source_key},
                        Key=saved_key,
                        ACL='public-read'
                    )
                    copied = True
                    print(f"[save-image] copied {source_key} to {saved_key} in Spaces (by name)")
                except Exception as e:
                    print("[save-image] failed to copy from outputs by name in Spaces:", e)

        # final check
        if not copied:
            return jsonify({"success": False, "error": "could_not_save_image"}), 500

        # register in saved index
        saved_url = f"{SPACE_CDN}/{saved_key}"
        meta = {
            "id": saved_id,
            "filename": saved_fname,
            "saved_key": saved_key,
            "saved_url": saved_url,
            "original_url": url,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        _register_saved(saved_id, meta)

        # Store in DB if user_id and workspace_id provided
        print(f"[save-image] Received user_id: {user_id}, workspace_id: {workspace_id}")
        try:
            if user_id and workspace_id:
                creative = Creative(
                    id=saved_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=saved_url,
                    filename=saved_fname,
                    type='saved'
                )
                db.session.add(creative)
                db.session.commit()
                print(f"[save-image] Stored saved image {saved_id} in DB for user {user_id} / workspace {workspace_id}")
        except Exception as e:
            print(f"[save-image] DB commit failed: {str(e)}")
            db.session.rollback()

        return jsonify({"success": True, "id": saved_id, "url": saved_url}), 200
    except Exception as e:
        print("[save-image] exception:", e)
        return jsonify({"success": False, "error": "server_error", "details": str(e)}), 500

@app.route("/api/v1/saved-images", methods=["GET"])
def list_saved_images():
    """
    List saved images metadata.
    """
    try:
        index = _load_saved_index()
        # convert to list sorted by saved_at desc
        arr = sorted(index.values(), key=lambda x: x.get("saved_at", ""), reverse=True)
        return jsonify({"success": True, "items": arr}), 200
    except Exception as e:
        print("[saved-images] failed:", e)
        return jsonify({"success": False, "error": "server_error", "details": str(e)}), 500

@app.route("/api/v1/post-image", methods=["POST"])
def post_image_endpoint():
    """
    Simulated posting endpoint.
    Body: { "image_id": "<saved-id>", "platforms": ["facebook","instagram"] }
    NOTE: This is a stub. Real posting requires OAuth and platform integrations on the server.
    """
    try:
        data = request.get_json() or {}
        image_id = data.get("image_id")
        platforms = data.get("platforms") or []
        if not image_id:
            return jsonify({"success": False, "error": "image_id_required"}), 400

        index = _load_saved_index()
        saved = index.get(image_id)
        if not saved:
            return jsonify({"success": False, "error": "image_not_found"}), 404

        # Simulate posting: log and return success.
        # Real implementation must handle OAuth tokens, target accounts, media upload endpoints, caption, scheduling etc.
        print(f"[post-image] posting saved image {image_id} to platforms: {platforms}. meta: {saved}")

        # Placeholder response structure
        result = {"success": True, "image_id": image_id, "posted_to": platforms, "message": "Simulated post; implement real integrations server-side."}
        return jsonify(result), 200
    except Exception as e:
        print("[post-image] exception:", e)
        return jsonify({"success": False, "error": "server_error", "details": str(e)}), 500

# --- Endpoints (existing) ---

@app.route("/api/v1/workspace-info", methods=["GET"])
def workspace_info():
    # small convenience endpoint for frontend header/title
    # Also include linked_platforms to help the frontend show options when posting
    return jsonify({
        "title": "sociovia.ai",
        "workspace": os.environ.get("WORKSPACE_NAME", "dname"),
        "owner": os.environ.get("WORKSPACE_OWNER", "owner@example.com"),
        "storage_used": 0,  # TODO: Query Spaces for size if needed
        "linked_platforms": ["facebook", "instagram", "twitter", "linkedin"],
    })
# --- Gemini-only validator + improved generate() route ---
import os
import json
import base64
import uuid
import traceback
from typing import List, Dict, Any
from flask import request, jsonify
import os
import json
import uuid
import base64
import traceback
from typing import List, Dict, Any
from flask import request, jsonify

# ---------- Helpers (use SDK method shape that works: contents=[prompt_string]) ----------

def _generate_image_from_prompt(
    prompt_text: str,
    model_id: str = MODEL_ID,
    candidate_count: int = 1,
    guidance_scale: float | None = None,
    max_output_tokens: int = 2048,
) -> Any:
    """
    Uses GENAI_CLIENT.models.generate_content with contents=[prompt_text].
    Tries one multi-candidate call first; if that fails, falls back to repeated single-candidate calls.
    Returns either a response object or a list of response objects (fallback).
    """
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")

    full_prompt = f"Generate an image of: {prompt_text}"

    # Build config in typed or dict form
    try:
        cfg = types.GenerateContentConfig(
            response_modalities=["TEXT", "IMAGE"],
            candidate_count=candidate_count,
            max_output_tokens=max_output_tokens,
        )
        if guidance_scale is not None:
            try:
                setattr(cfg, "guidance_scale", guidance_scale)
            except Exception:
                pass
    except Exception:
        cfg = {
            "response_modalities": ["TEXT", "IMAGE"],
            "candidate_count": 1,
            "max_output_tokens": max_output_tokens,
        }
        if guidance_scale is not None:
            cfg["guidance_scale"] = guidance_scale

    # Try multi-candidate call with simple contents shape
    try:
        resp = GENAI_CLIENT.models.generate_content(model=model_id, contents=[full_prompt], config=cfg)
        return resp
    except Exception as e:
        print(f"[_generate_image_from_prompt] multi-candidate call failed: {e}. Falling back to repeated single-candidate calls.", flush=True)

    # Fallback: repeated single-candidate calls
    responses = []
    for i in range(max(1, candidate_count)):
        try:
            try:
                single_cfg = types.GenerateContentConfig(
                    response_modalities=["TEXT", "IMAGE"],
                    candidate_count=1,
                    max_output_tokens=max_output_tokens,
                )
                if guidance_scale is not None:
                    try:
                        setattr(single_cfg, "guidance_scale", guidance_scale)
                    except Exception:
                        pass
            except Exception:
                single_cfg = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1, "max_output_tokens": max_output_tokens}
                if guidance_scale is not None:
                    single_cfg["guidance_scale"] = guidance_scale

            r = GENAI_CLIENT.models.generate_content(model=model_id, contents=[full_prompt], config=single_cfg)
            responses.append(r)
        except Exception as e2:
            print(f"[_generate_image_from_prompt] candidate call {i} failed: {e2}", flush=True)
            # continue to next candidate
    return responses


def generate_image_candidates(prompt_text: str, model_id: str = MODEL_ID, n: int = 3, guidance_scale: float | None = None):
    """
    Normalize generator output to a list of candidate-response-like objects.
    """
    resp = _generate_image_from_prompt(prompt_text, model_id=model_id, candidate_count=n, guidance_scale=guidance_scale)
    normalized = []
    if isinstance(resp, list):
        normalized.extend(resp)
        return normalized
    # resp is a single response object; try to extract resp.candidates
    if getattr(resp, "candidates", None):
        for cand in resp.candidates:
            normalized.append(cand)
        return normalized
    # otherwise return the single object as a single-item list
    normalized.append(resp)
    return normalized


def build_visual_prompt(product: Dict[str, Any], aspect_ratio_hint: str = "16:9", cta_text: str | None = None) -> str:
    title = product.get("title") or product.get("brand") or "Product"
    brand = product.get("brand") or ""
    short_desc = product.get("short_description") or product.get("description") or ""
    bullets = product.get("bullets") or []
    bullets_txt = " ; ".join(bullets[:6]) if bullets else ""
    primary_color = product.get("primary_color") or product.get("brand_color") or "brand accent color"
    logo_hint = "include brand logo bottom-right; reserve 8% safe area" if product.get("logo_url") or brand else "include brand name text bottom-right"

    musts = [
        f"MUST_INCLUDE: Product title or brand: '{title}'",
        f"MUST_INCLUDE: Clear Call-To-Action text: '{cta_text}'" if cta_text else "MUST_INCLUDE: Clear Call-To-Action text (e.g. 'Start Free Trial')",
        "MUST_INCLUDE: Product is the visual focus",
        f"MUST_INCLUDE: Brand accent color: {primary_color}",
        logo_hint
    ]
    negatives = [
        "DO_NOT: include watermarks, unrelated logos, or extraneous body copy",
        "DO_NOT: invent specs beyond supplied info",
        "AVOID: cartoonish or toy-like renderings for professional brands"
    ]

    parts = []
    parts.append(f"ASPECT_RATIO_HINT: {aspect_ratio_hint}")
    parts.append(f"PRODUCT_CONTEXT: {title} — {brand} — {short_desc}")
    if bullets_txt:
        parts.append(f"KEY_FEATURES: {bullets_txt}")
    parts.append("VISUAL_MUSTS_BEGIN:")
    for m in musts:
        parts.append(" - " + m)
    parts.append("PHOTOGRAPHY_AND_STYLE:")
    parts += [
        " - Composition: clean, professional; hero product prominent",
        " - Lighting: professional product lighting; minimal clutter",
        " - Typography: CTA must be legible; reserve overlay space",
        " - Deliverables: crops for requested aspect ratios"
    ]
    parts.append("VISUAL_NEGATIVES:")
    for n in negatives:
        parts.append(" - " + n)
    parts.append("VISUAL_MUSTS_END")
    return "\n".join(parts)


def gemini_validate_image_with_words(file_path: str, look_for_words: List[str], gemini_model: str | None = None, max_tokens: int = 512) -> Dict[str, Any]:
    """
    Use Gemini (GenAI) to extract visible text and check for presence of look_for_words.
    Returns dict with keys: ok (True/False/None), detected_text, contains, method, raw_model_text, raw_model_object, error
    """
    result = {"ok": None, "detected_text": "", "contains": {w: False for w in look_for_words}, "method": "gemini", "raw_model_text": None, "raw_model_object": None, "error": None}
    if not GENAI_CLIENT:
        result["error"] = "GENAI_CLIENT not initialized"
        return result
    try:
        with open(file_path, "rb") as f:
            img_bytes = f.read()
        b64 = base64.b64encode(img_bytes).decode("utf-8")
    except Exception as e:
        result["error"] = f"Failed to read file {file_path}: {e}"
        return result

    look_for_json_list = ", ".join([f"\"{w}\"" for w in look_for_words if w])
    instruction_text = (
        "You are a precise visual-text-extraction assistant. Given the provided image, extract any visible text and return a JSON object ONLY. Do NOT output any additional explanation.\n\n"
        "The JSON must have keys:\n"
        "  detected_text: string (full raw text extracted; empty string if none)\n"
        "  contains: { <word>: true|false, ... }  // whether each look_for word appears anywhere in the detected text\n\n"
        f"Look-for words: [{look_for_json_list}]\n\n"
        "Return valid JSON only."
    )

    # Build contents as the SDK accepts: a simple list with the text instruction and the base64 image inline
    # Some SDK variants accept {"type":"image","image":{"image_bytes":...}} inside the contents list.
    # We'll pass a minimal accepted shape: content that is a string with a special marker and the b64 appended.
    # This keeps us compatible with the contents=[prompt_string] shape you previously used.
    # Compose a combined prompt that includes the base64 string (models that accept will parse image bytes; others might not —
    # but we try the typical shapes; if your SDK supports Part.from_image_bytes, swap accordingly).
    combined_prompt = instruction_text + "\n\n" + "[IMAGE_BYTES_BASE64]\n" + b64

    try:
        cfg = types.GenerateContentConfig(temperature=0.0, max_output_tokens=max_tokens)
    except Exception:
        cfg = {"temperature": 0.0, "max_output_tokens": max_tokens}

    try:
        call_model = gemini_model 
        resp = GENAI_CLIENT.models.generate_content(model=call_model, contents=[combined_prompt], config=cfg)
        result["raw_model_object"] = resp

        # Extract text output robustly
        extracted_text = ""
        try:
            if getattr(resp, "candidates", None):
                cand = resp.candidates[0]
                if getattr(cand, "content", None) and getattr(cand.content, "parts", None):
                    for p in cand.content.parts:
                        extracted_text += serialize_part_text(p)
            else:
                extracted_text = str(resp)
        except Exception:
            try:
                extracted_text = str(resp)
            except Exception:
                extracted_text = ""

        result["raw_model_text"] = extracted_text

        json_block = extract_json_block(extracted_text)
        parsed = None
        if json_block:
            try:
                parsed = json.loads(json_block)
            except Exception:
                parsed = None

        if parsed and isinstance(parsed, dict):
            detected_text = parsed.get("detected_text", "") or ""
            contains_raw = parsed.get("contains", {}) or {}
            contains_map = {w: bool(contains_raw.get(w, False)) for w in look_for_words}
            result.update({"ok": any(contains_map.values()), "detected_text": detected_text, "contains": contains_map, "method": "gemini"})
            return result
        else:
            # fallback: substring check on extracted_text
            detected_text = extracted_text or ""
            contains_map = {w: (w.lower() in detected_text.lower()) for w in look_for_words}
            result.update({"ok": any(contains_map.values()), "detected_text": detected_text, "contains": contains_map, "method": "gemini_raw_text"})
            return result
    except Exception as e:
        result["error"] = f"Gemini validation failed: {e}\n{traceback.format_exc()}"
        return result
from flask import request, jsonify
import os, json, time, uuid, traceback
import requests
from PIL import Image, ImageDraw, ImageFont
import json, traceback, time

def _generate_text_from_prompt(master_prompt, model_id=None, candidate_count=1, response_modalities=None, temperature=0.4, max_output_tokens=1024):
    """
    Simplified text generator for Vertex AI's google.genai client.
    Works with: from google import genai; client = genai.Client()
    """
    import json, traceback

    client = globals().get("GENAI_CLIENT")
    if not client:
        raise RuntimeError("GENAI_CLIENT not initialized.")

    # normalize prompt
    if isinstance(master_prompt, (dict, list)):
        prompt_str = json.dumps(master_prompt, ensure_ascii=False, indent=2)
    else:
        prompt_str = str(master_prompt)

    model_id = model_id or globals().get("TEXT_MODEL") or "gemini-2.5-flash"

    print(f"[_generate_text_from_prompt] Using Vertex GenAI → model={model_id}", flush=True)

    try:
        # Official Vertex API call
        resp = client.models.generate_content(
            model=model_id,
            contents=prompt_str,
        )
        print("[_generate_text_from_prompt] Success: Vertex generate_content()", flush=True)
        return resp
    except Exception as e:
        print("[_generate_text_from_prompt] Vertex call failed:", e, flush=True)
        print(traceback.format_exc(), flush=True)
        raise
from flask import request, jsonify
import os, json, time, traceback, uuid, requests, io
from PIL import Image, ImageDraw, ImageFont

# --------------------------
# Helper: robust Vertex text call
# --------------------------
def _generate_text_from_prompt(master_prompt, model_id=None, candidate_count=1, response_modalities=None, temperature=0.2, max_output_tokens=512):
    """
    Vertex genai client wrapper. Uses GENAI_CLIENT from globals().
    Returns the raw client response object.
    """
    import json
    client = globals().get("GENAI_CLIENT")
    if not client:
        raise RuntimeError("GENAI_CLIENT not initialized.")
    # Normalize prompt -> string
    if isinstance(master_prompt, (dict, list)):
        prompt_str = json.dumps(master_prompt, ensure_ascii=False, indent=2)
    else:
        prompt_str = str(master_prompt)
    model_id = model_id or globals().get("TEXT_MODEL") or "gemini-flash-latest"
    print(f"[_generate_text_from_prompt] Using Vertex GenAI model={model_id}", flush=True)
    # Vertex client uses client.models.generate_content(model=..., contents=...)
    resp = client.models.generate_content(model=model_id, contents=prompt_str)
    print("[_generate_text_from_prompt] Success: generate_content()", flush=True)
    return resp

# --------------------------
# Small utilities / normalization
# --------------------------
def _ensure_dict(maybe):
    """If maybe is dict -> return. If JSON string -> parse. If plain string -> wrap under 'name'."""
    if maybe is None:
        return {}
    if isinstance(maybe, dict):
        return maybe
    if isinstance(maybe, str):
        try:
            parsed = json.loads(maybe)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except Exception:
            return {"name": maybe}
    try:
        return dict(maybe)
    except Exception:
        return {"value": str(maybe)}

def safe_get(d, *keys, default=None):
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default

# --------------------------
# Helpers for files/logo/overlay
# --------------------------
def ensure_local_file(fn):
    """Ensure outputs/<fn> exists; if missing try to download from SPACE_CDN."""
    out_dir = "outputs"
    os.makedirs(out_dir, exist_ok=True)
    local_path = os.path.join(out_dir, fn)
    if os.path.exists(local_path):
        return local_path
    cdn = globals().get("SPACE_CDN")
    if not cdn:
        print("[ensure_local_file] SPACE_CDN not configured; cannot download", fn, flush=True)
        return None
    cdn_url = f"{cdn.rstrip('/')}/outputs/{fn}"
    try:
        r = requests.get(cdn_url, stream=True, timeout=20)
        if r.status_code == 200:
            with open(local_path, "wb") as w:
                for chunk in r.iter_content(8192):
                    if chunk:
                        w.write(chunk)
            print("[ensure_local_file] downloaded from CDN:", cdn_url, "->", local_path, flush=True)
            return local_path
        else:
            print("[ensure_local_file] CDN download status", r.status_code, cdn_url, flush=True)
            return None
    except Exception as e:
        print("[ensure_local_file] CDN download exception:", e, flush=True)
        return None

def cache_logo(workspace_id, logo_url):
    """Download and cache workspace logo to cache/logos/"""
    if not logo_url:
        return None
    os.makedirs("cache/logos", exist_ok=True)
    ext = os.path.splitext(logo_url.split("?")[0])[1] or ".png"
    fname = f"cache/logos/logo_{workspace_id}{ext}"
    if os.path.exists(fname):
        return fname
    try:
        r = requests.get(logo_url, timeout=15)
        if r.status_code == 200:
            with open(fname, "wb") as f:
                f.write(r.content)
            print("[cache_logo] cached", fname, flush=True)
            return fname
        else:
            print("[cache_logo] download failed status", r.status_code, logo_url, flush=True)
            return None
    except Exception as e:
        print("[cache_logo] exception downloading logo:", e, flush=True)
        return None

def get_font_for_size(size):
    """Pick sensible font. If no TTF found, fallback to PIL default."""
    possible = [
        os.environ.get("OVERLAY_FONT_PATH"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "C:\\Windows\\Fonts\\arial.ttf"
    ]
    for p in possible:
        if p and os.path.exists(p):
            try:
                return ImageFont.truetype(p, size=size)
            except Exception:
                pass
    return ImageFont.load_default()

def overlay_logo_and_cta(local_input_path, logo_path, cta_text, out_path, primary_color="#111111", accent_color="#00A3E0"):
    """Deterministic overlay: top-left logo, bottom-right CTA button."""
    try:
        im = Image.open(local_input_path).convert("RGBA")
    except Exception as e:
        print("[overlay] failed to open", local_input_path, e, flush=True)
        return False
    W, H = im.size
    draw = ImageDraw.Draw(im)
    # paste logo
    if logo_path and os.path.exists(logo_path):
        try:
            logo = Image.open(logo_path).convert("RGBA")
            logo_w = int(W * 0.12)
            logo.thumbnail((logo_w, logo_w), Image.LANCZOS)
            margin = int(W * 0.03)
            im.paste(logo, (margin, margin), logo)
        except Exception as e:
            print("[overlay] logo paste failed:", e, flush=True)
    # draw CTA button
    try:
        font_size = max(14, int(H * 0.04))
        font = get_font_for_size(font_size)
        text_w, text_h = draw.textsize(cta_text, font=font)
        btn_w = text_w + int(W * 0.05)
        btn_h = text_h + int(H * 0.02)
        margin = int(W * 0.03)
        btn_x = W - margin - btn_w
        btn_y = H - margin - btn_h
        try:
            draw.rounded_rectangle([btn_x, btn_y, btn_x + btn_w, btn_y + btn_h], radius=int(min(btn_h, btn_w) * 0.15), fill=accent_color)
        except Exception:
            draw.rectangle([btn_x, btn_y, btn_x + btn_w, btn_y + btn_h], fill=accent_color)
        text_x = btn_x + (btn_w - text_w) / 2
        text_y = btn_y + (btn_h - text_h) / 2
        draw.text((text_x, text_y), cta_text, font=font, fill="#FFFFFF")
    except Exception as e:
        print("[overlay] CTA draw failed:", e, flush=True)
    try:
        im.convert("RGB").save(out_path, quality=92)
        print("[overlay] saved overlay to", out_path, flush=True)
        return True
    except Exception as e:
        print("[overlay] save failed:", e, flush=True)
        return False

def upload_to_space_if_available(local_path, dest_fn):
    """Upload to Spaces/S3 if s3 client and bucket configured."""
    try:
        s3_client = globals().get("s3") or globals().get("spaces_client")
        bucket = globals().get("SPACE_BUCKET") or globals().get("SPACES_BUCKET")
        if not s3_client or not bucket:
            print("[upload] no s3/spaces configured; skipping upload for", dest_fn, flush=True)
            return False
        key = f"outputs/{dest_fn}"
        try:
            s3_client.upload_file(local_path, bucket, key, ExtraArgs={"ACL": "public-read"})
        except Exception:
            with open(local_path, "rb") as f:
                s3_client.put_object(Bucket=bucket, Key=key, Body=f, ACL="public-read")
        print("[upload] uploaded to spaces:", dest_fn, flush=True)
        return True
    except Exception as e:
        print("[upload] exception:", e, flush=True)
        return False

# --------------------------
# Full route (drop-in)
# --------------------------
@app.route("/api/v1/generate", methods=["POST"])
def generate():
    dbg = lambda *a, **k: print("[generate-debug]", *a, **k, flush=True)
    # ensure directories
    os.makedirs("outputs", exist_ok=True)
    os.makedirs("outputs/debug", exist_ok=True)
    os.makedirs("cache/logos", exist_ok=True)

    if not globals().get("GENAI_CLIENT"):
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    data = request.get_json() or {}
    dbg("received keys:", list(data.keys()))

    # Normalize incoming payloads
    raw_ws = data.get("workspace_details") or request.headers.get("X-Workspace-Details")
    workspace_details = _ensure_dict(raw_ws)
    raw_prod = data.get("product") or data.get("productData") or data.get("product_payload")
    product_payload = _ensure_dict(raw_prod)

    dbg("normalized workspace keys:", list(workspace_details.keys())[:8])
    dbg("normalized product keys:", list(product_payload.keys())[:8])

    user_prompt = data.get("prompt") or data.get("text") or ""
    user_id = data.get("user_id") or request.headers.get("X-User-Id")
    workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")

    # canonical spec
    workspace_spec = {
        "brand": safe_get(workspace_details, "business_name", "brand", "name", "title", default="Brand"),
        "usp": safe_get(workspace_details, "usp", "description", "short_description", default=""),
        "primary_color": safe_get(workspace_details, "primary_color", "primaryColour", default="#111111"),
        "accent_color": safe_get(workspace_details, "accent_color", "accentColor", default="#00A3E0"),
        "audience": safe_get(workspace_details, "audience_description", "audience", default=""),
        "cta": (data.get("options") or {}).get("overlay_cta") or (data.get("options") or {}).get("cta") or "Start Free Trial",
        "logo_url": safe_get(workspace_details, "logo_path", "logo_url", "logo", default="")
    }
    dbg("workspace_spec:", {k: workspace_spec[k] for k in ("brand","primary_color","accent_color","cta")})

    # -----------------------
    # 1) Planner: ask Gemini for exactly 3 themes
    # -----------------------
    try:
        planner_instructions = f"""
You are an expert ad strategist. Produce STRICT valid JSON with exactly 3 ad THEMES.
Return only JSON in this exact structure:

{{ "themes": [ {{ "title":"", "one_line":"", "visual_prompt":"", "keywords":["k1"], "aspect_ratio":"16:9", "attached_prompt":"", "key_points":["p1","p2"] }}, ... (3 total) ] }}

Constraints:
- Use the workspace information below to derive a consistent palette and tone.
- Each theme MUST include 2–4 'key_points' drawn from the workspace or user prompt (short phrases).
- Do NOT include logos or full CTAs in visual_prompt.
- Ensure all three themes read as a coherent campaign (shared palette & tone).

Workspace Spec:
{json.dumps(workspace_spec, ensure_ascii=False, indent=2)}

Product / User Prompt:
{json.dumps({"user_prompt": user_prompt, "product": product_payload}, ensure_ascii=False, indent=2)}
"""
        dbg("Calling Gemini planner...")
        resp_text = _generate_text_from_prompt(planner_instructions, model_id=globals().get("TEXT_MODEL"))
        raw_text = None
        try:
            raw_text = resp_text.text if hasattr(resp_text, "text") else str(resp_text)
        except Exception:
            raw_text = str(resp_text)
        dbg("Planner raw_text snippet:", (raw_text or "")[:1500])
        parsed = parse_json_from_model_text(raw_text, retry_forced=True)
        themes = parsed.get("themes") if isinstance(parsed, dict) else None

        # strict enforcement: exactly 3 themes
        if not isinstance(themes, list) or len(themes) != 3:
            raise ValueError(f"Planner must return exactly 3 themes; got {len(themes) if isinstance(themes, list) else 'none'}")

        # save debug copy
        with open(os.path.join("outputs","debug", f"planner_{int(time.time())}.json"), "w", encoding="utf-8") as f:
            json.dump(themes, f, ensure_ascii=False, indent=2)

    except Exception as e:
        dbg("Planner failed; falling back to 3 basic themes:", e, traceback.format_exc())
        base = workspace_spec.get("brand","Brand")
        themes = [
            {
                "title": f"{base} Hero",
                "one_line": workspace_spec.get("usp") or user_prompt or "Hero",
                "visual_prompt": f"Hero product ad, left text-safe area, palette {workspace_spec['primary_color']}/{workspace_spec['accent_color']}, minimal, no logos, 16:9",
                "keywords": ["hero","brand"],
                "aspect_ratio": "16:9",
                "attached_prompt": user_prompt or "",
                "key_points": [workspace_spec.get("usp") or "", workspace_spec.get("audience") or ""]
            },
            {
                "title": f"{base} Team",
                "one_line": "Collaborate faster",
                "visual_prompt": f"Two professionals with floating dashboard, UI glow {workspace_spec['accent_color']}, leave space for overlays, 16:9",
                "keywords": ["team","collaboration"],
                "aspect_ratio": "16:9",
                "attached_prompt": user_prompt or "",
                "key_points": [workspace_spec.get("audience") or "", "collaboration"]
            },
            {
                "title": f"{base} Growth",
                "one_line": "Campaigns that scale",
                "visual_prompt": f"Rising analytics chart with accent highlights {workspace_spec['accent_color']}, top text-safe area, 16:9",
                "keywords": ["analytics","growth"],
                "aspect_ratio": "16:9",
                "attached_prompt": user_prompt or "",
                "key_points": ["growth","analytics"]
            }
        ]

    dbg("Planner returned themes count:", len(themes))

    # -----------------------
    # 2) For each theme generate exactly 1 image using workspace keys + key_points
    # -----------------------
    saved_files = []
    results = []

    for idx, theme in enumerate(themes):
        dbg("Processing theme", idx, theme.get("title"))
        try:
            theme_title = theme.get("title","")
            theme_one = theme.get("one_line","")
            visual_prompt = theme.get("visual_prompt","")
            key_points = theme.get("key_points") or []

            full_prompt_parts = [
                f"THEME_TITLE: {theme_title}",
                f"ONE_LINE: {theme_one}",
                f"KEY_POINTS: {', '.join(key_points)}",
                f"BRAND: {workspace_spec.get('brand')}",
                f"USP: {workspace_spec.get('usp')}",
                f"AUDIENCE: {workspace_spec.get('audience')}",
                f"PALETTE: primary {workspace_spec.get('primary_color')}, accent {workspace_spec.get('accent_color')}",
                f"ASPECT_RATIO: {theme.get('aspect_ratio','16:9')}",
                "VISUAL_PROMPT_BEGIN:",
                visual_prompt,
                "VISUAL_PROMPT_END",
                f"ATTACHED_PROMPT: {theme.get('attached_prompt','')}",
                f"SOURCE: gemini-theme-planner",
                f"USER_INPUT: {user_prompt}"
            ]
            full_prompt = "\n".join(p for p in full_prompt_parts if p is not None)
            dbg(f"[Theme {idx}] full prompt length:", len(full_prompt))

            # Generate exactly 1 candidate (n=1)
            candidate_responses = generate_image_candidates(full_prompt, model_id=globals().get("MODEL_ID"), n=1, guidance_scale=1.4)
            if not candidate_responses:
                raise RuntimeError("No responses from image model")

            first = candidate_responses[0]
            saved = save_images_from_genai_content(first, prefix=f"theme{idx}")
            if isinstance(saved, list):
                chosen = saved[0] if saved else None
            else:
                chosen = saved

            if chosen:
                saved_files.append(chosen)
                dbg("[Theme %d] saved -> %s" % (idx, chosen))
            else:
                dbg("[Theme %d] no file saved" % idx)

            results.append({
                "theme_index": idx,
                "theme": theme,
                "prompt_sent": full_prompt,
                "file": chosen
            })

        except Exception as e:
            dbg("Error generating theme", idx, e, traceback.format_exc())
            results.append({"theme_index": idx, "error": str(e)})

    # Build CDN URLs
    cdn_base = globals().get("SPACE_CDN", "")
    urls = [f"{cdn_base.rstrip('/')}/outputs/{fn}" for fn in saved_files]

    # Optional overlay step: overlay logo + CTA and upload overlays (keeps exactly 1 final image per theme)
    final_files = []
    final_urls = []
    try:
        logo_local = cache_logo(workspace_id or "unknown", workspace_spec.get("logo_url"))
        for fn in saved_files:
            local = ensure_local_file(fn)
            if not local:
                print("[generate] local missing for", fn, "skipping overlay", flush=True)
                continue
            overlay_fn = f"overlay_{fn}"
            overlay_local = os.path.join("outputs", overlay_fn)
            ok = overlay_logo_and_cta(local, logo_local, workspace_spec.get("cta","Start Free Trial"), overlay_local, primary_color=workspace_spec.get("primary_color"), accent_color=workspace_spec.get("accent_color"))
            if not ok:
                print("[generate] overlay failed for", fn, flush=True)
                continue
            uploaded = upload_to_space_if_available(overlay_local, overlay_fn)
            final_files.append(overlay_fn)
            final_urls.append(f"{cdn_base.rstrip('/')}/outputs/{overlay_fn}" if cdn_base else overlay_local)
            print("[generate] overlay ready:", overlay_fn, "uploaded:", uploaded, flush=True)
    except Exception as e:
        print("[generate] overlay stage failed:", e, traceback.format_exc(), flush=True)

    # Persist creatives to DB (use final_files if overlays created, else saved_files)
    to_store_files = final_files if final_files else saved_files
    to_store_urls = final_urls if final_urls else urls
    try:
        if user_id and workspace_id and to_store_files:
            for fn, url in zip(to_store_files, to_store_urls):
                creative_id = uuid.uuid4().hex
                creative = Creative(id=creative_id, user_id=user_id, workspace_id=workspace_id, url=url, filename=fn, type='generated')
                db.session.add(creative)
            db.session.commit()
            dbg(f"Stored {len(to_store_files)} generated creatives in DB")
    except Exception as e:
        dbg("DB commit failed:", e, traceback.format_exc())
        db.session.rollback()

    # Save conversation
    try:
        if user_id and workspace_id:
            conv_id = uuid.uuid4().hex
            conversation = Conversation(id=conv_id, user_id=user_id, workspace_id=workspace_id, prompt=user_prompt, response=json.dumps({"themes": themes, "results": results, "files": to_store_files, "urls": to_store_urls}))
            db.session.add(conversation)
            db.session.commit()
            dbg("Stored conversation", conv_id)
    except Exception as e:
        dbg("Conversation commit failed:", e, traceback.format_exc())
        db.session.rollback()

    return jsonify({"success": True, "themes": themes, "results": results, "files": to_store_files, "urls": to_store_urls}), 200

import os
import re
import json
import uuid
import time
import copy
import base64
import traceback
from typing import Tuple, Optional, Dict, Any


# -------------------------
def strip_workspace_from_prompt(text: str) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    If `text` contains the marker '--- Workspace Details (JSON):', split and:
      - return the trimmed prompt (left side, stripped)
      - attempt to parse the JSON on the right side; if parse succeeds return dict, else None
    If marker not found, returns (text, None).
    """
    if not isinstance(text, str):
        return text, None

    parts = re.split(r'---\s*Workspace Details\s*\(JSON\)\s*:', text, maxsplit=1, flags=re.I | re.DOTALL)
    if len(parts) == 1:
        return text.strip(), None

    left, right = parts[0].strip(), parts[1].strip()

    json_obj = None
    first_brace = right.find('{')
    last_brace = right.rfind('}')
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = right[first_brace:last_brace+1]
        try:
            json_obj = json.loads(candidate)
        except Exception:
            # try heuristic trimming lines until valid JSON found (best effort)
            lines = candidate.splitlines()
            for end in range(len(lines), 0, -1):
                try_text = "\n".join(lines[:end])
                try:
                    json_obj = json.loads(try_text)
                    break
                except Exception:
                    continue
    return left, json_obj

_WORKSPACE_IDENTIFIERS = {"business_name", "website", "logo_path", "creatives_path", "social_links", "description"}

def _is_workspace_like(d: dict) -> bool:
    if not isinstance(d, dict):
        return False
    return any(k in d for k in ("business_name", "website", "id", "logo_path"))

def sanitize_for_db(obj, *, max_string=1000, max_list=100, keep_workspace_minimal=True):
    """
    Recursively sanitize an object before saving to DB:
     - trim long strings to max_string chars
     - collapse large lists to first max_list items
     - reduce workspace-like dicts to minimal info
    """
    def _sanitize(item, depth=0):
        if item is None:
            return None
        if isinstance(item, (int, float, bool)):
            return item
        if isinstance(item, bytes):
            return "<binary omitted>"
        if isinstance(item, str):
            s = item
            if len(s) > max_string:
                return s[: max_string//2 ] + " ... " + s[- max_string//2 :]
            return s
        if isinstance(item, list):
            out = []
            for i, elem in enumerate(item):
                if i >= max_list:
                    out.append(f"...{len(item)-max_list} more items...")
                    break
                out.append(_sanitize(elem, depth+1))
            return out
        if isinstance(item, dict):
            if keep_workspace_minimal and _is_workspace_like(item):
                minimal = {}
                if "id" in item:
                    minimal["id"] = item.get("id")
                if "business_name" in item:
                    minimal["business_name"] = (item.get("business_name") or "")[:200]
                elif "name" in item:
                    minimal["name"] = (item.get("name") or "")[:200]
                if "website" in item:
                    minimal["website"] = (item.get("website") or "")[:200]
                if "logo_path" in item:
                    minimal["logo_path"] = (item.get("logo_path") or "")[:500]
                minimal["_trimmed_workspace"] = True
                return minimal
            out = {}
            for k, v in item.items():
                if keep_workspace_minimal and k in ("logo_path", "creatives_path", "social_links"):
                    continue
                if isinstance(v, str) and len(v) > max_string*5 and (k.lower().find("html") >= 0 or k.lower().find("jsonld") >= 0 or k.lower().find("raw") >=0):
                    out[k] = (v[: max_string ] + " ... <truncated>")
                    continue
                out[k] = _sanitize(v, depth+1)
            return out
        try:
            txt = str(item)
            return txt if len(txt) <= max_string else txt[:max_string] + " ... <truncated>"
        except Exception:
            return "<unserializable>"
    return _sanitize(copy.deepcopy(obj))

def minimal_workspace_ref(ws: Optional[dict]) -> Optional[dict]:
    if not isinstance(ws, dict):
        return None
    out = {}
    for key in ("id", "business_name", "website", "logo_path"):
        if key in ws:
            v = ws.get(key)
            if isinstance(v, str) and len(v) > 500:
                v = v[:500] + "...<truncated>"
            out[key] = v
    if out:
        out["_trimmed_workspace"] = True
        return out
    return None
# Replace existing route with this implementation
import os
import re
import json
import time
import base64
import uuid
import traceback
from flask import request, jsonify, current_app
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.genai.types import Part, Content, GenerateContentConfig
from google.genai.errors import ClientError


MODEL_ID = os.environ.get("IMAGE_MODEL", "gemini-2.5-flash-image")
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 60 * 1024 * 1024))
MAX_PROMPT_CHARS = int(os.environ.get("MAX_PROMPT_CHARS", 1400))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 3))
SPACE_CDN = os.environ.get("SPACE_CDN")  # optional

# Helper regexes & sanitize function (same as your snippet)
_url_re = re.compile(r"https?:\/\/\S+|www\.\S+", flags=re.IGNORECASE)
_json_block_re = re.compile(r"\{[\s\S]*?\}|\[[\s\S]*?\]")  # remove JSON-like blocks
_logo_key_re = re.compile(r"\b(?:logo|logo_url|image_url|file_uri|logo-path|logo_path|image-path)\b\s*[:=]?\s*\S*", flags=re.IGNORECASE)

def sanitize_prompt(text: str) -> str:
    if not text:
        return ""
    t = str(text)
    t = _json_block_re.sub(" ", t)
    t = _url_re.sub(" ", t)
    t = _logo_key_re.sub(" ", t)
    t = re.sub(r"\s{2,}", " ", t).strip()
    if len(t) > MAX_PROMPT_CHARS:
        t = t[:MAX_PROMPT_CHARS].rsplit(" ", 1)[0] + " ..."
    return t

# Helper: save bytes to local outputs/ folder (and optionally upload to a space/CDN) --
# replace or extend this to save to S3/Spaces and return (filename, public_url)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_bytes_to_spaces_or_local(b: bytes, prefix="img"):
    """
    Save bytes to local outputs directory and return (filename, url).
    If you add Spaces/S3 upload, return the public URL in the second value.
    """
    try:
        fname = f"{prefix}_{uuid.uuid4().hex[:8]}.png"
        path = os.path.join(OUTPUT_DIR, fname)
        with open(path, "wb") as f:
            f.write(b)
        # If you have SPACE_CDN or other hosting, create a URL; else return None as url (caller will fallback)
        url = None
        if SPACE_CDN:
            # naive mapping: you might prefer uploading to Spaces or S3 instead
            url = f"{SPACE_CDN.rstrip('/')}/{fname}"
        return fname, url
    except Exception:
        current_app.logger.exception("save_bytes_to_spaces_or_local failed")
        return None, None
def _try_extract_bytes_from_obj(obj):
    """
    Try to pull raw bytes (or base64 string decoded to bytes) from various shapes.
    Returns tuple (bytes_or_none, mime_or_none, summary_string_or_none)
    """
    # direct bytes
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj), None, "<raw-bytes>"

    # direct base64 string
    if isinstance(obj, str):
        s = obj.strip()
        # data URI?
        m = re.search(r"data:image\/([a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=]+)", s)
        if m:
            try:
                return base64.b64decode(m.group(2)), f"image/{m.group(1)}", "data-uri"
            except Exception:
                pass
        # bare base64?
        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) and len(s) > 200:
            try:
                return base64.b64decode("".join(s.split())), None, "base64-str"
            except Exception:
                pass
        # otherwise no bytes
        return None, None, None

    # dict-like -> try common keys
    if isinstance(obj, dict):
        candidates = []
        # direct common fields
        for key in ("blob", "bytes", "b64", "base64", "data", "value", "content"):
            if key in obj and obj[key] is not None:
                candidates.append((key, obj[key]))
        # nested 'inline_data' or 'image' keys
        if "inline_data" in obj and obj["inline_data"] is not None:
            candidates.append(("inline_data", obj["inline_data"]))
        if "image" in obj and obj["image"] is not None:
            candidates.append(("image", obj["image"]))
        # try each candidate recursively
        for k, v in candidates:
            b, mime, summary = _try_extract_bytes_from_obj(v)
            if b:
                return b, obj.get("mime_type") or obj.get("mime") or mime, f"dict.{k}"
        return None, None, None

    # proto-like object with attributes
    try:
        # build list of attribute names to try
        attrs = ["blob", "bytes", "b64", "base64", "data", "value", "inline_data", "image", "content"]
        for a in attrs:
            if hasattr(obj, a):
                try:
                    v = getattr(obj, a)
                    if v is None:
                        continue
                    b, mime, summary = _try_extract_bytes_from_obj(v)
                    if b:
                        # try to get mime from sibling attributes
                        mime_attr = None
                        for mm in ("mime_type", "content_type", "mime"):
                            if hasattr(obj, mm):
                                mime_attr = getattr(obj, mm)
                                break
                        return b, mime_attr or mime, f"attr.{a}"
                except Exception:
                    continue
    except Exception:
        pass

    return None, None, None


def extract_images_text_and_inline_from_stream(stream_iter):
    """
    Robust extraction from genai stream iterator.
    Returns (images_bytes_list, text_parts_list, inline_parts_summary, warnings)
    - This improved version attempts to decode inline_data shapes that may be objects with blob/bytes/b64 fields.
    """
    images = []
    text_parts = []
    inline_parts_summary = []
    warnings = []
    try:
        for chunk in stream_iter:
            # prefer candidates -> content -> parts if present
            cand_list = getattr(chunk, "candidates", None) or []
            # sometimes SDK returns a dict-like chunk, handle that too
            if not cand_list and isinstance(chunk, dict):
                cand_list = chunk.get("candidates", []) or []

            if cand_list:
                for cand in cand_list:
                    content = getattr(cand, "content", None) or (cand.get("content") if isinstance(cand, dict) else None)
                    # content.parts or content["parts"]
                    parts = []
                    if content is None and isinstance(cand, dict):
                        content = cand.get("content")
                    if content is not None:
                        parts = getattr(content, "parts", None) or (content.get("parts") if isinstance(content, dict) else None) or []
                    # iterate parts
                    for p in parts:
                        # 1) p.image.base64 (common)
                        img_obj = getattr(p, "image", None) or (p.get("image") if isinstance(p, dict) else None)
                        if img_obj:
                            # image may be proto-like or dict
                            base64_val = getattr(img_obj, "base64", None) or (img_obj.get("base64") if isinstance(img_obj, dict) else None)
                            if base64_val:
                                try:
                                    images.append(base64.b64decode(base64_val))
                                except Exception:
                                    current_app.logger.exception("failed decoding p.image.base64")
                        # 2) p.inline_data (various shapes)
                        inline = getattr(p, "inline_data", None) or (p.get("inline_data") if isinstance(p, dict) else None)
                        if inline is not None:
                            warnings.append("inline_data_present")
                            # attempt extraction
                            b, mime, summary = _try_extract_bytes_from_obj(inline)
                            if b:
                                images.append(b)
                                inline_parts_summary.append(summary or "inline_decoded")
                            else:
                                # if we couldn't decode bytes, store compact summary for debug
                                try:
                                    if isinstance(inline, (bytes, bytearray)):
                                        inline_parts_summary.append(base64.b64encode(bytes(inline)).decode("ascii")[:500] + "...")
                                    elif isinstance(inline, str):
                                        inline_parts_summary.append(inline[:500] + ("..." if len(inline)>500 else ""))
                                    elif isinstance(inline, dict):
                                        inline_parts_summary.append(json.dumps({k: (v if not isinstance(v,(bytes,bytearray)) else "<bytes>") for k,v in list(inline.items())[:10]})[:500])
                                    else:
                                        inline_parts_summary.append(str(type(inline)))
                                except Exception:
                                    inline_parts_summary.append("<inline_unserializable>")
                        # 3) p.text -> collect and look for data URIs
                        txt = getattr(p, "text", None) or (p.get("text") if isinstance(p, dict) else None)
                        if txt:
                            text_parts.append(txt)
                            m = re.search(r"data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)", txt)
                            if m:
                                try:
                                    images.append(base64.b64decode(m.group(1)))
                                except Exception:
                                    current_app.logger.exception("failed decode data uri in text")

            # fallback: chunk.binary or chunk.data or direct bytes at top level
            binary = getattr(chunk, "binary", None) or (chunk.get("binary") if isinstance(chunk, dict) else None)
            if binary:
                try:
                    images.append(bytes(binary))
                except Exception:
                    current_app.logger.exception("failed to append chunk.binary")

            # some SDKs include chunk.output or chunk.candidates[0].content.parts as nested dicts/strings:
            # try to inspect str(chunk) for data uri/base64 if nothing else found in this iteration
            # (keep this cheap: only do for chunks that carry little else)
            # Note: avoid expensive global repr calls in high-throughput loops
    except Exception:
        current_app.logger.exception("extract_images_text_and_inline_from_stream failed")
    # dedupe warnings
    warnings = list(dict.fromkeys(warnings))
    return images, text_parts, inline_parts_summary, warnings

# Image Edit Endpoint (drop-in replacement)
# Expects same environment and helpers as generate-from-image:
# - GENAI_CLIENT (initialized google.genai client)
# - sanitize_prompt(...)
# - extract_images_text_and_inline_from_stream(...)
# - save_bytes_to_spaces_or_local(...)
# - MAX_UPLOAD_BYTES, MAX_PROMPT_CHARS, MODEL_ID, MAX_WORKERS, etc.

from flask import request, jsonify, current_app
import base64
import json
import time
import uuid
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.genai.types import Part, Content, GenerateContentConfig
from google.genai.errors import ClientError

@app.route("/api/v1/edit-image2", methods=["POST", "OPTIONS"])
def edit_image_endpoint2():
    """
    Edit an existing image using the model. Accepts multipart/form-data or JSON.
    Multipart fields:
      - file (required): image file to edit
      - mask (optional): mask file (white = keep, black = edit) or alpha mask depending on your model's needs
      - edit_instructions (string): textual edit instructions (required)
      - user_id, workspace_id (optional)
    JSON fields:
      - file_bytes (base64) OR file_uri (string) - one required
      - mask_bytes (base64) OR mask_uri (string) - optional
      - edit_instructions (string)
    Response: same debug format as generate-from-image, returns saved files/urls when model returns image bytes.
    """

    if request.method == "OPTIONS":
        return ("", 200)
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    try:
        # parse inputs
        edit_instructions = ""
        file_bytes = None
        file_uri = None
        file_mime = None
        mask_bytes = None
        mask_uri = None
        mask_mime = None
        user_id = None
        workspace_id = None

        # Multipart form preferred
        if request.content_type and request.content_type.startswith("multipart/form-data"):
            f = request.files.get("file") or request.files.get("image") or request.files.get("photo")
            m = request.files.get("mask")
            edit_instructions = (request.form.get("edit_instructions") or request.form.get("prompt") or "").strip()
            user_id = request.form.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = request.form.get("workspace_id") or request.headers.get("X-Workspace-Id")
            if f:
                file_mime = f.mimetype or "image/png"
                file_bytes = f.read()
                try:
                    f.seek(0)
                except Exception:
                    pass
                if len(file_bytes) > MAX_UPLOAD_BYTES:
                    return jsonify({"success": False, "error": "file_too_large"}), 400
            else:
                file_uri = request.form.get("file_uri") or request.form.get("image_url")
                if not file_uri:
                    return jsonify({"success": False, "error": "file_or_file_uri_required"}), 400

            if m:
                mask_mime = m.mimetype or "image/png"
                mask_bytes = m.read()
                try:
                    m.seek(0)
                except Exception:
                    pass
                if len(mask_bytes) > MAX_UPLOAD_BYTES:
                    return jsonify({"success": False, "error": "mask_too_large"}), 400
            else:
                # optional mask URI
                mask_uri = request.form.get("mask_uri")

        else:
            # JSON body
            data = request.get_json(silent=True) or {}
            edit_instructions = (data.get("edit_instructions") or data.get("prompt") or "").strip()
            user_id = data.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")

            if data.get("file_bytes"):
                try:
                    file_bytes = base64.b64decode(data.get("file_bytes"))
                    file_mime = data.get("mime_type") or "image/png"
                    if len(file_bytes) > MAX_UPLOAD_BYTES:
                        return jsonify({"success": False, "error": "file_too_large"}), 400
                except Exception:
                    return jsonify({"success": False, "error": "invalid_base64_file_bytes"}), 400
            else:
                file_uri = data.get("file_uri") or data.get("image_url")
                if not file_uri:
                    return jsonify({"success": False, "error": "file_or_file_uri_required"}), 400

            # mask optional
            if data.get("mask_bytes"):
                try:
                    mask_bytes = base64.b64decode(data.get("mask_bytes"))
                    mask_mime = data.get("mask_mime") or "image/png"
                    if len(mask_bytes) > MAX_UPLOAD_BYTES:
                        return jsonify({"success": False, "error": "mask_too_large"}), 400
                except Exception:
                    return jsonify({"success": False, "error": "invalid_base64_mask_bytes"}), 400
            else:
                mask_uri = data.get("mask_uri")

        if not edit_instructions:
            return jsonify({"success": False, "error": "edit_instructions_required"}), 400

        # sanitize the edit instructions
        sanitized_instructions = sanitize_prompt(edit_instructions)
        if not sanitized_instructions:
            return jsonify({"success": False, "error": "instructions_empty_after_sanitization"}), 400

        # Build a call function similar to generate endpoint but includes mask if provided
        def call_edit_variation(variation_label: str, force_json_datauri=False, short_prompt_on_retry=False):
            parts = []
            # add original image (bytes or uri)
            if file_bytes is not None:
                parts.append(Part.from_bytes(data=file_bytes, mime_type=file_mime or "image/png"))
            else:
                parts.append(Part.from_uri(file_uri=file_uri))

            # if mask provided add it as separate part (some models expect mask as second part)
            if mask_bytes is not None:
                parts.append(Part.from_bytes(data=mask_bytes, mime_type=mask_mime or "image/png"))
            elif mask_uri:
                parts.append(Part.from_uri(file_uri=mask_uri))

            # instruction text: combine sanitized instructions + variation label
            instruction = f"{sanitized_instructions}\n\n{variation_label}\n\nEdit the provided image accordingly and return a single square PNG suitable for a social feed."
            if force_json_datauri:
                instruction += (
                    "\n\nIMPORTANT: Return EXACTLY a JSON object only like:\n"
                    '{ "images": [ { "index": 0, "mime": "image/png", "data_uri": "data:image/png;base64,<BASE64>" } ] }\n'
                    "Replace <BASE64> with base64 PNG bytes (no newlines)."
                )
            if short_prompt_on_retry:
                instruction = f"{variation_label}. Edit the image as instructed."

            parts.append(Part.from_text(text=instruction))

            cfg = GenerateContentConfig(
                temperature=1.0,
                top_p=0.95,
                max_output_tokens=8192,
                # If forcing JSON data URI, request TEXT mode only (model returns JSON)
                response_modalities=["IMAGE", "TEXT"] if not force_json_datauri else ["TEXT"],
                candidate_count=1,
            )

            try:
                stream = GENAI_CLIENT.models.generate_content_stream(
                    model=MODEL_ID,
                    contents=[Content(role="user", parts=parts)],
                    config=cfg,
                )

                images, text_parts, inline_parts_summary, warnings = extract_images_text_and_inline_from_stream(stream)

                result = {
                    "variation": variation_label,
                    "success": False,
                    "debug_text_parts": text_parts,
                    "debug_inline_parts": inline_parts_summary,
                    "warnings": warnings,
                }

                # save images if returned as bytes
                if images:
                    saved_files = []
                    saved_urls = []
                    for b in images:
                        try:
                            fname, url = save_bytes_to_spaces_or_local(b, prefix=f"edit_{uuid.uuid4().hex[:6]}")
                        except Exception:
                            current_app.logger.exception("save_bytes_to_spaces_or_local failed")
                            fname, url = None, None
                        if fname:
                            saved_files.append(fname)
                            saved_urls.append(url or f"outputs/{fname}")
                    if saved_files:
                        result.update({"success": True, "files": saved_files, "urls": saved_urls})
                        return result

                # try parse text parts for data URIs or JSON
                joined = "\n".join(text_parts or [])
                if joined:
                    m = re.search(r"data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)", joined)
                    if m:
                        try:
                            b = base64.b64decode(m.group(1))
                            fname, url = save_bytes_to_spaces_or_local(b, prefix=f"edit_{uuid.uuid4().hex[:6]}")
                            if fname:
                                result.update({"success": True, "files": [fname], "urls": [url or f"outputs/{fname}"]})
                                return result
                        except Exception:
                            current_app.logger.exception("failed decode datauri found in text")

                    jmatch = re.search(r"(\{[\s\S]*?\})", joined)
                    if jmatch:
                        try:
                            parsed = json.loads(jmatch.group(1))
                            arr = parsed.get("images") if isinstance(parsed, dict) else None
                            if isinstance(arr, list):
                                saved_files = []
                                saved_urls = []
                                for it in arr:
                                    if isinstance(it, dict):
                                        du = it.get("data_uri")
                                        if du:
                                            m2 = re.search(r"data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)", du)
                                            if m2:
                                                try:
                                                    b2 = base64.b64decode(m2.group(1))
                                                    fname, url = save_bytes_to_spaces_or_local(b2, prefix=f"edit_{uuid.uuid4().hex[:6]}")
                                                    if fname:
                                                        saved_files.append(fname); saved_urls.append(url or f"outputs/{fname}")
                                                except Exception:
                                                    current_app.logger.exception("failed decode data_uri from json")
                                if saved_files:
                                    result.update({"success": True, "files": saved_files, "urls": saved_urls})
                                    return result
                        except Exception:
                            current_app.logger.exception("json parse failed from text")

                return result

            except ClientError as ce:
                current_app.logger.exception("ClientError from model (edit): %s", ce)
                return {"variation": variation_label, "success": False, "error": "model_client_error", "details": str(ce)}
            except Exception as e:
                current_app.logger.exception("unhandled exception calling model (edit)")
                return {"variation": variation_label, "success": False, "error": "exception", "details": str(e), "trace": traceback.format_exc()}

        # Run the variations in parallel (same set as generate)
        variations = [
            "Edit image for FIRST THEME",
            "Edit image for SECOND THEME",
            "Edit image for THIRD THEME",
        ]
        results = []
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(variations))) as ex:
            futures = {ex.submit(call_edit_variation, v, False, False): v for v in variations}
            for fut in as_completed(futures):
                v = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    current_app.logger.exception("variation future failure (edit)")
                    res = {"variation": v, "success": False, "error": "future_exception"}
                results.append(res)

        # Retry failed edits with JSON-data-uri or short prompt (same logic)
        for r in results:
            if not r.get("success"):
                retry_json = call_edit_variation(r.get("variation"), force_json_datauri=True, short_prompt_on_retry=False)
                if retry_json.get("success"):
                    r.update(retry_json)
                    continue
                if "model_client_error" in (r.get("error") or "") or ("request is not supported" in (r.get("details") or "").lower()):
                    retry_short = call_edit_variation(r.get("variation"), force_json_datauri=False, short_prompt_on_retry=True)
                    if retry_short.get("success"):
                        r.update(retry_short)
                        continue
                r.setdefault("retry_attempts", []).append({
                    "json_retry": {"success": retry_json.get("success"), "details": retry_json.get("details")},
                })

        # Collect saved files & urls
        saved_files = []
        urls = []
        for r in results:
            if r.get("success"):
                saved_files.extend(r.get("files", []))
                urls.extend(r.get("urls", []))

        # Normalize results for JSON safeness
        safe_results = []
        for r in results:
            if not isinstance(r, dict):
                try:
                    safe_results.append(str(r))
                except Exception:
                    safe_results.append({"value": "unserializable"})
                continue
            safe_r = {}
            for k, v in r.items():
                try:
                    json.dumps(v)
                    safe_r[k] = v
                except Exception:
                    if isinstance(v, (bytes, bytearray)):
                        safe_r[k] = base64.b64encode(bytes(v)).decode("ascii")[:200] + "..."
                    else:
                        safe_r[k] = str(v)
            safe_results.append(safe_r)

        response = {
            "success": True,
            "sanitized_instructions": sanitized_instructions,
            "results": safe_results,
            "files": saved_files,
            "urls": urls,
            "timestamp": int(time.time())
        }
        return jsonify(response), 200

    except Exception as e:
        current_app.logger.exception("unexpected error in edit_image_endpoint: %s", e)
        return jsonify({"success": False, "error": "internal", "details": str(e), "trace": traceback.format_exc()}), 500
import base64
import json
import mimetypes
import re
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List

from flask import request, jsonify, current_app
from botocore.exceptions import ClientError  # if you're using this already

# assume these are already imported/defined somewhere in your file:
# from your_app import app, db
# from your_app.models import Generation, Creative, Conversation
# from google.genai import Client, types as genai_types
# from google.genai.types import Part, Content, GenerateContentConfig
# and helpers: sanitize_prompt, extract_images_text_and_inline_from_stream,
# save_bytes_to_spaces_or_local, _generate_image_with_input_images, save_images_from_response,
# master_prompt_json, extract_text_from_response, parse_json_from_model_text,
# escape_for_inline, _chat_image_edit_with_instruction, _generate_image_edit_with_instruction
# plus constants: GENAI_CLIENT, MODEL_ID, TEXT_MODEL, SPACE_CDN, PLATFORM_ASPECT_MAP,
# MAX_UPLOAD_BYTES, MAX_WORKERS

# -------------------------------------------------------------------
# Helper: trim workspace JSON block from prompts before saving to DB
# -------------------------------------------------------------------
def trim_workspace_details_from_prompt(text: str) -> str:
    """
    Trim any workspace-details block that starts with:
      ---\nWorkspace Details (JSON):
    Returns only the left-hand side (main user prompt).
    If marker not found, returns original text trimmed.
    """
    if not text:
        return text

    # pattern: '---' then optional whitespace/newlines then 'Workspace Details (JSON):'
    pattern = re.compile(
        r"---\s*Workspace\s+Details\s*\(JSON\)\s*:",
        re.IGNORECASE,
    )
    m = pattern.search(text)
    if m:
        return text[:m.start()].strip()

    # alternative: '---' on its own line, then 'Workspace Details (JSON):' next line
    alt_pattern = re.compile(
        r"---\s*\r?\n\s*Workspace\s+Details\s*\(JSON\)\s*:",
        re.IGNORECASE,
    )
    m2 = alt_pattern.search(text)
    if m2:
        return text[:m2.start()].strip()

    return text.strip()


# import base64
import json
import mimetypes
import re
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List
from decimal import Decimal

from flask import request, jsonify, current_app, redirect, make_response
from botocore.exceptions import ClientError  # if you're using this already

# assume these are already imported/defined somewhere in your file:
# from your_app import app, db
# from your_app.models import Generation, Creative, Conversation
# from google.genai.types import Part, Content, GenerateContentConfig
# from your_app.ai_usage import log_ai_usage
# and helpers: sanitize_prompt, extract_images_text_and_inline_from_stream,
# save_bytes_to_spaces_or_local, _generate_image_with_input_images, save_images_from_response,
# master_prompt_json, extract_text_from_response, parse_json_from_model_text,
# escape_for_inline, _chat_image_edit_with_instruction, _generate_image_edit_with_instruction
# plus constants: GENAI_CLIENT, MODEL_ID, TEXT_MODEL, SPACE_CDN, PLATFORM_ASPECT_MAP,
# MAX_UPLOAD_BYTES, MAX_WORKERS


# -------------------------------------------------------------------
# Helper: trim workspace JSON block from prompts before saving to DB
# -------------------------------------------------------------------
def trim_workspace_details_from_prompt(text: str) -> str:
    """
    Trim any workspace-details block that starts with:
      ---\nWorkspace Details (JSON):
    Returns only the left-hand side (main user prompt).
    If marker not found, returns original text trimmed.
    """
    if not text:
        return text

    # pattern: '---' then optional whitespace/newlines then 'Workspace Details (JSON):'
    pattern = re.compile(
        r"---\s*Workspace\s+Details\s*\(JSON\)\s*:",
        re.IGNORECASE,
    )
    m = pattern.search(text)
    if m:
        return text[:m.start()].strip()

    # alternative: '---' on its own line, then 'Workspace Details (JSON):' next line
    alt_pattern = re.compile(
        r"---\s*\r?\n\s*Workspace\s+Details\s*\(JSON\)\s*:",
        re.IGNORECASE,
    )
    m2 = alt_pattern.search(text)
    if m2:
        return text[:m2.start()].strip()

    return text.strip()



from decimal import Decimal

IMAGE_PRICING_INR = {
    # Gemini 2.5 Image Models
    "gemini-2.5-flash-image": Decimal("2.80"),      # You are using this
    "gemini-2.5-pro-image": Decimal("4.80"),
    "gemini-2.5-ultra-image": Decimal("9.60"),

    # Backup (Gemini 1.5 if used)
    "gemini-flash-image": Decimal("2.52"),
    "gemini-pro-image": Decimal("5.04"),

    # Imagen Series
    "imagen-3.0": Decimal("3.52"),
    "imagen-3.0-fast": Decimal("1.76"),

    # Nano / Banana (Test models – Free)
    "gemini-nano": Decimal("0.00"),
    "gemini-nano-banana": Decimal("0.00"),
}


def _normalize_model_name(model_name: str) -> str:
    """
    Normalizes a raw model_name/path to a short key for pricing lookup.
    Works for both 'projects/.../models/imagen-3.0-generate-001' and 'imagen-3.0'.
    """
    if not model_name:
        return ""
    short = model_name.split("/")[-1].lower()
    # trim trailing -001 / -002 etc.
    if len(short) > 4 and short[-4] == "-" and short[-3:].isdigit():
        short = short[:-4]
    # also trim '-generate' suffix if present
    if short.endswith("-generate"):
        short = short[:-9]
    return short


def calculate_image_cost_inr(model_name: str, num_images: int) -> Decimal:
    """
    Rough cost calculator for image generations/edit endpoints.
    We treat `num_images` as "units" and multiply by per-image INR pricing.
    """
    if not num_images:
        return Decimal("0")

    key = _normalize_model_name(model_name or "")
    price = IMAGE_PRICING_INR.get(key)

    if price is None:
        current_app.logger.warning(
            f"[AI_USAGE] No IMAGE_PRICING_INR for model={model_name} (key={key}); cost=0"
        )
        return Decimal("0")

    return (Decimal(num_images) * price).quantize(Decimal("0.0001"))


def _coerce_ids_for_usage(user_id, workspace_id):
    """Best-effort coercion of user_id/workspace_id into ints for logging."""
    uid_int = None
    wid_int = None

    # user id
    try:
        if user_id is not None:
            uid_int = int(user_id)
        else:
            hdr_uid = request.headers.get("X-User-Id")
            if hdr_uid:
                uid_int = int(hdr_uid)
    except Exception:
        uid_int = None

    # workspace id
    try:
        if workspace_id is not None:
            wid_int = int(workspace_id)
    except Exception:
        wid_int = None

    return uid_int, wid_int


# -------------------------------------------------------------------
# /api/v1/generate-from-image
# -------------------------------------------------------------------

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def _extract_usage(resp) -> Dict[str, int]:
    """
    Try to read token usage from either Vertex-style or google.genai-style responses.
    Logs the full usage_metadata (if present).
    """
    if resp is None:
        return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}

    usage_meta = getattr(resp, "usage_metadata", None) or {}

    # ---- log raw usage_metadata as much as possible ----
    try:
        if isinstance(usage_meta, dict):
            raw_usage = usage_meta
        else:
            # convert object -> dict of public attrs
            raw_usage = {
                k: getattr(usage_meta, k)
                for k in dir(usage_meta)
                if not k.startswith("_") and not callable(getattr(usage_meta, k, None))
            }
        logger.info(f"[AI_USAGE_META] raw_usage_metadata={raw_usage}")
    except Exception:
        logger.debug("Failed to serialize usage_metadata for logging", exc_info=True)

    # google.genai style
    input_tokens = getattr(usage_meta, "prompt_token_count", None)
    output_tokens = getattr(usage_meta, "candidates_token_count", None)
    total_tokens = getattr(usage_meta, "total_token_count", None)

    # Vertex / fallback naming
    if input_tokens is None:
        input_tokens = getattr(usage_meta, "input_token_count", 0)
    if output_tokens is None:
        output_tokens = getattr(usage_meta, "output_token_count", 0)
    if total_tokens is None:
        total_tokens = (input_tokens or 0) + (output_tokens or 0)

    usage = {
        "input_tokens": int(input_tokens or 0),
        "output_tokens": int(output_tokens or 0),
        "total_tokens": int(total_tokens or 0),
    }

    logger.info(f"[AI_USAGE_META_SUMMARY] usage={usage}")
    return usage


def _extract_usage_from_stream_obj(stream) -> Dict[str, int]:
    """
    Try to read token usage from a streaming response object.
    Many google.genai/Vertex clients attach the final response as
    stream.response or stream._response.
    """
    try:
        base_resp = getattr(stream, "response", None) or getattr(stream, "_response", None)
        logger.debug(f"_extract_usage_from_stream_obj: base_resp={base_resp}")
        logger.debug(
            f"_extract_usage_from_stream_obj: base_resp.usage_metadata="
            f"{getattr(base_resp, 'usage_metadata', None)}"
        )
        if base_resp is None:
            return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        return _extract_usage(base_resp)
    except Exception:
        logger.warning("Failed to extract usage from stream object", exc_info=True)
        return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


# -------------------------------------------------------------------
# /api/v1/generate-from-image
# -------------------------------------------------------------------
@app.route("/api/v1/generate-from-image", methods=["POST", "OPTIONS"])
def generate_from_image_endpoint():
    if request.method == "OPTIONS":
        return ("", 200)
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    try:
        # --- parse request (multipart preferred) ---
        prompt = ""
        file_bytes = None
        file_uri = None
        mime_type = None
        edit_only = False
        user_id = None
        workspace_id = None

        if request.content_type and request.content_type.startswith("multipart/form-data"):
            f = request.files.get("file") or request.files.get("image") or request.files.get("photo")
            prompt = (request.form.get("prompt") or request.form.get("text") or "").strip()
            edit_only = (request.form.get("edit_only") or request.form.get("single_edit") or "").lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
            file_uri = request.form.get("file_uri") or request.form.get("image_url")
            user_id = request.form.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = request.form.get("workspace_id") or request.headers.get("X-Workspace-Id")

            if f:
                mime_type = f.mimetype or "image/png"
                file_bytes = f.read()
                try:
                    f.seek(0)
                except Exception:
                    pass
                if len(file_bytes) > MAX_UPLOAD_BYTES:
                    return jsonify({"success": False, "error": "file_too_large"}), 400
            elif not file_uri:
                return jsonify({"success": False, "error": "file_or_file_uri_required"}), 400

        else:
            data = request.get_json(silent=True) or {}
            prompt = (data.get("prompt") or data.get("text") or "").strip()
            edit_only = bool(data.get("edit_only") or data.get("single_edit"))
            file_uri = data.get("file_uri") or data.get("image_url")
            user_id = data.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")

            if data.get("file_bytes"):
                try:
                    file_bytes = base64.b64decode(data.get("file_bytes"))
                    mime_type = data.get("mime_type") or "image/png"
                    if len(file_bytes) > MAX_UPLOAD_BYTES:
                        return jsonify({"success": False, "error": "file_too_large"}), 400
                except Exception:
                    return jsonify({"success": False, "error": "invalid_base64_file_bytes"}), 400
            elif not file_uri:
                return jsonify({"success": False, "error": "file_or_file_uri_required"}), 400

        # validate prompt
        if not prompt:
            return jsonify({"success": False, "error": "prompt_required"}), 400

        sanitized_prompt = sanitize_prompt(prompt)
        if not sanitized_prompt:
            return jsonify(
                {"success": False, "error": "prompt_empty_after_sanitization"}
            ), 400

        # ------------------------
        # model-call builder + usage accumulator
        # ------------------------
        total_usage: Dict[str, int] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        }

        def call_model_for_variation(
            variation_label: str,
            force_json_datauri: bool = False,
            short_prompt_on_retry: bool = False,
        ):
            parts = []
            if file_bytes is not None:
                parts.append(
                    Part.from_bytes(
                        data=file_bytes,
                        mime_type=mime_type or "image/png",
                    )
                )
            else:
                parts.append(Part.from_uri(file_uri=file_uri))

            instruction = (
                f"{sanitized_prompt}\n\n{variation_label}\n\n"
                "Produce a single square PNG suitable for a social feed."
            )
            if force_json_datauri:
                instruction += (
                    "\n\nIMPORTANT: Return EXACTLY a JSON object only like:\n"
                    '{ "images": [ { "index": 0, "mime": "image/png", '
                    '"data_uri": "data:image/png;base64,<BASE64>" } ] }\n'
                    "Replace <BASE64> with base64 PNG bytes (no newlines)."
                )
            if short_prompt_on_retry:
                instruction = f"{variation_label}. Produce a single square PNG."

            parts.append(Part.from_text(text=instruction))

            cfg = GenerateContentConfig(
                temperature=1.0,
                top_p=0.95,
                max_output_tokens=8192,
                response_modalities=["IMAGE", "TEXT"] if not force_json_datauri else ["TEXT"],
                candidate_count=1,
            )

            try:
                stream = GENAI_CLIENT.models.generate_content_stream(
                    model=MODEL_ID,
                    contents=[Content(role="user", parts=parts)],
                    config=cfg,
                )

                # usage from stream (if available)
                usage = _extract_usage_from_stream_obj(stream)
                total_usage["input_tokens"] += usage.get("input_tokens", 0)
                total_usage["output_tokens"] += usage.get("output_tokens", 0)
                total_usage["total_tokens"] += usage.get("total_tokens", 0)

                logger.info(
                    f"[IMAGE_GEN_VARIATION_USAGE] variation={variation_label} usage={usage}"
                )

                images, text_parts, inline_parts_summary, warnings = (
                    extract_images_text_and_inline_from_stream(stream)
                )

                result: Dict[str, Any] = {
                    "variation": variation_label,
                    "success": False,
                    "debug_text_parts": text_parts,
                    "debug_inline_parts": inline_parts_summary,
                    "warnings": warnings,
                    "usage": usage,
                }

                # Save received binary images first (if any)
                if images:
                    saved_files: List[str] = []
                    saved_urls: List[str] = []
                    for b in images:
                        try:
                            fname, url = save_bytes_to_spaces_or_local(
                                b, prefix=f"var_{uuid.uuid4().hex[:6]}"
                            )
                        except Exception:
                            current_app.logger.exception(
                                "save_bytes_to_spaces_or_local failed"
                            )
                            fname, url = None, None
                        if fname:
                            saved_files.append(fname)
                            saved_urls.append(url or f"outputs/{fname}")
                    if saved_files:
                        result.update(
                            {"success": True, "files": saved_files, "urls": saved_urls}
                        )
                        return result

                # Inspect text parts for data URIs or JSON images[]
                joined = "\n".join(text_parts or [])
                if joined:
                    # direct data URI
                    m = re.search(
                        r"data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)",
                        joined,
                    )
                    if m:
                        try:
                            b = base64.b64decode(m.group(1))
                            fname, url = save_bytes_to_spaces_or_local(
                                b, prefix=f"var_{uuid.uuid4().hex[:6]}"
                            )
                            if fname:
                                result.update(
                                    {
                                        "success": True,
                                        "files": [fname],
                                        "urls": [url or f"outputs/{fname}"],
                                    }
                                )
                                return result
                        except Exception:
                            current_app.logger.exception(
                                "failed decode datauri found in text"
                            )

                    # JSON { "images": [ { data_uri: ... } ] }
                    jmatch = re.search(r"(\{[\s\S]*?\})", joined)
                    if jmatch:
                        try:
                            parsed = json.loads(jmatch.group(1))
                            arr = parsed.get("images") if isinstance(parsed, dict) else None
                            if isinstance(arr, list):
                                saved_files: List[str] = []
                                saved_urls: List[str] = []
                                for it in arr:
                                    if not isinstance(it, dict):
                                        continue
                                    du = it.get("data_uri")
                                    if not du:
                                        continue
                                    m2 = re.search(
                                        r"data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)",
                                        du,
                                    )
                                    if m2:
                                        try:
                                            b2 = base64.b64decode(m2.group(1))
                                            fname, url = save_bytes_to_spaces_or_local(
                                                b2, prefix=f"var_{uuid.uuid4().hex[:6]}"
                                            )
                                            if fname:
                                                saved_files.append(fname)
                                                saved_urls.append(
                                                    url or f"outputs/{fname}"
                                                )
                                        except Exception:
                                            current_app.logger.exception(
                                                "failed decode data_uri from json"
                                            )
                                if saved_files:
                                    result.update(
                                        {
                                            "success": True,
                                            "files": saved_files,
                                            "urls": saved_urls,
                                        }
                                    )
                                    return result
                        except Exception:
                            current_app.logger.exception("json parse failed from text")

                return result

            except ClientError as ce:
                current_app.logger.exception("ClientError from model: %s", ce)
                return {
                    "variation": variation_label,
                    "success": False,
                    "error": "model_client_error",
                    "details": str(ce),
                    "usage": {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "total_tokens": 0,
                    },
                }
            except Exception as e:
                current_app.logger.exception("unhandled exception calling model")
                return {
                    "variation": variation_label,
                    "success": False,
                    "error": "exception",
                    "details": str(e),
                    "trace": traceback.format_exc(),
                    "usage": {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "total_tokens": 0,
                    },
                }

        # ------------------------
        # Execute variations in parallel
        # ------------------------
        variations = [
            "Generate image for FIRST THEME",
            "Generate image for SECOND THEME",
            "Generate image for THIRD THEME",
        ]
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(variations))) as ex:
            futures = {ex.submit(call_model_for_variation, v, False, False): v for v in variations}
            for fut in as_completed(futures):
                v = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    current_app.logger.exception("variation future failure")
                    res = {
                        "variation": v,
                        "success": False,
                        "error": "future_exception",
                    }
                results.append(res)

        # Retry strategy for failed variations
        for r in results:
            if not r.get("success"):
                retry_json = call_model_for_variation(
                    r.get("variation"),
                    force_json_datauri=True,
                    short_prompt_on_retry=False,
                )
                if retry_json.get("success"):
                    r.update(retry_json)
                    continue

                if "model_client_error" in (r.get("error") or "") or (
                    "request is not supported" in (r.get("details") or "").lower()
                ):
                    retry_short = call_model_for_variation(
                        r.get("variation"),
                        force_json_datauri=False,
                        short_prompt_on_retry=True,
                    )
                    if retry_short.get("success"):
                        r.update(retry_short)
                        continue

                r.setdefault("retry_attempts", []).append(
                    {
                        "json_retry": {
                            "success": retry_json.get("success"),
                            "details": retry_json.get("details"),
                        },
                    }
                )

        # Collect saved files & urls
        saved_files: List[str] = []
        urls: List[str] = []
        for r in results:
            if r.get("success"):
                saved_files.extend(r.get("files", []))
                urls.extend(r.get("urls", []))

        # Normalize results for JSON safety
        safe_results: List[Any] = []
        for r in results:
            safe_r: Dict[str, Any] = {}
            if not isinstance(r, dict):
                try:
                    safe_results.append(str(r))
                except Exception:
                    safe_results.append({"value": "unserializable"})
                continue

            for k, v in r.items():
                try:
                    json.dumps(v)
                    safe_r[k] = v
                except Exception:
                    if isinstance(v, (bytes, bytearray)):
                        safe_r[k] = (
                            base64.b64encode(bytes(v)).decode("ascii")[:200] + "..."
                        )
                    else:
                        safe_r[k] = str(v)
            safe_results.append(safe_r)

        # ------------------------
        # Persist Generation – trim prompt before saving
        # ------------------------
        try:
            db_user_id = None
            if user_id is None:
                hdr_uid = request.headers.get("X-User-Id")
                if hdr_uid:
                    try:
                        db_user_id = int(hdr_uid)
                    except Exception:
                        db_user_id = None
                else:
                    current_app.logger.warning(
                        "No user_id present; skipping DB save for generation "
                        "(Generation.user_id is required)."
                    )
                    db_user_id = None
            else:
                try:
                    db_user_id = int(user_id)
                except Exception:
                    current_app.logger.warning(
                        "Could not coerce user_id to int; skipping DB save."
                    )
                    db_user_id = None

            db_workspace_id = None
            if workspace_id is not None:
                try:
                    db_workspace_id = int(workspace_id)
                except Exception:
                    db_workspace_id = None

            if db_user_id is not None:
                gen_id = uuid.uuid4().hex[:32]
                saved_prompt = trim_workspace_details_from_prompt(prompt)
                gen_row = Generation(
                    id=gen_id,
                    user_id=db_user_id,
                    workspace_id=db_workspace_id,
                    prompt=saved_prompt,
                    response=json.dumps(safe_results),
                    created_at=datetime.utcnow(),
                )
                db.session.add(gen_row)
                db.session.commit()
                current_app.logger.info(
                    f"Saved generation {gen_id} for workspace={db_workspace_id}, "
                    f"user={db_user_id}"
                )
            else:
                current_app.logger.warning(
                    "Skipping DB save because user_id is not available or invalid."
                )
        except Exception as db_err:
            current_app.logger.exception(
                "Failed to save generation to DB: %s", db_err
            )
            try:
                db.session.rollback()
            except Exception:
                pass

        # ------------------------
        # AI usage logging (per-request image cost)
        # ------------------------
        try:
            num_images = len(saved_files)
            cost_inr = calculate_image_cost_inr(MODEL_ID, num_images)

            usage_payload = {
                "input_tokens": int(total_usage.get("input_tokens", 0)),
                "output_tokens": int(total_usage.get("output_tokens", 0)),
                "total_tokens": int(total_usage.get("total_tokens", 0)),
                "num_images": num_images,
                "num_variations": len(results),
                "edit_only": bool(edit_only),
            }

            uid_int, wid_int = _coerce_ids_for_usage(user_id, workspace_id)
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

            current_app.logger.info(
                "[AI_USAGE_DEBUG] feature=generate_from_image "
                f"model={MODEL_ID} usage={usage_payload} "
                f"files={saved_files} urls_count={len(urls)}"
            )

            log_ai_usage(
                feature="generate_from_image",
                route_path="/api/v1/generate-from-image",
                model=MODEL_ID,
                usage=usage_payload,
                cost_inr=cost_inr,
                user_id=uid_int,
                workspace_id=wid_int,
                ip_address=client_ip,
            )

            current_app.logger.info(
                f"[AI_USAGE] /generate-from-image model={MODEL_ID} "
                f"images={num_images} cost_inr={cost_inr} tokens={usage_payload}"
            )
        except Exception as e:
            current_app.logger.warning(
                f"[AI_USAGE] failed to log generate-from-image usage: {e}"
            )

        # Response
        response = {
            "success": True,
            "sanitized_prompt": sanitized_prompt,
            "results": safe_results,
            "files": saved_files,
            "urls": urls,
            "timestamp": int(time.time()),
        }
        return jsonify(response), 200

    except Exception as e:
        current_app.logger.exception(
            "unexpected error in generate_from_image_endpoint: %s", e
        )
        return (
            jsonify(
                {
                    "success": False,
                    "error": "internal",
                    "details": str(e),
                    "trace": traceback.format_exc(),
                }
            ),
            500,
        )




"""
@app.route("/api/v1/generate-from-images", methods=["POST"])
def generate_from_images_endpoint():
    
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    prompt = ""
    file_bytes_list: List[bytes] = []
    file_uris: List[str] = []
    mime_types: List[str] = []
    aspect_ratio = None
    platform = None
    use_themes = False
    user_id = None
    workspace_id = None

    try:
        content_type = request.content_type or ""
        print(f"[generate-from-images] content_type: {content_type}", flush=True)

        if content_type.startswith("multipart/form-data"):
            prompt = request.form.get("prompt") or request.form.get("text") or ""
            platform = request.form.get("platform")
            aspect_ratio = request.form.get("aspect_ratio")
            use_themes = (request.form.get("use_themes") or "").lower() in ("1", "true", "yes")
            user_id = request.form.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = request.form.get("workspace_id") or request.headers.get("X-Workspace-Id")

            uploaded_files_fields = request.form.getlist("uploaded_files") or []
            if uploaded_files_fields:
                print(f"[generate-from-images] uploaded_files form entries: {uploaded_files_fields}", flush=True)
                for entry in uploaded_files_fields:
                    if not entry:
                        continue
                    if entry.startswith("http://") or entry.startswith("https://") or entry.startswith("gs://"):
                        file_uris.append(entry)
                    else:
                        print(f"[generate-from-images] received uploaded_files token (not a URL): {entry}", flush=True)

            files = request.files.getlist("files") or request.files.getlist("files[]") or []
            if not files:
                single = request.files.get("file")
                if single:
                    files = [single]
            if not files and request.files:
                files = list(request.files.values())

            print(f"[generate-from-images] form keys: {list(request.form.keys())}", flush=True)
            print(f"[generate-from-images] files keys: {list(request.files.keys())}", flush=True)
            print(f"[generate-from-images] received {len(files)} uploaded file(s)", flush=True)

            for idx, f in enumerate(files):
                fname = getattr(f, "filename", None)
                if not f or not fname:
                    print(f"[generate-from-images] skipping empty file at index {idx}", flush=True)
                    continue
                try:
                    b = f.read()
                except Exception as e:
                    print(f"[generate-from-images] failed to read file[{idx}] {fname}: {e}", flush=True)
                    continue
                size = len(b) if b else 0
                print(f"[generate-from-images] file[{idx}] name={fname} mimetype={getattr(f,'mimetype',None)} size={size}", flush=True)
                if size > MAX_UPLOAD_BYTES:
                    print(f"[generate-from-images] file[{idx}] too large: {size} > {MAX_UPLOAD_BYTES}", flush=True)
                    return jsonify({"success": False, "error": "file_too_large"}), 400
                file_bytes_list.append(b)
                mime_types.append(f.mimetype or mimetypes.guess_type(fname)[0] or "image/png")

        else:
            data = request.get_json() or {}
            print(f"[generate-from-images] JSON body: keys={list(data.keys())}", flush=True)
            prompt = data.get("prompt") or data.get("text") or ""
            file_uris = data.get("file_uris") or data.get("image_urls") or []
            platform = data.get("platform")
            aspect_ratio = data.get("aspect_ratio")
            use_themes = bool(data.get("use_themes"))
            user_id = data.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
    except Exception as e:
        print("[generate-from-images] request parse failed:", e, flush=True)
        return jsonify({"success": False, "error": "bad_request", "details": str(e)}), 400

    if not aspect_ratio and platform:
        aspect_ratio = PLATFORM_ASPECT_MAP.get(platform)
    print(f"[generate-from-images] final aspect_ratio: {aspect_ratio} use_themes: {use_themes}", flush=True)
    print(f"[generate-from-images] prompt length: {len(prompt or '')}", flush=True)
    print(f"[generate-from-images] initial file_bytes_list count: {len(file_bytes_list)} file_uris count: {len(file_uris)}", flush=True)

    # THEMES FLOW
    if use_themes:
        try:
            first = None
            if file_bytes_list:
                first = Part.from_bytes(data=file_bytes_list[0], mime_type=mime_types[0] if mime_types else "image/png")
            elif file_uris:
                first = Part.from_uri(file_uri=file_uris[0])

            master = master_prompt_json(
                prompt or "",
                has_image=bool(first),
                image_hint=(file_uris[0] if file_uris else "uploaded image"),
            )
            contents = []
            if first:
                contents.append(first)
            contents.append(master)
            cfg = GenerateContentConfig(response_modalities=["TEXT"], candidate_count=1)
            resp = GENAI_CLIENT.models.generate_content(model=TEXT_MODEL, contents=contents, config=cfg)
            raw_text = extract_text_from_response(resp)
            print("[generate-from-images] RAW THEMES RESPONSE (text model):", flush=True)
            print(raw_text, flush=True)
            parsed = parse_json_from_model_text(raw_text, retry_forced=True)
            themes = parsed.get("themes")
        except Exception as e:
            print("[generate-from-images] theme generation failed:", e, flush=True)
            return jsonify({"success": False, "error": "theme_generation_failed", "details": str(e), "raw_response": (raw_text if 'raw_text' in locals() else '')}), 500

        results = []
        saved_files = []
        for idx, theme in enumerate(themes):
            visual_prompt = theme.get("visual_prompt")
            if not visual_prompt:
                results.append({"theme_index": idx, "error": "missing_visual_prompt"})
                continue
            parts = []
            for i, b in enumerate(file_bytes_list):
                parts.append(Part.from_bytes(data=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png"))
            for uri in file_uris:
                parts.append(Part.from_uri(file_uri=uri))

            final_prompt = f"{visual_prompt}\n\nUser prompt (priority): {escape_for_inline(prompt or '')}\nAttached_prompt: {escape_for_inline(theme.get('attached_prompt',''))}"
            print(f"[generate-from-images] theme[{idx}] final_prompt snippet: {final_prompt[:300]}...", flush=True)
            try:
                img_resp = _generate_image_with_input_images(final_prompt, parts, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
            except Exception as e:
                print(f"[generate-from-images] image generation failed for theme {idx}:", e, flush=True)
                results.append({"theme_index": idx, "error": "image_generation_failed", "details": str(e)})
                continue
            saved = save_images_from_response(img_resp, prefix=f"multi_theme{idx}")
            print(f"[generate-from-images] saved for theme {idx}: {saved}", flush=True)
            saved_files.extend(saved)
            results.append({"theme_index": idx, "theme": theme, "files": saved})

        urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved_files]
        print(f"[generate-from-images] returning saved files: {saved_files}", flush=True)

        # Store generated URLs in DB if user_id and workspace_id provided
        print(f"[generate-from-images][themes] Received user_id: {user_id}, workspace_id: {workspace_id}")
        try:
            if user_id and workspace_id:
                for fn, url in zip(saved_files, urls):
                    creative_id = uuid.uuid4().hex
                    creative = Creative(
                        id=creative_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        url=url,
                        filename=fn,
                        type='generated'
                    )
                    db.session.add(creative)
                db.session.commit()
                print(f"[generate-from-images][themes] Stored {len(saved_files)} generated images in DB for user {user_id} / workspace {workspace_id}")
        except Exception as e:
            print(f"[generate-from-images][themes] DB commit failed: {str(e)}")
            db.session.rollback()

        # Save conversation – TRIM prompt
        try:
            if user_id and workspace_id:
                conv_id = uuid.uuid4().hex
                response_data = {
                    "success": True,
                    "themes": themes,
                    "results": results,
                    "files": saved_files,
                    "urls": urls
                }
                conversation_prompt = trim_workspace_details_from_prompt(prompt)
                conversation = Conversation(
                    id=conv_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    prompt=conversation_prompt,
                    response=json.dumps(response_data)
                )
                db.session.add(conversation)
                db.session.commit()
                print(f"[generate-from-images][themes] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
        except Exception as e:
            print(f"[generate-from-images][themes] Conversation DB commit failed: {str(e)}")
            db.session.rollback()

        # ------------------------
        # AI usage logging: themed multi-image generation
        # ------------------------
        try:
            num_images = len(saved_files)
            cost_inr = calculate_image_cost_inr(MODEL_ID, num_images)

            usage_payload = {
                "input_tokens": 0,
                "output_tokens": num_images,
                "total_tokens": num_images,
            }

            uid_int, wid_int = _coerce_ids_for_usage(user_id, workspace_id)

            log_ai_usage(
                feature="generate_from_images_themes",
                model=MODEL_ID,
                usage=usage_payload,
                cost_inr=cost_inr,
                user_id=uid_int,
                workspace_id=wid_int,
                extra_meta={
                    "endpoint": "/api/v1/generate-from-images",
                    "num_images": num_images,
                    "themes_count": len(themes) if themes else 0,
                    "platform": platform,
                    "aspect_ratio": aspect_ratio,
                },
            )
            current_app.logger.info(
                f"[AI_USAGE] /generate-from-images (themes) model={MODEL_ID} images={num_images} cost_inr={cost_inr}"
            )
        except Exception as e:
            current_app.logger.warning(f"[AI_USAGE] failed to log generate-from-images (themes) usage: {e}")

        return jsonify({
            "success": True,
            "themes": themes,
            "results": results,
            "files": saved_files,
            "urls": urls
        }), 200

    # Default (no themes): direct multi-image-guided generation
    parts = []
    for i, b in enumerate(file_bytes_list):
        parts.append(Part.from_bytes(data=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png"))
    for uri in file_uris:
        parts.append(Part.from_uri(file_uri=uri))

    print(f"[generate-from-images] final parts count: {len(parts)}", flush=True)

    if not parts and not prompt:
        print("[generate-from-images] no inputs provided", flush=True)
        return jsonify({"success": False, "error": "no_inputs"}), 400

    final_prompt = (
        f"User prompt (priority): {escape_for_inline(prompt or '')}\n"
        f"This composition should sensibly blend/arrange the supplied reference images as instructed. "
        f"Do NOT invent recognizable personal details. Ensure composition leaves clear readable space if caption overlay is requested."
    )

    print("[generate-from-images] sending to image model with prompt snippet:", flush=True)
    print(final_prompt[:400], flush=True)

    try:
        img_resp = _generate_image_with_input_images(final_prompt, parts, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
        print("[generate-from-images] image model call succeeded", flush=True)
    except Exception as e:
        print("[generate-from-images] image generation failed:", e, flush=True)
        return jsonify({"success": False, "error": "image_generation_failed", "details": str(e)}), 500

    saved = save_images_from_response(img_resp, prefix="gen_multi")
    print(f"[generate-from-images] saved files: {saved}", flush=True)
    urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved]

    print(f"[generate-from-images] Received user_id: {user_id}, workspace_id: {workspace_id}")
    try:
        if user_id and workspace_id:
            for fn, url in zip(saved, urls):
                creative_id = uuid.uuid4().hex
                creative = Creative(
                    id=creative_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=url,
                    filename=fn,
                    type='generated'
                )
                db.session.add(creative)
            db.session.commit()
            print(f"[generate-from-images] Stored {len(saved)} generated images in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate-from-images] DB commit failed: {str(e)}")
        db.session.rollback()

    # Save conversation – TRIM prompt
    try:
        if user_id and workspace_id:
            conv_id = uuid.uuid4().hex
            response_data = {
                "success": True,
                "files": saved,
                "urls": urls
            }
            conversation_prompt = trim_workspace_details_from_prompt(prompt)
            conversation = Conversation(
                id=conv_id,
                user_id=user_id,
                workspace_id=workspace_id,
                prompt=conversation_prompt,
                response=json.dumps(response_data)
            )
            db.session.add(conversation)
            db.session.commit()
            print(f"[generate-from-images] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate-from-images] Conversation DB commit failed: {str(e)}")
        db.session.rollback()

    # ------------------------
    # AI usage logging: direct multi-image generation
    # ------------------------
    try:
        num_images = len(saved)
        cost_inr = calculate_image_cost_inr(MODEL_ID, num_images)

        usage_payload = {
            "input_tokens": 0,
            "output_tokens": num_images,
            "total_tokens": num_images,
        }

        uid_int, wid_int = _coerce_ids_for_usage(user_id, workspace_id)

        log_ai_usage(
            feature="generate_from_images",
            model=MODEL_ID,
            usage=usage_payload,
            cost_inr=cost_inr,
            user_id=uid_int,
            workspace_id=wid_int,
            extra_meta={
                "endpoint": "/api/v1/generate-from-images",
                "num_images": num_images,
                "platform": platform,
                "aspect_ratio": aspect_ratio,
            },
        )
        current_app.logger.info(
            f"[AI_USAGE] /generate-from-images model={MODEL_ID} images={num_images} cost_inr={cost_inr}"
        )
    except Exception as e:
        current_app.logger.warning(f"[AI_USAGE] failed to log generate-from-images usage: {e}")

    return jsonify({
        "success": True,
        "files": saved,
        "urls": urls
    }), 200


# -------------------------------------------------------------------
# /api/v1/edit-image
# -------------------------------------------------------------------
@app.route("/api/v1/edit-image", methods=["POST"])
def edit_image_endpoint():
    
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    try:
        use_chat = False
        user_id = None
        workspace_id = None
        instructions = None
        platform = None
        aspect_ratio = None

        if request.content_type and request.content_type.startswith("multipart/form-data"):
            f = request.files.get("file")
            instructions = request.form.get("instructions") or request.form.get("prompt")
            platform = request.form.get("platform")
            aspect_ratio = request.form.get("aspect_ratio")
            use_chat = request.form.get("use_chat") in ("1", "true", "True")
            user_id = request.form.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = request.form.get("workspace_id") or request.headers.get("X-Workspace-Id")
            if not f or not instructions:
                return jsonify({"success": False, "error": "file_and_instructions_required"}), 400
            b = f.read()
            if len(b) > MAX_UPLOAD_BYTES:
                return jsonify({"success": False, "error": "file_too_large"}), 400
            mime = f.mimetype or mimetypes.guess_type(f.filename)[0] or "image/png"
            part = Part.from_bytes(data=b, mime_type=mime)
        else:
            data = request.get_json() or {}
            instructions = data.get("instructions") or data.get("prompt")
            file_uri = data.get("file_uri")
            platform = data.get("platform")
            aspect_ratio = data.get("aspect_ratio")
            use_chat = bool(data.get("use_chat"))
            user_id = data.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
            if not instructions or not file_uri:
                return jsonify({"success": False, "error": "instructions_and_file_uri_required"}), 400
            part = Part.from_uri(file_uri=file_uri)
    except Exception as e:
        return jsonify({"success": False, "error": "bad_request", "details": str(e)}), 400

    if not aspect_ratio and platform:
        aspect_ratio = PLATFORM_ASPECT_MAP.get(platform)

    final_instruction = (
        f"Edit the provided image according to these instructions: {escape_for_inline(instructions)}. "
        "Do not add text overlays unless explicitly requested. Preserve important subject details and avoid hallucinated logos."
    )

    try:
        if use_chat:
            resp = _chat_image_edit_with_instruction(final_instruction, part, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
        else:
            resp = _generate_image_edit_with_instruction(final_instruction, part, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
    except Exception as e:
        print("[edit_image_endpoint] image edit failed:", e)
        return jsonify({"success": False, "error": "image_edit_failed", "details": str(e)}), 500

    saved = save_images_from_response(resp, prefix="edit")
    urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved]

    print(f"[edit-image] Received user_id: {user_id}, workspace_id: {workspace_id}")
    try:
        if user_id and workspace_id:
            for fn, url in zip(saved, urls):
                creative_id = uuid.uuid4().hex
                creative = Creative(
                    id=creative_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=url,
                    filename=fn,
                    type='generated'
                )
                db.session.add(creative)
            db.session.commit()
            print(f"[edit-image] Stored {len(saved)} generated images in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[edit-image] DB commit failed: {str(e)}")
        db.session.rollback()

    # Save conversation – TRIM instructions before saving
    try:
        if user_id and workspace_id:
            conv_id = uuid.uuid4().hex
            response_data = {
                "success": True,
                "files": saved,
                "urls": urls
            }
            conversation_prompt = trim_workspace_details_from_prompt(instructions or "")
            conversation = Conversation(
                id=conv_id,
                user_id=user_id,
                workspace_id=workspace_id,
                prompt=conversation_prompt,
                response=json.dumps(response_data)
            )
            db.session.add(conversation)
            db.session.commit()
            print(f"[edit-image] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[edit-image] Conversation DB commit failed: {str(e)}")
        db.session.rollback()

    # ------------------------
    # AI usage logging: image edit
    # ------------------------
    try:
        num_images = len(saved)
        cost_inr = calculate_image_cost_inr(MODEL_ID, num_images)

        usage_payload = {
            "input_tokens": 0,
            "output_tokens": num_images,
            "total_tokens": num_images,
        }

        uid_int, wid_int = _coerce_ids_for_usage(user_id, workspace_id)

        log_ai_usage(
            feature="edit_image",
            model=MODEL_ID,
            usage=usage_payload,
            cost_inr=cost_inr,
            user_id=uid_int,
            workspace_id=wid_int,
            extra_meta={
                "endpoint": "/api/v1/edit-image",
                "num_images": num_images,
                "platform": platform,
                "aspect_ratio": aspect_ratio,
                "use_chat": use_chat,
            },
        )
        current_app.logger.info(
            f"[AI_USAGE] /edit-image model={MODEL_ID} images={num_images} cost_inr={cost_inr}"
        )
    except Exception as e:
        current_app.logger.warning(f"[AI_USAGE] failed to log edit-image usage: {e}")

    return jsonify({
        "success": True,
        "files": saved,
        "urls": urls
    }), 200
"""

# -------------------------------------------------------------------
# Serve outputs (redirect to CDN)
# -------------------------------------------------------------------
@app.route("/outputs/<path:filename>", methods=["GET", "OPTIONS"])
def serve_output(filename):
    if request.method == "OPTIONS":
        resp = make_response()
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
        else:
            resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Accept"
        return resp

    cdn_url = f"{SPACE_CDN}/outputs/{filename}"
    return redirect(cdn_url)

#==================================================after  merge updatse========================================================

from typing import Any, Dict, List, Optional, Tuple
import json
import re
import time
import traceback


# Assume these exist in your environment (imported / configured elsewhere)
# from your_genai_setup import GENAI_CLIENT, TEXT_MODEL
# If you only have _generate_text_from_prompt available, you can call that instead.

JSON_EXTRACT_REGEX = re.compile(r"(\{[\s\S]*\}|\[[\s\S]*\])", re.MULTILINE)

def _safe_extract_text_from_resp1(resp: Any) -> str:
    """
    Try a variety of common response shapes returned by GenAI clients and extract a string:
    - resp.candidates[0].content / resp.candidates[0].output[0].content[0].text
    - resp.output[0].content[0].text
    - resp['candidates'][0]['content'] etc.
    Falls back to str(resp).
    """
    try:
        # object-like access
        if hasattr(resp, "candidates"):
            cands = getattr(resp, "candidates")
            if cands and len(cands) > 0:
                cand = cands[0]
                # many SDKs put text in different fields
                for attr in ("content", "output", "text"):
                    if hasattr(cand, attr):
                        val = getattr(cand, attr)
                        # if content is nested list/dict
                        if isinstance(val, (list, tuple)) and val:
                            # join text pieces if present
                            pieces = []
                            for item in val:
                                if isinstance(item, dict):
                                    # often: {"type": "output_text", "text": "..." }
                                    if "text" in item:
                                        pieces.append(item["text"])
                                elif isinstance(item, str):
                                    pieces.append(item)
                            if pieces:
                                return "\n".join(pieces)
                        elif isinstance(val, str):
                            return val
                # fallback: stringify candidate
                return str(cand)
        # dict-like access
        if isinstance(resp, dict):
            for key in ("candidates", "outputs", "choices", "result"):
                if key in resp and isinstance(resp[key], (list, tuple)) and len(resp[key]) > 0:
                    first = resp[key][0]
                    # try a few nested keys for text
                    for tk in ("content", "text", "message", "output_text"):
                        if isinstance(first, dict) and tk in first:
                            v = first[tk]
                            if isinstance(v, str):
                                return v
                            if isinstance(v, list):
                                # join pieces
                                return "\n".join([p.get("text", str(p)) if isinstance(p, dict) else str(p) for p in v])
                    # as fallback stringify
                    return json.dumps(first)
        # try attribute 'output' -> list -> content -> text
        if hasattr(resp, "output"):
            out = getattr(resp, "output")
            if isinstance(out, (list, tuple)) and out:
                first = out[0]
                if isinstance(first, dict) and "content" in first:
                    cont = first["content"]
                    if isinstance(cont, (list, tuple)) and cont:
                        # join any text parts
                        parts = []
                        for p in cont:
                            if isinstance(p, dict) and "text" in p:
                                parts.append(p["text"])
                            elif isinstance(p, str):
                                parts.append(p)
                        if parts:
                            return "\n".join(parts)
        # fallback
        return str(resp)
    except Exception:
        return str(resp)


def _parse_json_from_text(text: str) -> Optional[Any]:
    """
    Try to extract a JSON payload from text. This looks for the first {...} or [...] block,
    then attempts json.loads. Returns parsed JSON or None.
    """
    if not text:
        return None
    # try direct json
    text_strip = text.strip()
    try:
        return json.loads(text_strip)
    except Exception:
        pass
    # try to find first JSON-like substring
    m = JSON_EXTRACT_REGEX.search(text)
    if not m:
        return None
    candidate = m.group(1)
    # attempt to fix common trailing commas
    candidate_fixed = re.sub(r",\s*([}\]])", r"\1", candidate)
    try:
        return json.loads(candidate_fixed)
    except Exception:
        # fail gracefully
        return None


def generate_objective_suggestions_from_workspace(
    workspace: Dict[str, Any],
    model_id: str = None,
    *,
    response_modalities: List[str] = ["TEXT"],
    candidate_count: int = 1,
    max_retries: int = 2,
    timeout_between_retries: float = 0.8,
) -> Dict[str, Any]:
    """
    Build a contextual prompt from the workspace, call the GenAI client to obtain objective suggestions,
    and attempt to parse structured JSON output.

    Returns a dict with keys:
      - raw: the raw response object returned by the GenAI client
      - text: the best-effort extracted text
      - suggestions: parsed JSON suggestions if model returned JSON (or None)
      - source: "ai"
      - model: model_id used
      - ok: bool
      - error: optional error message

    Example 'suggestions' expected structure (the model is instructed to return JSON):
      { "suggestions": ["TRAFFIC","CONVERSIONS"], "reasons": ["short reason 1", "short reason 2"] }
    """

    # prefer provided model_id, fallback to a global TEXT_MODEL if available
    if model_id is None:
        try:
            from your_genai_setup import TEXT_MODEL  # type: ignore
            model_id = TEXT_MODEL
        except Exception:
            model_id = "text-bison"  # fallback; replace with your default model id

    # Build a compact but information-rich workspace summary to include in the prompt.
    # Only include key fields (avoid excessive tokens).
    def _short(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, (dict, list)):
            try:
                return json.dumps(v, ensure_ascii=False)[:800]
            except Exception:
                return str(v)[:800]
        return str(v)[:800]

    workspace_summary = {
        "business_name": workspace.get("business_name") or workspace.get("name") or "",
        "usp": _short(workspace.get("usp") or ""),
        "description": _short(workspace.get("description") or ""),
        "audience_description": _short(workspace.get("audience_description") or ""),
        "website": workspace.get("website") or "",
        "creatives_count": len(workspace.get("creatives_path") or workspace.get("creatives") or []),
        "saved_id": workspace.get("id") or workspace.get("workspace_id") or None,
    }

    # Prompt template: instruct the model to return strict JSON array + reasons.
    # Encourage short, deterministic output (and provide the allowed objective IDs).
    prompt = f"""
You are an assistant that maps marketing workspace descriptions to a shortlist of advertising objectives.
Return ONLY a JSON object with the following fields: "suggestions" (list of objective IDs, most recommended first),
and "reasons" (list of short strings explaining each suggestion). Do NOT return any other text outside the JSON object.

Valid objective IDs: ["BRAND_AWARENESS","REACH","ENGAGEMENT","LEAD_GENERATION","TRAFFIC","CONVERSIONS"]

Workspace summary (JSON):
{json.dumps(workspace_summary, ensure_ascii=False, indent=2)}

Requirements:
- Pick up to 3 objectives (return an empty list if unsure).
- Keep reasons short (max 18 words each).
- Be concise and deterministic.
- Output valid JSON only.

Return the JSON now.
""".strip()

    # Use the same client call pattern as your original helper
    attempt = 0
    last_err = None
    while attempt <= max_retries:
        try:
            if not globals().get("GENAI_CLIENT"):
                raise RuntimeError("GenAI client (GENAI_CLIENT) not initialized in this process")

            # Build config object (compatible with your earlier usage)
            try:
                # If GenerateContentConfig is defined/imported in your runtime, use it
                from google.generativeai.types import GenerateContentConfig  # type: ignore
                cfg = GenerateContentConfig(
                    response_modalities=response_modalities,
                    candidate_count=max(1, int(candidate_count or 1)),
                )
                resp = GENAI_CLIENT.models.generate_content(
                    model=model_id,
                    contents=[prompt],
                    config=cfg,
                )
            except Exception:
                # Fallback: call client in the generic manner (keeps compatibility)
                resp = GENAI_CLIENT.models.generate_content(
                    model=model_id,
                    contents=[prompt],
                    config={
                        "response_modalities": response_modalities,
                        "candidate_count": max(1, int(candidate_count or 1)),
                    },
                )

            # extract text robustly
            text = _safe_extract_text_from_resp1(resp)

            # attempt parsing JSON
            parsed = _parse_json_from_text(text)
            result = {
                "raw": resp,
                "text": text,
                "suggestions": None,
                "model": model_id,
                "ok": True,
                "source": "ai",
            }
            if parsed and isinstance(parsed, dict) and "suggestions" in parsed:
                result["suggestions"] = parsed
                return result
            # If parsing failed: try to find objective IDs in plain text as a fallback
            found_ids = re.findall(r"\b(BRAND_AWARENESS|REACH|ENGAGEMENT|LEAD_GENERATION|TRAFFIC|CONVERSIONS)\b", text)
            if found_ids:
                # try to dedupe while preserving order
                seen = set()
                ordered = [x for x in found_ids if not (x in seen or seen.add(x))]
                result["suggestions"] = {"suggestions": ordered[:3], "reasons": []}
                return result

            # nothing parsed — return raw text in result
            return result

        except Exception as e:
            last_err = e
            attempt += 1
            if attempt > max_retries:
                break
            time.sleep(timeout_between_retries)

    # If we get here, every attempt failed
    return {"raw": None, "text": "", "suggestions": None, "ok": False, "error": str(last_err or "unknown error")}



@app.route("/api/workspace/<int:workspace_id>/ai-suggest-objectives", methods=["GET", "POST"])
def ai_suggest_objectives(workspace_id: int):
    """
    AI route that generates campaign objective suggestions from a workspace.
    - GET: Uses workspace_id to load workspace from DB.
    - POST: Accepts workspace JSON directly (overrides DB data if given).
    """

    try:
        # If you have a Workspace model
        from models import Workspace  # adjust import
        workspace_data: Dict[str, Any] = {}

        # Try to get workspace from DB
        ws = Workspace.query.get(workspace_id)
        if ws:
            workspace_data = {
                "id": ws.id,
                "business_name": ws.business_name,
                "usp": ws.usp,
                "description": ws.description,
                "audience_description": ws.audience_description,
                "website": ws.website,
                "creatives_path": ws.creatives_path or [],
            }

        # If JSON payload exists, merge it (POST override)
        if request.is_json:
            posted_data = request.get_json(silent=True) or {}
            workspace_data.update(posted_data)

        # Validate
        if not workspace_data:
            return jsonify({"success": False, "error": "Workspace not found"}), 404

        # Call the AI generator
        ai_result = generate_objective_suggestions_from_workspace(
            workspace=workspace_data,
            model_id=TEXT_MODEL,
            response_modalities=["TEXT"],
            candidate_count=1,
        )

        # Return standardized response
        if not ai_result.get("ok"):
            return jsonify({
                "success": False,
                "error": ai_result.get("error", "AI generation failed"),
                "workspace_id": workspace_id
            }), 500

        return jsonify({
            "success": True,
            "workspace_id": workspace_id,
            "suggestions": ai_result.get("suggestions"),
            "raw_text": ai_result.get("text"),
            "model": ai_result.get("model"),
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(e),
            "trace": traceback.format_exc(),
        }), 500
 


"""
ai_audience.py

Single-file Flask route + helper that produces an AI-powered audience suggestion
from a provided workspace JSON. It tries to call your GenAI client (via the
helper `_generate_text_from_prompt` if available, or directly via `GENAI_CLIENT`)
and falls back to a tiny heuristic if no GenAI client is present.

Route:
  POST /api/workspace/<workspace_id>/ai-suggest-audience
  Body: either {"workspace": { ... }} or raw workspace object (JSON)

Response (200):
{
  "ok": true,
  "source": "ai" | "heuristic",
  "model": "<model-id-or-null>",
  "suggestion": {
    "location": {"country": "...", "region": "..."},
    "age": [min, max],
    "gender": "all"|"male"|"female",
    "interests": ["..."],
    "estimated_size_label": "12K - 45K"
  },
  "confidence": 0.82,
  "reasons": ["short reason 1", "short reason 2"],
  "raw_text": "<raw model text if any>"
}
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
from typing import Any, Dict, Optional, Tuple, List



# If you have these in your environment, the helper will use them:
# - _generate_text_from_prompt(prompt_text, model_id=..., response_modalities=[...], candidate_count=1)
# - GENAI_CLIENT and TEXT_MODEL


JSON_BLOCK_RE = re.compile(r"(\{[\s\S]*\}|\[[\s\S]*\])", re.MULTILINE)
import re
import json
from typing import Optional, Any, Dict

def _extract_json_from_model_text(text: Optional[str]) -> Optional[Any]:
    """
    Try multiple strategies to extract a JSON object from model output:
      1) Look for ```json { ... } ``` fenced block
      2) Look for any fenced ``` { ... } ```
      3) If the string contains a `Content(...)` wrapper, attempt to extract inner `.parts[*].text` blocks
      4) Find first balanced {...} using a stack-based scan
    Returns parsed JSON (dict/list) or None.
    """
    if not text:
        return None

    # If the text looks like a python-style Content(...) debug, try to pull the inner triple-quoted parts
    # Example: content=Content(parts=[Part(text="""```json\n{ ... }\n```""")])
    # Extract any triple-quoted sections first
    triple_quoted = re.findall(r'("""|\'\'\')(.+?)(\1)', text, flags=re.DOTALL)
    for _, inner, _ in triple_quoted:
        # try fenced json inside the triple quoted
        m = re.search(r"```json\s*(\{.*\})\s*```", inner, flags=re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        m = re.search(r"```\s*(\{.*\})\s*```", inner, flags=re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        # try direct balanced object in the triple quoted inner string
        parsed = _find_first_balanced_json(inner)
        if parsed is not None:
            return parsed

    # 1) fenced ```json ... ```
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass

    # 2) fenced ``` ... ```
    m = re.search(r"```\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass

    # 3) attempt to locate and parse a JSON-looking substring extracted from Content(...) textual representations
    # e.g. content=Content(parts=[Part(text="...")])
    # Try to extract `text="...{...}..."` patterns
    m = re.search(r'text\s*=\s*(?P<q>["\']{1,3})(?P<body>.*?)(?P=q)', text, flags=re.DOTALL)
    if m:
        body = m.group("body")
        parsed = _find_first_balanced_json(body)
        if parsed is not None:
            return parsed

    # 4) last resort: balanced { ... } scanning on the whole text
    parsed = _find_first_balanced_json(text)
    if parsed is not None:
        return parsed

    # nothing found
    return None

import json
from typing import Any, Optional

def _extract_text_from_model_resp(resp: Any) -> Optional[str]:
    """
    Turn a model response into a plain text string.
    Handles:
      - plain string responses
      - dict responses with common keys
      - objects (repr fallback)
      - Vertex/GENAI-like responses where content may be nested
    Always returns a string (or None if resp is None).
    """
    if resp is None:
        return None

    # If already a string
    if isinstance(resp, str):
        return resp

    # If a bytes-like object
    try:
        if isinstance(resp, (bytes, bytearray)):
            return resp.decode("utf-8", errors="replace")
    except Exception:
        pass

    # If it's a dict-like mapping, prefer explicit text fields
    if isinstance(resp, dict):
        # try common keys in order
        for key in ("text", "raw_text", "content", "output", "outputs", "result", "candidates"):
            if key in resp:
                val = resp[key]
                # candidates might be a list of dicts or strings
                if isinstance(val, list) and val:
                    first = val[0]
                    if isinstance(first, dict):
                        # try keys inside candidate dict
                        for tkey in ("text", "content", "output"):
                            if tkey in first:
                                return str(first[tkey])
                        return json.dumps(first)
                    return str(first)
                if isinstance(val, (str, int, float)):
                    return str(val)
                try:
                    return json.dumps(val)
                except Exception:
                    return str(val)

    # If it has attributes (like objects from SDKs), try common attribute names
    try:
        # Vertex-like object: may have .content, .outputs, .candidates, .text
        for attr in ("content", "outputs", "candidates", "text", "result"):
            if hasattr(resp, attr):
                val = getattr(resp, attr)
                # val could be list/object/string; handle similarly to dict branch
                if isinstance(val, str):
                    return val
                if isinstance(val, (bytes, bytearray)):
                    return val.decode("utf-8", errors="replace")
                if isinstance(val, (list, tuple)) and val:
                    first = val[0]
                    if isinstance(first, str):
                        return first
                    if isinstance(first, dict) and "text" in first:
                        return str(first["text"])
                    return str(first)
                try:
                    return json.dumps(val)
                except Exception:
                    return str(val)
    except Exception:
        pass

    # Fallback: string representation of the whole object
    try:
        return str(resp)
    except Exception:
        return None


def _find_first_balanced_json(s: str) -> Optional[Any]:
    """
    Find the first balanced JSON object in string `s` and attempt to json.loads it.
    Returns parsed object or None.
    """
    start = s.find("{")
    if start == -1:
        return None

    stack = []
    in_string = False
    escape = False
    for i in range(start, len(s)):
        ch = s[i]
        if ch == '"' and not escape:
            in_string = not in_string
        if ch == "\\" and not escape:
            escape = True
            continue
        escape = False
        if in_string:
            continue
        if ch == "{":
            stack.append(i)
        elif ch == "}":
            if stack:
                stack.pop()
                if not stack:
                    candidate = s[start:i+1]
                    # Try to clean common leading/trailing non-json characters
                    try:
                        return json.loads(candidate)
                    except Exception:
                        # Try to trim leading/trailing whitespace/newlines and retry
                        try:
                            return json.loads(candidate.strip())
                        except Exception:
                            return None
    return None


def generate_audience_suggestion_from_workspace(
    workspace: Dict[str, Any],
    model_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Call an LLM (default: Gemini model) to produce a JSON-only audience suggestion.
    Sends the FULL workspace JSON to the model (not a compact summary).
    Returns usage (tokens) as well for cost tracking.
    """
    if model_id is None:
        model_id = "gemini-flash-latest"

    # Defensive: ensure workspace is JSON-serializable
    try:
        workspace_json = json.dumps(workspace, ensure_ascii=False, indent=2)
    except Exception:
        def _safe(obj):
            try:
                return json.loads(json.dumps(obj))
            except Exception:
                return str(obj)
        safe_workspace = {k: _safe(v) for k, v in (workspace or {}).items()}
        workspace_json = json.dumps(safe_workspace, ensure_ascii=False, indent=2)

    prompt = f"""
You are an assistant that proposes a target audience for an advertising campaign given a full workspace object (JSON).
You will be provided the complete workspace JSON below. Understand the meaning of the fields (business_name, description, usp, address, creatives_path, website, social_links, competitors, audience_description, etc.) and use them to produce a single JSON object.

Return ONLY a JSON object with the following shape:
{{
  "suggestion": {{
     "location": {{ "country": "...", "region": "..." }} use workspace address dont make it null or just make it global,
     "age": [min_age, max_age],
     "gender": "all"|"male"|"female",
     "interests": ["...","..."],
     "estimated_size_label": "12K - 45K"  // optional
  }},
  "confidence": 0.0,
  "reasons": ["short reason 1", "short reason 2"]
}}

Constraints:
- Do NOT include any extra text, explanation, or markdown — only return the JSON object.
- Pick up to 6 interest tokens, prioritized by relevance to the workspace.
- Keep each reason short (max 12 words).
- If workspace contains address or location-like fields, use them to set suggestion.location.
- If any field is missing, set the corresponding suggestion subfield to null or a reasonable default.

Here is the full workspace JSON (use it directly):
{workspace_json}

Return the JSON now and nothing else.
""".strip()

    raw_text: Optional[str] = None
    model_used: Optional[str] = None

    def _extract_usage(resp) -> Dict[str, int]:
        """
        Try to read token usage from either Vertex-style or google.genai-style responses.
        """
        usage_meta = getattr(resp, "usage_metadata", None) or {}
        # google.genai
        input_tokens = getattr(usage_meta, "prompt_token_count", None)
        output_tokens = getattr(usage_meta, "candidates_token_count", None)
        total_tokens = getattr(usage_meta, "total_token_count", None)

        # Vertex / fallback naming
        if input_tokens is None:
            input_tokens = getattr(usage_meta, "input_token_count", 0)
        if output_tokens is None:
            output_tokens = getattr(usage_meta, "output_token_count", 0)
        if total_tokens is None:
            total_tokens = (input_tokens or 0) + (output_tokens or 0)

        return {
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "total_tokens": int(total_tokens or 0),
        }

    try:
        # Prefer local helper if available (Vertex-style)
        if _generate_text_from_prompt:
            model_used = model_id
            resp = _generate_text_from_prompt(
                prompt,
                model_id=model_id,
                response_modalities=["TEXT"],
                candidate_count=1,
            )
            raw_text = _extract_text_from_model_resp(resp)
            parsed = _extract_json_from_model_text(raw_text)
            usage = _extract_usage(resp)

            if parsed and isinstance(parsed, dict) and parsed.get("suggestion"):
                return {
                    "ok": True,
                    "source": "ai",
                    "model": model_used,
                    "suggestion": parsed.get("suggestion"),
                    "confidence": float(parsed.get("confidence", 0.0) or 0.0),
                    "reasons": parsed.get("reasons") or [],
                    "raw_text": raw_text,
                    "usage": usage,
                }

            return {
                "ok": False,
                "error": "Model returned unparsable or missing 'suggestion' field.",
                "model": model_used,
                "raw_text": raw_text,
                "usage": usage,
            }

        # Try google.genai client
        if GENAI_CLIENT:
            model_used = model_id
            try:
                cfg = {"response_modalities": ["TEXT"], "candidate_count": 1}
                resp = GENAI_CLIENT.models.generate_content(
                    model=model_id,
                    contents=[prompt],
                    config=cfg,
                )
            except Exception:
                resp = GENAI_CLIENT.models.generate_content(
                    model=model_id,
                    contents=[prompt],
                )

            raw_text = _extract_text_from_model_resp(resp)
            parsed = _extract_json_from_model_text(raw_text)
            usage = _extract_usage(resp)

            if parsed and isinstance(parsed, dict) and parsed.get("suggestion"):
                return {
                    "ok": True,
                    "source": "ai",
                    "model": model_used,
                    "suggestion": parsed.get("suggestion"),
                    "confidence": float(parsed.get("confidence", 0.0) or 0.0),
                    "reasons": parsed.get("reasons") or [],
                    "raw_text": raw_text,
                    "usage": usage,
                }

            return {
                "ok": False,
                "error": "Model returned unparsable or missing 'suggestion' field.",
                "model": model_used,
                "raw_text": raw_text,
                "usage": usage,
            }

        # No model clients available
        return {
            "ok": False,
            "error": "No model client available (_generate_text_from_prompt and GENAI_CLIENT are both missing).",
            "model": None,
            "raw_text": raw_text,
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        }

    except Exception as e:
        return {
            "ok": False,
            "error": f"Model call failed with exception: {str(e)}",
            "model": model_used,
            "raw_text": raw_text,
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        }

from decimal import Decimal

MODEL_PRICING_INR = {
    "gemini-2.5-flash": {
        "input_per_1k":  Decimal("0.02646075"),
        "output_per_1k": Decimal("0.22050625"),
    },
    "gemini-2.5-pro": {
        "input_per_1k":  Decimal("0.110253125"),
        "output_per_1k": Decimal("0.882025"),
    },
    "gemini-3.0-pro": {
        "input_per_1k":  Decimal("0.176405"),
        "output_per_1k": Decimal("1.05843"),
    },
    # Alias mapping: gemini-flash-latest ≈ 2.5-flash pricing
    "gemini-flash-latest": {
        "input_per_1k":  Decimal("0.02646075"),
        "output_per_1k": Decimal("0.22050625"),
    },
}

def calculate_cost_inr(model_name, input_tokens, output_tokens):
    """
    Accepts any raw model_name (full path or short code),
    auto-normalizes it, and calculates INR cost if pricing is configured.
    """
    if not model_name:
        return Decimal("0")

    short_name = model_name.split("/")[-1].lower()

    # Try exact match
    if short_name in MODEL_PRICING_INR:
        key = short_name
    # Try removing a '-001' style suffix, but only if long enough
    elif len(short_name) > 4 and short_name[:-4] in MODEL_PRICING_INR:
        key = short_name[:-4]
    else:
        # Fallback: substring match
        key = next((k for k in MODEL_PRICING_INR.keys() if k in short_name), None)

    if not key:
        print(f"[WARNING] Pricing not found for model: {model_name}")
        return Decimal("0")

    p = MODEL_PRICING_INR[key]
    cost_in = (Decimal(input_tokens) / 1000) * p["input_per_1k"]
    cost_out = (Decimal(output_tokens) / 1000) * p["output_per_1k"]
    total_cost = cost_in + cost_out

    return total_cost.quantize(Decimal("0.0001"))
from flask_login import current_user
def get_current_user_id_safe():
    """
    Try Flask-Login if available; otherwise return None.
    """
    try:
        from flask_login import current_user
        if current_user and not current_user.is_anonymous:
            return current_user.id
    except Exception:
        return None
    return None


@app.route("/api/workspace/<workspace_id>/ai-suggest-audience", methods=["POST"])
def ai_suggest_audience_route(workspace_id):
    try:
        payload = request.get_json(force=True, silent=True) or {}

        # Flow fields
        workspace = payload.get("workspace") or {}
        industry = payload.get("industry")
        creative_desc = payload.get("creative_desc")
        workspace_preview = payload.get("workspace_preview")

        workspace["id"] = workspace.get("id") or int(workspace_id)

        # (Optional) Use extra flow context inside workspace *only for prompt*
        workspace["_flow_context"] = {
            "industry": industry,
            "creative_desc": creative_desc,
            "workspace_preview": workspace_preview,
        }

        result = generate_audience_suggestion_from_workspace(
            workspace,
            model_id=TEXT_MODEL if 'TEXT_MODEL' in globals() else None
        )

        usage = result.get("usage") or {}
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)

        if result.get("model"):
            cost_inr_dec = calculate_cost_inr(result["model"], input_tokens, output_tokens)
            cost_inr = float(cost_inr_dec)
            result["cost_inr"] = cost_inr
        else:
            cost_inr = 0.0
            result["cost_inr"] = None

        print(
            f"[Token Usage] Model: {result.get('model')} | "
            f"Input: {input_tokens}, Output: {output_tokens}, Cost ₹{cost_inr}"
        )

        # Resolve user_id: try session, fallback to workspace.user_id, else skip logging
        user_id = get_current_user_id_safe()
        if user_id is None:
            user_id = workspace.get("user_id")

        if user_id is not None:
            try:
                log_ai_usage(
                    user_id=int(user_id),
                    workspace_id=int(workspace_id),
                    feature="ai_suggest_audience",
                    route_path="/api/workspace/<workspace_id>/ai-suggest-audience",
                    model=result.get("model") or "",
                    usage=usage,
                    cost_inr=cost_inr,
                    request_id=request.headers.get("X-Request-ID"),
                    ip_address=request.remote_addr,
                )
            except Exception as log_err:
                app.logger.warning(f"Failed to log ai_usage: {log_err}")

        return jsonify(result), 200

    except Exception as e:
        app.logger.exception("ai_suggest_audience error")
        return jsonify({"ok": False, "error": str(e)}), 500

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import requests
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.campaign import Campaign
from facebook_business.adobjects.adset import AdSet
from facebook_business.adobjects.ad import Ad

# ---------------- Config ----------------
FB_API_VERSION = os.getenv("FB_API_VERSION", "v17.0")
#FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "EAAZAVAy1umqcBPlzb3eKWh9xtAdafi3nDF9DAu0xrVjSUhTlb2zZB2xV5ZAuLkeiISzSye85SZC3LTwLrsVZAAerce0YOqQllvirE04ihZBIKXfJY3V0h0mZAtMUxGTrQ8CB2qW5Ahkdsv1k8D7nIHcAU73wTApQeq3ZCWvDZAe1umrqjBREvlaqioDn6aYBniJeDSr5KFKgdCdNUiww7vcs8OowYOG4XHRvHaHAS")  # set this
#FB_AD_ACCOUNT_ID = os.getenv("FB_AD_ACCOUNT_ID", "act_1101316788803604")
FB_AD_ACCOUNT_ID = os.getenv("FB_AD_ACCOUNT_ID", "act_4351995088408853")
FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "EAAZAVAy1umqcBQFSEw3Ih1M9F7KcsHfTFqkiaGiGuEZBzGl7MRlZAjKPaLVt2OMLfaoeiaeTtTOIiGDNfueCvUYdH4ubCchgQKZAnZA0D2BZAPSZAHRxk9OkA8sUzr9y2m0XF8k7vkeEMZCTO6RlE749282cnZB7ViP3NSekzxZBd0WmUJC335za8scB9khn2CGAZDZD")  # set this
FB_PAGE_ID = os.getenv("FB_PAGE_ID", "826620477192551")
DEFAULT_IMAGE_HASH = os.getenv("DEFAULT_IMAGE_HASH", "706094911862292")
MIN_DAILY_BUDGET = int(os.getenv("MIN_DAILY_BUDGET", "10000"))

if not FB_ACCESS_TOKEN:
    logging.warning("FB_ACCESS_TOKEN not set. Set FB_ACCESS_TOKEN env var before using live API calls.")

GRAPH_BASE = f"https://graph.facebook.com/{FB_API_VERSION}"

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',level=logging.DEBUG)
logger = logging.getLogger(__name__)


FacebookAdsApi.init(access_token=FB_ACCESS_TOKEN, app_id=FB_APP_ID, app_secret=FB_APP_SECRET)

# Keep a convenience cache of last created ids
LAST: Dict[str, Optional[str]] = {
    "campaign_id": None,
    "adset_id": None,
    "creative_id": None,
    "ad_id": None,
    "image_hash": None,
}

# ---------------- HTTP helpers ----------------
def fb_get(path: str, params: dict = None) -> Dict[str, Any]:
    url = f"{GRAPH_BASE}/{path}"
    p = params.copy() if params else {}
    p["access_token"] = FB_ACCESS_TOKEN
    try:
        r = requests.get(url, params=p, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.exception("FB GET %s failed: %s", path, e)
        result = {"error": str(e)}
        try:
            result["raw"] = e.response.text
        except Exception:
            pass
        return result

def fb_post(path: str, data: dict = None, files: dict = None) -> Dict[str, Any]:
    url = f"{GRAPH_BASE}/{path}"
    params = data.copy() if data else {}
    params["access_token"] = FB_ACCESS_TOKEN
    try:
        if files:
            r = requests.post(url, data=params, files=files, timeout=60)
        else:
            r = requests.post(url, data=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.exception("FB POST %s failed: %s -> %s", path, e, getattr(e.response, "text", ""))
        try:
            return {"error": e.response.json()}
        except Exception:
            return {"error": str(e)}
    except Exception as e:
        logger.exception("FB POST %s exception: %s", path, e)
        return {"error": str(e)}

def fb_delete(path: str) -> Dict[str, Any]:
    url = f"{GRAPH_BASE}/{path}"
    params = {"access_token": FB_ACCESS_TOKEN}
    try:
        r = requests.delete(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.exception("FB DELETE %s failed: %s", path, e)
        return {"error": str(e)}

# ---------------- FB helpers ----------------
def _acct_id(ad_account_id: str) -> str:
    return ad_account_id.split("act_")[-1]

def upload_image_by_url(ad_account_id: str, image_url: str) -> Optional[str]:
    acct = _acct_id(ad_account_id)
    resp = fb_post(f"act_{acct}/adimages", data={"url": image_url})
    if isinstance(resp, dict) and "images" in resp:
        for v in resp["images"].values():
            if "hash" in v:
                return v["hash"]
    logger.warning("upload_image_by_url failed: %s", resp)
    return None

def upload_image_file(ad_account_id: str, file_field) -> Optional[str]:
    acct = _acct_id(ad_account_id)
    files = {"source": (file_field.filename, file_field.stream, file_field.mimetype)}
    resp = fb_post(f"act_{acct}/adimages", data={}, files=files)
    if isinstance(resp, dict) and "images" in resp:
        for v in resp["images"].values():
            if "hash" in v:
                return v["hash"]
    logger.warning("upload_image_file failed: %s", resp)
    return None

def create_campaign(ad_account_id: str, name: str, objective: str = "OUTCOME_TRAFFIC", status: str = "PAUSED") -> Optional[str]:
    acct = _acct_id(ad_account_id)
    resp = fb_post(f"act_{acct}/campaigns", data={"name": name, "objective": objective, "status": status, "special_ad_categories": json.dumps([])})
    if "id" in resp:
        return resp["id"]
    logger.warning("create_campaign failed: %s", resp)
    return None
def create_adset(ad_account_id: str, campaign_id: str, name: str, daily_budget: int,
                 start_time: str, end_time: str, page_id: str, country: str = "US",
                 status: str = "PAUSED") -> Optional[str]:
    acct = _acct_id(ad_account_id)
    # ensure daily_budget is at least MIN_DAILY_BUDGET
    if daily_budget < MIN_DAILY_BUDGET:
        logger.info("bumping daily_budget %s -> %s", daily_budget, MIN_DAILY_BUDGET)
        daily_budget = MIN_DAILY_BUDGET

    # normalize country to ISO2
    country_code = country_to_iso(country)

    params = {
        "name": name,
        "campaign_id": campaign_id,
        "daily_budget": int(daily_budget),
        "billing_event": "IMPRESSIONS",
        "optimization_goal": "LINK_CLICKS",
        "bid_amount": max(1, int(daily_budget // 1000)),
        "promoted_object": json.dumps({"page_id": page_id}),
        "targeting": json.dumps({"geo_locations": {"countries": [country_code]}}),
        "start_time": start_time,
        "end_time": end_time,
        "status": status,
    }
    resp = fb_post(f"act_{acct}/adsets", data=params)
    if isinstance(resp, dict) and "id" in resp:
        return resp["id"]
    logger.warning("create_adset failed: %s", resp)
    return None

def create_adcreative(ad_account_id: str, page_id: str, image_hash: str, link: str, message: str, name: str = "Auto Creative") -> Optional[str]:
    acct = _acct_id(ad_account_id)
    object_story_spec = {"page_id": page_id, "link_data": {"image_hash": image_hash, "link": link, "message": message}}
    resp = fb_post(f"act_{acct}/adcreatives", data={"name": name, "object_story_spec": json.dumps(object_story_spec)})
    if "id" in resp:
        return resp["id"]
    logger.warning("create_adcreative failed: %s", resp)
    return None

def create_ad(ad_account_id: str, adset_id: str, creative_id: str, name: str = "Auto Ad", status: str = "PAUSED") -> Optional[str]:
    acct = _acct_id(ad_account_id)
    resp = fb_post(f"act_{acct}/ads", data={"name": name, "adset_id": adset_id, "creative": json.dumps({"creative_id": creative_id}), "status": status})
    if "id" in resp:
        return resp["id"]
    logger.warning("create_ad failed: %s", resp)
    return None

def fetch_insights_for(object_id: str, fields: Optional[list] = None, since: Optional[str] = None, until: Optional[str] = None) -> Dict[str, Any]:
    if fields is None:
        fields = ["impressions", "clicks", "spend", "actions", "ctr", "cpc"]
    params = {"access_token": FB_ACCESS_TOKEN, "fields": ",".join(fields)}
    if since and until:
        params["time_range"] = json.dumps({"since": since, "until": until})
    url = f"{GRAPH_BASE}/{object_id}/insights"
    try:
        r = requests.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.exception("fetch_insights_for %s failed: %s", object_id, e)
        return {"error": str(e)}

# ---------------- API endpoints (matching your React) ----------------

# GET /api/campaigns
@app.route("/api/campaigns", methods=["GET"])
def api_campaigns():
    acct = _acct_id(FB_AD_ACCOUNT_ID)
    resp = fb_get(f"act_{acct}/campaigns", params={"fields": "id,name,status,objective,created_time"})
    return jsonify(resp)

# GET /api/campaigns/<campaign_id>/adsets
@app.route("/api/campaigns/<campaign_id>/adsets", methods=["GET"])
def api_campaign_adsets(campaign_id):
    acct = _acct_id(FB_AD_ACCOUNT_ID)
    params = {"fields": "id,name,status,campaign_id,daily_budget,start_time,end_time"}
    # filter by campaign id
    params["filtering"] = json.dumps([{"field":"campaign.id","operator":"EQUAL","value":campaign_id}])
    resp = fb_get(f"act_{acct}/adsets", params=params)
    return jsonify(resp)

# GET /api/adsets/<adset_id>/ads
@app.route("/api/adsets/<adset_id>/ads", methods=["GET"])
def api_adset_ads(adset_id):
    acct = _acct_id(FB_AD_ACCOUNT_ID)
    params = {"fields": "id,name,status,adset_id,creative"}
    params["filtering"] = json.dumps([{"field":"adset.id","operator":"EQUAL","value":adset_id}])
    resp = fb_get(f"act_{acct}/ads", params=params)
    # Optionally extract creative preview URL for UI (best-effort)
    return jsonify(resp)

# GET /api/creatives
# GET /api/creatives  (improved: returns list with preview_url)
@app.route("/api/creatives", methods=["GET"])
def api_creatives():
    acct = _acct_id(FB_AD_ACCOUNT_ID)
    # request both object_story_spec and thumbnail_url; thumbnail_url often contains small preview
    fields = "id,name,object_story_spec,thumbnail_url,body,asset_feed_spec"
    resp = fb_get(f"act_{acct}/adcreatives", params={"fields": fields})
    # normalize entries to include preview_url where possible
    try:
        data_list = resp.get("data", []) if isinstance(resp, dict) else []
        normalized = []
        for c in data_list:
            preview = None
            # 1) thumbnail_url (Graph may provide)
            if c.get("thumbnail_url"):
                preview = c["thumbnail_url"]
            # 2) object_story_spec.link_data.image_url or picture
            elif c.get("object_story_spec"):
                ods = c["object_story_spec"]
                link_data = ods.get("link_data") or {}
                media_url = link_data.get("image_url") or link_data.get("picture") or None
                if media_url:
                    preview = media_url
            # 3) asset_feed_spec items (carousel feed)
            elif c.get("asset_feed_spec"):
                afs = c["asset_feed_spec"]
                if isinstance(afs, dict) and afs.get("bodies"):
                    # not guaranteed; skip heavy parsing
                    preview = None
            normalized.append({
                "id": c.get("id"),
                "name": c.get("name"),
                "preview_url": preview,
                "raw": c,
            })
        return jsonify({"ok": True, "data": normalized})
    except Exception as e:
        logger.exception("api_creatives normalization failed: %s", e)
        return jsonify({"ok": False, "error": str(e), "data": resp}), 500

# GET /api/creatives/<creative_id> (full details)
@app.route("/api/creatives/<creative_id>", methods=["GET"])
def api_creative_get(creative_id):
    fields = "id,name,object_story_spec,thumbnail_url,body,asset_feed_spec"
    resp = fb_get(f"{creative_id}", params={"fields": fields})
    if isinstance(resp, dict) and resp.get("error"):
        return jsonify({"ok": False, "error": resp["error"]}), 400
    # attempt to extract preview_url same as above
    preview = None
    if resp.get("thumbnail_url"):
        preview = resp["thumbnail_url"]
    elif resp.get("object_story_spec"):
        od = resp["object_story_spec"]
        ld = od.get("link_data") or {}
        preview = ld.get("image_url") or ld.get("picture") or None
    return jsonify({"ok": True, "data": resp, "preview_url": preview})

# DELETE /api/creatives/<creative_id>
@app.route("/api/creatives/<creative_id>", methods=["DELETE"])
def api_creative_delete(creative_id):
    # Note: Graph API returns {"success": true} on success
    resp = fb_delete(creative_id)
    return jsonify(resp)


# POST /api/publish  (accepts JSON or multipart/form-data)
@app.route("/api/publish", methods=["POST"])
def api_publish():
    try:
        # Support both JSON and multipart form
        if request.content_type and request.content_type.startswith("application/json"):
            body = request.get_json(silent=True) or {}
            image_file = None
            image_url = body.get("image_url", "").strip()
        else:
            body = request.form.to_dict() or {}
            image_file = request.files.get("image_file")
            image_url = (body.get("image_url") or "").strip()

        campaign_name = body.get("campaign_name") or f"Sandbox {datetime.utcnow().isoformat()}"
        adset_name = body.get("adset_name") or f"AdSet {datetime.utcnow().isoformat()}"
        ad_name = body.get("ad_name") or f"Ad {datetime.utcnow().isoformat()}"
        link = body.get("link") or "https://www.sociovia.com"
        message = body.get("message") or "Check this out!"
        start_in_days = int(body.get("start_in_days") or 0)
        duration_days = max(1, int(body.get("duration_days") or 2))
        daily_budget = int(body.get("daily_budget") or 100000)

        start_dt = datetime.utcnow() + timedelta(days=start_in_days)
        end_dt = start_dt + timedelta(days=duration_days)
        start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%S-0000")
        end_time = end_dt.strftime("%Y-%m-%dT%H:%M:%S-0000")

        # Create Campaign
        campaign_id = create_campaign(FB_AD_ACCOUNT_ID, campaign_name)
        if not campaign_id:
            return jsonify({"error": "campaign_create_failed"}), 500
        LAST["campaign_id"] = campaign_id

        # Create AdSet
        adset_id = create_adset(FB_AD_ACCOUNT_ID, campaign_id, adset_name, daily_budget, start_time, end_time, FB_PAGE_ID)
        if not adset_id:
            return jsonify({"error": "adset_create_failed"}), 500
        LAST["adset_id"] = adset_id

        # Upload image
        image_hash = None
        if image_file and getattr(image_file, "filename", ""):
            image_hash = upload_image_file(FB_AD_ACCOUNT_ID, image_file)
        elif image_url:
            image_hash = upload_image_by_url(FB_AD_ACCOUNT_ID, image_url)

        if not image_hash:
            if DEFAULT_IMAGE_HASH:
                logger.warning("Using DEFAULT_IMAGE_HASH fallback")
                image_hash = DEFAULT_IMAGE_HASH
            else:
                return jsonify({"error": "image_upload_failed"}), 500
        LAST["image_hash"] = image_hash

        # Create Creative
        creative_id = create_adcreative(FB_AD_ACCOUNT_ID, FB_PAGE_ID, image_hash, link, message, name="Auto Creative")
        if not creative_id:
            return jsonify({"error": "creative_create_failed"}), 500
        LAST["creative_id"] = creative_id

        # Create Ad
        ad_id = create_ad(FB_AD_ACCOUNT_ID, adset_id, creative_id, name=ad_name)
        if not ad_id:
            return jsonify({"error": "ad_create_failed"}), 500
        LAST["ad_id"] = ad_id

        return jsonify({
            "campaign_id": campaign_id,
            "adset_id": adset_id,
            "image_hash": image_hash,
            "creative_id": creative_id,
            "ad_id": ad_id,
        })
    except Exception as e:
        logger.exception("publish failed: %s", e)
        return jsonify({"error": str(e)}), 500

# Pause ad
@app.route("/api/ads/<ad_id>/pause", methods=["POST"])
def api_pause_ad(ad_id):
    resp = fb_post(ad_id, data={"status": "PAUSED"})
    return jsonify(resp)

# Resume ad
@app.route("/api/ads/<ad_id>/resume", methods=["POST"])
def api_resume_ad(ad_id):
    resp = fb_post(ad_id, data={"status": "ACTIVE"})
    return jsonify(resp)

# Delete ad
@app.route("/api/ads/<ad_id>", methods=["DELETE"])
def api_delete_ad(ad_id):
    resp = fb_delete(ad_id)
    return jsonify(resp)

# Generic object actions (pause / resume) - optional
@app.route("/api/object/action", methods=["POST"])
def api_object_action():
    body = request.get_json(force=True, silent=True) or {}
    level = body.get("level")  # unused here; we expect object id param
    obj_id = body.get("id")
    action = body.get("action")
    if not obj_id or not action:
        return jsonify({"error": "id and action required"}), 400
    status = "PAUSED" if action == "pause" else "ACTIVE" if action == "resume" else None
    if not status:
        return jsonify({"error": "unknown action"}), 400
    resp = fb_post(obj_id, data={"status": status})
    return jsonify(resp)

# Update adset (daily_budget, end_time)
@app.route("/api/object/update/adset", methods=["POST"])
def api_update_adset():
    body = request.get_json(force=True, silent=True) or {}
    adset_id = body.get("adset_id")
    if not adset_id:
        return jsonify({"error": "adset_id required"}), 400
    data = {}
    if "daily_budget" in body:
        data["daily_budget"] = int(body["daily_budget"])
    if "end_time" in body:
        data["end_time"] = body["end_time"]
    if not data:
        return jsonify({"error": "nothing to update"}), 400
    resp = fb_post(adset_id, data=data)
    return jsonify(resp)

# Upload image (URL)
@app.route("/api/image/upload_url", methods=["POST"])
def api_image_upload_url():
    body = request.get_json(force=True, silent=True) or {}
    image_url = (body.get("image_url") or "").strip()
    if not image_url:
        return jsonify({"error": "image_url required"}), 400
    h = upload_image_by_url(FB_AD_ACCOUNT_ID, image_url)
    if not h:
        return jsonify({"error": "upload_failed"}), 500
    return jsonify({"hash": h})

# Insights proxy (account / campaign / adset / ad)
@app.route("/api/insights", methods=["GET"])
def api_insights():
    level = request.args.get("level", "campaign")
    obj = request.args.get("id")
    since = request.args.get("since")
    until = request.args.get("until")
    fields = request.args.get("fields")
    fields_list = [f.strip() for f in fields.split(",")] if fields else None
    if level == "account":
        object_id = FB_AD_ACCOUNT_ID
    else:
        if not obj:
            return jsonify({"error": "id required for campaign/adset/ad level"}), 400
        object_id = obj
    data = fetch_insights_for(object_id, fields=fields_list, since=since, until=until)
    return jsonify(data)

@app.route("/api/object/delete", methods=["POST", "OPTIONS"])
def object_delete():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.json
    print("Received delete request:", data)  # <-- log input

    if not data or "id" not in data or "level" not in data:
        return jsonify({"success": False, "error": "Missing id or level"}), 400

    object_id = data["id"]
    level = data["level"]

    try:
        if level == "campaign":
            campaign = Campaign(object_id)
            print("Deleting campaign", object_id)
            campaign.api_delete()
            message = f"Campaign {object_id} deleted"
        elif level == "adset":
            adset = AdSet(object_id)
            print("Deleting adset", object_id)
            adset.api_delete()
            message = f"AdSet {object_id} deleted"
        elif level == "ad":
            ad = Ad(object_id)
            print("Deleting ad", object_id)
            ad.api_delete()
            message = f"Ad {object_id} deleted"
        else:
            return jsonify({"success": False, "error": f"Unknown level {level}"}), 400

        return jsonify({"success": True, "message": message, "id": object_id, "level": level})
    
    except Exception as e:
        import traceback
        print("Delete error:", traceback.format_exc())  # <-- detailed error
        return jsonify({"success": False, "error": str(e)}), 500


# Simple convenience route to return "last created" and UI
@app.route("/api/last", methods=["GET"])
def api_last():
    return jsonify(LAST)



# ---------------- New route: /api/publish_v2 ----------------
# Paste into your Flask app module. Assumes `app = Flask(__name__)` exists above.
# Single-file helpers + /api/publish_v2 route. No external SDK required (uses requests).

def _acct_prefix(acct: str) -> str:
    if not acct:
        return ""
    return acct if str(acct).startswith("act_") else f"act_{acct}"

def fb_post(path: str, params: Optional[Dict[str, Any]] = None, data: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None, timeout: int = 30) -> Dict[str, Any]:
    """
    Generic FB POST helper. `path` may be like "act_<id>/campaigns" or "me/feed".
    Always adds access_token param automatically if set.
    Returns parsed JSON or raises requests.HTTPError which can be caught.
    """
    base = f"https://graph.facebook.com/{FB_API_VERSION}"
    url = f"{base}/{path}"
    params = params.copy() if params else {}
    if FB_ACCESS_TOKEN:
        params["access_token"] = FB_ACCESS_TOKEN
    try:
        resp = requests.post(url, params=params, data=data, files=files, timeout=timeout)
        # Don't swallow HTTP errors; caller can inspect resp.text
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as he:
        text = None
        try:
            text = resp.text
        except Exception:
            text = "<no body>"
        logger.error("FB POST %s failed: %s -- body: %s", path, he, text)
        # Try to parse JSON error body if available
        try:
            return resp.json()
        except Exception:
            return {"error": {"message": str(he), "raw": text}}
    except Exception as e:
        logger.exception("FB POST %s exception: %s", path, e)
        return {"error": {"message": str(e)}}

def download_image_bytes(image_url: str, timeout: int = 20) -> Tuple[Optional[bytes], Optional[str]]:
    try:
        logger.info("Downloading image: %s", image_url)
        r = requests.get(image_url, timeout=timeout, stream=True)
        r.raise_for_status()
        content_type = r.headers.get("Content-Type", "image/jpeg")
        content = r.content
        return content, content_type
    except Exception as e:
        logger.exception("download_image_bytes failed: %s", e)
        return None, None
import tempfile
def save_bytes_to_tmpfile(img_bytes: bytes, suffix: str = ".jpg") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="sociovia_img_")
    os.close(fd)
    with open(path, "wb") as f:
        f.write(img_bytes)
    logger.info("Saved image to %s for debugging", path)
    return path


import io
import json

def upload_image_bytes_to_fb(ad_account_id: str, img_bytes: bytes, content_type: str = "image/jpeg") -> Optional[str]:
    """
    Uploads raw bytes to /act_<id>/adimages. Returns image_hash or None on failure.
    Uses 'bytes' multipart field which commonly works for FB Graph adimages.
    """
    if not FB_ACCESS_TOKEN:
        logger.error("FB_ACCESS_TOKEN missing")
        return None
    if not ad_account_id:
        logger.error("ad_account_id missing")
        return None

    path = f"{_acct_prefix(ad_account_id)}/adimages"
    files = {"bytes": ("image.jpg", io.BytesIO(img_bytes), content_type)}
    resp = fb_post(path, files=files)
    # success shape: {"images": { "<hash>": { "hash": "...", ... } } }
    images = resp.get("images") or {}
    if images:
        image_hash = next(iter(images.keys()))
        logger.info("FB adimages upload success: %s", image_hash)
        return image_hash
    # maybe FB returned {"error": {...}}
    logger.warning("FB adimages unexpected response: %s", resp)
    return None

def upload_image_by_url(ad_account_id: str, image_url: str) -> Optional[str]:
    img_bytes, content_type = download_image_bytes(image_url)
    if not img_bytes:
        return None
    image_hash = upload_image_bytes_to_fb(ad_account_id, img_bytes, content_type or "image/jpeg")
    if image_hash:
        return image_hash
    try:
        save_bytes_to_tmpfile(img_bytes)
    except Exception:
        logger.exception("failed to save fallback image")
    return None

def upload_image_from_base64(ad_account_id: str, b64_payload: str, content_type_hint: Optional[str] = None) -> Optional[str]:
    try:
        if b64_payload.startswith("data:"):
            _, _, b64 = b64_payload.partition("base64,")
        else:
            b64 = b64_payload
        img_bytes = base64.b64decode(b64)
    except Exception as e:
        logger.exception("Invalid base64 payload: %s", e)
        return None
    image_hash = upload_image_bytes_to_fb(ad_account_id, img_bytes, content_type_hint or "image/jpeg")
    if image_hash:
        return image_hash
    try:
        save_bytes_to_tmpfile(img_bytes)
    except Exception:
        logger.exception("failed to save base64 fallback")
    return None

def obtain_image_hash(body: Dict[str, Any]) -> Optional[str]:
    """
    Try, in order:
    - request.files['image_file'] (handled externally - but we check request.files below in route)
    - creative.image_base64 or image_base64
    - creative.image_url or image_url
    - DEFAULT_IMAGE_HASH fallback
    """
    creative = body.get("creative") or {}
    if isinstance(creative, str):
        try:
            creative = json.loads(creative)
        except Exception:
            creative = {}

    # base64
    b64 = creative.get("image_base64") or body.get("image_base64")
    if b64:
        logger.info("Attempt upload from base64")
        img_hash = upload_image_from_base64(FB_AD_ACCOUNT_ID, b64, creative.get("image_content_type"))
        if img_hash:
            return img_hash
        logger.warning("upload from base64 failed")

    # url
    img_url = creative.get("image_url") or body.get("image_url")
    if img_url:
        logger.info("Attempt upload from image_url")
        img_hash = upload_image_by_url(FB_AD_ACCOUNT_ID, img_url)
        if img_hash:
            return img_hash
        logger.warning("upload by url failed")

    # fallback default
    if DEFAULT_IMAGE_HASH:
        logger.info("Falling back to DEFAULT_IMAGE_HASH")
        return DEFAULT_IMAGE_HASH

    logger.error("No image hash available (base64/url failed and no DEFAULT_IMAGE_HASH)")
    return None

import requests
import json
from datetime import datetime, timedelta
from flask import request, jsonify
from flask import request, jsonify
from datetime import datetime, timedelta
import json, io, requests
# sociovia_publish.py


# Helpers
# -------------------------
def _acct_prefix(account_id):
    """Return 'act_<id>' formatted prefix. Accepts numeric or act_ prefixed."""
    if not account_id:
        return None
    s = str(account_id)
    if s.startswith("act_"):
        return s
    return f"act_{s}"


def _acct_id(account_id):
    """Return numeric id string (strip 'act_' if present)."""
    if not account_id:
        return None
    s = str(account_id)
    if s.startswith("act_"):
        return s.split("act_", 1)[1]
    return s

# add at top
from datetime import datetime, timedelta, timezone

# Replace / add this _graph_url helper (robust against double-version)
def _graph_url(path):
    """
    Build Graph URL robustly. Handles cases where GRAPH_BASE may include a version.
    Ensures we don't produce .../v16.0/v16.0/...
    """
    base = (GRAPH_BASE or "https://graph.facebook.com").rstrip('/')
    ver = (FB_API_VERSION or "").strip().lstrip('/')
    # if GRAPH_BASE already contains a '/vX.Y' suffix, drop ver
    # simple heuristic: check for '/v' + digits at end of base
    import re
    if re.search(r"/v\d+(\.\d+)?$", base):
        # base already has version; use base as-is and ignore FB_API_VERSION
        return f"{base}/{path.lstrip('/')}"
    # else include version only if provided
    if ver:
        return f"{base}/{ver}/{path.lstrip('/')}"
    return f"{base}/{path.lstrip('/')}"

# Replace fb_post with instrumented variant to log the final URL and response
def fb_post(path, data=None, files=None, timeout=30):
    url = _graph_url(path)
    payload = dict(data or {})
    if FB_ACCESS_TOKEN:
        payload["access_token"] = FB_ACCESS_TOKEN

    # DEBUG: log constructed URL and payload keys (do NOT log token)
    logger.info("FB POST -> url=%s", url)
    logger.debug("FB POST payload keys=%s files=%s", list(payload.keys()), bool(files))

    try:
        if files:
            resp = requests.post(url, data=payload, files=files, timeout=timeout)
        else:
            resp = requests.post(url, data=payload, timeout=timeout)

        # ALWAYS log status and body snippet for debugging
        logger.info("FB resp status=%s", resp.status_code)
        logger.debug("FB resp text: %s", resp.text[:1500])

        try:
            parsed = resp.json()
        except ValueError:
            logger.error("Non-JSON response from Graph; first 1000 chars: %s", resp.text[:1000])
            return {"error": {"message": "Non-JSON response", "raw": resp.text, "status_code": resp.status_code}}

        if resp.status_code >= 400 or (isinstance(parsed, dict) and parsed.get("error")):
            logger.debug("FB POST %s returned error status %s; body=%s", path, resp.status_code, parsed)
            return parsed
        return parsed
    except requests.RequestException as e:
        logger.exception("fb_post exception for %s: %s", path, e)
        return {"error": {"message": f"request_exception: {e}"}}

# Add startup logging to show environment values (helps confirm correct config)
logger.info("GRAPH_BASE=%s FB_API_VERSION=%s FB_AD_ACCOUNT_ID=%s",
            GRAPH_BASE, FB_API_VERSION, FB_AD_ACCOUNT_ID)

# Replace datetime.utcnow() uses with timezone-aware now where appropriate:
# e.g. in your publish_v2 place, change:
# start_dt = datetime.utcnow() + timedelta(days=start_in_days)
# to:




def detect_content_type(image_bytes):
    """
    Try to detect type via imghdr. Returns (content_type, filename) or (None, None).
    """
    try:
        fmt = imghdr.what(None, h=image_bytes)
    except Exception:
        fmt = None

    if fmt == "jpeg":
        return "image/jpeg", "image.jpg"
    if fmt == "png":
        return "image/png", "image.png"
    if fmt == "gif":
        return "image/gif", "image.gif"
    if fmt == "bmp":
        return "image/bmp", "image.bmp"
    return None, None


def download_bytes(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        r.raise_for_status()
        return r.content
    except Exception as e:
        logger.warning("download_bytes failed for %s: %s", url, e)
        return None


# put near other imports
from PIL import Image, UnidentifiedImageError

# robust detect_content_type using Pillow + imghdr fallback
def detect_content_type(image_bytes):
    """
    Return (content_type, filename) or (None, None).
    Uses Pillow for robust detection, falls back to imghdr.
    """
    if not image_bytes or len(image_bytes) < 20:
        return None, None

    # try Pillow
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            fmt = (img.format or "").lower()
            if fmt in ("jpeg", "jpg"):
                return "image/jpeg", "image.jpg"
            if fmt == "png":
                return "image/png", "image.png"
            if fmt == "gif":
                return "image/gif", "image.gif"
            if fmt == "bmp":
                return "image/bmp", "image.bmp"
            if fmt == "webp":
                return "image/webp", "image.webp"
            # Unknown Pillow format -> fall back
    except UnidentifiedImageError:
        pass
    except Exception:
        # Pillow could throw other exceptions on truncated files; fall back
        pass

    # fallback to imghdr
    try:
        fmt = imghdr.what(None, h=image_bytes)
        if fmt == "jpeg":
            return "image/jpeg", "image.jpg"
        if fmt == "png":
            return "image/png", "image.png"
        if fmt == "gif":
            return "image/gif", "image.gif"
        if fmt == "bmp":
            return "image/bmp", "image.bmp"
    except Exception:
        pass

    return None, None


def upload_image_bytes(account_id, image_bytes, content_type=None):
    """
    Upload bytes to /adimages. Tries multiple detection/upload strategies:
      1) detect content type and upload with multipart key 'file'
      2) if Graph returns FileTypeNotSupported, retry with multipart key 'bytes'
    Returns image_hash or None.
    """
    try:
        if not image_bytes:
            logger.warning("upload_image_bytes: empty bytes")
            return None

        # detect if content-type not provided or suspicious
        if not content_type or not content_type.startswith("image/"):
            detected_type, filename = detect_content_type(image_bytes)
            if not detected_type:
                logger.warning("upload_image_bytes: could not detect image type (len=%d)", len(image_bytes))
                return None
            content_type = detected_type
        else:
            ext = content_type.split("/")[-1]
            filename = f"image.{ext}"

        # attempt 1: multipart key 'file'
        files = {"file": (filename, io.BytesIO(image_bytes), content_type)}
        resp = fb_post(f"{_acct_prefix(account_id)}/adimages", files=files)
        # If success return
        if isinstance(resp, dict) and resp.get("images"):
            first_key = next(iter(resp["images"].keys()))
            return resp["images"][first_key].get("hash") or first_key

        # check for FileTypeNotSupported error_subcode = 1487411 (or general 100)
        err_code = None
        err_sub = None
        if isinstance(resp, dict) and resp.get("error"):
            try:
                err_code = resp["error"].get("code")
                err_sub = resp["error"].get("error_subcode")
            except Exception:
                pass

        # If Graph complains about filetype, try 'bytes' param (some examples use this param name)
        if err_code == 100 and err_sub == 1487411:
            logger.info("upload_image_bytes: retrying using multipart key 'bytes' due to FileTypeNotSupported")
            files2 = {"bytes": (filename, io.BytesIO(image_bytes), content_type)}
            resp2 = fb_post(f"{_acct_prefix(account_id)}/adimages", files=files2)
            if isinstance(resp2, dict) and resp2.get("images"):
                first_key = next(iter(resp2["images"].keys()))
                return resp2["images"][first_key].get("hash") or first_key
            logger.warning("upload_image_bytes retry (bytes) response: %s", resp2)
            return None

        # If other error or unexpected structure, log and return
        logger.warning("upload_image_bytes unexpected response (file): %s", resp)
        return None
    except Exception as e:
        logger.exception("upload_image_bytes exception: %s", e)
        return None


def upload_image_by_url(account_id, url):
    """
    Try Graph API direct URL upload first (data={'url': url}),
    fallback to download & upload bytes.
    """
    try:
        if not url:
            return None
        resp = fb_post(f"{_acct_prefix(account_id)}/adimages", data={"url": url})
        if isinstance(resp, dict) and resp.get("images"):
            first_key = next(iter(resp["images"].keys()))
            return resp["images"][first_key].get("hash") or first_key

        # If Graph returned an error that indicates url was rejected, try download & upload
        logger.info("upload_image_by_url: graph url upload failed, trying download fallback; graph_resp=%s", resp)
        b = download_bytes(url)
        if b:
            return upload_image_bytes(account_id, b)
        return None
    except Exception as e:
        logger.exception("upload_image_by_url exception: %s", e)
        return None

import re
import base64
from typing import Optional

DATA_URI_RE = re.compile(r"^data:(?P<mediatype>[\w/+.-]+/[\w.+-]+)?(?P<params>;[^\s,;=]+=[^,;]+)*;base64,(?P<data>.+)$", re.I)
RAW_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")

def _is_data_uri(s: str) -> bool:
    return isinstance(s, str) and s.strip().startswith("data:")

def _decode_data_uri(s: str) -> Optional[tuple]:
    """
    Returns (bytes, content_type) or (None, None) on failure.
    """
    try:
        m = DATA_URI_RE.match(s.strip())
        if not m:
            return None, None
        content_type = m.group("mediatype") or "application/octet-stream"
        b64 = m.group("data")
        b = base64.b64decode(b64)
        return b, content_type
    except Exception:
        return None, None

def _maybe_decode_raw_base64(s: str) -> Optional[tuple]:
    """
    If s looks like a raw base64 blob (no data: prefix) decode and guess content-type as octet-stream.
    Returns (bytes, "application/octet-stream") or (None, None).
    """
    if not isinstance(s, str):
        return None, None
    t = s.strip()
    # quick heuristic: length, only base64 chars, and padding '=' present sometimes
    if len(t) > 100 and RAW_BASE64_RE.match(t) and (len(t) % 4 == 0 or t.endswith("=")):
        try:
            b = base64.b64decode(t)
            return b, "application/octet-stream"
        except Exception:
            return None, None
    return None, None

def resolve_image_hash(body, image_file):
    """
    Resolve image hash from:
      1) uploaded file (image_file)
      2) creative.image_url or body.image_url (handles data URI and base64)
      3) selectedImages fallback
      4) DEFAULT_IMAGE_HASH
    Returns image_hash string or None
    """
    # 1) file upload
    if image_file and getattr(image_file, "filename", ""):
        try:
            content_type = getattr(image_file, "mimetype", None) or None
            b = image_file.read()
            # If file-like, rewind if needed for downstream use
            try:
                image_file.seek(0)
            except Exception:
                pass
            if b:
                # prefer your existing helper if available
                if "upload_image_bytes" in globals() and callable(globals()["upload_image_bytes"]):
                    try:
                        h = upload_image_bytes(FB_AD_ACCOUNT_ID, b, content_type=content_type)
                        if h:
                            return h
                    except Exception:
                        logger.exception("upload_image_bytes failed for image_file")
                # fallback: upload to spaces and then /adimages via URL
                public_url = None
                if "upload_bytes_to_spaces" in globals() and callable(globals()["upload_bytes_to_spaces"]):
                    public_url = upload_bytes_to_spaces(b, image_file.filename or "upload.bin", content_type=content_type or "application/octet-stream")
                if public_url and "upload_image_by_url" in globals() and callable(globals()["upload_image_by_url"]):
                    h = upload_image_by_url(FB_AD_ACCOUNT_ID, public_url)
                    if h:
                        return h
        except Exception:
            logger.exception("image_file upload failed")

    # helper to try decode-and-upload a data/base64 string
    def _try_handle_inline_image(src: str) -> Optional[str]:
        if not src or not isinstance(src, str):
            return None
        # data URI
        if _is_data_uri(src):
            b, ctype = _decode_data_uri(src)
            if not b:
                logger.debug("data URI decode failed")
                return None
            # prefer upload_image_bytes if available
            if "upload_image_bytes" in globals() and callable(globals()["upload_image_bytes"]):
                try:
                    h = upload_image_bytes(FB_AD_ACCOUNT_ID, b, content_type=ctype)
                    if h:
                        return h
                except Exception:
                    logger.exception("upload_image_bytes failed for data URI")
            # otherwise upload bytes to Spaces and then adimages by url
            if "upload_bytes_to_spaces" in globals() and callable(globals()["upload_bytes_to_spaces"]):
                filename = f"inline.{(ctype.split('/')[-1] if '/' in ctype else 'bin')}"
                public_url = upload_bytes_to_spaces(b, filename, content_type=ctype)
                if public_url and "upload_image_by_url" in globals() and callable(globals()["upload_image_by_url"]):
                    try:
                        h = upload_image_by_url(FB_AD_ACCOUNT_ID, public_url)
                        if h:
                            return h
                    except Exception:
                        logger.exception("upload_image_by_url failed for Spaces URL")
            return None

        # raw base64 (no data: prefix)
        maybe = _maybe_decode_raw_base64(src)
        if maybe and maybe[0]:
            b, ctype = maybe
            if "upload_image_bytes" in globals() and callable(globals()["upload_image_bytes"]):
                try:
                    h = upload_image_bytes(FB_AD_ACCOUNT_ID, b, content_type=ctype)
                    if h:
                        return h
                except Exception:
                    logger.exception("upload_image_bytes failed for raw base64")
            if "upload_bytes_to_spaces" in globals() and callable(globals()["upload_bytes_to_spaces"]):
                filename = "inline.bin"
                public_url = upload_bytes_to_spaces(b, filename, content_type=ctype)
                if public_url and "upload_image_by_url" in globals() and callable(globals()["upload_image_by_url"]):
                    try:
                        h = upload_image_by_url(FB_AD_ACCOUNT_ID, public_url)
                        if h:
                            return h
                    except Exception:
                        logger.exception("upload_image_by_url failed for Spaces URL (raw base64)")
        return None

    # 2) candidate URLs and inline data
    creative_in = (body.get("creative") or {}) if isinstance(body, dict) else {}
    candidates = []
    if isinstance(creative_in, dict):
        candidates.append(creative_in.get("image_url") or creative_in.get("imageUrl") or creative_in.get("image"))
    candidates.append(body.get("image_url") or body.get("imageUrl") or body.get("image"))

    # selectedImages support
    sel = body.get("selectedImages") or body.get("selected_images")
    if isinstance(sel, dict) and isinstance(sel.get("images"), list) and sel.get("images"):
        first = sel["images"][0]
        if isinstance(first, dict):
            candidates.append(first.get("url") or first.get("image") or first.get("src"))
    elif isinstance(sel, list) and sel:
        first = sel[0]
        if isinstance(first, dict):
            candidates.append(first.get("url") or first.get("image") or first.get("src"))

    # iterate candidates
    for u in (candidates or []):
        if not u:
            continue
        # 2a) if inline (data URI or base64) -> decode & upload
        try:
            h_inline = _try_handle_inline_image(u)
            if h_inline:
                return h_inline
        except Exception:
            logger.exception("inline image handling failed for candidate")

        # 2b) otherwise try uploading by URL (existing helper)
        try:
            h = None
            if "upload_image_by_url" in globals() and callable(globals()["upload_image_by_url"]):
                h = upload_image_by_url(FB_AD_ACCOUNT_ID, u)
            else:
                # no helper available: try direct POST to /adimages (best-effort)
                try:
                    upload_url = f"https://graph.facebook.com/v{FB_GRAPH_API_VERSION or '18.0'}/{_acct_prefix(FB_AD_ACCOUNT_ID)}/adimages"
                    params = {"access_token": FB_ACCESS_TOKEN}
                    rimg = requests.post(upload_url, params=params, data={"url": u}, timeout=30)
                    try:
                        img_json = rimg.json()
                    except Exception:
                        img_json = {"text": rimg.text}
                    images_obj = img_json.get("images") if isinstance(img_json, dict) else None
                    if images_obj and isinstance(images_obj, dict):
                        for k, v in images_obj.items():
                            if isinstance(v, dict) and (v.get("hash") or v.get("image_hash")):
                                h = v.get("hash") or v.get("image_hash")
                                break
                except Exception:
                    logger.exception("direct /adimages attempt failed for url")
            if h:
                return h
        except Exception:
            logger.exception("upload_image_by_url failed for candidate")

    # 3) fallback to DEFAULT_IMAGE_HASH if set
    if DEFAULT_IMAGE_HASH:
        logger.info("Using DEFAULT_IMAGE_HASH fallback")
        return DEFAULT_IMAGE_HASH

    return None

def normalize_countries(raw):
    """
    Accepts single string or list. Returns list of ISO2 codes (upper).
    Tries pycountry if available, else uses a small fallback map.
    """
    if not raw:
        return []
    vals = []
    if isinstance(raw, str):
        # CSV or single
        if "," in raw and len(raw) > 2:
            vals = [v.strip() for v in raw.split(",") if v.strip()]
        else:
            vals = [raw.strip()]
    elif isinstance(raw, (list, tuple)):
        vals = [str(v).strip() for v in raw if v]
    else:
        vals = [str(raw).strip()]

    resolved = []
    try:
        import pycountry  # optional
    except Exception:
        pycountry = None

    FALLBACK = {
        "UNITED STATES": "US", "USA": "US", "US": "US",
        "INDIA": "IN", "IN": "IN",
        "UNITED KINGDOM": "GB", "UK": "GB", "GB": "GB",
        "AUSTRALIA": "AU", "CA": "CA", "CANADA": "CA",
    }

    for v in vals:
        if not v:
            continue
        s = v.strip()
        if len(s) == 2 and s.isalpha():
            resolved.append(s.upper())
            continue
        up = s.upper()
        if up in FALLBACK:
            resolved.append(FALLBACK[up])
            continue
        if pycountry:
            try:
                maybe = pycountry.countries.get(name=s)
                if not maybe:
                    maybe = pycountry.countries.get(common_name=s)
                if not maybe:
                    maybe = pycountry.countries.get(alpha_3=s.upper())
                if not maybe:
                    # partial match
                    for c in pycountry.countries:
                        if s.lower() in getattr(c, "name", "").lower():
                            maybe = c
                            break
                if maybe:
                    resolved.append(maybe.alpha_2)
                    continue
            except Exception:
                pass
    # dedupe preserve order
    out = []
    for c in resolved:
        if c and c not in out:
            out.append(c)
    return out

from datetime import datetime, timedelta
import json
import os
from flask import request, jsonify
# assumes logger is configured globally as `logger`
# assumes helpers fb_post, resolve_image_hash, _acct_prefix, normalize_countries exist

@app.route("/api/publish_v2", methods=["POST"])
def publish_v2():
    """
    One-stop publish route:
      - accepts JSON or multipart/form-data
      - maps developer-friendly objective -> Graph API outcome enums
      - resolves image (file / url) and uploads to FB /adimages (or uses DEFAULT_IMAGE_HASH)
      - creates campaign, adset, creative and ad (PAUSED)
    Returns JSON with FB ids or descriptive error stage/details.
    """
    try:
        def parse_request():
            content_type = (request.content_type or "").lower()
            if content_type.startswith("application/json"):
                body = request.get_json(silent=True) or {}
                image_file = None
            else:
                body = request.form.to_dict() or {}
                image_file = request.files.get("image_file")
                # parse creative JSON string if present
                if body.get("creative") and isinstance(body.get("creative"), str):
                    try:
                        body["creative"] = json.loads(body["creative"])
                    except Exception:
                        pass
            return body, image_file

        # parse request
        body, image_file = parse_request()
        creative_in = (body.get("creative") or {}) if isinstance(body, dict) else {}

        campaign_name = body.get("campaign_name") or f"Campaign {datetime.utcnow().isoformat()}"
        adset_name = body.get("adset_name") or f"AdSet {datetime.utcnow().isoformat()}"
        ad_name = body.get("ad_name") or f"Ad {datetime.utcnow().isoformat()}"

        # creative fields (HARD-CODE CTA to avoid invalid values)
        primary_text = (creative_in.get("primaryText") or creative_in.get("message") or "").strip()
        headline = (creative_in.get("headline") or "").strip()
        description = (creative_in.get("description") or "").strip()

        # HARD-CODED: always use a valid CTA to prevent Graph API errors
        cta = "LEARN_MORE"

        link = (creative_in.get("url") or creative_in.get("link") or body.get("link") or "https://www.sociovia.com").strip()

        start_in_days = int(body.get("start_in_days") or 0)
        duration_days = max(1, int(body.get("duration_days") or 2))
        # handle numeric or string daily_budget robustly
        raw_daily = body.get("daily_budget") or body.get("dailyBudget") or None
        try:
            # if provided in rupees (e.g. 1000) convert to cents/paise by *100 as original code
            daily_budget = int(float(raw_daily) * 100) if raw_daily is not None else 100000
        except Exception:
            daily_budget = 100000

        # country(s) normalization
        raw_country = body.get("country") or body.get("countries") or (body.get("context") or {}).get("country")
        country_list = normalize_countries(raw_country)
        if not country_list:
            logger.warning("No valid countries resolved from request; defaulting to US")
            country_list = ["US"]

        # objective mapping
        OBJECTIVE_MAP = {
            "TRAFFIC": "OUTCOME_TRAFFIC",
            "LINK_CLICKS": "OUTCOME_TRAFFIC",
            "REACH": "OUTCOME_AWARENESS",
            "BRAND_AWARENESS": "OUTCOME_AWARENESS",
            "CONVERSIONS": "OUTCOME_SALES",
            "SALES": "OUTCOME_SALES",
            "LEADS": "OUTCOME_LEADS",
            "ENGAGEMENT": "OUTCOME_ENGAGEMENT",
            "AWARENESS": "OUTCOME_AWARENESS",
            "APP_PROMOTION": "OUTCOME_APP_PROMOTION",
        }
        requested_obj = (body.get("objective") or body.get("objective_type") or "TRAFFIC")
        requested_obj_upper = str(requested_obj).strip().upper()
        mapped_obj = OBJECTIVE_MAP.get(requested_obj_upper)
        if not mapped_obj:
            if requested_obj_upper.startswith("OUTCOME_") and requested_obj_upper in {
                "OUTCOME_LEADS", "OUTCOME_SALES", "OUTCOME_ENGAGEMENT", "OUTCOME_AWARENESS", "OUTCOME_TRAFFIC", "OUTCOME_APP_PROMOTION"
            }:
                mapped_obj = requested_obj_upper
            else:
                logger.warning("Unknown objective %s, falling back to OUTCOME_TRAFFIC", requested_obj)
                mapped_obj = "OUTCOME_TRAFFIC"

        # special_ad_categories (Graph requires param present; can be empty array)
        _special = body.get("special_ad_categories") or body.get("special_ad_category") or []
        if isinstance(_special, str):
            try:
                _special = json.loads(_special)
            except Exception:
                _special = [s.strip() for s in _special.split(",") if s.strip()]
        if not isinstance(_special, list):
            _special = []

        # compute start/end timestamps
        start_dt = datetime.utcnow() + timedelta(days=start_in_days)
        end_dt = start_dt + timedelta(days=duration_days)
        start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%S-0000")
        end_time = end_dt.strftime("%Y-%m-%dT%H:%M:%S-0000")

        # -------------------------
        # 1) create campaign
        # -------------------------
        if not FB_AD_ACCOUNT_ID or not FB_ACCESS_TOKEN:
            logger.error("Missing FB_AD_ACCOUNT_ID or FB_ACCESS_TOKEN in environment")
            return jsonify({"ok": False, "stage": "init", "details": "missing_config"}), 500

        campaign_payload = {
            "name": campaign_name,
            "objective": mapped_obj,
            "status": "PAUSED",
            "special_ad_categories": json.dumps(_special),
        }
        campaign_resp = fb_post(f"{_acct_prefix(FB_AD_ACCOUNT_ID)}/campaigns", data=campaign_payload)
        if isinstance(campaign_resp, dict) and campaign_resp.get("error"):
            logger.error("campaign create failed: %s", campaign_resp)
            return jsonify({"ok": False, "stage": "create_campaign", "details": campaign_resp}), 500
        campaign_id = campaign_resp.get("id") or campaign_resp.get("campaign_id")
        logger.info("Created campaign: %s (objective=%s)", campaign_id, mapped_obj)

        # -------------------------
        # 2) create adset
        # -------------------------
        OPT_GOAL_MAP = {
            "OUTCOME_TRAFFIC": "LINK_CLICKS",
            "OUTCOME_AWARENESS": "REACH",
            "OUTCOME_ENGAGEMENT": "POST_ENGAGEMENT",
            "OUTCOME_LEADS": "LEAD_GENERATION",
            "OUTCOME_SALES": "OFFSITE_CONVERSIONS",
            "OUTCOME_APP_PROMOTION": "APP_INSTALLS",
        }
        optimization_goal = OPT_GOAL_MAP.get(mapped_obj, "LINK_CLICKS")

        requested_bid_strategy = (body.get("bid_strategy") or body.get("bidStrategy") or "").strip().upper() or None
        requested_bid_amount = body.get("bid_amount") or body.get("bidAmount") or None
        bid_amount_val = None
        if requested_bid_amount is not None:
            try:
                bid_amount_val = int(requested_bid_amount)
            except Exception:
                bid_amount_val = None

        bid_strategy = requested_bid_strategy or "LOWEST_COST_WITHOUT_CAP"

        targeting = {"geo_locations": {"countries": country_list}}

        # ---------- PROMOTED OBJECT / CONVERSION handling ----------
        promoted_object = None
        adset_billing_event = "IMPRESSIONS"  # default

        # accept multiple possible request keys for product set / product id
        requested_product_set = (body.get("product_set_id")
                                 or body.get("productSetId")
                                 or body.get("product_set")
                                 or body.get("product_setid")
                                 or body.get("product_id")
                                 or body.get("productSet")
                                 or None)

        # allow caller to pass pixel_id or fb_pixel_id in request (optional)
        requested_pixel = (body.get("pixel_id") or body.get("fb_pixel_id") or body.get("pixel") or None)
        fb_pixel_env = globals().get("FB_PIXEL_ID") or os.environ.get("FB_PIXEL_ID")

        # prefer request pixel if provided
        fb_pixel = None
        if requested_pixel:
            try:
                fb_pixel = int(requested_pixel)
            except Exception:
                fb_pixel = requested_pixel
        elif fb_pixel_env:
            try:
                fb_pixel = int(fb_pixel_env)
            except Exception:
                fb_pixel = fb_pixel_env

        if optimization_goal == "OFFSITE_CONVERSIONS" or mapped_obj == "OUTCOME_SALES":
            # prefer pixel if present, otherwise use product_set if provided
            if fb_pixel:
                promoted_object = {"pixel_id": fb_pixel, "custom_event_type": "PURCHASE"}
                adset_billing_event = "OFFSITE_CONVERSIONS"
                logger.info("Using Pixel for promoted_object: %s", fb_pixel)
            elif requested_product_set:
                promoted_object = {"product_set_id": str(requested_product_set)}
                # For catalog sales, IMPRESSIONS is a safe default billing_event in many setups
                adset_billing_event = "IMPRESSIONS"
                logger.info("Using Product Set for promoted_object: %s", requested_product_set)
            else:
                logger.error("Missing FB_PIXEL_ID or product_set_id for OFFSITE_CONVERSIONS adset")
                return jsonify({
                    "ok": False,
                    "stage": "create_adset",
                    "details": "missing_pixel_or_productset",
                    "message": "AdSet for conversions requires FB_PIXEL_ID (env or pixel_id in request) or product_set_id in request."
                }), 400
        else:
            # non-conversion goals keep default billing event; optionally map for traffic
            if optimization_goal == "LINK_CLICKS":
                adset_billing_event = "IMPRESSIONS"

        # build adset payload
        adset_payload = {
            "name": adset_name,
            "campaign_id": campaign_id,
            "daily_budget": str(int(daily_budget)),  # FB expects smallest currency unit in some cases
            "start_time": start_time,
            "end_time": end_time,
            "billing_event": adset_billing_event,
            "optimization_goal": optimization_goal,
            "status": "PAUSED",
            "targeting": json.dumps(targeting),
            "bid_strategy": bid_strategy,
        }
        if bid_amount_val is not None:
            adset_payload["bid_amount"] = str(bid_amount_val)

        if promoted_object is not None:
            try:
                adset_payload["promoted_object"] = json.dumps(promoted_object)
            except Exception:
                adset_payload["promoted_object"] = promoted_object  # fallback (fb_post should serialize)

        if body.get("bid_constraints"):
            try:
                bc = body.get("bid_constraints")
                adset_payload["bid_constraints"] = json.dumps(bc) if not isinstance(bc, str) else bc
            except Exception:
                logger.warning("Invalid bid_constraints provided; ignoring")

        adset_resp = fb_post(f"{_acct_prefix(FB_AD_ACCOUNT_ID)}/adsets", data=adset_payload)
        if isinstance(adset_resp, dict) and adset_resp.get("error"):
            logger.error("adset create failed: %s", adset_resp)
            return jsonify({"ok": False, "stage": "create_adset", "details": adset_resp}), 500
        adset_id = adset_resp.get("id")
        logger.info("Created adset: %s (opt_goal=%s, bid_strategy=%s)", adset_id, optimization_goal, bid_strategy)

        # -------------------------
        # 3) image resolution & upload
        # -------------------------
        image_hash = resolve_image_hash(body, image_file)
        if not image_hash:
            logger.error("image resolution/upload failed")
            return jsonify({"ok": False, "stage": "image_upload", "details": "image_upload_failed"}), 500
        logger.info("Resolved image_hash: %s", image_hash)

        # -------------------------
        # 4) create creative (object_story_spec)
        # -------------------------
        link_data = {"image_hash": image_hash, "link": link, "message": primary_text or description or headline or " "}
        if headline:
            link_data["name"] = headline
        if description:
            link_data["description"] = description
        if cta:
            link_data["call_to_action"] = {"type": cta}

        object_story_spec = {"page_id": FB_PAGE_ID, "link_data": link_data} if FB_PAGE_ID else {"link_data": link_data}
        creative_payload = {"name": f"Auto Creative {datetime.utcnow().isoformat()}", "object_story_spec": json.dumps(object_story_spec)}
        creative_resp = fb_post(f"{_acct_prefix(FB_AD_ACCOUNT_ID)}/adcreatives", data=creative_payload)
        if isinstance(creative_resp, dict) and creative_resp.get("error"):
            logger.error("create adcreative failed: %s", creative_resp)
            return jsonify({"ok": False, "stage": "create_creative", "details": creative_resp}), 500
        creative_id = creative_resp.get("id")
        logger.info("Created creative: %s", creative_id)

        # -------------------------
        # 5) create ad (PAUSED)
        # -------------------------
        ad_payload = {"name": ad_name, "adset_id": adset_id, "creative": json.dumps({"creative_id": creative_id}), "status": "PAUSED"}
        ad_resp = fb_post(f"{_acct_prefix(FB_AD_ACCOUNT_ID)}/ads", data=ad_payload)
        if isinstance(ad_resp, dict) and ad_resp.get("error"):
            logger.error("create ad failed: %s", ad_resp)
            return jsonify({"ok": False, "stage": "create_ad", "details": ad_resp}), 500
        ad_id = ad_resp.get("id")
        logger.info("Created ad: %s", ad_id)

        return jsonify({
            "ok": True,
            "campaign_id": campaign_id,
            "adset_id": adset_id,
            "creative_id": creative_id,
            "ad_id": ad_id,
            "image_hash": image_hash,
        }), 200

    except Exception as exc:
        logger.exception("publish_v2 unexpected error: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500



def country_to_iso(country: str) -> str:
    """
    Convert a country name or code to a 2-letter ISO country code for FB targeting.
    If unsure, fallback to uppercase input (FB will validate).
    """
    if not country:
        return "US"
    c = country.strip()
    # quick common-name mapping
    common = {
        "india": "IN",
        "in": "IN",
        "ind": "IN",
        "united states": "US",
        "usa": "US",
        "us": "US",
        "united kingdom": "GB",
        "uk": "GB",
        "great britain": "GB",
        "australia": "AU",
        "canada": "CA",
        "germany": "DE",
        "france": "FR",
        "singapore": "SG",
    }
    key = c.lower()
    if key in common:
        return common[key]
    # if already two letters, assume ISO2 and return uppercased
    if len(c) == 2 and c.isalpha():
        return c.upper()
    # try pycountry if installed (best-effort)
    try:
        import pycountry
        # try direct name match
        match = pycountry.countries.get(name=c)
        if match:
            return match.alpha_2
        # try common name / search
        for country_obj in pycountry.countries:
            names = [country_obj.name]
            if getattr(country_obj, "official_name", None):
                names.append(country_obj.official_name)
            if any(c.lower() in n.lower() for n in names):
                return country_obj.alpha_2
    except Exception:
        # pycountry not installed or failed — ignore
        pass
    # fallback: uppercase the given string and let FB validate
    return c.upper()





# ai_suggestions_genai.py
import os
import re
import json
import uuid
from typing import Any, Dict, List, Optional
from flask import Flask, request, jsonify, current_app




def _extract_json_from_textt(text: str) -> Optional[Any]:
    """Find and parse first JSON object/array in the model output text."""
    if not text:
        return None
    # try direct parse
    try:
        return json.loads(text)
    except Exception:
        pass
    # find first {...} or [...]
    obj_match = re.search(r"(\{(?:[^{}]|\{[^{}]*\})*\})", text, flags=re.DOTALL)
    arr_match = re.search(r"(\[(?:[^\[\]]|\[[^\[\]]*\])*\])", text, flags=re.DOTALL)
    candidate = obj_match.group(1) if obj_match else (arr_match.group(1) if arr_match else None)
    if not candidate:
        return None
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
    try:
        return json.loads(candidate)
    except Exception:
        # try stripping weird chars then parse
        cleaned = re.sub(r"[^\x09\x0A\x0D\x20-\x7F]", "", candidate)
        try:
            return json.loads(cleaned)
        except Exception:
            return None


def _build_prompt(workspace_summary: Dict[str, Any], image_url: Optional[str], selected_images: List[Dict[str, Any]],
                  context: Dict[str, Any], max_suggestions: int = 6) -> str:
    """Strict prompt asking the model to return ONLY a JSON with suggestions array."""
    summary_json = json.dumps(workspace_summary, ensure_ascii=False, indent=2)
    sel_imgs_json = json.dumps(selected_images or [], ensure_ascii=False, indent=2)
    ctx_json = json.dumps(context or {}, ensure_ascii=False, indent=2)

    prompt = f"""
You are an assistant that generates ad creative suggestions (copy + CTA + optional URL) for a social ads campaign.
Return ONLY a JSON object with a single top-level key "suggestions" whose value is an array of suggestion objects.
Each suggestion object must have these fields:
  - id: string (unique id)
  - primaryText: string
  - headline: string
  - description: string (optional)
  - cta: one of ["SHOP_NOW","LEARN_MORE","SIGN_UP","APPLY_NOW","CONTACT_US"] or a short label
  - url: string|null
  - score: number (optional, 0.0-1.0)

Return up to {max_suggestions} suggestions. Keep texts concise ad-friendly.
Return JSON ONLY and nothing else (no commentary).

Workspace summary:
{summary_json}

Image URL: {image_url or "null"}

Selected images:
{sel_imgs_json}

Context:
{ctx_json}

Return the JSON object now and nothing else.
""".strip()
    return prompt


def _extract_text_from_genai_response(resp: Any) -> str:
    """
    Try multiple common response shapes from genai/vertex clients and extract
    textual content for JSON parsing.
    """
    if resp is None:
        return ""
    # If response is already a string
    if isinstance(resp, str):
        return resp

    parts: List[str] = []

    # google-genai "client.generate(...)" often returns a simple object with .text or .content
    try:
        if hasattr(resp, "text") and isinstance(resp.text, str):
            parts.append(resp.text)
    except Exception:
        pass

    # Vertex `predict()` responses commonly have .predictions list
    try:
        preds = getattr(resp, "predictions", None)
        if preds:
            for p in preds:
                if isinstance(p, str):
                    parts.append(p)
                elif isinstance(p, dict):
                    # common keys
                    parts.append(p.get("content") or p.get("text") or json.dumps(p))
    except Exception:
        pass

    # google genai `generate` might return dict/list
    try:
        if isinstance(resp, dict):
            # prefer top-level "content" or "text"
            content = resp.get("content") or resp.get("text")
            if content:
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for c in content:
                        if isinstance(c, str):
                            parts.append(c)
                        elif isinstance(c, dict):
                            parts.append(c.get("text") or json.dumps(c))
            # maybe "candidates"
            cand = resp.get("candidates")
            if cand and isinstance(cand, list):
                for c in cand:
                    if isinstance(c, dict):
                        parts.append(c.get("content") or c.get("text") or json.dumps(c))
        elif isinstance(resp, (list, tuple)):
            for item in resp:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(item.get("content") or item.get("text") or json.dumps(item))
    except Exception:
        pass

    # fallback to string conversion
    if not parts:
        try:
            parts.append(json.dumps(resp))
        except Exception:
            parts.append(str(resp))

    return "\n".join(parts)


def generate_ai_suggestions_using_genai(
    workspace: Optional[Dict[str, Any]],
    image_url: Optional[str],
    selected_images: List[Dict[str, Any]],
    context: Dict[str, Any],
    model: Optional[str] = None,
    max_suggestions: int = 6,
) -> Dict[str, Any]:
    """
    Use the global GENAI_CLIENT to generate ad-copy suggestions.
    Returns dict with keys: ok(bool), suggestions(list), raw_text(str|null), error(str|null)
    """
    if not GENAI_CLIENT:
        return {"ok": False, "error": "GENAI_CLIENT not initialized", "suggestions": [], "raw_text": None}

    # compact workspace summary
    def _short(v: Any, n: int = 300) -> str:
        if v is None:
            return ""
        if isinstance(v, (dict, list)):
            try:
                return json.dumps(v, ensure_ascii=False)[:n]
            except Exception:
                return str(v)[:n]
        return str(v)[:n]

    workspace_summary = {
        "business_name": (workspace or {}).get("business_name") or (workspace or {}).get("name") or "",
        "usp": _short((workspace or {}).get("usp")),
        "description": _short((workspace or {}).get("description")),
        "audience_description": _short((workspace or {}).get("audience_description")),
        "website": (workspace or {}).get("website") or "",
        "creatives_count": len((workspace or {}).get("creatives_path") or (workspace or {}).get("creatives") or []),
        "saved_id": (workspace or {}).get("id") or None,
    }

    prompt = _build_prompt(workspace_summary, image_url, selected_images or [], context or {}, max_suggestions)

    # prefer a model id from payload or env
    model_id = model or os.environ.get("TEXT_MODEL") or os.environ.get("GENAI_MODEL") or None

    raw_text = None
    try:
        # Try several invocation patterns to support various genai/vertex client shapes.
        resp = None
        # 1) genai.Client.generate(model=..., input=...)
        try:
            if hasattr(GENAI_CLIENT, "generate"):
                if model_id:
                    resp = GENAI_CLIENT.generate(model=model_id, input=prompt)
                else:
                    resp = GENAI_CLIENT.generate(input=prompt)
        except Exception:
            resp = None

        # 2) genai client may have models.generate or models.generate_content
        if resp is None and hasattr(GENAI_CLIENT, "models"):
            try:
                models_obj = getattr(GENAI_CLIENT, "models")
                # models.generate_content(model=..., contents=[prompt], config={...})
                if hasattr(models_obj, "generate_content"):
                    cfg = {"response_modalities": ["TEXT"], "candidate_count": 1}
                    resp = models_obj.generate_content(model=model_id or "text-model", contents=[prompt], config=cfg)
                elif hasattr(models_obj, "generate"):
                    resp = models_obj.generate(model=model_id or "text-model", input=prompt)
            except Exception:
                resp = None

        # 3) If still None and genai client exposes a `predict` or `predict_text` try that
        if resp is None and hasattr(GENAI_CLIENT, "predict"):
            try:
                resp = GENAI_CLIENT.predict(prompt)
            except Exception:
                resp = None

        if resp is None:
            return {"ok": False, "error": "Could not call GENAI_CLIENT with known methods", "suggestions": [], "raw_text": None}

        raw_text = _extract_text_from_genai_response(resp)
        parsed = _extract_json_from_textt(raw_text)
        if parsed is None:
            return {"ok": False, "error": "Failed to parse JSON from model output", "raw_text": raw_text, "suggestions": []}

        # normalize suggestions
        suggestions_raw = []
        if isinstance(parsed, dict) and "suggestions" in parsed and isinstance(parsed["suggestions"], list):
            suggestions_raw = parsed["suggestions"]
        elif isinstance(parsed, list):
            suggestions_raw = parsed
        elif isinstance(parsed, dict):
            suggestions_raw = [parsed]
        else:
            return {"ok": False, "error": "Unexpected JSON shape from model", "raw_text": raw_text, "suggestions": []}

        suggestions: List[Dict[str, Any]] = []
        for item in suggestions_raw[:max_suggestions]:
            if not isinstance(item, dict):
                continue
            s = {
                "id": str(item.get("id") or item.get("uid") or item.get("uuid") or uuid.uuid4().hex),
                "primaryText": item.get("primaryText") or item.get("primary_text") or item.get("body") or item.get("text") or "",
                "headline": item.get("headline") or item.get("title") or "",
                "description": item.get("description") or item.get("desc") or "",
                "cta": item.get("cta") or item.get("call_to_action") or "SHOP_NOW",
                "url": item.get("url") or item.get("destination") or None,
                "score": None,
            }
            try:
                if item.get("score") is not None:
                    s["score"] = float(item.get("score"))
            except Exception:
                s["score"] = None
            suggestions.append(s)

        return {"ok": True, "suggestions": suggestions, "raw_text": raw_text, "error": None}
    except Exception as e:
        return {"ok": False, "error": f"Model call failed: {str(e)}", "suggestions": [], "raw_text": raw_text}


@app.route("/api/ai/suggestions", methods=["POST"])
def ai_suggestions_route():
    """
    POST /api/ai/suggestions
    Body: { workspace, imageUrl, selectedImages, context, model? }
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        workspace = payload.get("workspace") if isinstance(payload.get("workspace"), dict) else payload.get("workspace") or None
        image_url = payload.get("imageUrl") or payload.get("image_url") or None
        selected_images = payload.get("selectedImages") or payload.get("selected_images") or []
        context = payload.get("context") or {}
        model = payload.get("model") or os.environ.get("TEXT_MODEL") or None

        current_app.logger.debug("[ai/suggestions] payload keys=%s", list(payload.keys()))

        result = generate_ai_suggestions_using_genai(
            workspace=workspace,
            image_url=image_url,
            selected_images=selected_images,
            context=context,
            model=model,
            max_suggestions=6,
        )

        if not result.get("ok"):
            current_app.logger.error("[ai/suggestions] error: %s", result.get("error"))
            return jsonify(result), 500

        return jsonify({"ok": True, "suggestions": result["suggestions"], "raw_text": result.get("raw_text")}), 200
    except Exception as e:
        current_app.logger.exception("Unexpected error in /api/ai/suggestions")
        return jsonify({"ok": False, "error": str(e)}), 500


def _graph_account_url(ad_account_id):
    # build account node url like: https://graph.facebook.com/v16.0/act_<id>
    base = GRAPH_BASE.rstrip('/')
    ver = FB_API_VERSION.strip().lstrip('/')
    return f"{base}/act_{str(ad_account_id).lstrip('act_')}"

def get_ad_account_for_user(user_id):
    """
    Best-effort resolver: replace with your DB lookup / business logic.
    Expected to return the ad account numeric id (e.g. '785545867549907') or None.
    """
    try:
        # Example: if you have a helper / ORM, call it here.
        # from yourapp.models import User
        # user = User.query.get(user_id)
        # return user.fb_ad_account_id if user else None

        # Fallback: if you keep a mapping dict in-memory for tests:
        USER_AD_MAP = globals().get("USER_AD_MAP")
        if USER_AD_MAP and str(user_id) in USER_AD_MAP:
            return USER_AD_MAP[str(user_id)]

    except Exception:
        logger.exception("get_ad_account_for_user lookup failed; falling back to env var")

    # final fallback: global FB_AD_ACCOUNT_ID env var
    if FB_AD_ACCOUNT_ID:
        return FB_AD_ACCOUNT_ID
    return None


@app.route("/api/account/balance", methods=["GET"])
def account_balance_route():
    """
    Query: /api/account/balance?user_id=<userId>
    Returns JSON:
      { "balance": <int|null>, "amount": <int|null>, "currency": "USD", "raw": {...} }
    balance and amount are in the account currency smallest unit (e.g. cents).
    """
    user_id = request.args.get("user_id")
    ad_account = get_ad_account_for_user(user_id)

    if not ad_account:
        return jsonify({"error": "no_ad_account", "message": "No ad account mapped for user and no fallback configured."}), 400

    if not FB_ACCESS_TOKEN:
        return jsonify({"error": "missing_token", "message": "Server missing FB access token configuration."}), 500

    url = _graph_account_url(ad_account)
    print(url)
    params = {"fields": "balance,amount_spent,spend_cap,currency,account_status", "access_token": FB_ACCESS_TOKEN}

    try:
        resp = requests.get(url, params=params, timeout=15)
    except requests.RequestException as e:
        logger.exception("Graph request failed for ad account %s: %s", ad_account, e)
        return jsonify({"error": "request_failed", "message": str(e)}), 502

    try:
        data = resp.json()
    except ValueError:
        logger.error("Non-JSON response from Graph for %s: %s", url, resp.text[:1000])
        return jsonify({"error": "invalid_response", "raw": resp.text}), 502

    if resp.status_code >= 400 or isinstance(data, dict) and data.get("error"):
        logger.error("Graph API returned error for %s: %s", ad_account, data)
        return jsonify({"error": "graph_error", "details": data}), 502

    # parse balance/amount as ints when possible
    def to_int_or_none(v):
        if v is None:
            return None
        try:
            return int(v)
        except Exception:
            try:
                # sometimes it's a numeric string with decimal - not typical for these fields, but try float->int
                return int(float(v))
            except Exception:
                return None

    balance_small = to_int_or_none(data.get("balance"))
    amount_spent = to_int_or_none(data.get("amount_spent") or data.get("amount") or data.get("amountSpent"))
    spend_cap = to_int_or_none(data.get("spend_cap"))

    result = {
        "balance": balance_small,        # frontend will prefer this
        "amount": amount_spent,          # alias used by your client code
        "spend_cap": spend_cap,
        "currency": data.get("currency"),
        "account_status": data.get("account_status"),
        "raw": data
    }

    # optional: convert to simple human-friendly value if you want (not required by your client)
    # e.g. result["balance_human"] = balance_small / 100.0 if balance_small is not None else None

    return jsonify(result), 200


from sociovia_meta_estimate import _meta_reachestimate, _build_targeting_spec_from_payload, _deterministic_fallback_estimate
_META_ESTIMATE_CACHE: Dict[str, Any] = {}
USE_META_FALLBACK = os.getenv("USE_META_FALLBACK", "true").lower() in ("1", "true", "yes")
_META_CACHE_TTL = 60 * 5  # 5 minutes

@app.route("/api/meta/estimate", methods=["POST", "OPTIONS"])
def meta_estimate():
    """
    Compute a single deterministic or Meta-based estimate only when client sends {"run": true}.
    Accepts payload either flat or with wrapper { "workspace": {...}, ... }.
    """
    
    if request.method == "OPTIONS":
        resp = Response("", status=204)
        resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    try:
        payload = request.get_json(silent=True) or {}
        workspace = payload.get("workspace") if isinstance(payload.get("workspace"), dict) else {}

        # Build cache key from payload minus the 'run' flag
        key_payload = dict(payload)
        key_payload.pop("run", None)
        key = hashlib.sha256(json.dumps(key_payload, sort_keys=True, default=str).encode()).hexdigest()

        now = time.time()
        cached = _META_ESTIMATE_CACHE.get(key)
        wants_run = bool(payload.get("run") is True)

        if not wants_run:
            # If caller didn't ask to run, return cached if available and fresh
            if cached and (now - cached["ts"] < _META_CACHE_TTL):
                current_app.logger.info("meta_estimate: returning cached estimate (no run requested)")
                return jsonify(cached["data"])
            # No cached estimate — instruct client to explicitly request computation
            return jsonify({
                "ok": False,
                "error": "No cached estimate available. Set {\"run\": true} in the request body to compute now."
            }), 400

        # Build targeting_spec (may raise RuntimeError)
        try:
            targeting_spec = _build_targeting_spec_from_payload(payload)
        except RuntimeError as e:
            current_app.logger.error("targeting_spec build error: %s", str(e))
            if USE_META_FALLBACK:
                current_app.logger.info("Falling back to deterministic estimate due to targetingsearch error")
                resp = _deterministic_fallback_estimate(payload)
                _META_ESTIMATE_CACHE[key] = {"ts": now, "data": resp}
                return jsonify(resp)
            return jsonify({"ok": False, "error": "targeting_spec build failed", "meta_raw": str(e)}), 400
        except Exception as e:
            current_app.logger.exception("Failed to build targeting_spec")
            return jsonify({"ok": False, "error": f"Failed to build targeting_spec: {str(e)}"}), 500

        # Call Meta Reach Estimate
        try:
            meta_resp = _meta_reachestimate(targeting_spec)

            # Extract numeric bounds
            lower = meta_resp.get("users_lower_bound") or meta_resp.get("data", {}).get("lower_bound")
            upper = meta_resp.get("users_upper_bound") or meta_resp.get("data", {}).get("upper_bound")

            if lower is None and upper is None:
                est = meta_resp.get("estimate") or meta_resp.get("data", {}).get("estimate")
                if isinstance(est, dict):
                    lower = lower or est.get("lower_bound")
                    upper = upper or est.get("upper_bound")

            try:
                lower_n = int(lower) if lower is not None else None
            except Exception:
                lower_n = None
            try:
                upper_n = int(upper) if upper is not None else None
            except Exception:
                upper_n = None

            if lower_n and upper_n:
                estimated_reach = int((lower_n + upper_n) / 2)
            elif upper_n:
                estimated_reach = int(upper_n)
            elif lower_n:
                estimated_reach = int(lower_n)
            else:
                estimated_reach = int(meta_resp.get("estimate", {}).get("users", 0) or meta_resp.get("users", 0) or 0)

            # derive other metrics similar to existing logic
            budget = payload.get("budget") or workspace.get("budget") or {}
            try:
                amount = float(budget.get("amount") or budget.get("value") or MIN_DAILY_BUDGET)
            except Exception:
                amount = float(MIN_DAILY_BUDGET)

            estimated_daily_impressions = int(max(1, estimated_reach * 2.5))
            estimated_daily_clicks = int(max(0, estimated_daily_impressions * 0.03))
            estimated_conversions_per_week = int(max(0, (estimated_daily_clicks * 7) * 0.02))
            estimated_leads = int(max(0, estimated_conversions_per_week * 0.25))

            est_cpc = (amount / max(1.0, estimated_daily_clicks)) if estimated_daily_clicks > 0 else float(amount)
            est_cpa = (amount / max(1.0, estimated_conversions_per_week)) if estimated_conversions_per_week > 0 else float(amount)

            audience = payload.get("audience") or workspace.get("audience") or {}
            interests = audience.get("interests") or workspace.get("interests") or []
            interest_count = len(interests) if isinstance(interests, list) else 0
            confidence = min(0.95, max(0.25, 0.5 + (interest_count * 0.05)))

            predicted_audience = {
                "location": audience.get("location") or workspace.get("location") or {"country": "Global"},
                "age": audience.get("age") or workspace.get("age") or [18, 65],
                "gender": audience.get("gender") or workspace.get("gender") or "all",
                "interests": interests if isinstance(interests, list) else [],
            }

            resp = {
                "ok": True,
                "estimated_reach": int(estimated_reach),
                "estimated_daily_impressions": estimated_daily_impressions,
                "estimated_daily_clicks": estimated_daily_clicks,
                "estimated_cpc": float(round(est_cpc, 2)),
                "estimated_cpa": float(round(est_cpa, 2)),
                "estimated_conversions_per_week": estimated_conversions_per_week,
                "estimated_leads": estimated_leads,
                "confidence": float(round(confidence, 2)),
                "predicted_audience": predicted_audience,
                "breakdown": {"by_targeting_spec": targeting_spec},
                "meta_raw": meta_resp,
            }

            # Cache & return
            _META_ESTIMATE_CACHE[key] = {"ts": now, "data": resp}
            current_app.logger.info("meta_estimate: Meta computed estimate reach=%s for key=%s", estimated_reach, key[:8])
            return jsonify(resp)

        except RuntimeError as e:
            # includes errors raised by _meta_reachestimate (body included)
            current_app.logger.error("Meta reachestimate error: %s", str(e))
            if USE_META_FALLBACK:
                current_app.logger.info("Falling back to deterministic estimate due to Meta error")
                resp = _deterministic_fallback_estimate(payload)
                # include meta error body for debugging
                resp["meta_raw"] = {"error": str(e)}
                _META_ESTIMATE_CACHE[key] = {"ts": now, "data": resp}
                return jsonify(resp)
            else:
                return jsonify({"ok": False, "error": "Meta reachestimate failed", "meta_raw": str(e)}), 502

        except Exception as exc:
            current_app.logger.exception("Meta estimate failed")
            return jsonify({"ok": False, "error": str(exc)}), 500

    except Exception as exc:
        current_app.logger.exception("meta_estimate failed early")
        return jsonify({"ok": False, "error": str(exc)}), 500

@app.route("/say_hello",methods=["post"])
def say_hello():
    return "hello!!!"














# filename: app.py
# Requirements:
#   pip install google-genai Flask
# Set environment:
#   export GEMINI_API_KEY="your_key_here"

import os
import json
from flask import Flask, request, Response, jsonify
from google import genai
from google.genai import types


# filename: app.py
# Requirements:
#   pip install google-genai Flask
# Set environment:
#   export GEMINI_API_KEY="your_key_here"

import os
from flask import Flask, request, Response, jsonify
from google import genai
from google.genai import types



def genai_stream(prompt_text: str):
    """
    Minimal wrapper around your original genai streaming code.
    Yields plain text chunks (no JSON serialization) so it can be streamed
    directly to the client with minimal transformation.
    """
    client = genai.Client(api_key="AIzaSyDIcAh8KPAafF6Oii2thk2jGGMoRZZDW-c")
    model = "gemini-flash-latest"

    contents = [
        types.Content(
            role="user",
            parts=[ types.Part.from_text(text=prompt_text) ],
        ),
    ]
    tools = [
        types.Tool(url_context=types.UrlContext()),
        types.Tool(code_execution=types.ToolCodeExecution()),
        types.Tool(googleSearch=types.GoogleSearch()),
    ]
    generate_content_config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=0),
        tools=tools,
    )

    for chunk in client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    ):
        if (
            chunk.candidates is None
            or chunk.candidates[0].content is None
            or chunk.candidates[0].content.parts is None
        ):
            continue

        # iterate all parts in this chunk and yield plain text for each available field
        for part in chunk.candidates[0].content.parts:
            # text (most common)
            if getattr(part, "text", None):
                yield part.text
            # executable_code (convert to string)
            if getattr(part, "executable_code", None):
                try:
                    yield str(part.executable_code)
                except Exception:
                    # best-effort fallback
                    yield "<executable_code (unprintable)>\n"
            # code execution result (convert to string)
            if getattr(part, "code_execution_result", None):
                try:
                    yield str(part.code_execution_result)
                except Exception:
                    yield "<code_execution_result (unprintable)>\n"



def serialize_part_text(part):
    """Return text for common part fields (text, executable_code, code_execution_result)."""
    out = ""
    if getattr(part, "text", None):
        out += part.text or ""
    # include code pieces as plain text if present
    if getattr(part, "executable_code", None):
        try:
            out += "\n" + str(part.executable_code)
        except Exception:
            out += "\n<executable_code>\n"
    if getattr(part, "code_execution_result", None):
        try:
            out += "\n" + str(part.code_execution_result)
        except Exception:
            out += "\n<code_execution_result>\n"
    return out

def extract_json_block(full_text: str):
    """
    Try to extract JSON from streaming output.
    Prefer blocks between ```json ... ``` fences.
    Fallback to first {...} .. last } attempt.
    """
    # 1) look for ```json ... ```
    m = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", full_text, re.IGNORECASE)
    if m:
        return m.group(1)
    # 2) try to find first { and matching last } (naive but often works)
    first = full_text.find("{")
    last = full_text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return full_text[first:last+1]
    return None

# app.py
import os
import re
import json
import time
import traceback
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify, Response

# Playwright
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

# google-genai
try:
    from google import genai
    from google.genai import types
except Exception:
    genai = None
    types = None



# Config (prefer environment)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", os.environ.get("GENAI_API_KEY", None))
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", os.environ.get("GENAI_MODEL", "gemini-flash-latest"))
SCRAPER_OUTPUT = os.environ.get("SCRAPER_OUTPUT", "scraper_output")
os.makedirs(SCRAPER_OUTPUT, exist_ok=True)
if boto3 is not None and ACCESS_KEY and SECRET_KEY and SPACE_NAME and SPACE_REGION:
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            endpoint_url=SPACE_ENDPOINT,
        )
        app.logger.info("[startup] S3 client initialized for DigitalOcean Spaces.")
    except Exception as e:
        s3 = None
        app.logger.warning("[startup] Failed to initialize S3 client: %s", str(e))
else:
    s3 = None
    app.logger.warning("[startup] S3 client not configured (missing ACCESS_KEY/SECRET_KEY/SPACE_NAME).")

# --------------------
# Utilities & helpers
# --------------------
def is_valid_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def save_snapshot(screenshot_bytes, url, idx):
    host = re.sub(r"[^\w\d\-_.]", "_", urlparse(url).netloc)
    ts = int(time.time())
    filename = f"{host}_{idx}_{ts}.png"
    path = os.path.join(SCRAPER_OUTPUT, filename)
    with open(path, "wb") as f:
        f.write(screenshot_bytes)
    return path


def extract_basic_metadata_from_page(page):
    out = {"json_ld": None, "og": {}, "title": None, "description": None, "detected_price": None, "images": []}
    # JSON-LD
    try:
        scripts = page.eval_on_selector_all("script[type='application/ld+json']", "nodes => nodes.map(n => n.innerText).filter(Boolean)")
        if scripts:
            parsed = []
            for s in scripts:
                try:
                    parsed.append(json.loads(s))
                except Exception:
                    first = s.find("{")
                    last = s.rfind("}")
                    if first != -1 and last != -1 and last > first:
                        try:
                            parsed.append(json.loads(s[first:last+1]))
                        except Exception:
                            pass
            if parsed:
                out["json_ld"] = parsed
    except Exception:
        pass

    # OpenGraph fallback
    try:
        og_title = page.get_attribute("meta[property='og:title']", "content")
        og_desc = page.get_attribute("meta[property='og:description']", "content")
        og_img = page.get_attribute("meta[property='og:image']", "content")
        if og_title:
            out["og"]["title"] = og_title
            out["title"] = og_title
        if og_desc:
            out["og"]["description"] = og_desc
            out["description"] = og_desc
        if og_img:
            out["og"]["image"] = og_img
            out["images"].append({"url": og_img, "role": "og:image"})
    except Exception:
        pass

    # title/description meta fallback
    try:
        if not out["title"]:
            t = page.query_selector("title")
            if t:
                out["title"] = t.inner_text().strip()
    except Exception:
        pass
    try:
        if not out["description"]:
            m = page.get_attribute("meta[name='description']", "content")
            if m:
                out["description"] = m
    except Exception:
        pass

    # price heuristics
    try:
        price_selectors = ["[itemprop=price]", ".price", ".product-price", ".Price", ".offer-price", ".selling-price"]
        for sel in price_selectors:
            el = page.query_selector(sel)
            if el:
                txt = el.inner_text().strip()
                m = re.search(r"([₹$€£]\s?[\d,]+(?:\.\d{1,2})?)", txt)
                if m:
                    out["detected_price"] = m.group(1)
                    break
    except Exception:
        pass

    # collect some images
    try:
        imgs = page.query_selector_all("img")
        seen = set()
        for img in imgs:
            try:
                src = img.get_attribute("src") or img.get_attribute("data-src") or img.get_attribute("data-lazy-src")
                if not src or src in seen:
                    continue
                seen.add(src)
                dims = img.evaluate("(n) => ({w: n.naturalWidth || n.width || 0, h: n.naturalHeight || n.height || 0})")
                out["images"].append({"url": src, "role": "detail", "width": dims.get("w"), "height": dims.get("h")})
                if len(out["images"]) >= 8:
                    break
            except Exception:
                continue
    except Exception:
        pass

    return out


def extract_json_block(text: str):
    m = re.search(r"```json\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if m:
        return m.group(1)
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return text[first:last+1]
    return None


def serialize_part_text(part) -> str:
    out = ""
    try:
        if getattr(part, "text", None):
            out += part.text or ""
        if getattr(part, "executable_code", None):
            out += "\n" + str(getattr(part, "executable_code"))
        if getattr(part, "code_execution_result", None):
            out += "\n" + str(getattr(part, "code_execution_result"))
    except Exception:
        try:
            out += str(part)
        except Exception:
            pass
    return out

# --------------------
# S3 / Spaces upload helper
# --------------------
def upload_to_spaces(local_path):
    meta = {"local_path": local_path}
    global s3, SPACE_NAME, SPACE_REGION, SPACE_CDN
    if s3 is None:
        meta["error"] = "S3 client not configured; credentials missing"
        return meta, None

    key = f"snapshots/{os.path.basename(local_path)}"
    try:
        extra_args = {"ACL": "public-read", "ContentType": "image/png"}
        s3.upload_file(local_path, SPACE_NAME, key, ExtraArgs=extra_args)
        if SPACE_CDN:
            url = f"{SPACE_CDN.rstrip('/')}/{key}"
        else:
            url = f"https://{SPACE_NAME}.{SPACE_REGION}.digitaloceanspaces.com/{key}"
        meta.update({"s3_key": key, "url": url})
        return meta, {"name": key, "url": url}
    except ClientError as e:
        meta["error"] = str(e)
        return meta, None
    except Exception as e:
        meta["error"] = str(e)
        return meta, None

# --------------------
# Hybrid upload_file: try GENAI client files.upload() -> fallback to Spaces
# --------------------
def upload_file(pth):
    gen_err = None
    # 1) Try GENAI files.upload (Developer client)
    try:
        if getattr(GENAI_CLIENT, "files", None) and callable(getattr(GENAI_CLIENT.files, "upload", None)):
            try:
                uploaded = GENAI_CLIENT.files.upload(file=pth)
                meta = {"local_path": pth, "uploaded_name": getattr(uploaded, "name", None), "id": getattr(uploaded, "name", None)}
                return meta, uploaded
            except Exception as e:
                gen_err = str(e)
        else:
            gen_err = "GENAI_CLIENT.files.upload not available"
    except Exception as e:
        gen_err = str(e)

    # 2) Fallback to Spaces
    try:
        meta_spaces, uploaded_spaces = upload_to_spaces(pth)
        if gen_err:
            meta_spaces["genai_upload_error"] = gen_err
        return meta_spaces, uploaded_spaces
    except Exception as e:
        return {"local_path": pth, "error": f"fallback_upload_failed: {str(e)}", "genai_upload_error": gen_err}, None

# --------------------
# Schema snippet for model prompts
# --------------------
SCHEMA_SNIPPET = r"""
{{
  "status": "ok" | "blocked" | "error",
  "status_reason": null,
  "quick_bullets": [ "", "", "", "" ],
  "product": {{
    "page_type": "product" | "category" | "article" | "landing" | "other",
    "title": null,
    "asin_or_sku": null,
    "brand": null,
    "short_description": null,
    "long_description": null,
    
    "availability": null,
    "seller": {{ "name": null, "seller_url": null, "seller_rating": null }},
    "ratings": {{ "average": null, "count": null }},
    "images": [],
    "variants": null,
    "key_specs": [],
    "bullets": [],
    "technical_table": {{ "raw_html": null, "parsed": [] }},
    "raw_jsonld": null,
    "source_urls": []
  }},
  "ad_campaign_ready": {{ "one_sentence_tagline": null, "top_3_usps": [], "recommended_ad_formats": [], "audience_suggestions": [], "kpi_suggestions": {{}} }},
  "notes_and_confidence": {{ "field_confidence": {{}}, "notes": null }}
}}
"""
import os
import json
import time
import traceback
import logging
from concurrent.futures import ThreadPoolExecutor
from flask import request, jsonify
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# ---- LOGGING CONFIG ----
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.DEBUG),
    format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s",
)
log = logging.getLogger("generatec")

def _trim(value, max_len=400):
    """Helper to safely shorten long logs."""
    try:
        s = json.dumps(value, ensure_ascii=False)
    except Exception:
        s = str(value)
    return s if len(s) < max_len else s[:max_len] + f"...<{len(s)-max_len} more>"

def _timed(label):
    """Context manager to time a section."""
    class Timer:
        def __enter__(self):
            self.start = time.time()
            log.debug(f"[START] {label}")
        def __exit__(self, exc_type, exc_val, tb):
            elapsed = (time.time() - self.start) * 1000
            if exc_val:
                log.error(f"[FAIL] {label} after {elapsed:.1f} ms -> {exc_val}")
            else:
                log.debug(f"[DONE] {label} in {elapsed:.1f} ms")
    return Timer()

# --------------------
# Crawler Function
# --------------------
def crawl_url(url: str, max_snapshots: int = 4):
    log.debug(f"Entered crawl_url(url={url}, max_snapshots={max_snapshots})")

    snapshots_paths, uploaded_files_meta, uploaded_files_objs, snapshots_summary = [], [], [], []
    metadata = {}

    with sync_playwright() as p:
        log.debug("Starting Playwright...")
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])

        context = browser.new_context(viewport={"width": 1200, "height": 900}, user_agent="Mozilla/5.0")
        page = context.new_page()
        log.debug("Browser + page initialized")

        try:
            try:
                with _timed("page.goto(domcontentloaded)"):
                    page.goto(url, wait_until="domcontentloaded", timeout=10000)
                page.wait_for_timeout(1000)
                log.debug("Page loaded (domcontentloaded)")
            except PlaywrightTimeoutError as e:
                log.warning(f"Timeout on domcontentloaded: {e}. Retrying full load.")
                with _timed("page.goto(load)"):
                    page.goto(url, wait_until="load", timeout=5000)

            with _timed("extract_basic_metadata_from_page"):
                metadata = extract_basic_metadata_from_page(page)
            log.debug(f"Metadata extracted: {_trim(metadata.keys())}")

            viewport_h = page.evaluate("() => window.innerHeight")
            scroll_y = 0
            scroll_height = page.evaluate("() => document.documentElement.scrollHeight")
            log.debug(f"viewport_h={viewport_h}, scroll_height={scroll_height}")
            snaps = 0

            while snaps < max_snapshots and scroll_y < scroll_height:
                log.debug(f"[SNAP {snaps}] scroll_y={scroll_y}")
                page.wait_for_timeout(200)
                with _timed(f"screenshot #{snaps}"):
                    shot = page.screenshot(type="png", full_page=False)
                log.debug(f"[SNAP {snaps}] screenshot bytes={len(shot)}")

                local_path = save_snapshot(shot, url, snaps)
                log.debug(f"[SNAP {snaps}] saved to {local_path}")

                snapshots_paths.append(local_path)
                snapshots_summary.append({
                    "index": snaps, "y": int(scroll_y), "file": os.path.basename(local_path)
                })
                snaps += 1
                scroll_y += int(viewport_h * 0.8)
                page.evaluate(f"window.scrollTo(0, {scroll_y});")
                scroll_height = page.evaluate("() => document.documentElement.scrollHeight")
                page.wait_for_timeout(150)
        finally:
            try:
                browser.close()
                log.debug("Browser closed successfully")
            except Exception as e:
                log.warning(f"Error closing browser: {e}")

    if snapshots_paths:
        log.debug(f"Uploading {len(snapshots_paths)} snapshots in parallel")
        with ThreadPoolExecutor(max_workers=min(4, len(snapshots_paths))) as executor:
            futures = [executor.submit(upload_file, pth) for pth in snapshots_paths]
            for idx, fut in enumerate(futures):
                try:
                    with _timed(f"upload_file #{idx}"):
                        meta, uploaded = fut.result()
                    uploaded_files_meta.append(meta)
                    if uploaded:
                        uploaded_files_objs.append(uploaded)
                    log.debug(f"[UPLOAD {idx}] meta={_trim(meta)} uploaded={bool(uploaded)}")
                except Exception as e:
                    log.error(f"[UPLOAD {idx}] failed: {e}")

    out = {
        "snapshots_paths": snapshots_paths,
        "snapshots_summary": snapshots_summary,
        "uploaded_files_meta": uploaded_files_meta,
        "uploaded_files_objs": uploaded_files_objs,
        "metadata": metadata,
    }
    log.debug(f"crawl_url completed -> {len(snapshots_paths)} paths, {len(uploaded_files_meta)} metas")
    return out

# ---------- Vertex AI + std imports (put near the top of your file) ----------
import os
import json
import traceback
import logging
from flask import request, jsonify
from google import genai
from google.auth.exceptions import DefaultCredentialsError

log = logging.getLogger("generatec")


import os
import json
import traceback
import logging
from flask import request, jsonify
from google import genai
from google.auth.exceptions import DefaultCredentialsError

log = logging.getLogger("generatec")


GENAI_CLIENT = init_client()


# ======================================================
# /generatec Endpoint
# ======================================================
@app.route("/generatec", methods=["POST"])
def generatec():
    log.info("Entered /generatec endpoint")

    try:
        # Parse body safely
        log.debug("Parsing request body...  debug_level=1")
        body = request.get_json(silent=True)
        if body is None:
            raw = request.get_data(as_text=True)
            body = json.loads(raw) if raw else {}
        log.debug(f"Parsed body={_trim(body)}")

        url = (body.get("url") or "").strip()
        max_snapshots_raw = body.get("max_snapshots", 4)
        try:
            max_snapshots = int(max_snapshots_raw)
        except Exception:
            log.warning(f"Invalid max_snapshots={max_snapshots_raw}, defaulting to 4")
            max_snapshots = 4

        if url and not url.startswith(("http://", "https://")):
            url = "https://" + url
            log.debug(f"Normalized URL to {url}")

        if not url or not isinstance(url, str) or not is_valid_url(url):
            log.warning("Validation failed: missing/invalid 'url'")
            return jsonify({"ok": False, "error": "missing/invalid 'url'"}), 400

        # Crawl
        with _timed("crawl_url"):
            crawl_res = crawl_url(url, max_snapshots=max_snapshots)
        metadata = crawl_res.get("metadata", {})
        snapshots_summary = crawl_res.get("snapshots_summary", [])
        log.debug(f"crawl_res keys={list(crawl_res.keys())}")

        # Schema
        schema_snippet = SCHEMA_SNIPPET if "SCHEMA_SNIPPET" in globals() else None
        if not schema_snippet:
            log.error("SCHEMA_SNIPPET missing in globals()")
            return jsonify({"ok": False, "error": "server_misconfig"}), 500

        # Build model prompt
        prompt_text = f"""SYSTEM: You are a grounded web researcher + ad-campaign suggester.
            INPUT:
            page_url: {url}
            json_ld: {json.dumps(metadata.get("json_ld"), ensure_ascii=False) if metadata.get("json_ld") else "null"}
            og_meta: {json.dumps(metadata.get("og", {}), ensure_ascii=False)}
            title: {json.dumps(metadata.get("title"), ensure_ascii=False)}
            description: {json.dumps(metadata.get("description"), ensure_ascii=False)}
            images: {json.dumps(metadata.get("images", []), ensure_ascii=False)}
            snapshots_summary: {json.dumps(snapshots_summary, ensure_ascii=False)}

            TASK:
            Analyze the page thoroughly and return EXACTLY ONE fenced JSON block ```json ... ``` following this schema:
            {schema_snippet}

            Rules:
            - Use only provided structured inputs.
            - Do not invent prices or specs.
            - Return valid JSON only inside one fenced block.
            """
        log.debug(f"Prompt built (trimmed): {_trim(prompt_text, max_len=600)}")

        # Collect snapshot URLs
        snapshot_urls = []
        for meta in crawl_res.get("uploaded_files_meta", []):
            if isinstance(meta, dict) and meta.get("url"):
                snapshot_urls.append(meta["url"])
            elif isinstance(meta, dict) and meta.get("uploaded_name"):
                snapshot_urls.append(f"file:{meta['uploaded_name']}")
        for path in crawl_res.get("snapshots_paths", []):
            if isinstance(path, str):
                if path.startswith(("http://", "https://", "file:")):
                    snapshot_urls.append(path)
                else:
                    snapshot_urls.append(f"file:{os.path.basename(path)}")
        snapshot_urls = list(dict.fromkeys(snapshot_urls))
        log.debug(f"snapshot_urls={snapshot_urls}")

        if snapshot_urls:
            prompt_text += "\n\nSNAPSHOT_URLS:\n" + "\n".join(snapshot_urls)
            prompt_text += "\n\nNOTE: include snapshot references in product.source_urls for provenance."

        # ---------------- Vertex AI model call ----------------
        contents = [{"role": "user", "parts": [{"text": prompt_text}]}]
        try:
            cfg = {"candidate_count": 1}
            with _timed("GENAI_CLIENT.generate_content"):
                resp = GENAI_CLIENT.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=contents,
                    config=cfg
                )
        except Exception as e:
            log.error(f"GenAI call failed: {e}\n{traceback.format_exc()}")
            return jsonify({"ok": False, "error": "genai_call_failed", "detail": str(e)}), 500
        # -------------------------------------------------------

        # Extract text output
        model_text = None
        try:
            cand = getattr(resp, "candidates", [None])[0]
            if cand and getattr(cand, "content", None) and getattr(cand.content, "parts", None):
                pieces = [getattr(p, "text", "") for p in cand.content.parts if getattr(p, "text", None)]
                model_text = "\n".join(pieces).strip()
            log.debug(f"model_text preview: {_trim(model_text, max_len=400)}")
        except Exception as e:
            log.warning(f"Error parsing model response: {e}")

        # Parse fenced JSON block
        parsed_json = None
        if model_text:
            with _timed("extract_json_block"):
                block = extract_json_block(model_text)
                log.info(f"Extracted JSON block: {block}")
                if block:
                    try:
                        parsed_json = json.loads(block)
                        log.debug("JSON successfully parsed from model output")
                    except Exception as e:
                        log.warning(f"JSON parse failed: {e}")

        # Merge provenance
        if parsed_json and isinstance(parsed_json, dict):
            prod = parsed_json.get("product") or {}
            existing_srcs = prod.get("source_urls") or []
            if isinstance(existing_srcs, str):
                existing_srcs = [existing_srcs]
            merged = list(dict.fromkeys(existing_srcs + snapshot_urls))
            prod["source_urls"] = merged
            parsed_json["product"] = prod
            log.debug(f"Merged product.source_urls={merged}")
        else:
            parsed_json = {"product": {"source_urls": snapshot_urls}}
            log.debug("Model returned no JSON; built minimal parsed_json")

        # Final response
        response_payload = {
            "ok": True,
            "page_url": url,
            "snapshots": crawl_res.get("snapshots_paths", []),
            "snapshot_urls": snapshot_urls,
            "uploaded_files_meta": crawl_res.get("uploaded_files_meta", []),
            "extracted_metadata": metadata,
            "model_text": model_text,
            "parsed_json": parsed_json,
        }

        log.info(f"/generatec success for {url}")
        return jsonify(response_payload)

    except Exception as e:
        
        log.error(f"Unhandled error in generatec: {e}\n{traceback.format_exc()}")
        return jsonify({
            "ok": False,
            "error": "internal",
            "detail": str(e),
            "trace": traceback.format_exc()
        }), 500

# --------------------
# Streaming endpoint (optional)
# --------------------
@app.route("/generate-by-link", methods=["POST", "OPTIONS"])
def generate_by_link():
    body = request.get_json(silent=True) or {}
    url = body.get("url") or body.get("link") or body.get("prompt")
    if not url or not isinstance(url, str):
        return jsonify({"error": "missing or invalid 'url' in request body"}), 400
    if not is_valid_url(url):
        return jsonify({"error": "invalid url scheme or host"}), 400

    prompt = f"""SYSTEM: You are a grounded web researcher. Use only verifiable information from the target page and directly linked product pages. Do NOT hallucinate.

USER: Fetch and analyze: {url}
Return JSON following this schema exactly:
{SCHEMA_SNIPPET}
"""

    try:
        try:
            cfg = types.GenerateContentConfig(candidate_count=1)
        except Exception:
            cfg = {"candidate_count": 1}
        contents = [types.Content(role="user", parts=[types.Part.from_text(text=prompt)])]
    except Exception as e:
        return jsonify({"error": "genai_setup_failed", "detail": str(e)}), 500

    def event_stream():
        buffer = ""
        try:
            for chunk in GENAI_CLIENT.models.generate_content_stream(model=GEMINI_MODEL, contents=contents, config=cfg):
                if not chunk or not getattr(chunk, "candidates", None):
                    continue
                cand = chunk.candidates[0]
                if not getattr(cand, "content", None) or not getattr(cand.content, "parts", None):
                    continue
                for part in cand.content.parts:
                    text_piece = serialize_part_text(part)
                    if not text_piece:
                        continue
                    buffer += text_piece
                    payload = {"type": "partial", "text": text_piece}
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

            json_block = extract_json_block(buffer)
            if json_block:
                try:
                    parsed = json.loads(json_block)
                    payload = {"type": "result", "json": parsed}
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                except Exception as e:
                    payload = {"type": "error", "message": "Failed to parse JSON from model output", "detail": str(e)}
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            else:
                payload = {"type": "error", "message": "No JSON block found in model output", "detail": "Model output did not contain a fenced JSON block"}
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
        except Exception as exc:
            tb = traceback.format_exc()
            payload = {"type": "error", "message": "Streaming error", "detail": str(exc), "trace": tb}
            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

    headers = {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }
    return Response(event_stream(), headers=headers)


import uuid
import time
import mimetypes

# Helper: save inline image data from model response inline_data object
def _save_inline_image_inline_data(inline_data, prefix="gen"):
    """
    inline_data: object with attributes mime_type (str) and data (bytes)
    returns saved filename (relative to SCRAPER_OUTPUT)
    """
    try:
        ext = mimetypes.guess_extension(getattr(inline_data, "mime_type", "") or "") or ".png"
    except Exception:
        ext = ".png"
    ts = time.strftime("%Y%m%dT%H%M%S")
    fname = f"{prefix}_{ts}_{uuid.uuid4().hex[:8]}{ext}"
    local_path = os.path.join(SCRAPER_OUTPUT, fname)
    try:
        data_buf = getattr(inline_data, "data", None)
        if not data_buf:
            # Some SDKs expose inline_data.data as bytes-like, others may use memoryview
            data_buf = bytes(inline_data.data) if getattr(inline_data, "data", None) else None
        with open(local_path, "wb") as fw:
            fw.write(data_buf)
        app.logger.info(f"[save_inline] wrote {local_path}")
        return fname
    except Exception as e:
        app.logger.exception("failed to save inline image")
        raise

# Helper: streaming wrapper -> returns list of saved filenames OR raises
def _generate_and_save_streaming(model_id, contents, config):
    """
    Use GENAI_CLIENT.models.generate_content_stream to stream results and save inline images.
    Returns: dict with keys:
       - saved_files: [filenames]
       - text_accum: concatenated text parts
    """
    if not getattr(GENAI_CLIENT.models, "generate_content_stream", None):
        raise RuntimeError("streaming_not_supported")

    saved = []
    text_accum = ""
    try:
        for chunk in GENAI_CLIENT.models.generate_content_stream(model=model_id, contents=contents, config=config):
            # chunk may be None or missing candidates
            if not chunk or not getattr(chunk, "candidates", None):
                continue
            cand = chunk.candidates[0]
            if not getattr(cand, "content", None) or not getattr(cand.content, "parts", None):
                continue
            for part in cand.content.parts:
                # If inline image bytes present
                inline = getattr(part, "inline_data", None)
                if inline and getattr(inline, "data", None):
                    # save
                    try:
                        fname = _save_inline_image_inline_data(inline, prefix="gen_stream")
                        saved.append(fname)
                    except Exception as e:
                        app.logger.exception("save inline failed")
                else:
                    # append textual pieces (some parts may be text)
                    txt = getattr(part, "text", None)
                    if txt:
                        text_accum += txt
        return {"saved_files": saved, "text_accum": text_accum}
    except Exception as e:
        app.logger.exception("streaming generate failed")
        raise

# --------------------
# Updated: generate-creatives-from-base (streaming-enabled)
# --------------------
@app.route("/api/v1/generate-creatives-from-base", methods=["POST"])
def generate_creatives_from_base():
    if GENAI_CLIENT is None:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    try:
        content_type = request.content_type or ""
        prompt = ""
        file_bytes_list = []
        mime_types = []
        file_uris = []
        count = 1
        aspect_ratio = None

        if content_type.startswith("multipart/form-data"):
            prompt = request.form.get("prompt") or ""
            aspect_ratio = request.form.get("aspect_ratio")
            count = int(request.form.get("count") or 1)
            files = request.files.getlist("files") or request.files.getlist("files[]") or []
            if not files:
                single = request.files.get("file")
                if single:
                    files = [single]
            for f in files:
                if not f:
                    continue
                b = f.read()
                if not b:
                    continue
                if len(b) > MAX_UPLOAD_BYTES:
                    return jsonify({"success": False, "error": "file_too_large"}), 400
                file_bytes_list.append(b)
                mime_types.append(f.mimetype or mimetypes.guess_type(getattr(f, "filename", "file"))[0] or "image/png")
            file_uris += request.form.getlist("file_uris") or request.form.getlist("image_urls") or []
        else:
            data = request.get_json() or {}
            prompt = data.get("prompt") or ""
            aspect_ratio = data.get("aspect_ratio")
            count = int(data.get("count", 1))
            file_uris = data.get("file_uris") or data.get("image_urls") or []
            fb64_list = data.get("file_bytes_list") or []
            mime_list = data.get("mime_types") or []
            for i, fb64 in enumerate(fb64_list):
                try:
                    b = base64.b64decode(fb64)
                except Exception:
                    b = None
                if b:
                    if len(b) > MAX_UPLOAD_BYTES:
                        return jsonify({"success": False, "error": "file_too_large"}), 400
                    file_bytes_list.append(b)
                    mime_types.append(mime_list[i] if i < len(mime_list) else "image/png")

        if not prompt:
            return jsonify({"success": False, "error": "prompt_required"}), 400
        if not file_bytes_list and not file_uris:
            return jsonify({"success": False, "error": "no_input_images_provided"}), 400

        # Build ad planner prompt
        planner_prompt = f"""SYSTEM: You are an ad creative planner. Return a JSON block with:
{{"tagline":"...","caption":"...","hashtags":["..."],"cta":"...","themes":[{{"title":"...","visual_prompt":"...","aspect_ratio_hint":"1:1"}}]}}
INPUT: {prompt}
Return only the JSON block (fenced or plain).
"""
        ad_plan = None
        try:
            try:
                cfg = types.GenerateContentConfig(candidate_count=1)
            except Exception:
                cfg = {"candidate_count": 1}
            contents = [types.Content(role="user", parts=[types.Part.from_text(text=planner_prompt)])] if types else [{"role":"user","parts":[{"text":planner_prompt}]}]
            resp = GENAI_CLIENT.models.generate_content(model=TEXT_MODEL, contents=contents, config=cfg)
            raw = extract_text_from_response(resp)
            if raw:
                jblk = extract_json_block(raw)
                if jblk:
                    ad_plan = json.loads(jblk)
                else:
                    ad_plan = parse_json_from_model_text(raw, retry_forced=False) if callable(globals().get("parse_json_from_model_text")) else None
        except Exception:
            app.logger.exception("planner failed; falling back")

        if not ad_plan:
            ad_plan = {
                "tagline": (prompt.split(".")[0] if prompt else "Great product")[:80],
                "caption": (prompt[:200] + "...") if len(prompt) > 200 else prompt,
                "hashtags": ["#new", "#sale"],
                "cta": "Shop now",
                "themes": [{"title":"Hero shot","visual_prompt": prompt, "aspect_ratio_hint": aspect_ratio or "1:1"}]
            }

        results = []

        def _build_meta(local_path, fn):
            meta = {"local_path": local_path, "filename": fn}
            try:
                if s3 is not None:
                    meta_spaces, uploaded_spaces = upload_to_spaces(local_path)
                    meta.update(meta_spaces or {})
                    if uploaded_spaces and uploaded_spaces.get("url"):
                        meta["url"] = uploaded_spaces["url"]
                else:
                    meta["url"] = f"file://{local_path}"
            except Exception as e:
                meta["upload_error"] = str(e)
                meta["url"] = f"file://{local_path}"
            return meta

        # generate for uploaded bytes (prefer streaming image generation)
        for i, b in enumerate(file_bytes_list):
            base_name = f"uploaded_file_{i+1}"
            per_base = {"base": base_name, "generated": []}
            for c in range(count):
                theme = ad_plan.get("themes", [{}])[c % max(1, len(ad_plan.get("themes", [])))]
                visual_prompt = theme.get("visual_prompt") or prompt
                final_prompt = f"{visual_prompt}\n\nContext: {prompt}\nTagline: {ad_plan.get('tagline')}\nCaption: {ad_plan.get('caption')}\nCTA: {ad_plan.get('cta')}\nPlace product prominently."

                # Build streaming contents: include image part (bytes) then prompt part
                streaming_done = False
                if getattr(GENAI_CLIENT.models, "generate_content_stream", None):
                    try:
                        parts = []
                        # include the bytes as Part if Part.from_bytes exists
                        if Part:
                            parts.append(Part.from_bytes(data=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png"))
                        # include the prompt as a content part
                        parts.append(types.Part.from_text(text=final_prompt) if getattr(types.Part, "from_text", None) else types.Part.from_text(text=final_prompt))
                        contents = [types.Content(role="user", parts=parts)]
                        cfg = types.GenerateContentConfig(response_modalities=["IMAGE","TEXT"], candidate_count=1)
                        stream_res = _generate_and_save_streaming(model_id=MODEL_ID, contents=contents, config=cfg)
                        saved_files = stream_res.get("saved_files", [])
                        # Map saved files to meta
                        for fn in saved_files:
                            local_path = os.path.join(SCRAPER_OUTPUT, fn)
                            meta = _build_meta(local_path, fn)
                            per_base["generated"].append(meta)
                        streaming_done = True
                    except Exception:
                        app.logger.exception("streaming generation for bytes failed; will fallback to helper")

                if streaming_done:
                    continue

                # fallback: use existing helper
                if "_generate_image_with_input_image" not in globals() or not callable(globals()["_generate_image_with_input_image"]):
                    return jsonify({"success": False, "error": "_generate_image_with_input_image_not_implemented"}), 501
                try:
                    img_resp = _generate_image_with_input_image(final_prompt, file_bytes=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png", file_uri=None, model_id=MODEL_ID, aspect_ratio=theme.get("aspect_ratio_hint") or aspect_ratio)
                except Exception as e:
                    per_base["generated"].append({"error": "image_generation_failed", "details": str(e)})
                    continue

                try:
                    saved = save_images_from_response(img_resp, prefix=f"base_{i+1}_c{c}")
                except NotImplementedError:
                    return jsonify({"success": False, "error": "save_images_from_response_not_implemented"}), 501
                except Exception as e:
                    per_base["generated"].append({"error": "save_failed", "details": str(e)})
                    continue

                for fn in saved:
                    local_path = os.path.join(SCRAPER_OUTPUT, fn)
                    meta = _build_meta(local_path, fn)
                    per_base["generated"].append(meta)

            results.append(per_base)

        # generate for file URIs
        for i, uri in enumerate(file_uris):
            per_base = {"base": uri, "generated": []}
            for c in range(count):
                theme = ad_plan.get("themes", [{}])[c % max(1, len(ad_plan.get("themes", [])))]
                visual_prompt = theme.get("visual_prompt") or prompt
                final_prompt = f"{visual_prompt}\n\nContext: {prompt}\nTagline: {ad_plan.get('tagline')}\nCaption: {ad_plan.get('caption')}\nCTA: {ad_plan.get('cta')}\nPlace product prominently."

                streaming_done = False
                if getattr(GENAI_CLIENT.models, "generate_content_stream", None):
                    try:
                        parts = []
                        if Part:
                            parts.append(Part.from_uri(file_uri=uri))
                        parts.append(types.Part.from_text(text=final_prompt))
                        contents = [types.Content(role="user", parts=parts)]
                        cfg = types.GenerateContentConfig(response_modalities=["IMAGE","TEXT"], candidate_count=1)
                        stream_res = _generate_and_save_streaming(model_id=MODEL_ID, contents=contents, config=cfg)
                        saved_files = stream_res.get("saved_files", [])
                        for fn in saved_files:
                            local_path = os.path.join(SCRAPER_OUTPUT, fn)
                            meta = _build_meta(local_path, fn)
                            per_base["generated"].append(meta)
                        streaming_done = True
                    except Exception:
                        app.logger.exception("streaming generation for uri failed; falling back")

                if streaming_done:
                    continue

                # fallback
                if "_generate_image_with_input_image" not in globals() or not callable(globals()["_generate_image_with_input_image"]):
                    return jsonify({"success": False, "error": "_generate_image_with_input_image_not_implemented"}), 501
                try:
                    img_resp = _generate_image_with_input_image(final_prompt, file_bytes=None, mime_type=None, file_uri=uri, model_id=MODEL_ID, aspect_ratio=theme.get("aspect_ratio_hint") or aspect_ratio)
                except Exception as e:
                    per_base["generated"].append({"error": "image_generation_failed", "details": str(e)})
                    continue

                try:
                    saved = save_images_from_response(img_resp, prefix=f"base_uri_{i+1}_c{c}")
                except NotImplementedError:
                    return jsonify({"success": False, "error": "save_images_from_response_not_implemented"}), 501
                except Exception as e:
                    per_base["generated"].append({"error": "save_failed", "details": str(e)})
                    continue

                for fn in saved:
                    local_path = os.path.join(SCRAPER_OUTPUT, fn)
                    meta = _build_meta(local_path, fn)
                    per_base["generated"].append(meta)

            results.append(per_base)

        return jsonify({"success": True, "ad_plan": ad_plan, "results": results}), 200

    except Exception as exc:
        app.logger.exception("generate_creatives_from_base error")
        return jsonify({"success": False, "error": "internal", "detail": str(exc), "trace": traceback.format_exc()}), 500


# --------------------
# Updated: generate-creatives (streaming-enabled)
# --------------------
@app.route("/api/v1/generate-creatives", methods=["POST"])
def generate_creatives():
    if GENAI_CLIENT is None:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    # debug - keep as you had
    print(request.get_json())

    try:
        content_type = request.content_type or ""
        prompt = ""
        mode = "per_image"
        aspect_ratio = None
        count = 1
        file_bytes_list = []
        mime_types = []
        file_uris = []

        # helper: normalize product.source_urls -> list of public URLs (skip index 0)
        def normalize_product_source_urls(product_obj):
            out = []
            try:
                srcs = product_obj.get("source_urls") or []
                # skip the first index (0th) as requested
                for s in srcs[1:]:
                    if not s:
                        continue
                    # already a public URL
                    if s.startswith("http://") or s.startswith("https://"):
                        out.append(s)
                        continue
                    # handle file:NAME => map to SPACE_CDN if available or local outputs path
                    if s.startswith("file:"):
                        fname = s.split(":", 1)[1]
                        # if uploaded to spaces and SPACE_CDN configured, prefer CDN path
                        if globals().get("SPACE_CDN"):
                            out.append(f"{SPACE_CDN.rstrip('/')}/{fname}")
                        elif globals().get("SPACE_NAME") and globals().get("SPACE_REGION"):
                            out.append(f"https://{SPACE_NAME}.{SPACE_REGION}.digitaloceanspaces.com/{fname}")
                        else:
                            # fallback to local /outputs mapping (served by your app)
                            base = request.url_root.rstrip("/")
                            out.append(f"{base}/outputs/{fname}")
                        continue
                    # some amazon urls may be schemeless like "//..."; fix to https:
                    if s.startswith("//"):
                        out.append("https:" + s)
                        continue
                    # fallback: treat as relative filename -> map to outputs
                    out.append(s)
            except Exception:
                app.logger.exception("normalize_product_source_urls failed")
            return out

        if content_type.startswith("multipart/form-data"):
            prompt = request.form.get("prompt") or ""
            mode = request.form.get("mode") or "per_image"
            aspect_ratio = request.form.get("aspect_ratio")
            count = int(request.form.get("count") or 1)
            files = request.files.getlist("files") or request.files.getlist("files[]") or []
            for f in files:
                if not f:
                    continue
                b = f.read()
                if len(b) > MAX_UPLOAD_BYTES:
                    return jsonify({"success": False, "error": "file_too_large"}), 400
                file_bytes_list.append(b)
                mime_types.append(f.mimetype or mimetypes.guess_type(getattr(f, "filename", "file"))[0] or "image/png")
            file_uris = request.form.getlist("file_uris") or request.form.getlist("image_urls") or []
        else:
            body = request.get_json() or {}
            prompt = body.get("prompt") or ""
            mode = body.get("mode") or "per_image"
            aspect_ratio = body.get("aspect_ratio")
            count = int(body.get("count", 1))
            file_uris = body.get("file_uris") or body.get("image_urls") or []
            fb64_list = body.get("file_bytes_list") or []
            mime_types = body.get("mime_types") or []
            decoded_bytes = []
            for i, fb64 in enumerate(fb64_list):
                try:
                    decoded_bytes.append(base64.b64decode(fb64))
                except Exception:
                    decoded_bytes.append(None)
            file_bytes_list = decoded_bytes

            # --- NEW: if no explicit file_uris provided, try product.source_urls (skip index 0) ---
            if (not file_uris) and isinstance(body.get("product"), dict):
                prod = body.get("product")
                derived = normalize_product_source_urls(prod)
                if derived:
                    # append only the derived ones; this will be used as the base images
                    file_uris = derived

        # If still no prompt, fail early
        if not prompt:
            return jsonify({"success": False, "error": "prompt_required"}), 400

        # Build ad plan (same as above)
        planner_prompt = f"""SYSTEM: You are an ad creative planner. Return JSON: {{'tagline','caption','hashtags','cta','themes':[{{'title','visual_prompt','aspect_ratio_hint'}}]}}
INPUT: {prompt}
Return only JSON.
"""
        ad_plan = None
        try:
            try:
                cfg = types.GenerateContentConfig(candidate_count=1)
            except Exception:
                cfg = {"candidate_count": 1}
            contents = [types.Content(role="user", parts=[types.Part.from_text(text=planner_prompt)])] if types else [{"role":"user","parts":[{"text":planner_prompt}]}]
            resp = GENAI_CLIENT.models.generate_content(model=TEXT_MODEL, contents=contents, config=cfg)
            raw = extract_text_from_response(resp)
            if raw:
                jblk = extract_json_block(raw)
                if jblk:
                    ad_plan = json.loads(jblk)
                else:
                    ad_plan = parse_json_from_model_text(raw, retry_forced=False) if callable(globals().get("parse_json_from_model_text")) else None
        except Exception:
            app.logger.exception("planner failed; fallback")

        if not ad_plan:
            ad_plan = {"tagline": prompt.split(".")[0][:80], "caption": prompt[:200], "hashtags": ["#new"], "cta": "Shop now", "themes":[{"title":"Default","visual_prompt":prompt,"aspect_ratio_hint":aspect_ratio or "1:1"}]}

        # BLEND mode (same logic as before) ...
        if mode == "blend":
            parts = []
            if Part is None:
                return jsonify({"success": False, "error": "genai_part_not_available"}), 500
            for i, b in enumerate(file_bytes_list):
                if not b:
                    continue
                parts.append(Part.from_bytes(data=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png"))
            for uri in file_uris:
                parts.append(Part.from_uri(file_uri=uri))
            if not parts:
                return jsonify({"success": False, "error": "no_inputs_for_blend"}), 400

            # Try streaming first
            streaming_saved = []
            if getattr(GENAI_CLIENT.models, "generate_content_stream", None):
                try:
                    visual_prompt = (
                        ad_plan.get("themes", [{"visual_prompt": prompt}])[0]
                        .get("visual_prompt", prompt)
                        if isinstance(ad_plan, dict)
                        else prompt
                    )
                    final_text = f"{visual_prompt}\n\nContext: {prompt}\nTagline: {ad_plan.get('tagline', '') if isinstance(ad_plan, dict) else ''}"
                    parts_list = parts + [types.Part.from_text(text=final_text)]
                    contents = [types.Content(role="user", parts=parts_list)]
                    cfg = types.GenerateContentConfig(response_modalities=["IMAGE","TEXT"], candidate_count=1)
                    stream_res = _generate_and_save_streaming(model_id=MODEL_ID, contents=contents, config=cfg)
                    for fn in stream_res.get("saved_files", []):
                        local_path = os.path.join(SCRAPER_OUTPUT, fn)
                        if s3 is not None:
                            meta_spaces, uploaded_spaces = upload_to_spaces(local_path)
                            meta = meta_spaces or {"local_path": local_path}
                            if uploaded_spaces and uploaded_spaces.get("url"):
                                meta["url"] = uploaded_spaces["url"]
                            else:
                                meta["url"] = meta.get("url") or f"file://{local_path}"
                        else:
                            meta = {"local_path": local_path, "url": f"file://{local_path}"}
                        streaming_saved.append({"filename": fn, "url": meta.get("url"), "meta": meta})
                    return jsonify({"success": True, "mode": "blend", "ad_plan": ad_plan, "items": streaming_saved}), 200
                except Exception:
                    app.logger.exception("blend streaming failed; falling back")

            # fallback to helper
            if "_generate_image_with_input_images" not in globals() or not callable(globals()["_generate_image_with_input_images"]):
                return jsonify({"success": False, "error": "_generate_image_with_input_images_not_implemented"}), 501
            final_prompt = f"{ad_plan.get('themes',[{'visual_prompt':prompt}])[0].get('visual_prompt')}\n\nContext: {prompt}\nTagline:{ad_plan.get('tagline')}\nCaption:{ad_plan.get('caption')}\nCTA:{ad_plan.get('cta')}\nBlend the provided references into a single ad creative."
            try:
                img_resp = _generate_image_with_input_images(final_prompt, parts, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
            except Exception as e:
                return jsonify({"success": False, "error": "image_generation_failed", "details": str(e)}), 500
            try:
                saved = save_images_from_response(img_resp, prefix="blend")
            except NotImplementedError:
                return jsonify({"success": False, "error": "save_images_from_response_not_implemented"}), 501
            items = []
            for fn in saved:
                local_path = os.path.join(SCRAPER_OUTPUT, fn)
                try:
                    if s3 is not None:
                        meta_spaces, uploaded_spaces = upload_to_spaces(local_path)
                        meta = meta_spaces or {"local_path": local_path}
                        if uploaded_spaces and uploaded_spaces.get("url"):
                            meta["url"] = uploaded_spaces["url"]
                        else:
                            meta["url"] = meta.get("url") or f"file://{local_path}"
                    else:
                        meta = {"local_path": local_path, "url": f"file://{local_path}"}
                except Exception as e:
                    meta = {"local_path": local_path, "upload_error": str(e), "url": f"file://{local_path}"}
                items.append({"filename": fn, "url": meta.get("url"), "meta": meta})
            return jsonify({"success": True, "mode": "blend", "ad_plan": ad_plan, "items": items}), 200

        # PER_IMAGE mode -> same as before (uses file_uris derived above if present)
        aggregated = []

        def _upload_local_and_build(local_fn):
            local_path = os.path.join(SCRAPER_OUTPUT, local_fn)
            try:
                if s3 is not None:
                    meta_spaces, uploaded_spaces = upload_to_spaces(local_path)
                    meta = meta_spaces or {"local_path": local_path}
                    if uploaded_spaces and uploaded_spaces.get("url"):
                        meta["url"] = uploaded_spaces["url"]
                    else:
                        meta["url"] = meta.get("url") or f"file://{local_path}"
                else:
                    meta = {"local_path": local_path, "url": f"file://{local_path}"}
            except Exception as e:
                meta = {"local_path": local_path, "upload_error": str(e), "url": f"file://{local_path}"}
            return meta

        # generate for uploaded bytes
        for i, b in enumerate(file_bytes_list):
            per_base = {"base": f"uploaded_file_{i+1}", "generated": []}
            for c in range(count):
                theme = ad_plan.get("themes", [{}])[c % max(1, len(ad_plan.get("themes", [])))]
                visual_prompt = theme.get("visual_prompt") or prompt
                final_prompt = f"{visual_prompt}\n\nContext: {prompt}\nTagline: {ad_plan.get('tagline')}\nCaption: {ad_plan.get('caption')}\nCTA: {ad_plan.get('cta')}\nPlace the product prominently."

                streaming_done = False
                if getattr(GENAI_CLIENT.models, "generate_content_stream", None):
                    try:
                        parts = []
                        parts.append(Part.from_bytes(data=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png"))
                        parts.append(types.Part.from_text(text=final_prompt))
                        contents = [types.Content(role="user", parts=parts)]
                        cfg = types.GenerateContentConfig(response_modalities=["IMAGE","TEXT"], candidate_count=1)
                        stream_res = _generate_and_save_streaming(model_id=MODEL_ID, contents=contents, config=cfg)
                        for fn in stream_res.get("saved_files", []):
                            meta = _upload_local_and_build(fn)
                            per_base["generated"].append(meta)
                        streaming_done = True
                    except Exception:
                        app.logger.exception("per-image streaming failed; fallback")

                if streaming_done:
                    continue

                if "_generate_image_with_input_image" not in globals() or not callable(globals()["_generate_image_with_input_image"]):
                    return jsonify({"success": False, "error": "_generate_image_with_input_image_not_implemented"}), 501
                try:
                    img_resp = _generate_image_with_input_image(final_prompt, file_bytes=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png", file_uri=None, model_id=MODEL_ID, aspect_ratio=theme.get("aspect_ratio_hint") or aspect_ratio)
                except Exception as e:
                    per_base["generated"].append({"error": "image_generation_failed", "details": str(e)})
                    continue
                try:
                    saved = save_images_from_response(img_resp, prefix=f"perimage_{i+1}_c{c}")
                except NotImplementedError:
                    return jsonify({"success": False, "error": "save_images_from_response_not_implemented"}), 501
                for fn in saved:
                    meta = _upload_local_and_build(fn)
                    per_base["generated"].append(meta)
            aggregated.append(per_base)

        # generate for URIs (including those derived from product.source_urls)
        for i, uri in enumerate(file_uris):
            per_base = {"base": uri, "generated": []}
            for c in range(count):
                theme = ad_plan.get("themes", [{}])[c % max(1, len(ad_plan.get("themes", [])))]
                visual_prompt = theme.get("visual_prompt") or prompt
                final_prompt = f"{visual_prompt}\n\nContext: {prompt}\nTagline: {ad_plan.get('tagline')}\nCaption: {ad_plan.get('caption')}\nCTA: {ad_plan.get('cta')}\nPlace the product prominently."

                streaming_done = False
                if getattr(GENAI_CLIENT.models, "generate_content_stream", None):
                    try:
                        parts = []
                        parts.append(Part.from_uri(file_uri=uri))
                        parts.append(types.Part.from_text(text=final_prompt))
                        contents = [types.Content(role="user", parts=parts)]
                        cfg = types.GenerateContentConfig(response_modalities=["IMAGE","TEXT"], candidate_count=1)
                        stream_res = _generate_and_save_streaming(model_id=MODEL_ID, contents=contents, config=cfg)
                        for fn in stream_res.get("saved_files", []):
                            meta = _upload_local_and_build(fn)
                            per_base["generated"].append(meta)
                        streaming_done = True
                    except Exception:
                        app.logger.exception("uri streaming failed; fallback")

                if streaming_done:
                    continue

                if "_generate_image_with_input_image" not in globals() or not callable(globals()["_generate_image_with_input_image"]):
                    return jsonify({"success": False, "error": "_generate_image_with_input_image_not_implemented"}), 501
                try:
                    img_resp = _generate_image_with_input_image(final_prompt, file_bytes=None, mime_type=None, file_uri=uri, model_id=MODEL_ID, aspect_ratio=theme.get("aspect_ratio_hint") or aspect_ratio)
                except Exception as e:
                    per_base["generated"].append({"error": "image_generation_failed", "details": str(e)})
                    continue
                try:
                    saved = save_images_from_response(img_resp, prefix=f"peruri_{i+1}_c{c}")
                except NotImplementedError:
                    return jsonify({"success": False, "error": "save_images_from_response_not_implemented"}), 501
                for fn in saved:
                    meta = _upload_local_and_build(fn)
                    per_base["generated"].append(meta)
            aggregated.append(per_base)

        return jsonify({"success": True, "mode": "per_image", "ad_plan": ad_plan, "results": aggregated}), 200

    except Exception as exc:
        app.logger.exception("generate_creatives error")
        return jsonify({"success": False, "error": "internal", "detail": str(exc), "trace": traceback.format_exc()}), 500

import os
import time
import uuid
import mimetypes
import traceback# add these imports at top of file if not already present
import time
import uuid
import json
import mimetypes
import traceback
import os
from flask import request, jsonify
from PIL import Image  # pip install pillow

@app.route("/api/v1/generate-from-prodlink", methods=["POST"])
def generate_from_prodlink():
    """
    Generate three marketing creatives (one per requested ratio) using only Sociovia snapshot URLs.

    - Requests exactly three aspect ratios (1:1, 4:5, 9:16).
    - Does NOT set image_size (avoids pydantic validation error).
    - Uses streaming as primary; falls back to non-stream generate_content if no inline image found.
    - Robustly handles inline image data (bytes or base64 string).
    - Optionally performs server-side resizing when export_resizes=True in request body.
    """
    if GENAI_CLIENT is None:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    try:
        body = request.get_json(silent=True) or {}
        product = body.get("product") or {}
        user_prompt = (body.get("prompt") or "").strip()
        model_id = body.get("model_id") or MODEL_ID

        export_resizes = bool(body.get("export_resizes", False))
        max_stream_seconds_total = int(body.get("max_stream_seconds") or 130)

        # EXACT three ratio specs
        ratio_specs = [
            {"aspect": "1:1", "size": "1080x1080", "pixels": (1080, 1080), "label": "square"},
            {"aspect": "4:5", "size": "1080x1350", "pixels": (1080, 1350), "label": "vertical_4_5"},
            {"aspect": "9:16", "size": "1080x1920", "pixels": (1080, 1920), "label": "vertical_9_16"},
        ]

        # Filter only Sociovia snapshot URLs
        source_urls = product.get("source_urls") or []
        sociovia_snapshots = [
            u for u in source_urls
            if isinstance(u, str) and u.startswith("https://sociovia.blr1.cdn.digitaloceanspaces.com/snapshots/")
        ]

        if not sociovia_snapshots:
            return jsonify({
                "success": False,
                "error": "no_valid_snapshots",
                "detail": "No Sociovia snapshot URLs found in product.source_urls",
                "provided_source_urls": source_urls
            }), 400

        title = product.get("title") or product.get("name") or "Product"
        one_line_tag = (product.get("ad_campaign_ready") or {}).get("one_sentence_tagline") or ""

        # Concise marketing brief
        marketing_brief = (
            f"""Marketing creative brief for: {title}

OUTPUT FORMAT (MANDATORY)
1) First line: a single inline image data URI only (e.g. `data:image/png;base64,...`) OR a single <img> tag with a data URI. Nothing else on that line.
2) Then exactly TWO newlines.
3) Then a single JSON code block fenced with triple backticks and the language marker: ```json
   The JSON block must be the only text after the image line (no extra prose, no comments).

REQUIRED JSON FIELDS (include exactly these keys; keep values as described)
- variant_id: unique string id for this variant
- layout: one-word layout (single, carousel, story, reel, square, vertical)
- headline: final, SPELL-CHECKED headline (concise)
- body_text: final, SPELL-CHECKED body copy (concise)
- cta: final, SPELL-CHECKED call-to-action (e.g. "Shop now")
- price_value: numeric price (float) OR null
- price_currency: currency code like "USD" / "INR" OR null
- price_text: exact raw OCR text for price OR null (do NOT modify)
- ocr_confidence: number between 0 and 1 OR null
- language: language code, e.g. "en"
- image_thumbnail_hint: short hint string OR null
- meta: object with client (sociovia-spa) and created_at (ISO8601)

TEXTUAL RULES (do not ignore)
1. ONLY use the provided snapshot images as visual reference. Do not invent or add facts.
2. OCR & PRICE RULES
   - Use OCR to extract price ONLY from the provided images.
   - If OCR returns no clearly readable numeric price OR the price is crossed-out/struck-through/blurred/obscured, set price_value=null, price_currency=null, price_text=null, ocr_confidence=null.
   - If OCR returns a price string, put the exact raw OCR result into price_text (do NOT normalize or change it).
   - Derive price_value by extracting only the numeric portion (float) from price_text and set price_currency to an ISO code if currency symbol is unambiguous. If currency is ambiguous, set price_currency=null.
   - If OCR confidence < 0.60, treat as NOT confident: set price_value=null but you may include price_text and ocr_confidence.
   - NEVER invent or guess a price. If uncertain, use nulls.
3. SPELLING & GRAMMAR
   - Perform an internal spell- and grammar-check on headline, body_text, and cta. These fields must be error-free and idiomatic marketing English (or the detected language).
   - Correct spelling/grammar without changing factual meaning.
4. NO EXTRA TEXT OR HALLUCINATION
   - Do not output any commentary, explanation, or extra fields.
   - The JSON must be valid and parseable (no trailing commas, no comments).
   - Do not include additional keys beyond the required list.
5. IMAGE
   - The generated image must use the snapshots only as a visual reference. Produce one representative variant only.
6. FAILURE MODE
   - If any required textual field can't be produced, return the JSON with empty strings ("") for those text fields and nulls for price fields. Still return a valid JSON block.
7. DETERMINISM
   - Run model with temperature=0 (or as low as possible) to minimize spelling/wording variability.

EXAMPLE USAGE (do not output this example; for implementer only):
- Provide images + this prompt to the model; expect one image line + two newlines + a JSON block.

End of prompt.
"""
        )
        if one_line_tag:
            marketing_brief += f"Suggested tagline: {one_line_tag}\n"
        if user_prompt:
            marketing_brief += f"Extra instructions: {user_prompt}\n"
        marketing_brief += (
            "\nReturn a fenced JSON block in the TEXT part with fields: label, headline, caption, cta_short, cta_long, hashtags, alt_text, "
            "price_extracted_from_image (bool), price_value (string|null), price_currency (string|null), price_source_detail (string|null), suggested_exports, colors, fonts.\n"
        )

        PartLocal = getattr(types, "Part", None)
        if PartLocal is None:
            return jsonify({"success": False, "error": "genai_part_not_available"}), 500

        # Build parts (snapshots + brief text)
        parts_for_request = []
        used_sources, skipped_sources = [], []
        for url in sociovia_snapshots:
            try:
                parts_for_request.append(PartLocal.from_uri(file_uri=url))
                used_sources.append(url)
            except Exception:
                app.logger.exception("Part.from_uri failed for %s", url)
                skipped_sources.append(url)

        parts_for_request.append(PartLocal.from_text(text=marketing_brief))

        items = []
        overall_start = time.time()
        per_call_timeout = max(8, int(max_stream_seconds_total / len(ratio_specs)))

        def _write_inline_data_to_file(inline_data, prefix_label):
            """
            Accepts inline_data which may be:
              - bytes / bytearray -> write directly
              - str (base64) -> decode then write
            Returns (local_path, fname, mime_type) on success, else None.
            """
            try:
                mime_type = getattr(inline_data, "mime_type", None) or getattr(inline_data, "type", None) or "image/png"
                data_blob = getattr(inline_data, "data", None) or inline_data
                # If it's bytes-like, write directly
                if isinstance(data_blob, (bytes, bytearray)):
                    raw_bytes = data_blob
                elif isinstance(data_blob, str):
                    # likely base64 string, attempt decode (strip data URL if present)
                    s = data_blob
                    if s.startswith("data:"):
                        # data:<mime>;base64,<data>
                        try:
                            raw_bytes = base64.b64decode(s.split(",", 1)[1])
                        except Exception:
                            raw_bytes = base64.b64decode(s)
                    else:
                        raw_bytes = base64.b64decode(s)
                else:
                    # Unexpected type
                    return None

                ext = mimetypes.guess_extension(mime_type) or ".png"
                fname = f"gen_marketing_{prefix_label}_{int(time.time())}_{uuid.uuid4().hex[:8]}{ext}"
                local_path = os.path.join(SCRAPER_OUTPUT, fname)
                os.makedirs(SCRAPER_OUTPUT, exist_ok=True)
                with open(local_path, "wb") as fh:
                    fh.write(raw_bytes)
                return local_path, fname, mime_type
            except Exception:
                app.logger.exception("Failed to write inline data to file")
                return None

        # For each ratio: try streaming; if no image, fallback to non-streaming single request
        for idx, rs in enumerate(ratio_specs):
            if time.time() - overall_start > max_stream_seconds_total:
                app.logger.warning("generate-from-prodlink: overall timeout reached before finishing all ratios")
                break

            requested_aspect = rs["aspect"]
            prefix_label = rs.get("label") or requested_aspect.replace(":", "")

            # Build config: DO NOT pass image_size
            try:
                img_cfg = types.ImageConfig(aspect_ratio=requested_aspect)
                cfg = types.GenerateContentConfig(
                    response_modalities=["IMAGE", "TEXT"],
                    image_config=img_cfg,
                    candidate_count=1,
                )
                try:
                    setattr(cfg, "temperature", 1.0)
                    setattr(cfg, "top_p", 0.95)
                except Exception:
                    pass
            except Exception:
                cfg = {
                    "response_modalities": ["IMAGE", "TEXT"],
                    "candidate_count": 1,
                    "temperature": 1.0,
                    "top_p": 0.95,
                    "image_config": {"aspect_ratio": requested_aspect},
                }

            saved_for_this_ratio = []
            file_index = 0
            stream_start = time.time()
            last_candidate = None

            # Primary: streaming call
            try:
                for chunk in GENAI_CLIENT.models.generate_content_stream(
                    model=model_id,
                    contents=[types.Content(role="user", parts=parts_for_request)],
                    config=cfg
                ):
                    # per-call timeout
                    if time.time() - stream_start > per_call_timeout:
                        app.logger.warning("per-call timeout for ratio %s", requested_aspect)
                        break

                    if not chunk or not getattr(chunk, "candidates", None):
                        continue

                    cand = chunk.candidates[0]
                    last_candidate = cand
                    if not getattr(cand, "content", None) or not getattr(cand.content, "parts", None):
                        continue

                    for part in cand.content.parts:
                        if getattr(part, "text", None):
                            app.logger.debug("[gen stream text part][%s] %s", requested_aspect, (part.text or "")[:400])

                        inline = getattr(part, "inline_data", None)
                        if inline and getattr(inline, "data", None):
                            file_index += 1
                            res = _write_inline_data_to_file(inline, prefix_label + f"_{file_index}")
                            if res:
                                local_path, fname, mime = res
                                meta = {"local_path": local_path, "filename": fname, "requested_aspect": requested_aspect, "requested_size": rs["size"]}
                                try:
                                    if s3 is not None:
                                        _, uploaded_spaces = upload_to_spaces(local_path)
                                        meta_url = uploaded_spaces.get("url") if uploaded_spaces else f"file://{local_path}"
                                    else:
                                        meta_url = f"file://{local_path}"
                                except Exception:
                                    app.logger.exception("upload failed for %s", local_path)
                                    meta_url = f"file://{local_path}"

                                saved_for_this_ratio.append({"filename": fname, "local_path": local_path, "url": meta_url, "meta": meta, "variant_index": idx + 1})
                                # stop after first inline image for this ratio
                                break
                    if saved_for_this_ratio:
                        break
            except Exception:
                app.logger.exception("Streaming call failed for ratio %s, will attempt non-stream fallback", requested_aspect)

            # Fallback: if no image from streaming, do a single non-streaming generate_content call
            if not saved_for_this_ratio:
                try:
                    app.logger.info("Attempting non-stream fallback for ratio %s", requested_aspect)
                    resp = GENAI_CLIENT.models.generate_content(
                        model=model_id,
                        contents=[types.Content(role="user", parts=parts_for_request)],
                        config=cfg
                    )
                    # resp may have candidates -> content -> parts with inline_data
                    if getattr(resp, "candidates", None):
                        cand = resp.candidates[0]
                        last_candidate = cand
                        if getattr(cand, "content", None) and getattr(cand.content, "parts", None):
                            for part in cand.content.parts:
                                inline = getattr(part, "inline_data", None)
                                if inline and getattr(inline, "data", None):
                                    res = _write_inline_data_to_file(inline, prefix_label + "_fallback")
                                    if res:
                                        local_path, fname, mime = res
                                        meta = {"local_path": local_path, "filename": fname, "requested_aspect": requested_aspect, "requested_size": rs["size"]}
                                        try:
                                            if s3 is not None:
                                                _, uploaded_spaces = upload_to_spaces(local_path)
                                                meta_url = uploaded_spaces.get("url") if uploaded_spaces else f"file://{local_path}"
                                            else:
                                                meta_url = f"file://{local_path}"
                                        except Exception:
                                            app.logger.exception("upload failed for %s", local_path)
                                            meta_url = f"file://{local_path}"
                                        saved_for_this_ratio.append({"filename": fname, "local_path": local_path, "url": meta_url, "meta": meta, "variant_index": idx + 1})
                                        break
                except Exception:
                    app.logger.exception("Non-streaming fallback failed for ratio %s", requested_aspect)

            # Attempt to parse JSON metadata from last_candidate text parts
            variant_meta = None
            try:
                if last_candidate and getattr(last_candidate, "content", None):
                    for part in last_candidate.content.parts:
                        if getattr(part, "text", None):
                            txt = (part.text or "").strip()
                            # find fenced JSON block first
                            s = txt.find("```json")
                            if s != -1:
                                e = txt.find("```", s + 7)
                                if e != -1:
                                    raw_json = txt[s + 7:e].strip()
                                    try:
                                        variant_meta = json.loads(raw_json)
                                        break
                                    except Exception:
                                        pass
                            # fallback: try to extract first {...} JSON object
                            try:
                                if txt.startswith("{") or txt.startswith("["):
                                    variant_meta = json.loads(txt)
                                    break
                                else:
                                    s2 = txt.find("{")
                                    e2 = txt.rfind("}")
                                    if s2 != -1 and e2 != -1 and e2 > s2:
                                        jsub = txt[s2:e2+1]
                                        variant_meta = json.loads(jsub)
                                        break
                            except Exception:
                                pass
            except Exception:
                app.logger.exception("Error parsing candidate text for ratio %s", requested_aspect)

            if not saved_for_this_ratio:
                app.logger.warning("No image produced for ratio %s (both stream and fallback)", requested_aspect)
                # do not abort overall run; continue to next ratio
                continue

            sf = saved_for_this_ratio[0]

            # Optionally create resized exports (server-side) for requested export sizes
            resized_exports = []
            if export_resizes:
                try:
                    master_path = sf["local_path"]
                    base_name, _ = os.path.splitext(sf["filename"])
                    export_targets = [
                        ("1:1", (1080, 1080)),
                        ("4:5", (1080, 1350)),
                        ("9:16", (1080, 1920)),
                        ("1.91:1", (1918, 1080)),
                    ]
                    for aspect_label, (w, h) in export_targets:
                        out_fname = f"{base_name}_export_{aspect_label.replace(':','')}_{w}x{h}.jpg"
                        out_path = os.path.join(SCRAPER_OUTPUT, out_fname)
                        try:
                            with Image.open(master_path) as im:
                                im_ratio = im.width / im.height
                                target_ratio = w / h
                                if abs(im_ratio - target_ratio) > 0.01:
                                    if im_ratio > target_ratio:
                                        new_width = int(im.height * target_ratio)
                                        left = (im.width - new_width) // 2
                                        im_cropped = im.crop((left, 0, left + new_width, im.height))
                                    else:
                                        new_height = int(im.width / target_ratio)
                                        top = (im.height - new_height) // 2
                                        im_cropped = im.crop((0, top, im.width, top + new_height))
                                else:
                                    im_cropped = im.copy()
                                im_resized = im_cropped.resize((w, h), Image.LANCZOS)
                                im_resized.save(out_path, format="JPEG", quality=90)
                                # upload resized
                                try:
                                    if s3 is not None:
                                        _, uploaded = upload_to_spaces(out_path)
                                        url_out = uploaded.get("url") if uploaded else f"file://{out_path}"
                                    else:
                                        url_out = f"file://{out_path}"
                                except Exception:
                                    app.logger.exception("upload resized failed for %s", out_path)
                                    url_out = f"file://{out_path}"
                                resized_exports.append({"path": out_path, "filename": out_fname, "url": url_out, "size": f"{w}x{h}", "aspect": aspect_label})
                        except Exception:
                            app.logger.exception("Resizing failed for %s -> %s", sf["local_path"], out_path)
                            continue
                except Exception:
                    app.logger.exception("export_resizes main error for ratio %s", requested_aspect)

            # Suggest exports (unique and ordered)
            suggested_exports = [
                {"aspect": requested_aspect, "size": rs["size"]},
                {"aspect": "1:1", "size": "1080x1080"},
                {"aspect": "4:5", "size": "1080x1350"},
                {"aspect": "9:16", "size": "1080x1920"},
                {"aspect": "1.91:1", "size": "1918x1080"}
            ]
            seen = set(); uniq_exports = []
            for ex in suggested_exports:
                key = (ex["aspect"], ex["size"])
                if key in seen: continue
                seen.add(key); uniq_exports.append(ex)

            label = None
            if isinstance(variant_meta, dict):
                label = variant_meta.get("label") or variant_meta.get("title") or None

            item = {
                "filename": sf["filename"],
                "local_path": sf["local_path"],
                "url": sf["url"],
                "meta": sf.get("meta", {}),
                "requested_aspect": requested_aspect,
                "requested_size": rs["size"],
                "variant_meta": variant_meta or {},
                "label": label or f"Variant {idx+1} ({requested_aspect})",
                "suggested_exports": uniq_exports,
                "resized_exports": resized_exports,
            }
            items.append(item)

        # Ensure we return exactly three items where possible; if some ratios produced no image, return fewer with warnings
        if not items:
            return jsonify({
                "success": False,
                "error": "no_images_generated",
                "detail": "Model did not produce any images for the requested ratios",
                "used_sources": used_sources,
                "skipped_sources": skipped_sources,
            }), 500

        # If user expects exactly 3 always and some are missing, include a notice in response
        notice = None
        if len(items) < len(ratio_specs):
            notice = f"Only {len(items)} / {len(ratio_specs)} variants produced."

        return jsonify({
            "success": True,
            "items": items,
            
            "note": notice,
            "ad_plan_prompt_used": marketing_brief
        }), 200

    except Exception as exc:
        tb = traceback.format_exc()
        app.logger.exception("generate-from-prodlink failed: %s", exc)
        return jsonify({"success": False, "error": "internal", "detail": str(exc), "trace": tb}), 500



@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


FB_API_VERSION = os.getenv("FB_API_VERSION", "v17.0")
FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "EAAZAVAy1umqcBPlzb3eKWh9xtAdafi3nDF9DAu0xrVjSUhTlb2zZB2xV5ZAuLkeiISzSye85SZC3LTwLrsVZAAerce0YOqQllvirE04ihZBIKXfJY3V0h0mZAtMUxGTrQ8CB2qW5Ahkdsv1k8D7nIHcAU73wTApQeq3ZCWvDZAe1umrqjBREvlaqioDn6aYBniJeDSr5KFKgdCdNUiww7vcs8OowYOG4XHRvHaHAS")  # set this
FB_AD_ACCOUNT_ID = os.getenv("FB_AD_ACCOUNT_ID", "act_785545867549907")

# Add near your other imports
import os
import json
import requests
from flask import request, jsonify
from flask import Flask, request, jsonify
import os, json, requests



@app.route("/api/facebook/metrics/extended", methods=["POST"])
def facebook_metrics_extended():
    """
    Extended Facebook Insights route with computed metrics.
    Supports filtering by campaign_id, adset_id, or ad_id.
    """
    body = request.get_json(silent=True) or {}

    # Resolve account_id and access_token
    account_id = body.get("account_id") or os.getenv("FB_AD_ACCOUNT_ID")
    access_token = body.get("access_token") or os.getenv("FB_ACCESS_TOKEN")
    api_version = os.getenv("FB_GRAPH_API_VERSION", "v18.0")

    if not account_id:
        return jsonify({"ok": False, "error": "missing account_id"}), 400
    if not access_token:
        return jsonify({"ok": False, "error": "missing access_token"}), 400

    # Level and fields
    level = body.get("level", "campaign")
    default_fields = (
        "campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,"
        "impressions,clicks,spend,reach,frequency,unique_clicks,"
        "inline_link_clicks,actions,action_values,video_30_sec_watched_actions"
    )
    fields = body.get("fields", default_fields)
    limit = int(body.get("limit", 500))
    max_pages = int(body.get("max_pages", 10))
    time_increment = body.get("time_increment")
    
    params = {
        "access_token": access_token,
        "fields": fields,
        "level": level,
        "limit": limit,
    }

    # Time filters
    since = body.get("since")
    until = body.get("until")
    date_preset = body.get("date_preset")
    if since and until:
        params["time_range"] = json.dumps({"since": since, "until": until})
    elif date_preset:
        params["date_preset"] = date_preset
    if time_increment:
        params["time_increment"] = str(time_increment)

    # Filtering by campaign/adset/ad IDs
    filtering = body.get("filtering") or []
    # Convert single campaign/adset/ad to filtering automatically
    for key in ["campaign_id", "adset_id", "ad_id"]:
        if body.get(key):
            filtering.append({"field": f"{key}.id", "operator": "EQUAL", "value": body[key]})
    if filtering:
        params["filtering"] = json.dumps(filtering)

    # Fetch data from FB
    base_url = f"https://graph.facebook.com/{api_version}/act_{account_id}/insights"
    all_rows, paging = [], None
    try:
        r = requests.get(base_url, params=params, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        return jsonify({"ok": False, "error": "network_error", "detail": str(e)}), 502

    j = r.json()
    all_rows.extend(j.get("data", []))
    print(all_rows)
    paging = j.get("paging")

    page_count = 1
    while paging and paging.get("next") and page_count < max_pages:
        try:
            r = requests.get(paging.get("next"), timeout=30)
            r.raise_for_status()
            j = r.json()
        except Exception:
            break
        all_rows.extend(j.get("data", []))
        print(all_rows)
        paging = j.get("paging")
        page_count += 1

    # Helper functions
    def to_float(x):
        try:
            if x is None: return 0.0
            if isinstance(x, (int, float)): return float(x)
            return float(str(x).replace(",", ""))
        except: return 0.0

    def parse_actions(actions_field):
        convs, revenue, total_conv, total_rev = {}, {}, 0, 0.0
        if not actions_field: return convs, revenue, total_conv, total_rev
        actions = actions_field
        if isinstance(actions_field, str):
            try: actions = json.loads(actions_field)
            except: actions = []
        if not isinstance(actions, list): actions = []

        for a in actions:
            atype = a.get("action_type") or a.get("action_type_full") or a.get("action") or None
            val = a.get("value")
            try: count = int(float(val)) if val is not None and str(val).replace('.', '', 1).isdigit() else None
            except: count = None

            key = atype or str(a)
            if key and ("purchase" in key or "offsite_conversion" in key or "omni_purchase" in key):
                v = to_float(val)
                if v: revenue[key] = revenue.get(key, 0.0) + v; total_rev += v
                else:
                    c = a.get("c")
                    if c: 
                        try: cnum = int(c); convs[key] = convs.get(key, 0) + cnum; total_conv += cnum
                        except: pass
            else:
                if count is not None: convs[key] = convs.get(key, 0) + count; total_conv += count
                else:
                    for maybe in ("count", "action_count", "value_count"):
                        if maybe in a:
                            try: cnum = int(float(a.get(maybe))); convs[key] = convs.get(key, 0) + cnum; total_conv += cnum; break
                            except: pass
        return convs, revenue, total_conv, total_rev

    # Compute metrics per row
    summary = {"impressions":0,"clicks":0,"spend":0.0,"reach":0,"unique_clicks":0,"total_conversions":0,"total_revenue":0.0}
    agg_conversions_by_type, agg_revenue_by_type = {}, {}
    augmented_rows = []

    for row in all_rows:
        imp = to_float(row.get("impressions"))
        clicks = to_float(row.get("clicks") or row.get("inline_link_clicks") or row.get("unique_clicks"))
        spend = to_float(row.get("spend"))
        reach = int(to_float(row.get("reach")))
        freq = to_float(row.get("frequency"))
        unique_clicks = int(to_float(row.get("unique_clicks") or 0))
        convs_by_type, revenue_by_type, total_conv, total_rev = parse_actions(row.get("actions") or row.get("action_values"))

        ctr_pct = (clicks/imp*100) if imp>0 else None
        cpc = (spend/clicks) if clicks>0 else None
        cpm = (spend/imp*1000) if imp>0 else None
        conversion_rate_pct = (total_conv/clicks*100) if clicks>0 else None
        cpa = (spend/total_conv) if total_conv>0 else None
        roas = (total_rev/spend) if spend>0 else None

        computed = {
            "impressions": int(imp), "clicks": int(clicks), "spend": round(spend,4), "reach": reach,
            "frequency": round(freq,2), "unique_clicks": unique_clicks, "ctr_pct": round(ctr_pct,3) if ctr_pct else None,
            "cpc": round(cpc,4) if cpc else None, "cpm": round(cpm,4) if cpm else None,
            "conversions_total": int(total_conv), "conversions_by_type": convs_by_type,
            "revenue_total": round(total_rev,4), "revenue_by_type": {k:round(v,4) for k,v in revenue_by_type.items()},
            "conversion_rate_pct": round(conversion_rate_pct,3) if conversion_rate_pct else None,
            "cpa": round(cpa,4) if cpa else None, "roas": round(roas,4) if roas else None
        }

        summary["impressions"] += int(imp)
        summary["clicks"] += int(clicks)
        summary["spend"] += spend
        summary["reach"] += reach
        summary["unique_clicks"] += unique_clicks
        summary["total_conversions"] += int(total_conv)
        summary["total_revenue"] += float(total_rev or 0.0)
        for k,v in convs_by_type.items(): agg_conversions_by_type[k] = agg_conversions_by_type.get(k,0)+int(v)
        for k,v in revenue_by_type.items(): agg_revenue_by_type[k] = agg_revenue_by_type.get(k,0.0)+float(v)

        augmented = dict(row)
        augmented["computed_metrics"] = computed
        augmented_rows.append(augmented)

    # Aggregate summary metrics
    total_imp, total_clicks, total_spend = summary["impressions"], summary["clicks"], summary["spend"]
    total_conversions, total_revenue = summary["total_conversions"], summary["total_revenue"]

    summary_metrics = {
        "impressions": total_imp, "clicks": total_clicks, "spend": round(total_spend,4),
        "ctr_pct": round((total_clicks/total_imp*100),3) if total_imp>0 else None,
        "cpc": round((total_spend/total_clicks),4) if total_clicks>0 else None,
        "cpm": round((total_spend/total_imp*1000),4) if total_imp>0 else None,
        "total_conversions": total_conversions,
        "conversion_rate_pct": round((total_conversions/total_clicks*100),3) if total_clicks>0 else None,
        "cpa": round((total_spend/total_conversions),4) if total_conversions>0 else None,
        "roas": round((total_revenue/total_spend),4) if total_spend>0 else None,
        "agg_conversions_by_type": agg_conversions_by_type,
        "agg_revenue_by_type": {k:round(v,4) for k,v in agg_revenue_by_type.items()}
    }

    return jsonify({
        "ok": True,
        "account_id": account_id,
        "rows_count": len(augmented_rows),
        "summary": summary_metrics,
        "data": augmented_rows,
        "raw_paging": paging
    })
    
import os
import time
import json
import re
import hmac
import hashlib
import requests
from flask import request, jsonify, current_app

import re
import json
import traceback
import uuid
import ast
from typing import Any, List, Optional
from flask import Flask, request, jsonify

import os
import re
import json
import time
import hmac
import base64
import hashlib
import logging
import traceback
from typing import Tuple, Optional, Dict, Any, List
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, current_app
from botocore.client import Config

try:
    import boto3
except Exception:
    boto3 = None




LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s")
log = logging.getLogger("facebook_adpreviews")


def _acct_prefix(account_id: str) -> str:
    """Return account prefix expected by Graph (e.g. act_<id>) if user passed raw id."""
    if account_id is None:
        return ""
    account_id = str(account_id)
    return account_id if account_id.startswith("act_") else f"act_{account_id}"


# put these near top of your module (imports + env)
import os
import sys
import time
import hashlib
import logging
from urllib.parse import urlparse

try:
    import boto3
    from botocore.client import Config
except Exception:
    boto3 = None

log = logging.getLogger("facebook_adpreviews")



SPACE_NAME = os.environ.get("SPACE_NAME", "")            # bucket name
SPACE_REGION = os.environ.get("SPACE_REGION", "")        # e.g. "nyc3"
SPACE_ENDPOINT = os.environ.get("SPACE_ENDPOINT") or (f"https://{SPACE_REGION}.digitaloceanspaces.com" if SPACE_REGION else None)
SPACE_CDN = os.environ.get("SPACE_CDN") or (f"https://{SPACE_NAME}.{SPACE_REGION}.cdn.digitaloceanspaces.com" if SPACE_NAME and SPACE_REGION else None)

ACCESS_KEY = os.environ.get("ACCESS_KEY")   # DO Spaces access key
SECRET_KEY = os.environ.get("SECRET_KEY")   # DO Spaces secret key

# Initialize S3 client (DigitalOcean Spaces)
if ACCESS_KEY and SECRET_KEY and SPACE_ENDPOINT:
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            endpoint_url=SPACE_ENDPOINT,
            config=Config(signature_version="s3v4"),
            region_name=SPACE_REGION or None,
        )
        log.info("[startup] S3 client initialized for DigitalOcean Spaces. endpoint=%s bucket=%s", SPACE_ENDPOINT, SPACE_NAME)
    except Exception as e:
        s3 = None
        log.exception("[startup] Failed to initialize S3 client: %s", e)
else:
    s3 = None
    log.warning("[startup] DigitalOcean Spaces credentials/endpoint not set. Set ACCESS_KEY, SECRET_KEY, and SPACE_REGION/SPACE_ENDPOINT.")

# --- upload helper that uses the s3 client above ---
def upload_bytes_to_spaces(data: bytes, filename: str, content_type: str = "application/octet-stream") -> Optional[str]:
    """
    Upload `data` bytes to DigitalOcean Spaces using the `s3` client created above.
    Returns a public URL (using SPACE_CDN if provided) or None on failure.
    """
    if not s3:
        log.debug("upload_bytes_to_spaces: s3 client not configured.")
        return None

    bucket = SPACE_NAME
    endpoint = SPACE_ENDPOINT
    public_base = SPACE_CDN  # prefer CDN if provided

    if not bucket or not endpoint:
        log.warning("upload_bytes_to_spaces: missing SPACE_NAME or SPACE_ENDPOINT.")
        return None

    key_name = f"previews/{int(time.time())}_{hashlib.sha1(data).hexdigest()[:12]}_{os.path.basename(filename)}"
    try:
        log.info("Uploading to Spaces: bucket=%s key=%s content_type=%s", bucket, key_name, content_type)
        resp = s3.put_object(Bucket=bucket, Key=key_name, Body=data, ACL="public-read", ContentType=content_type)
        # Log response keys if available
        try:
            if isinstance(resp, dict):
                log.debug("put_object response keys: %s", list(resp.keys()))
            else:
                log.debug("put_object response: %s", resp)
        except Exception:
            pass
    except Exception as e:
        log.exception("upload_bytes_to_spaces: put_object failed: %s", e)
        # If botocore ClientError present, try to log more info
        try:
            import botocore
            if isinstance(e, botocore.exceptions.ClientError):
                log.error("Boto3 ClientError: %s", e.response)
        except Exception:
            pass
        return None

    # Build public URL
    if public_base:
        url = public_base.rstrip("/") + "/" + key_name
        log.info("upload_bytes_to_spaces: returning CDN URL: %s", url)
        return url

    # Fallback: construct using endpoint host
    parsed = urlparse(endpoint)
    host = parsed.netloc or parsed.path
    url = f"https://{bucket}.{host}/{key_name}"
    log.info("upload_bytes_to_spaces: returning default URL: %s", url)
    return url

# -----------------------------
# Image utilities
# -----------------------------
def is_data_uri(s: str) -> bool:
    return isinstance(s, str) and s.strip().startswith("data:")

def decode_data_uri_to_bytes(data_uri: str) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Decode data URI (data:[<mediatype>][;base64],<data>) -> (bytes, content_type)
    """
    try:
        header, b64 = data_uri.split(",", 1)
        parts = header.split(";")
        content_type = parts[0].split(":")[1] if ":" in parts[0] else "application/octet-stream"
        if "base64" in header:
            return base64.b64decode(b64), content_type
        else:
            return b64.encode("utf-8"), content_type
    except Exception as e:
        current_app.logger.exception("Failed to decode data URI: %s", e)
        return None, None

def fetch_url_bytes(url: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetch URL and return (bytes, content_type) or (None, None) on failure."""
    try:
        r = requests.get(url, timeout=20, stream=True)
        r.raise_for_status()
        content_type = r.headers.get("Content-Type", "application/octet-stream")
        return r.content, content_type
    except Exception as e:
        current_app.logger.exception("Failed to fetch remote image URL: %s", e)
        return None, None

def get_image_hash_from_payload(payload: dict, image_url_or_data: str, api_version: str, fb_ad_account: str, access_token: str) -> Optional[str]:
    """
    Given either a data URI or remote URL, attempt:
    1) direct /adimages with the remote URL,
    2) fetch and upload to DO Spaces (or S3) and then /adimages with public URL,
    3) return image_hash or None.
    """
    if payload.get("image_hash"):
        return str(payload.get("image_hash"))

    src = (image_url_or_data or "").strip()
    if not src:
        return None

    final_public_url = None

    if is_data_uri(src):
        bts, ctype = decode_data_uri_to_bytes(src)
        if not bts:
            current_app.logger.warning("Data URI decode failed.")
            return None
        ext = ctype.split("/")[-1].split(";")[0] if ctype and "/" in ctype else "bin"
        filename = f"preview.{ext}"
        final_public_url = upload_bytes_to_spaces(bts, filename, content_type=ctype or "application/octet-stream")
        if not final_public_url:
            current_app.logger.warning("Upload of data URI to Spaces failed.")
            return None

    else:
        # Attempt direct adimages with remote URL (fast path)
        try:
            create_url = f"https://graph.facebook.com/{api_version}/{_acct_prefix(fb_ad_account)}/adimages"
            params = {"access_token": access_token}
            rimg = requests.post(create_url, params=params, data={"url": src}, timeout=30)
            try:
                img_json = rimg.json()
            except Exception:
                img_json = {"text": rimg.text}
            images_obj = img_json.get("images") if isinstance(img_json, dict) else None
            if images_obj and isinstance(images_obj, dict):
                for k, v in images_obj.items():
                    if isinstance(v, dict) and (v.get("hash") or v.get("image_hash")):
                        return v.get("hash") or v.get("image_hash")
        except Exception as e:
            current_app.logger.debug("Direct adimages attempt failed for url=%s -> %s", src, e)

        # Fetch & upload to Spaces and then call adimages with public URL
        bts, ctype = fetch_url_bytes(src)
        if not bts:
            current_app.logger.warning("Failed to fetch remote image bytes for %s", src)
            return None
        parsed = urlparse(src)
        filename = os.path.basename(parsed.path) or f"preview_{int(time.time())}.img"
        final_public_url = upload_bytes_to_spaces(bts, filename, content_type=ctype or "application/octet-stream")
        if not final_public_url:
            current_app.logger.warning("Uploading fetched remote image to Spaces failed for %s", src)
            return None

    # Submit the final_public_url to FB /adimages to get image_hash
    try:
        create_url = f"https://graph.facebook.com/{api_version}/{_acct_prefix(fb_ad_account)}/adimages"
        params = {"access_token": access_token}
        rimg = requests.post(create_url, params=params, data={"url": final_public_url}, timeout=30)
        try:
            img_json = rimg.json()
        except Exception:
            img_json = {"text": rimg.text}
        images_obj = img_json.get("images") if isinstance(img_json, dict) else None
        if images_obj and isinstance(images_obj, dict):
            first_key = next(iter(images_obj.keys()), None)
            if first_key:
                img_info = images_obj.get(first_key) or {}
                return img_info.get("hash") or img_info.get("image_hash") or None
        if isinstance(img_json, dict):
            for k, v in (img_json.get("images") or {}).items():
                if isinstance(v, dict) and (v.get("hash") or v.get("image_hash")):
                    return v.get("hash") or v.get("image_hash")
    except Exception as e:
        current_app.logger.exception("adimages upload of Spaces URL failed: %s", e)

    return None

# -----------------------------
# Main route: /api/facebook/adpreviews
# -----------------------------
@app.route("/api/facebook/adpreviews", methods=["POST", "OPTIONS"])
def facebook_adpreviews():
    """
    Create temporary adcreative (if needed) and fetch creative previews.

    Accepts either:
     - { "creative_id": "123" }
     OR
     - { "creative": { title, body, image_url/image_hash, object_url, object_story_spec } }
    """
    try:
        body = request.get_json(silent=True) or {}
        api_version = body.get("api_version") or os.getenv("FB_GRAPH_API_VERSION", "v18.0")
        access_token = os.getenv("FB_ACCESS_TOKEN") or globals().get("FB_ACCESS_TOKEN")
        fb_ad_account = os.getenv("FB_AD_ACCOUNT_ID") or globals().get("FB_AD_ACCOUNT_ID")
        fb_page_id = os.getenv("FB_PAGE_ID") or globals().get("FB_PAGE_ID")

        if not access_token:
            return jsonify({"ok": False, "error": "missing access_token"}), 400

        provided_creative_id = body.get("creative_id") or os.getenv("FB_CREATIVE_ID") or None
        creative_id = str(provided_creative_id) if provided_creative_id else None
        created_creative_id = None

        creative_blob = body.get("creative") or body.get("creative_for_preview") or None
        if creative_blob and not creative_id:
            try:
                oss = creative_blob.get("object_story_spec") if isinstance(creative_blob, dict) else None
                if oss and isinstance(oss, dict):
                    object_story_spec = oss
                else:
                    title = (creative_blob.get("title") or creative_blob.get("headline") or "").strip()
                    body_text = (creative_blob.get("body") or creative_blob.get("primaryText") or creative_blob.get("message") or "").strip()
                    object_url = (creative_blob.get("object_url") or creative_blob.get("url") or creative_blob.get("link") or "").strip()
                    image_url = (creative_blob.get("image_url") or creative_blob.get("imageUrl") or creative_blob.get("image") or "").strip()

                    link_data = {"link": object_url or "https://www.sociovia.com", "message": body_text or " "}
                    if title:
                        link_data["name"] = title
                    if creative_blob.get("description"):
                        link_data["description"] = creative_blob.get("description")

                    if creative_blob.get("call_to_action"):
                        cta = creative_blob.get("call_to_action")
                        if isinstance(cta, str):
                            link_data["call_to_action"] = {"type": cta}
                        elif isinstance(cta, dict):
                            link_data["call_to_action"] = cta

                    # Resolve image_hash:
                    image_hash = None

                    # 1) Provided image_hash
                    if creative_blob.get("image_hash"):
                        image_hash = str(creative_blob.get("image_hash"))

                    # 2) Try resolve_image_hash helper if present
                    if not image_hash and "resolve_image_hash" in globals() and callable(globals()["resolve_image_hash"]):
                        try:
                            image_hash = resolve_image_hash({"image_url": image_url, **creative_blob}, None)
                        except Exception as e:
                            current_app.logger.debug("resolve_image_hash() failed: %s", e)
                            image_hash = None

                    # 3) Use helper to process data URI / remote URL and attempt to get image_hash
                    if not image_hash and (image_url or creative_blob.get("image")) and fb_ad_account:
                        try:
                            src = image_url or creative_blob.get("image")
                            image_hash = get_image_hash_from_payload(creative_blob or {}, src, api_version, fb_ad_account, access_token)
                            if image_hash:
                                current_app.logger.info("Obtained image_hash via payload helper: %s", image_hash)
                            else:
                                current_app.logger.warning("get_image_hash_from_payload returned no image_hash for source: ")
                        except Exception as e:
                            current_app.logger.exception("get_image_hash_from_payload exception: %s", e)
                            image_hash = None

                    # 4) Fallback DEFAULT_IMAGE_HASH env var
                    if not image_hash:
                        default_hash = os.getenv("DEFAULT_IMAGE_HASH") or globals().get("DEFAULT_IMAGE_HASH")
                        if default_hash:
                            image_hash = str(default_hash)
                            current_app.logger.info("Using DEFAULT_IMAGE_HASH for preview: %s", image_hash)

                    if image_hash:
                        link_data["image_hash"] = image_hash
                    link_data.pop("image_url", None)

                    if fb_page_id:
                        object_story_spec = {"page_id": fb_page_id, "link_data": link_data}
                    else:
                        object_story_spec = {"link_data": link_data}

                    # Create temporary adcreative if ad account present
                    if fb_ad_account:
                        try:
                            creative_payload = {
                                "name": f"Preview Creative {int(time.time())}",
                                "object_story_spec": json.dumps(object_story_spec),
                            }
                            created = None
                            if "fb_post" in globals() and callable(globals()["fb_post"]):
                                try:
                                    created = fb_post(f"{_acct_prefix(fb_ad_account)}/adcreatives", data=creative_payload)
                                except TypeError:
                                    created = None

                            if created is None:
                                create_url = f"https://graph.facebook.com/{api_version}/{_acct_prefix(fb_ad_account)}/adcreatives"
                                params = {"access_token": access_token}
                                r = requests.post(create_url, params=params, data=creative_payload, timeout=30)
                                current_app.logger.info("adcreatives create status=%s", getattr(r, "status_code", None))
                                try:
                                    created = r.json()
                                except Exception:
                                    created = {"text": r.text}

                            if isinstance(created, dict) and created.get("id"):
                                created_creative_id = str(created.get("id"))
                                creative_id = created_creative_id
                                current_app.logger.info("Created temporary creative for preview: %s", created_creative_id)
                            else:
                                current_app.logger.warning("Adcreative creation didn't return id; response=%s", created)

                            if isinstance(created, dict) and created.get("error"):
                                return jsonify({"ok": False, "error": "adcreative_create_failed", "details": created}), 400
                        except Exception as e:
                            current_app.logger.exception("Failed to create adcreative for preview: %s", e)
                    else:
                        current_app.logger.warning("FB_AD_ACCOUNT_ID not configured; cannot create adcreative.")
            except Exception:
                current_app.logger.exception("Creative blob handling failed; will try using provided creative_id if any.")

        if not creative_id:
            return jsonify({"ok": False, "error": "missing creative_id and could not create creative from provided payload"}), 400

        # ad_formats handling (string or list)
        ad_formats = body.get("ad_formats") or body.get("ad_format") or "MOBILE_FEED_STANDARD"
        if isinstance(ad_formats, str):
            if "," in ad_formats:
                ad_formats = [a.strip() for a in ad_formats.split(",") if a.strip()]
            else:
                ad_formats = [ad_formats]
        elif not isinstance(ad_formats, list):
            ad_formats = [str(ad_formats)]

        preview_options = body.get("preview_options") or {}
        app_secret = os.getenv("FB_APP_SECRET")
        appsecret_proof = None
        if app_secret:
            try:
                appsecret_proof = hmac.new(app_secret.encode("utf-8"), access_token.encode("utf-8"), hashlib.sha256).hexdigest()
            except Exception:
                appsecret_proof = None

        previews: List[Dict[str, Any]] = []
        any_success = False
        last_error = None

        for fmt in ad_formats:
            preview_url = f"https://graph.facebook.com/{api_version}/{creative_id}/previews"
            params = {"access_token": access_token, "ad_format": fmt}

            if isinstance(preview_options, dict):
                for k, v in preview_options.items():
                    params[k] = json.dumps(v) if isinstance(v, (dict, list)) else str(v)

            if appsecret_proof:
                params["appsecret_proof"] = appsecret_proof

            try:
                r = requests.get(preview_url, params=params, timeout=30)
                redacted_params = {k: (v if k != "access_token" else "<REDACTED>") for k, v in params.items()}
                current_app.logger.info("FB GET -> url=%s params=%s", preview_url, redacted_params)
                r.raise_for_status()
            except requests.RequestException as e:
                status = getattr(e, "response", None) and getattr(e.response, "status_code", None)
                text = getattr(e, "response", None) and getattr(e.response, "text", None)
                last_error = {"format": fmt, "error": str(e), "status": status, "response_text": text}
                previews.append({"format": fmt, "ok": False, "error": str(e), "status": status, "response_text": text})
                continue

            content_type = (r.headers.get("Content-Type") or "").lower()
            try:
                parsed = r.json() if "application/json" in content_type or r.text.strip().startswith("{") else {"text": r.text}
            except Exception:
                parsed = {"text": r.text}

            entry: Dict[str, Any] = {"format": fmt, "ok": True, "raw": parsed}
            try:
                if isinstance(parsed, dict) and parsed.get("data") and isinstance(parsed.get("data"), list) and parsed["data"]:
                    entry["data"] = parsed["data"]
                    first = parsed["data"][0]
                    if isinstance(first, dict):
                        html_fragment = first.get("body") or first.get("html") or first.get("iframe") or None
                        if html_fragment:
                            entry["preview_html"] = html_fragment
                            m = re.search(r'<iframe[^>]+src=["\']([^"\']+)["\']', html_fragment, re.I)
                            if m:
                                entry["iframe_src"] = m.group(1)
                elif isinstance(parsed, dict) and parsed.get("body"):
                    entry["preview_html"] = parsed.get("body")
                    m = re.search(r'<iframe[^>]+src=["\']([^"\']+)["\']', entry["preview_html"], re.I)
                    if m:
                        entry["iframe_src"] = m.group(1)
                elif isinstance(parsed, dict) and "text" in parsed and isinstance(parsed["text"], str):
                    entry["preview_html"] = parsed["text"]
                    m = re.search(r'<iframe[^>]+src=["\']([^"\']+)["\']', entry["preview_html"], re.I)
                    if m:
                        entry["iframe_src"] = m.group(1)
            except Exception as e:
                current_app.logger.exception("Error extracting preview_html: %s", e)

            previews.append(entry)
            any_success = True

        if not any_success:
            payload = {"ok": False, "error": "all_preview_requests_failed", "detail": last_error, "previews": previews}
            return jsonify(payload), 502

        resp = {"ok": True, "creative_id": creative_id, "previews": previews}
        if created_creative_id:
            resp["created_creative_id"] = created_creative_id

        return jsonify(resp)

    except Exception as exc:
        current_app.logger.exception("facebook_adpreviews unexpected error: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500




def _safe_model_generate(contents: List[str], candidate_count: int = 3, temperature: float = 0.2, max_output_tokens: int = 800) -> Any:
    """
    Wraps model generate call and returns the model response object.
    Adjust to your SDK's exact function signuture if needed.
    """
    try:
        # Try SDK typed config first (older/newer SDK variations)
        try:
            import types as _types  # some SDKs use types.GenerateContentConfig
            cfg = _types.GenerateContentConfig(temperature=temperature, candidate_count=candidate_count, max_output_tokens=max_output_tokens)
            resp = GENAI_CLIENT.models.generate_content(model=TEXT_MODEL, contents=contents, config=cfg)
            return resp
        except Exception:
            # fallback to dict-shaped config
            cfg = {"temperature": temperature, "candidate_count": candidate_count, "max_output_tokens": max_output_tokens}
            resp = GENAI_CLIENT.models.generate_content(model=TEXT_MODEL, contents=contents, config=cfg)
            return resp
    except Exception:
        # bubble up error so caller can handle/log
        raise

from flask import Flask, request, jsonify
import os
import json
import traceback
from typing import Optional
from google import genai
from google.genai import types

# Make sure to set GOOGLE_CLOUD_API_KEY in environment or replace below.
GENAI_MODEL = os.environ.get("GENAI_MODEL", "gemini-2.5-flash")
# optional: set max tokens / temperature defaults
GENAI_TEMPERATURE = float(os.environ.get("GENAI_TEMPERATURE", "0.2"))
GENAI_MAX_TOKENS = int(os.environ.get("GENAI_MAX_TOKENS", "32768"))


@app.route("/api/v1/generate-copy", methods=["POST"])
def generate_copy():
    """
    Lightweight streaming integration with Google GenAI.
    - Uses image URI when product fields are missing.
    - Assumes the model returns a single valid JSON object (as described by you).
    - Returns that parsed JSON directly as the API response, with workspace attached when available.
    """
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    body = request.get_json(silent=True) or {}
    product = body.get("product") or {}
    try:
        count = max(1, int(body.get("count") or 3))
    except Exception:
        count = 3
    free_prompt = (body.get("prompt") or "").strip()

    # resolve workspace (client may send workspace or workspace_id)
    workspace = body.get("workspace", None)
    workspace_id = body.get("workspace_id") or body.get("workspaceId") or None
    if workspace is None and workspace_id:
        try:
            ws_url = f"{WORKSPACE_API_ROOT}/api/workspace?workspace_id={int(workspace_id)}"
            r = requests.get(ws_url, timeout=6)
            if r.ok:
                parsed = r.json()
                workspace = parsed.get("workspace") if isinstance(parsed, dict) and parsed.get("workspace") else parsed
        except Exception:
            app.logger.exception("fetch_workspace_failed")
            workspace = None

    # Build prompt body (lean). If product missing, instruct model to analyze image.
    title = product.get("title") or product.get("brand") or ""
    short_desc = product.get("short_description") or product.get("description") or ""

    # use provided image if product lacks textual fields
    image_url = body.get("imageUrl") or product.get("imageUrl") or (None if not body.get("selectedImages") else body["selectedImages"][0].get("url") or None)

    # Compose user text part for model
    prompt_lines = []
    prompt_lines.append("TASK: Generate 3 high-quality Meta Ad copy variations for TRAFFIC.")
    if title:
        prompt_lines.append(f"Product title: {title}")
    if short_desc:
        prompt_lines.append(f"Short description: {short_desc}")
    # include workspace context if available
    if workspace:
        try:
            wname = workspace.get("name") or workspace.get("business_name") or ""
            wsite = workspace.get("website") or ""
            wdesc = workspace.get("description") or ""
            prompt_lines.append(f"Workspace name: {wname}")
            if wsite:
                prompt_lines.append(f"Website: {wsite}")
            if wdesc:
                prompt_lines.append(f"Workspace description: {wdesc}")
        except Exception:
            pass

    if image_url and not (title or short_desc):
        prompt_lines.append("No product text fields provided — analyze the image and infer product category, visual tone, and likely messaging. Do NOT invent specs.")
        prompt_lines.append(f"Image URL: {image_url}")

    prompt_lines.append("Output Requirements:")
    prompt_lines.append("- Return exactly one JSON object (no extra text). Keys: raw_model_text, success (true), variations (array of 3).")
    prompt_lines.append("- Each variation must include: id, primary_text (40-120 words), headline (<=40 chars), description (<=125 chars), cta (Shop Now / Learn More / Discover More / Explore), destination_url (https://www.apple.com/).")
    prompt_lines.append("- Tone: Premium, Elegant, Minimalist, High-trust, Global.")
    prompt_lines.append("- Do NOT include pricing or technical specifications.")
    if free_prompt:
        prompt_lines.append("") 
        prompt_lines.append("USER OVERRIDE PROMPT:")
        prompt_lines.append(free_prompt)

    user_text = "\n".join(prompt_lines)

    # prepare content parts: textual + image (if present)
    parts = [types.Part.from_text(text=user_text)]
    if image_url:
        # attempt to include the image as a URI part (model can analyze it)
        parts.append(types.Part.from_uri(file_uri=image_url, mime_type="image/jpeg"))

    contents = [types.Content(role="user", parts=parts)]

    # config for generate_content_stream
    gen_config = types.GenerateContentConfig(
        temperature=GENAI_TEMPERATURE,
        top_p=1.0,
        max_output_tokens=GENAI_MAX_TOKENS,
        response_mime_type="application/json",
        # optional: you can include a response_schema here to strengthen structure, omitted for brevity
    )

    # stream and accumulate text
    accumulated = ""
    try:
        for chunk in GENAI_CLIENT.models.generate_content_stream(
            model=GENAI_MODEL,
            contents=contents,
            config=gen_config,
        ):
            # chunk.text contains incremental text pieces
            txt = getattr(chunk, "text", None)
            if txt:
                accumulated += txt
    except Exception as e:
        app.logger.exception("genai_stream_failed")
        tb = traceback.format_exc()
        return jsonify({"success": False, "error": "genai_stream_failed", "detail": str(e), "trace": tb}), 502

    # The model is expected to return a single JSON object. Try to parse it directly.
    parsed = None
    try:
        parsed = json.loads(accumulated)
    except Exception:
        # If direct load fails, attempt to extract first JSON object substring
        try:
            start = accumulated.find("{")
            end = accumulated.rfind("}")
            if start != -1 and end != -1 and end > start:
                candidate = accumulated[start:end+1]
                parsed = json.loads(candidate)
        except Exception:
            app.logger.exception("failed_to_parse_model_json")
            return jsonify({"success": False, "error": "invalid_model_output", "raw_model_output": accumulated}), 502

    # normalize/validate the parsed object minimally
    if not isinstance(parsed, dict):
        return jsonify({"success": False, "error": "model_output_not_object", "raw_model_output": accumulated}), 502

    # ensure variations exist and shape them to your API contract
    variations = parsed.get("variations") or []
    normalized = []
    for i, var in enumerate(variations[:count]):
        # accept either the exact keys or synonyms
        vid = var.get("id") or str(i+1)
        primary_text = var.get("primary_text") or var.get("primaryText") or var.get("text") or ""
        headline = var.get("headline") or var.get("title") or ""
        description = var.get("description") or var.get("desc") or ""
        cta = var.get("cta") or var.get("call_to_action") or "Learn More"
        destination_url = var.get("destination_url") or var.get("destinationUrl") or var.get("url") or (workspace.get("website") if workspace else "")

        normalized.append({
            "id": str(vid),
            "primary_text": str(primary_text).strip(),
            "headline": str(headline).strip(),
            "description": str(description).strip(),
            "cta": str(cta).strip(),
            "destination_url": str(destination_url).strip() or "https://www.apple.com/"
        })

    # If model returned no variations, create a very small fallback
    if not normalized:
        normalized = [
            {"id": "1", "primary_text": (product.get("description") or "Discover this product."), "headline": f"Discover {title or 'Product'}", "description": (short_desc or "Explore more on the website.")[:125], "cta": "Learn More", "destination_url": workspace.get("website") if workspace else "https://www.apple.com/"},
        ][:count]

    response_payload = {
        "raw_model_text": accumulated,
        "success": True,
        "variations": normalized
    }
    if workspace:
        response_payload["workspace"] = workspace

    return jsonify(response_payload), 200

"""
agentic setup for contionus campaing management and ads ptimization]

simiulated with  mock / random data co'z no statical data 

data sent to gemini ai for knowing wheter its performing well or not 

email confirmation 

launch



"""
def _extract_json_block(text):
    """Return first valid top-level JSON object string found in text, or None."""
    if not text:
        return None

    # 1) Try to capture fenced ```json ... ``` block first
    m = re.search(r"```json(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    candidate_source = m.group(1) if m else text

    # Find first '{' then scan forward for balanced braces
    start = candidate_source.find("{")
    if start == -1:
        return None

    stack = 0
    for i, ch in enumerate(candidate_source[start:], start):
        if ch == "{":
            stack += 1
        elif ch == "}":
            stack -= 1
            if stack == 0:
                candidate = candidate_source[start:i+1]
                try:
                    # validate it's real JSON
                    json.loads(candidate)
                    return candidate
                except Exception:
                    # not valid JSON — keep searching in outer text
                    break

    # Fallback: try scanning the whole original text for a balanced {...} block
    start_all = text.find("{")
    if start_all == -1:
        return None
    stack = 0
    for i, ch in enumerate(text[start_all:], start_all):
        if ch == "{":
            stack += 1
        elif ch == "}":
            stack -= 1
            if stack == 0:
                candidate = text[start_all:i+1]
                try:
                    json.loads(candidate)
                    return candidate
                except Exception:
                    return None
    return None


# Generate plausible mock metrics when no campaigns are active
def _generate_mock_metrics(num_rows: int = 3):
    import random, datetime
    rows = []
    base_date = datetime.date.today()
    for i in range(num_rows):
        imp = random.randint(5000, 120000)
        clicks = max( int(imp * random.uniform(0.002, 0.03)), 1 )
        spend = round(random.uniform(imp * 0.001, imp * 0.01), 2)
        conv = max(int(clicks * random.uniform(0.01, 0.12)), 0)
        revenue = round(conv * random.uniform(10.0, 120.0), 2)
        rows.append({
            "campaign_id": f"mock_camp_{i+1}",
            "campaign_name": f"Mock Campaign {i+1}",
            "adset_id": f"mock_adset_{i+1}",
            "adset_name": f"Mock AdSet {i+1}",
            "ad_id": f"mock_ad_{i+1}",
            "ad_name": f"Mock Ad {i+1}",
            "impressions": imp,
            "clicks": clicks,
            "spend": f"{spend:.2f}",
            "reach": max(int(imp * random.uniform(0.6, 0.95)), 1),
            "frequency": round(random.uniform(1.0, 3.5), 2),
            "unique_clicks": max(int(clicks * random.uniform(0.8, 1.0)), 0),
            # basic actions structure similar to FB format
            "actions": json.dumps([{"action_type": "offsite_conversion.purchase", "value": f"{revenue:.2f}"},
                                   {"action_type": "link_click", "value": str(clicks)}]),
            "action_values": None
        })
    return rows

# Compose and send email (simple SMTP)
def _send_email(subject: str, html_body: str, plain_body: str = None):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    smtp_from = os.getenv("SMTP_FROM") or smtp_user
    to_addr = os.getenv("ALERT_EMAIL_TO")
    if not (smtp_host and smtp_port and smtp_user and smtp_pass and smtp_from and to_addr):
        return {"ok": False, "error": "missing_smtp_config"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = to_addr
    plain_body = plain_body or re.sub(r'<[^>]+>', '', html_body)  # naive fallback
    part1 = MIMEText(plain_body, "plain")
    part2 = MIMEText(html_body, "html")
    msg.attach(part1)
    msg.attach(part2)

    try:
        s = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.sendmail(smtp_from, [to_addr], msg.as_string())
        s.quit()
        return {"ok": True, "sent_to": to_addr}
    except Exception as e:
        return {"ok": False, "error": "smtp_failed", "detail": str(e)}
# Add or merge these imports at top of your Flask app/module
import os
import re
import json
import traceback
import requests
from flask import Flask, request, jsonify
# If you use a specific genai SDK, ensure GENAI_CLIENT, types, TEXT_MODEL are configured elsewhere
# from your_genai_sdk import GENAI_CLIENT, types, TEXT_MODEL



# -------------------------
# Helper / placeholder functions
# -------------------------
def _generate_mock_metrics(num_rows=3):
    """Return list of mock metric rows similar to FB Graph API structure.
    Replace with your real mock generator if you already have one."""
    rows = []
    for i in range(num_rows):
        rows.append({
            "campaign_id": f"camp_{i}",
            "campaign_name": f"Mock Campaign {i}",
            "adset_id": f"adset_{i}",
            "adset_name": f"Mock Adset {i}",
            "ad_id": f"ad_{i}",
            "ad_name": f"Mock Ad {i}",
            "impressions": 1000 + i * 100,
            "clicks": 10 + i,
            "spend": round(50.0 + i * 5.5, 2),
            "reach": 900 + i * 50,
            "frequency": 1.1 + i * 0.1,
            "actions": [{"action_type": "purchase", "value": "1"}] if i % 2 == 0 else []
        })
    return rows

def _extract_json_block(text):
    """Extract best-effort JSON object from text, even if incomplete."""
    if not text:
        return None

    m = re.search(r"```json(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    candidate_source = m.group(1) if m else text
    candidate_source = candidate_source.strip()

    start = candidate_source.find("{")
    if start == -1:
        return None

    # Try scanning until braces seem balanced or we reach end
    stack = 0
    for i, ch in enumerate(candidate_source[start:], start):
        if ch == "{":
            stack += 1
        elif ch == "}":
            stack -= 1
            if stack == 0:
                candidate = candidate_source[start:i + 1]
                try:
                    json.loads(candidate)
                    return candidate
                except Exception:
                    pass

    # If we never found a balanced block, try adding missing braces
    partial = candidate_source[start:]
    missing = partial.count("{") - partial.count("}")
    if missing > 0:
        partial += "}" * missing
        try:
            json.loads(partial)
            return partial
        except Exception:
            return None

    return None


def _send_email(subject, html_body, text_body):
    """
    Placeholder email sender. Replace with your actual email integration.
    Should return a dict describing the result (skipped, success, info, etc.)
    """
    # Example return - implement real sending here
    return {"skipped": False, "status": "sent", "subject": subject}

# -------------------------
# The complete route
# -------------------------
@app.route("/api/v1/ads/optimize-run", methods=["POST"])
def ads_optimize_run():
    """
    Synchronous optimization run.
    POST JSON:
      {
         "account_id": "<fb account id>",            # optional, will use env
         "access_token": "<fb token>",               # optional, will use env
         "force_mock": false,                        # if true, always use mock data
         "count_mock_rows": 3,
         "prompt_override": "<optional extra instructions for AI>",
         "notify": true                              # whether to send email
      }
    Response:
      { success: true, metrics_source: "mock"|"facebook"|"facebook_error", model_parsed: {...}, email: {...} }
    """
    body = request.get_json(silent=True) or {}
    account_id = body.get("account_id") or os.getenv("FB_AD_ACCOUNT_ID")
    access_token = body.get("access_token") or os.getenv("FB_ACCESS_TOKEN")
    force_mock = bool(body.get("force_mock"))
    notify = body.get("notify", True)
    mock_rows = int(body.get("count_mock_rows") or 3)
    prompt_override = (body.get("prompt_override") or "").strip()

    # Try to fetch real metrics only if access provided and not forced to mock
    metrics_rows = []
    metrics_source = "none"
    if not force_mock and account_id and access_token:
        try:
            api_ver = os.getenv("FB_GRAPH_API_VERSION", "v18.0")
            base_url = f"https://graph.facebook.com/{api_ver}/act_{account_id}/insights"
            params = {
                "access_token": access_token,
                "fields": "campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,impressions,clicks,spend,reach,frequency,unique_clicks,actions,action_values",
                "limit": 50,
                "time_increment": 1
            }
            r = requests.get(base_url, params=params, timeout=20)
            r.raise_for_status()
            j = r.json()
            metrics_rows = j.get("data", []) or []
            metrics_source = "facebook"
        except Exception:
            metrics_rows = []
            metrics_source = "facebook_error"

    # If none, use mock data
    if not metrics_rows:
        metrics_rows = _generate_mock_metrics(num_rows=mock_rows)
        metrics_source = metrics_source if metrics_source != "facebook_error" else "facebook_error"
        if not metrics_rows:
            metrics_source = "mock"
        else:
            metrics_source = "mock"

    # Build a compact metrics summary to include in the prompt (keep it short)
    def _summarize_rows(rows):
        summary_lines = []
        total_imp = total_clicks = total_spend = total_conv = 0.0
        for r in rows:
            try:
                imp = float(r.get("impressions") or 0)
            except Exception:
                imp = 0.0
            try:
                clicks = float(r.get("clicks") or r.get("inline_link_clicks") or 0)
            except Exception:
                clicks = 0.0
            try:
                spend = float(str(r.get("spend") or 0).replace(",", ""))
            except Exception:
                spend = 0.0
            # parse actions for simple conversions if present
            try:
                acts = r.get("actions")
                if acts:
                    if isinstance(acts, str):
                        acts_parsed = json.loads(acts)
                    else:
                        acts_parsed = acts
                    for a in acts_parsed:
                        t = a.get("action_type", "") or a.get("action_type_full", "") or a.get("action", "")
                        if "purchase" in str(t) or "offsite_conversion" in str(t) or "omni_purchase" in str(t):
                            try:
                                v = float(a.get("value") or 0)
                                if v > 0:
                                    total_conv += 1
                            except Exception:
                                pass
            except Exception:
                pass
            total_imp += imp
            total_clicks += clicks
            total_spend += spend
        ctr = (total_clicks / total_imp * 100) if total_imp > 0 else 0.0
        cpc = (total_spend / total_clicks) if total_clicks > 0 else None
        return {
            "rows_count": len(rows),
            "total_impressions": int(total_imp),
            "total_clicks": int(total_clicks),
            "total_spend": round(total_spend, 2),
            "ctr_pct": round(ctr, 3),
            "avg_cpc": round(cpc, 4) if cpc else None
        }

    summary = _summarize_rows(metrics_rows)

    # Build the AI prompt (ask for JSON output enclosed in a ```json ... ``` fenced block).
    # Keep it concise so model tokens are reasonable.
    model_prompt = f"""
SYSTEM: You are an ads optimization analyst. Use only the metrics provided. Do NOT hallucinate facts.

USER: I will provide an account summary and rows of performance data (campaign/adset/ad). Evaluate overall performance, identify up to 5 prioritized optimization actions (with estimated % impact and confidence 0-1), and draft a short email to the account owner proposing a single recommended action (Yes/No) to run now. Output EXACTLY one JSON object wrapped in a ```json ... ``` fenced block.

DATA_SUMMARY:
{json.dumps(summary)}

SAMPLE_ROWS:
{json.dumps(metrics_rows[:5], default=str)}

INSTRUCTIONS:
- Provide keys:
  - performance_assessment: short text (1-2 sentences)
  - actions: array of up to 5 objects {{ "id", "title", "description", "estimated_impact_percent", "confidence" }}
  - recommended_action: {{ "id": <action id or null>, "run_now": true|false, "reason": short string }}
  - email_subject: short subject line
  - email_body_html: html email body (include summary + recommended action + action link placeholder)
  - email_body_text: plain text version
  - notes: optional notes about data quality
- Keep JSON values concise. Use numeric values for estimated_impact_percent and confidence.
- Use provided OPTIMIZER_CONFIRM_URL_BASE env var to create an action confirm link if present.

{json.dumps({"extra_instructions": prompt_override})}
"""

    # Call the model (example pattern that works with a "GENAI_CLIENT" and "types" if you have them)
    model_output_text = ""
    model_parsed = None
    try:
        # If you have genai types and client, adapt the next block accordingly.
        try:
            cfg = types.GenerateContentConfig(temperature=0.0, candidate_count=1, max_output_tokens=800)
        except Exception:
            cfg = {"temperature": 0.0, "candidate_count": 1, "max_output_tokens": 800}

        if "GENAI_CLIENT" in globals() and "types" in globals():
            contents = [types.Content(role="user", parts=[types.Part.from_text(text=model_prompt)])] if hasattr(types, "Content") else [model_prompt]
            resp = GENAI_CLIENT.models.generate_content(model=TEXT_MODEL, contents=contents, config=cfg)
            if getattr(resp, "candidates", None):
                cand = resp.candidates[0]
                if getattr(cand, "content", None) and getattr(cand.content, "parts", None):
                    for p in cand.content.parts:
                        try:
                            if getattr(p, "text", None):
                                model_output_text += p.text or ""
                            else:
                                model_output_text += str(p)
                        except Exception:
                            model_output_text += str(p)
                else:
                    model_output_text = str(cand)
            else:
                model_output_text = str(resp)
        else:
            # No GENAI client configured — create a conservative fallback text describing the request
            model_output_text = "MODEL_NOT_CONFIGURED: No GENAI client available in this runtime."
    except Exception as e:
        model_output_text = f"MODEL_CALL_FAILED: {str(e)}\n{traceback.format_exc()}"

    # Try to extract JSON block returned by the model
    extracted = _extract_json_block(model_output_text)
    if extracted:
        try:
            model_parsed = json.loads(extracted)
        except Exception:
            model_parsed = None

    # If parsing failed, build a conservative fallback recommendation (use valid Python dict with quoted keys)
    if model_parsed is None:
        model_parsed = {
            "performance_assessment": "Model output could not be parsed. Data may be incomplete.",
            "actions": [
                {
                    "id": "a1",
                    "title": "Reduce budget on low-CTR adsets",
                    "description": "Lower bids or pause adsets with CTR below 0.5%",
                    "estimated_impact_percent": 3,
                    "confidence": 0.5
                }
            ],
            "recommended_action": {
                "id": "a1",
                "run_now": False,
                "reason": "Need clearer data to be confident."
            },
            "email_subject": f"Ad optimization recommendations for {account_id or 'account'} - Manual review required",
            "email_body_html": "<p>Could not parse AI analysis. Please check logs.</p>",
            "email_body_text": "Could not parse AI analysis. Please check logs.",
            "notes": "model parse_failed"
        }

    # Build action confirmation link if base provided
    confirm_base = os.getenv("OPTIMIZER_CONFIRM_URL_BASE", "").rstrip("/")
    recommended = model_parsed.get("recommended_action") or {}
    confirm_link = None
    if confirm_base and recommended and recommended.get("id"):
        confirm_link = f"{confirm_base}/confirm-action?account_id={account_id}&action_id={recommended.get('id')}"
        if "email_body_html" in model_parsed:
            model_parsed["email_body_html"] = (model_parsed.get("email_body_html") or "") + f"<p><a href='{confirm_link}'>Confirm & Run Action</a></p>"
        if "email_body_text" in model_parsed:
            model_parsed["email_body_text"] = (model_parsed.get("email_body_text") or "") + f"\nConfirm & Run: {confirm_link}"

    email_result = {"skipped": True}
    if notify:
        subj = model_parsed.get("email_subject") or f"Ad optimization recommendations for {account_id or 'account'}"
        html = model_parsed.get("email_body_html") or "<p>No HTML body provided.</p>"
        text = model_parsed.get("email_body_text") or re.sub(r"<[^>]+>", "", html)
        email_result = _send_email(subj, html, text)

    # Return a full response
    return jsonify({
        "success": True,
        "metrics_source": metrics_source,
        "metrics_count": len(metrics_rows),
        "metrics_summary": summary,
        "model_raw_text": model_output_text,
        "model_parsed": model_parsed,
        "email": email_result
    }), 200
# app.py
import os
import json
import re
import time
import logging
import threading
from typing import Optional
from datetime import datetime, timezone

import httplib2
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy


GS_SPREADSHEET_ID = os.getenv("GS_SPREADSHEET_ID", "1KIaVXGXBse8CiOmcxtdoo4qAAR4GQ7u3zQ8FIwx6Rdw")
GS_SHEET_NAME = os.getenv("GS_SHEET_NAME", "Sheet1")

# Prefer SERVICE_ACCOUNT_JSON, fallback to GS_CREDS_JSON (some environments)
_ENV_JSON = os.getenv("SERVICE_ACCOUNT_JSON") or os.getenv("GS_CREDS_JSON")

# -------------------------
# Logging + Flask + DB init
# -------------------------
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s)')
logger = logging.getLogger("waitlist_app")


# -------------------------
# Robust SA JSON loader
# -------------------------
def _load_service_account_info(env_value: Optional[str]):
    """
    Accepts:
      - raw JSON text
      - double-encoded JSON string
      - JSON with escaped newlines (\n)
    Returns dict or None.
    """
    if not env_value:
        return None
    s = env_value.strip()
    # try parse normally
    try:
        info = json.loads(s)
        if isinstance(info, str):
            info = json.loads(info)
        if isinstance(info, dict):
            return info
    except Exception:
        pass
    # try replacing literal \n sequences with real newlines and parse
    try:
        fixed = s.replace("\\n", "\n")
        info = json.loads(fixed)
        if isinstance(info, dict):
            return info
    except Exception:
        pass
    return None

_SA_INFO = _load_service_account_info(_ENV_JSON)
if _SA_INFO:
    logger.info("Loaded service account info from env; client_email=%s", _SA_INFO.get("client_email"))
else:
    logger.info("No SERVICE_ACCOUNT_JSON/GS_CREDS_JSON loaded; will attempt ADC if available (GOOGLE_APPLICATION_CREDENTIALS)")

# -------------------------
# DB model
# -------------------------
class Waitlist(db.Model):
    __tablename__ = "waitlist",
    
    __table_args__ = {"extend_existing": True}
   
    email = db.Column(db.String(255), primary_key=True, index=True)
    name = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

with app.app_context():
    db.create_all()

# -------------------------
# Validation regexes
# -------------------------
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^[0-9+\-\s()]{6,30}$")

def is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email or ""))

def is_valid_phone(phone: Optional[str]) -> bool:
    if not phone:
        return True
    return bool(_PHONE_RE.match(phone))

# -------------------------
# Google Sheets helpers
# -------------------------
def get_sheets_service(timeout_sec: int = 30):
    """
    Build Google Sheets client using AuthorizedHttp so we can provide a timeout.
    Uses _SA_INFO (service account) if present, otherwise attempts ADC.
    """
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    try:
        raw_http = httplib2.Http(timeout=timeout_sec)

        if _SA_INFO:
            creds = service_account.Credentials.from_service_account_info(_SA_INFO, scopes=scopes)
            authed_http = AuthorizedHttp(creds, http=raw_http)
            return build("sheets", "v4", http=authed_http)
        else:
            # try Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS or runtime)
            try:
                import google.auth
                creds, _ = google.auth.default(scopes=scopes)
                authed_http = AuthorizedHttp(creds, http=raw_http)
                return build("sheets", "v4", http=authed_http)
            except Exception:
                logger.warning("ADC not available; building Sheets client without custom timeout")
                return build("sheets", "v4")
    except Exception:
        logger.exception("Failed to build Google Sheets service client")
        raise

def append_waitlist_row_to_sheet_sync(name: str, email: str, phone: Optional[str], retries: int = 3, timeout_sec: int = 30) -> bool:
    if not GS_SPREADSHEET_ID:
        logger.info("GS_SPREADSHEET_ID not configured; skipping Sheets append")
        return False

    rng = f"{GS_SHEET_NAME}!A:D"
    values = [[datetime.now(timezone.utc).isoformat(), name or "", email or "", phone or ""]]
    body = {"values": values}

    backoff = 1.0
    for attempt in range(1, retries + 1):
        try:
            service = get_sheets_service(timeout_sec=timeout_sec)
            res = service.spreadsheets().values().append(
                spreadsheetId=GS_SPREADSHEET_ID,
                range=rng,
                valueInputOption="USER_ENTERED",
                insertDataOption="INSERT_ROWS",
                body=body
            ).execute()
            logger.info("Appended to sheet (attempt %s) updates=%s", attempt, res.get("updates"))
            return True
        except HttpError as e:
            status = None
            try:
                status = getattr(e, "status_code", None) or (getattr(e, "resp", None) and getattr(e.resp, "status", None))
            except Exception:
                status = None
            logger.warning("Sheets HttpError attempt %s: status=%s error=%s", attempt, status, e)
            # don't retry on most 4xx (except 408/429)
            if status and 400 <= int(status) < 500 and int(status) not in (408, 429):
                logger.warning("Non-retryable Sheets HttpError %s; aborting", status)
                return False
        except (TimeoutError, OSError, ConnectionError) as e:
            logger.warning("Sheets network error attempt %s: %s", attempt, e)
        except Exception as e:
            logger.exception("Unexpected error during Sheets append attempt %s: %s", attempt, e)

        if attempt < retries:
            logger.info("Retrying in %s seconds (attempt %s -> %s)", backoff, attempt, attempt + 1)
            time.sleep(backoff)
            backoff *= 2.0

    logger.exception("All attempts to append to Google Sheet failed")
    return False

def _background_append_worker(name: str, email: str, phone: Optional[str]):
    try:
        ok = append_waitlist_row_to_sheet_sync(name, email, phone)
        if not ok:
            logger.warning("Background Sheets append ultimately failed for %s", email)
    except Exception:
        logger.exception("Background worker error while appending to sheet for %s", email)

def enqueue_append_waitlist_row(name: str, email: str, phone: Optional[str]):
    try:
        t = threading.Thread(target=_background_append_worker, args=(name, email, phone), daemon=True)
        t.start()
        logger.debug("Spawned background Sheets append thread for %s", email)
    except Exception:
        logger.exception("Failed to spawn background thread for Sheets append")

# -------------------------
# Routes
# -------------------------
@app.route("/api/waitlist", methods=["POST"])
def api_waitlist():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip() or None

    if not name:
        return jsonify({"success": False, "error": "Name is required"}), 400
    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400
    if not is_valid_email(email):
        return jsonify({"success": False, "error": "Invalid email format"}), 400
    if not is_valid_phone(phone):
        return jsonify({"success": False, "error": "Invalid phone format"}), 400

    try:
        existing = Waitlist.query.filter_by(email=email).first()
    except Exception:
        logger.exception("DB error while querying waitlist")
        return jsonify({"success": False, "error": "Database error"}), 500

    if existing:
        try:
            updated = False
            if name and (existing.name or "") != name:
                existing.name = name
                updated = True
            if phone and (existing.phone or "") != (phone or ""):
                existing.phone = phone
                updated = True
            if updated:
                db.session.add(existing)
                db.session.commit()
                logger.info("Updated existing waitlist entry for %s", email)
        except Exception:
            db.session.rollback()
            logger.exception("Failed updating existing waitlist entry; continuing")

        try:
            enqueue_append_waitlist_row(name, email, phone)
        except Exception:
            logger.exception("Failed to enqueue background Sheets append; continuing")

        return jsonify({"success": True, "message": "Already registered"}), 200

    try:
        new_entry = Waitlist(email=email, name=name or None, phone=phone or None, created_at=datetime.now(timezone.utc))
        db.session.add(new_entry)
        db.session.commit()
        logger.info("Added new waitlist entry: %s (name=%s phone=%s)", email, name, phone)

        try:
            enqueue_append_waitlist_row(name, email, phone)
        except Exception:
            logger.exception("Failed to enqueue background Sheets append after insert; continuing")

        return jsonify({"success": True, "message": "Added to waitlist"}), 201
    except Exception:
        db.session.rollback()
        logger.exception("Failed to add email to waitlist")
        return jsonify({"success": False, "error": "Failed to save email"}), 500

@app.route("/api/debug-creds", methods=["GET"])
def debug_creds():
    """
    Temporary debug route to confirm loaded client_email (do not leave in production).
    """
    if _SA_INFO:
        return jsonify({"ok": True, "client_email": _SA_INFO.get("client_email")}), 200
    gac = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    return jsonify({"ok": False, "msg": "No SERVICE_ACCOUNT_JSON/GS_CREDS_JSON loaded", "GOOGLE_APPLICATION_CREDENTIALS": bool(gac)}), 200

from flask import request, jsonify, current_app
from datetime import datetime
import json

# ---------- Utility helpers ----------
def _get_request_user_id():
    # canonical header we used in other endpoints
    return request.headers.get("X-User-Id") or request.args.get("user_id")

def _safe_trim(s: str, max_len: int = 200) -> str:
    if s is None:
        return ""
    s = str(s).strip()
    return s if len(s) <= max_len else s[:max_len].rstrip() + " ..."

def _load_response_json(conv):
    """
    Try to load conversation.response field to python object; return dict or {}
    """
    try:
        if getattr(conv, "response", None):
            return json.loads(conv.response)
    except Exception:
        current_app.logger.debug("Could not parse conversation.response; will replace with {}")
    return {}

def _save_response_json(conv, obj):
    try:
        conv.response = json.dumps(obj)
    except Exception as e:
        current_app.logger.exception("Failed to json.dumps response for conv %s: %s", getattr(conv, "id", "<nil>"), e)
        conv.response = "{}"

# ---------- Route: Delete conversation ----------
@app.route("/api/v1/conversations/<conv_id>", methods=["DELETE"])
def delete_conversation(conv_id):
    """
    Delete or soft-delete a conversation.
    Query params:
      - hard=true       => perform hard delete (remove DB row)
      - delete_creatives=true => if hard delete, also delete Creative rows for this conversation
    Permission: only owner (user_id from X-User-Id) can delete.
    """
    user_id = _get_request_user_id()
    hard = str(request.args.get("hard", "") or "").lower() in ("1", "true", "yes")
    delete_creatives = str(request.args.get("delete_creatives", "") or "").lower() in ("1", "true", "yes")


    try:
        conv = db.session.get(Conversation, conv_id) if hasattr(db.session, "get") else Conversation.query.get(conv_id)
        if not conv:
            return jsonify({"ok": False, "error": "conversation_not_found"}), 404

        # Permission check: owner only
        conv_owner = getattr(conv, "user_id", None)
        if str(conv_owner) != str(user_id):
            current_app.logger.warning("User %s attempted to delete conv %s owned by %s", user_id, conv_id, conv_owner)
            return jsonify({"ok": False, "error": "forbidden"}), 403

        if hard:
            # Optionally delete creatives associated with this conversation (best-effort)
            if delete_creatives:
                try:
                    # assumes Creative model has conversation_id or conversation reference (best-effort)
                    # Try two methods: column 'conversation_id' or 'conversation' relationship.
                    if hasattr(Creative, "conversation_id"):
                        deleted = Creative.query.filter_by(conversation_id=conv_id).delete(synchronize_session=False)
                        current_app.logger.info("Hard delete: removed %s creatives with conversation_id=%s", deleted, conv_id)
                    else:
                        # fallback using workspace_id/file matching - best-effort, skip if model differs
                        current_app.logger.debug("Creative model has no 'conversation_id' column; skip delete_creatives")
                except Exception as e:
                    current_app.logger.exception("Failed to delete creatives for conversation %s: %s", conv_id, e)

            try:
                db.session.delete(conv)
                db.session.commit()
                current_app.logger.info("Hard deleted conversation %s by user %s", conv_id, user_id)
                return jsonify({"ok": True, "deleted": True, "hard": True}), 200
            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("Hard delete DB error for conv %s: %s", conv_id, e)
                return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500

        else:
            # Soft-delete: prefer 'deleted' boolean or 'deleted_at' timestamp if model has them
            try:
                if hasattr(conv, "deleted"):
                    setattr(conv, "deleted", True)
                    # optional deleted_at
                    if hasattr(conv, "deleted_at"):
                        setattr(conv, "deleted_at", datetime.utcnow())
                elif hasattr(conv, "deleted_at"):
                    setattr(conv, "deleted_at", datetime.utcnow())
                else:
                    # fallback: mark in response JSON
                    resp = _load_response_json(conv)
                    resp["_deleted"] = True
                    resp["_deleted_at"] = datetime.utcnow().isoformat()
                    _save_response_json(conv, resp)

                db.session.add(conv)
                db.session.commit()
                current_app.logger.info("Soft-deleted conversation %s by user %s", conv_id, user_id)
                return jsonify({"ok": True, "deleted": True, "hard": False}), 200
            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("Soft delete DB error for conv %s: %s", conv_id, e)
                return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500

    except Exception as e:
        current_app.logger.exception("Unexpected error deleting conversation %s: %s", conv_id, e)
        return jsonify({"ok": False, "error": "internal", "details": str(e)}), 500


@app.route("/api/v1/conversations/<conv_id>/rename", methods=["POST"])
def rename_conversation(conv_id):
    """
    Rename a conversation/chat.
    Expects JSON body: { "title": "New name" } or form param.
    If Conversation has a 'title' column it is updated. Otherwise the rename is stored inside response JSON under _renamed_to.
    Permission: only owner (X-User-Id) can rename.
    """
    user_id = _get_request_user_id()
    if not user_id:
        return jsonify({"ok": False, "error": "missing_user_id_header"}), 400

    data = request.get_json(silent=True) or {}
    new_title = (data.get("title") or request.form.get("title") or "").strip()
    if not new_title:
        return jsonify({"ok": False, "error": "missing_title"}), 400

    # sanitize length
    new_title = _safe_trim(new_title, max_len=200)

    try:
        conv = db.session.get(Conversation, conv_id) if hasattr(db.session, "get") else Conversation.query.get(conv_id)
        if not conv:
            return jsonify({"ok": False, "error": "conversation_not_found"}), 404

        # Permission check
        if str(getattr(conv, "user_id", None)) != str(user_id):
            current_app.logger.warning("User %s attempted to rename conv %s owned by %s", user_id, conv_id, getattr(conv, "user_id", None))
            return jsonify({"ok": False, "error": "forbidden"}), 403

        # Update title if model has attribute/column
        try:
            if hasattr(conv, "title"):
                setattr(conv, "title", new_title)
                db.session.add(conv)
                db.session.commit()
                current_app.logger.info("Updated title for conv %s by user %s", conv_id, user_id)
                return jsonify({"ok": True, "id": conv_id, "title": new_title}), 200
            else:
                # fallback: record rename in response JSON under _renamed_to and save
                resp = _load_response_json(conv)
                # preserve previous title if any
                prev = getattr(conv, "prompt", None) or resp.get("_renamed_to_previous") or None
                if prev:
                    resp["_renamed_to_previous"] = _safe_trim(prev, 500)
                resp["_renamed_to"] = new_title
                resp["_renamed_at"] = datetime.utcnow().isoformat()
                _save_response_json(conv, resp)
                db.session.add(conv)
                db.session.commit()
                current_app.logger.info("Stored rename in response JSON for conv %s by user %s", conv_id, user_id)
                return jsonify({"ok": True, "id": conv_id, "title": new_title}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("DB error renaming conversation %s: %s", conv_id, e)
            return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500

    except Exception as e:
        current_app.logger.exception("Unexpected error renaming conversation %s: %s", conv_id, e)
        return jsonify({"ok": False, "error": "internal", "details": str(e)}), 500
# SMS / OTP helpers (replace your existing block with this)
import urllib.parse
import requests
# logger assumed to be defined elsewhere (logger = logging.getLogger(...))

# ---------------- SMS config (updated to match your PHP creds) ----------------
SMS_USER = os.getenv("SMS_USER", "profes")
SMS_APIKEY = os.getenv("SMS_APIKEY", "ghSV6w6TthpzHc3ytnGj")
SMS_SEND_URL = os.getenv("SMS_SEND_URL", "https://smshorizon.co.in/api/sendsms.php")
# EXACT values from your PHP
SMS_SENDERID = os.getenv("SMS_SENDERID", "TRVTKT")   # 6 chars
SMS_TID = os.getenv("SMS_TID", "1207176191702982105")  # 19-digit template id

OTP_TTL_MIN = int(app.config.get("PHONE_OTP_TTL_MIN", os.getenv("PHONE_OTP_TTL_MIN", 10)))
OTP_RESEND_COOLDOWN_SEC = int(app.config.get("PHONE_OTP_RESEND_COOLDOWN_SEC", os.getenv("PHONE_OTP_RESEND_COOLDOWN_SEC", 30)))

# ---------------- helpers ----------------
import random
from datetime import datetime, timezone, timedelta

def _generate_numeric_otp(length=6):
    start = 10**(length-1)
    return str(random.randint(start, start*10 - 1))

def _normalize_phone(phone: str) -> str:
    cleaned = re.sub(r"\D", "", phone or "")
    if len(cleaned) == 10:
        return "91" + cleaned
    if cleaned.startswith("0") and len(cleaned) == 11:
        cleaned2 = cleaned.lstrip("0")
        if len(cleaned2) == 10:
            return "91" + cleaned2
    return cleaned

def _now_utc():
    return datetime.now(timezone.utc)

# ----------------- SMS provider wrapper (PHP-style URL) --------------------
def send_sms_horizon(mobile_digits: str, message_text: str) -> (bool, str):
    """
    Build the GET URL exactly like your PHP implementation and call it.
    Returns (success, response_text_or_error).
    mobile_digits must be digits-only (e.g., '919876543210').
    """
    try:
        # encode message exactly like PHP urlencode
        encoded_message = urllib.parse.quote_plus(message_text)

        # build URL exactly like PHP: ?user=...&apikey=...&mobile=...&senderid=...&message=...&type=txt&tid=...
        url = (
            f"{SMS_SEND_URL}"
            f"?user={SMS_USER}"
            f"&apikey={SMS_APIKEY}"
            f"&mobile={mobile_digits}"
            f"&senderid={SMS_SENDERID}"
            f"&message={encoded_message}"
            f"&type=txt"
            f"&tid={SMS_TID}"
        )

        resp = requests.get(url, timeout=10)
        resp_text = (resp.text or "").strip()

        logger.info("SMS request => url=%s status=%s response=%s", url, resp.status_code, resp_text)

        if not resp.ok:
            return False, f"HTTP {resp.status_code}: {resp_text}"

        # provider returns "ERROR: ..." or numeric id on success
        if resp_text.upper().startswith("ERROR"):
            err_lower = resp_text.lower()
            if "sender id" in err_lower or "senderid" in err_lower:
                return False, "ERROR from provider: Sender ID missing or not approved for this account/senderid."
            if "tid" in err_lower or "template" in err_lower:
                return False, "ERROR from provider: Template ID (tid) missing/not approved or message doesn't match template."
            return False, resp_text

        return True, resp_text

    except requests.exceptions.RequestException as e:
        logger.exception("HTTP request to SMS provider failed")
        return False, str(e)
    except Exception as e:
        logger.exception("Unexpected error sending SMS")
        return False, str(e)

# sms_routes.py
import re
import logging
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------- Helper utilities -----------------
def _now_utc():
    # timezone-aware UTC datetime
    return datetime.now(timezone.utc)

def _normalize_phone(phone_in: str) -> str:
    """
    Normalizes Indian phone input to a canonical digits-only string.
    Example conversions:
      +91 70131 23744  -> 917013123744
      07013123744      -> 7013123744  (if you want leading 0 removed)
    Implement or replace with a proper E.164 normalization if you prefer.
    """
    if not phone_in:
        return ""
    s = str(phone_in).strip()
    # remove all non-digits except leading '+'
    if s.startswith("+"):
        digits = "+" + re.sub(r"\D", "", s[1:])
    else:
        digits = re.sub(r"\D", "", s)
    # Example: convert leading '91' or '+91' -> keep '91' (country code)
    # Return digits-only (without '+') to match how you store phones in DB.
    if digits.startswith("+"):
        digits = digits[1:]
    return digits

def _generate_numeric_otp(length=4):
    import random
    start = 10 ** (length - 1)
    end = (10 ** length) - 1
    return str(random.randint(start, end))


# ----------------------------------------------------

@app.route("/api/sms/send-otp", methods=["POST"])
def api_sms_send_otp():
    """
    POST JSON:
      { "phone": "9876543210" or "+919876543210", "email": "... (optional)", "otp_length": 4 }
    """
    data = request.get_json() or {}
    phone_in = (data.get("phone") or "").strip()
    email = (data.get("email") or "").strip().lower()
    otp_length = int(data.get("otp_length",4 ))

    logger.info("Incoming send-otp JSON: %s", data)
    logger.info("Lookup keys: phone_in=%r, email=%r", phone_in, email)

    if not phone_in and not email:
        return jsonify({"success": False, "error": "phone_or_email_required"}), 400

    # find user (email preferred if provided)
    user = None
    if email:
        user = User.query.filter_by(email=email).first()
    if not user and phone_in:
        normalized = _normalize_phone(phone_in)
        # try match either stored canonical phone or raw
        user = User.query.filter((User.phone == normalized) | (User.phone == phone_in)).first()

    if not user:
        logger.info("send-otp: user not found for phone=%r email=%r", phone_in, email)
        return jsonify({"success": False, "error": "user_not_found"}), 404

    now = _now_utc()
    last_sent = getattr(user, "phone_last_sent_at", None)
    if last_sent and (now - last_sent).total_seconds() < OTP_RESEND_COOLDOWN_SEC:
        retry_after = OTP_RESEND_COOLDOWN_SEC - int((now - last_sent).total_seconds())
        logger.info("send-otp: cooldown for user=%s retry_after=%s", user.id, retry_after)
        return jsonify({"success": False, "error": "otp_cooldown", "retry_after_seconds": retry_after}), 429

    # generate and persist OTP
    otp = _generate_numeric_otp(otp_length)
    otp_hash = generate_password_hash(otp)
    expires_at = now + timedelta(minutes=OTP_TTL_MIN)

    user.phone_otp_hash = otp_hash
    user.phone_otp_expires_at = expires_at
    user.phone_last_sent_at = now

    # Optionally ensure canonical phone stored on user
    normalized_mobile = _normalize_phone(phone_in) or getattr(user, "phone", "") or ""
    # if you want to persist canonical phone:
    if normalized_mobile and (not getattr(user, "phone", None) or user.phone != normalized_mobile):
        user.phone = normalized_mobile

    db.session.add(user)
    db.session.commit()

    # Build message EXACTLY matching DLT template if required
    message_text = (
        " Dear Customer,\n"
        f"Your One-Time Password (OTP) is {otp}.\n"
        "Please do not share this code with anyone for security reasons.\n\n"
        "Regards,\n"
        "Profes"
    )

    # Basic sanity checks & warnings
    if SMS_SENDERID and len(SMS_SENDERID) != 6:
        logger.warning("Configured SMS_SENDERID appears invalid (not 6 chars): %r", SMS_SENDERID)
    if SMS_TID and (not SMS_TID.isdigit() or len(SMS_TID) not in (19,)):
        logger.warning("Configured SMS_TID appears unusual: %r", SMS_TID)

    # send via provider
    try:
        success, provider_resp = send_sms_horizon(normalized_mobile, message_text)
    except Exception as exc:
        logger.exception("SMS provider call raised exception for user=%s mobile=%s", user.id, normalized_mobile)
        return jsonify({"success": False, "error": "sms_provider_error", "detail": str(exc)}), 502

    if not success:
        logger.warning("SMS send failed for mobile=%s user=%s detail=%s", normalized_mobile, user.id, provider_resp)
        return jsonify({"success": False, "error": "sms_provider_error", "detail": provider_resp}), 502

    msgid = provider_resp
    logger.info("SMS sent msgid=%s mobile=%s user=%s", msgid, normalized_mobile, user.id)

    # Return user_id and normalized_mobile to help client avoid formatting mismatches
    return jsonify({
        "success": True,
        "msgid": msgid,
        "expires_at": expires_at.isoformat(),
        "user_id": user.id,
        "normalized_mobile": normalized_mobile
    }), 200


@app.route("/api/sms/verify-otp", methods=["POST"])
def api_sms_verify_otp():
    """
    POST JSON:
      { "phone": "...", "code": "1234", "email": "..." (optional), "user_id": 123 (optional) }
    Prefer passing user_id returned by send-otp to avoid phone formatting issues.
    """
    data = request.get_json() or {}
    phone_in = (data.get("phone") or "").strip()
    code = (data.get("code") or "").strip()
    email = (data.get("email") or "").strip().lower()
    user_id = data.get("user_id")

    logger.info("Verify incoming JSON: %s", data)
    logger.info("Verify lookup keys: phone=%r email=%r user_id=%r", phone_in, email, user_id)

    if not code or not (phone_in or email or user_id):
        return jsonify({"success": False, "error": "phone_and_code_required"}), 400

    # Prefer user_id if provided (more robust)
    user = None
    if user_id:
        try:
            user = User.query.get(int(user_id))
        except Exception:
            user = None

    if not user:
        if email:
            user = User.query.filter_by(email=email).first()
        if not user and phone_in:
            cleaned = _normalize_phone(phone_in)
            user = User.query.filter((User.phone == cleaned) | (User.phone == phone_in)).first()

    if not user:
        logger.info("Verify: user not found for phone=%r email=%r user_id=%r", phone_in, email, user_id)
        return jsonify({"success": False, "error": "user_not_found"}), 404

    # ensure latest DB state in case of concurrent writes
    try:
        db.session.refresh(user)
    except Exception:
        # refresh may fail in some ORMs/backends; ignore but keep logging
        logger.debug("db.session.refresh failed or unsupported for user=%s", user.id)

    logger.info("Verify: found user id=%s stored_phone=%r phone_otp_hash_present=%s expires=%s",
                user.id, getattr(user, "phone", None),
                bool(getattr(user, "phone_otp_hash", None)),
                getattr(user, "phone_otp_expires_at", None))

    if not getattr(user, "phone_otp_hash", None) or not getattr(user, "phone_otp_expires_at", None):
        return jsonify({
            "success": False,
            "error": "otp_not_requested",
            "user_id": user.id,
            "stored_phone": getattr(user, "phone", None)
        }), 400

    if user.phone_otp_expires_at < _now_utc():
        return jsonify({"success": False, "error": "otp_expired"}), 400

    if not check_password_hash(user.phone_otp_hash, code):
        return jsonify({"success": False, "error": "invalid_otp"}), 400

    # Success: mark verified & clear otp fields
    user.phone_verified = True
    user.phone_otp_hash = None
    user.phone_otp_expires_at = None
    user.phone_last_sent_at = None
    db.session.add(user)
    db.session.commit()

    logger.info("User %s phone verified", user.id)
    return jsonify({"success": True, "message": "phone_verified", "user_id": user.id}), 200

@app.route("/generate_workspace", methods=["POST"])
def generate_workspace():
    """
    AI-powered extractor for Workspace Setup fields.
    Input:
      { "url": "https://example.com", "max_snapshots": 5 (optional) }

    Output: {
      ok: True,
      page_url: "...",
      snapshots: [...],
      snapshot_urls: [...],
      workspace: { ... },
      parsed_json: {...},
      model_text: "..."
    }
    """
    log.info("Entered /generate_workspace endpoint")

    try:
        # --- Parse request ---
        body = request.get_json(silent=True)
        if body is None:
            raw = request.get_data(as_text=True)
            body = json.loads(raw) if raw else {}
        log.debug(f"Parsed body={_trim(body)}")

        url = (body.get("url") or "").strip()
        max_snapshots_raw = body.get("max_snapshots", 5)

        try:
            max_snapshots = min(int(max_snapshots_raw), 5)
        except Exception:
            log.warning(f"Invalid max_snapshots={max_snapshots_raw}, defaulting to 5")
            max_snapshots = 5

        if url and not url.startswith(("http://", "https://")):
            url = "https://" + url
            log.debug(f"Normalized URL to {url}")

        if not url or not isinstance(url, str) or not is_valid_url(url):
            log.warning("Validation failed: missing/invalid 'url'")
            return jsonify({"ok": False, "error": "missing/invalid 'url'"}), 400

        # --- Crawl snapshots ---
        with _timed("crawl_url"):
            crawl_res = crawl_url(url, max_snapshots=max_snapshots)

        metadata = crawl_res.get("metadata", {})
        snapshots_summary = crawl_res.get("snapshots_summary", [])
        log.debug(f"crawl_res keys={list(crawl_res.keys())}")

        # --------------------------
        # Custom Schema Snippet (for Workspace Setup)
        # --------------------------
        WORKSPACE_SCHEMA_SNIPPET = """
{
  "workspace": {
    "business_name": "string - official or common business name",
    "business_type": "string - one of ['Pvt Ltd', 'Public', 'Sole Proprietorship', 'Partnership', 'LLP'] or similar",
    "registered_address": "string or null",
    "b2b_b2c": "string - 'B2B' or 'B2C' (if clearly indicated)",
    "industry": "string - concise industry/category (e.g., 'SaaS', 'Retail', 'Marketing Tech')",
    "describe_business": "short paragraph about what the company does (1-2 paragraphs)",
    "describe_audience": "short paragraph describing the target customers or audience",
    "website": "official website URL or null",
    "direct_competitors": [
      { "name": "string", "website": "string or null" }
    ],
    "indirect_competitors": [
      { "name": "string", "website": "string or null" }
    ],
    "social_links": [
      { "platform": "string", "url": "string" }
    ],
    "usp": "string - unique selling proposition or tagline",
    "additional_remarks": "string - any extra notable details or quick bullet summary"
  }
}
        """.strip()

        # --------------------------
        # Build prompt
        # --------------------------
        prompt_text = f"""
SYSTEM: You are a precise data extractor that prepares workspace setup information for an AI-driven marketing platform.

INPUT:
  page_url: {url}
  og_meta: {json.dumps(metadata.get('og', {}), ensure_ascii=False)}
  title: {json.dumps(metadata.get('title'), ensure_ascii=False)}
  description: {json.dumps(metadata.get('description'), ensure_ascii=False)}
  json_ld: {json.dumps(metadata.get('json_ld'), ensure_ascii=False) if metadata.get('json_ld') else "null"}
  snapshots_summary: {json.dumps(snapshots_summary, ensure_ascii=False)}

TASK:
  Analyze the given page data and output EXACTLY ONE fenced JSON block (```json ... ```).
  The JSON must follow this schema:

  {WORKSPACE_SCHEMA_SNIPPET}

RULES:
  - Use only the provided metadata and structured content.
  - Keep descriptions concise (around 150-300 words total).
  - Infer business_type (Pvt Ltd, Public, etc.) from text if visible.
  - Return valid JSON with all fields, filling nulls where data is missing.
  - DO NOT include any markdown or explanations outside the fenced block.
        """.strip()

        # --------------------------
        # Snapshot URLs for provenance
        # --------------------------
        snapshot_urls = []
        for meta in crawl_res.get("uploaded_files_meta", []):
            if isinstance(meta, dict) and meta.get("url"):
                snapshot_urls.append(meta["url"])
            elif isinstance(meta, dict) and meta.get("uploaded_name"):
                snapshot_urls.append(f"file:{meta['uploaded_name']}")
        for path in crawl_res.get("snapshots_paths", []):
            if isinstance(path, str):
                if path.startswith(("http://", "https://", "file:")):
                    snapshot_urls.append(path)
                else:
                    snapshot_urls.append(f"file:{os.path.basename(path)}")

        snapshot_urls = list(dict.fromkeys(snapshot_urls))
        if snapshot_urls:
            prompt_text += "\n\nSNAPSHOT_URLS:\n" + "\n".join(snapshot_urls)
            prompt_text += "\n\nNOTE: Include snapshot references in workspace.source_urls."

        # --------------------------
        # GenAI Call
        # --------------------------
        contents = [{"role": "user", "parts": [{"text": prompt_text}]}]
        try:
            cfg = {"candidate_count": 1}
            with _timed("GENAI_CLIENT.generate_content"):
                resp = GENAI_CLIENT.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=contents,
                    config=cfg
                )
        except Exception as e:
            log.error(f"GenAI call failed: {e}\n{traceback.format_exc()}")
            return jsonify({"ok": False, "error": "genai_call_failed", "detail": str(e)}), 500

        # --------------------------
        # Extract and parse output
        # --------------------------
        model_text = None
        parsed_json = None

        try:
            cand = getattr(resp, "candidates", [None])[0]
            if cand and getattr(cand, "content", None) and getattr(cand.content, "parts", None):
                parts = [getattr(p, "text", "") for p in cand.content.parts if getattr(p, "text", None)]
                model_text = "\n".join(parts).strip()
            log.debug(f"model_text preview: {_trim(model_text, max_len=400)}")
        except Exception as e:
            log.warning(f"Error parsing model response: {e}")

        if model_text:
            with _timed("extract_json_block"):
                block = extract_json_block(model_text)
                if block:
                    try:
                        parsed_json = json.loads(block)
                        log.debug("Workspace JSON successfully parsed")
                    except Exception as e:
                        log.warning(f"JSON parse failed: {e}")

        # --------------------------
        # Merge provenance & finalize
        # --------------------------
        if parsed_json and isinstance(parsed_json, dict):
            ws = parsed_json.get("workspace") or {}
            ws["source_urls"] = list(dict.fromkeys(snapshot_urls + [url]))
            parsed_json["workspace"] = ws
        else:
            parsed_json = {
                "workspace": {
                    "website": url,
                    "source_urls": snapshot_urls,
                }
            }

        # --------------------------
        # Response payload
        # --------------------------
        resp_payload = {
            "ok": True,
            "page_url": url,
            "snapshots": crawl_res.get("snapshots_paths", []),
            "snapshot_urls": snapshot_urls,
            "workspace": parsed_json.get("workspace", {}),
            "parsed_json": parsed_json,
            "model_text": model_text,
        }

        log.info(f"/generate_workspace success for {url}")
        return jsonify(resp_payload)

    except Exception as e:
        log.error(f"Unhandled error in /generate_workspace: {e}\n{traceback.format_exc()}")
        return jsonify({
            "ok": False,
            "error": "internal",
            "detail": str(e),
            "trace": traceback.format_exc(),
        }), 500

# flask_genai_workspace_three_variations.py
"""
Flask endpoint to:
 - run planner text model once (verbatim prompt + workspace details)
 - send the planner text 3x to image model with appended instructions:
     "Generate image for FIRST THEME"
     "Generate image for SECOND THEME"
     "Generate image for THIRD THEME"
 - capture one image per call, save to DO Spaces (if configured) or local outputs/
 - return JSON { success: true, planner_text: "...", results: [{ theme:1, url, error? }, ...] }
"""

import os
import re
import io
import json
import time
import uuid
import base64
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, List, Optional, Any
from flask import Flask, request, jsonify
import logging

# Google GenAI client imports (assumes your environment has google.genai)
from google import genai
from google.genai import types

# Optional: boto3 for DigitalOcean Spaces
try:
    import boto3
except Exception:
    boto3 = None

# --------
PLANNER_TEXT_MODEL = os.environ.get("PLANNER_TEXT_MODEL", "gemini-2.5-flash-preview-09-2025")
IMAGE_MODEL = os.environ.get("IMAGE_MODEL", "gemini-2.5-flash-image")

SPACE_NAME = os.environ.get("SPACE_NAME")
SPACE_REGION = os.environ.get("SPACE_REGION", "blr1")
SPACE_ENDPOINT = os.environ.get("SPACE_ENDPOINT")  # e.g. https://blr1.digitaloceanspaces.com
SPACE_CDN = os.environ.get("SPACE_CDN")  # optional CDN base
ACCESS_KEY = os.environ.get("ACCESS_KEY")
SECRET_KEY = os.environ.get("SECRET_KEY")

MAX_IMAGE_BYTES = int(os.environ.get("MAX_IMAGE_BYTES", 60 * 1024 * 1024))
MAX_LOGO_BYTES = int(os.environ.get("MAX_LOGO_BYTES", 15 * 1024 * 1024))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 3))

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("gen_workspace_three_variations")

# ---------------- GenAI client init ----------------


# ---------------- Spaces client (optional) ----------------
s3_client = None
if ACCESS_KEY and SECRET_KEY and SPACE_ENDPOINT and SPACE_NAME and boto3:
    try:
        s3_client = boto3.client(
            "s3",
            region_name=SPACE_REGION,
            endpoint_url=SPACE_ENDPOINT,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
        )
        logger.info("S3/Spaces client initialized")
    except Exception:
        logger.exception("Failed to initialize S3 client for Spaces")

# ---------------- Helpers ----------------
def save_bytes_to_spaces_or_local(data_bytes: bytes, prefix="gen", ext=".png") -> Tuple[Optional[str], Optional[str]]:
    """
    Save bytes to outputs/ locally and attempt upload to DO Spaces.
    Returns (filename, public_url_or_local_path)
    """
    try:
        os.makedirs("outputs", exist_ok=True)
    except Exception:
        logger.exception("mkdir outputs failed")

    ts = int(time.time())
    fname = f"{prefix}_{ts}_{uuid.uuid4().hex[:8]}{ext}"
    local_path = os.path.join("outputs", fname)
    try:
        with open(local_path, "wb") as wf:
            wf.write(data_bytes)
    except Exception:
        logger.exception("local write failed")
        return None, None

    final_url = None
    if s3_client and SPACE_NAME:
        key = f"outputs/{fname}"
        try:
            # upload_file preferred
            s3_client.upload_file(local_path, SPACE_NAME, key, ExtraArgs={"ACL": "public-read", "ContentType": "image/png"})
        except Exception:
            try:
                with open(local_path, "rb") as fp:
                    s3_client.put_object(Bucket=SPACE_NAME, Key=key, Body=fp, ACL="public-read", ContentType="image/png")
            except Exception:
                logger.exception("spaces put failed")
                return fname, local_path
        if SPACE_CDN:
            final_url = f"{SPACE_CDN.rstrip('/')}/{key}"
        else:
            endpoint_host = SPACE_ENDPOINT.replace("https://", "").rstrip("/") if SPACE_ENDPOINT else "digitaloceanspaces.com"
            final_url = f"https://{SPACE_NAME}.{endpoint_host}/{key}"
    else:
        logger.debug("Spaces not configured; returning local path")
        final_url = local_path

    return fname, final_url

def extract_images_and_text_from_stream(stream_iterator) -> Tuple[List[bytes], List[str]]:
    """
    Pull images (bytes) and text parts out of the genai stream iterator.
    Returns (list_of_image_bytes, list_of_text_parts)
    """
    images = []
    text_parts = []
    try:
        for chunk in stream_iterator:
            # candidates -> content -> parts
            if hasattr(chunk, "candidates") and chunk.candidates:
                for cand in (chunk.candidates or []):
                    content = getattr(cand, "content", None)
                    parts = getattr(content, "parts", None) or []
                    for p in parts:
                        # image in part (structured)
                        if getattr(p, "image", None) and getattr(p.image, "base64", None):
                            try:
                                images.append(base64.b64decode(p.image.base64))
                            except Exception:
                                logger.exception("failed to decode p.image.base64")
                        # text part
                        if getattr(p, "text", None):
                            text = p.text
                            text_parts.append(text)
                            # find data URI in text
                            m = re.search(r"data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)", text)
                            if m:
                                try:
                                    images.append(base64.b64decode(m.group(1)))
                                except Exception:
                                    logger.exception("failed to decode data uri found in text part")
                        # inline_data
                        if getattr(p, "inline_data", None):
                            inline = p.inline_data
                            if isinstance(inline, (bytes, bytearray)):
                                images.append(bytes(inline))
                            elif isinstance(inline, str):
                                # try base64
                                m2 = re.fullmatch(r"([A-Za-z0-9+/=]+)", inline.strip())
                                if m2:
                                    try:
                                        images.append(base64.b64decode(inline.strip()))
                                    except Exception:
                                        pass
            # chunk.binary (raw binary payload)
            if getattr(chunk, "binary", None):
                try:
                    images.append(bytes(chunk.binary))
                except Exception:
                    logger.exception("failed to extract chunk.binary")
    except Exception:
        logger.exception("extract_images_from_stream failed")
    return images, text_parts

def find_first_datauri_in_text(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"(data:image\/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=]+)", text)
    if m:
        return m.group(1)
    return None

# ---------------- Image call (single variation) ----------------
def image_call_single_variation(planner_text: str, variation_instruction: str, logo_bytes: Optional[bytes], logo_mime: Optional[str]) -> dict:
    """
    Send the *planner_text* with a small appended instruction to the image model,
    capture the first image produced (binary or data-uri), save it and return { success, url, error, debug }.
    """
    try:
        # Prepare parts: include logo (bytes or uri) as first part so model can use it
        parts = []
        if logo_bytes:
            parts.append(types.Part.from_bytes(data=logo_bytes, mime_type=logo_mime or "image/png"))
        # Compose the full user instruction: planner_text verbatim + explicit instruction
        # We keep planner_text exactly as returned and append a short directive
        full_instruction = f"{planner_text}\n\n{variation_instruction}\n\nProduce ONE square PNG image (1:1) suitable for a social feed. " \
                           "Return image either as inline binary or as a data URI (data:image/png;base64,...). " \
                           "Do not output additional JSON wrappers — just produce the image content or a single data URI in the text."
        parts.append(types.Part.from_text(text=full_instruction))

        content = types.Content(role="user", parts=parts)

        img_cfg = types.GenerateContentConfig(
            temperature=1.0,
            top_p=0.95,
            max_output_tokens=16384,
            response_modalities=["IMAGE", "TEXT"],
            candidate_count=1,
        )

        stream = GENAI_CLIENT.models.generate_content_stream(
            model=IMAGE_MODEL,
            contents=[content],
            config=img_cfg,
        )

        images, text_parts = extract_images_and_text_from_stream(stream)

        # Prefer binary images captured in stream
        chosen_bytes = None
        if images:
            # pick first valid bytes
            for b in images:
                if isinstance(b, (bytes, bytearray)) and len(b) > 0:
                    chosen_bytes = bytes(b)
                    break

        # If none, try to find a data URI in joined text parts
        if chosen_bytes is None:
            joined = "\n".join(text_parts or [])
            data_uri = find_first_datauri_in_text(joined)
            if data_uri:
                m = re.search(r"data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)", data_uri)
                if m:
                    try:
                        chosen_bytes = base64.b64decode(m.group(1))
                    except Exception:
                        logger.exception("failed to decode data_uri base64")

        if chosen_bytes is None:
            # as a last attempt, some streams may include a long base64 blob in text parts without data URI
            for t in text_parts or []:
                tstr = t.strip()
                if len(tstr) > 200 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", tstr):
                    # try decode
                    try:
                        cand = base64.b64decode(tstr.encode())
                        if cand and len(cand) > 100:
                            chosen_bytes = cand
                            break
                    except Exception:
                        pass

        if chosen_bytes is None:
            return {"success": False, "error": "no_image_returned", "debug_text_parts": text_parts}

        if len(chosen_bytes) > MAX_IMAGE_BYTES:
            return {"success": False, "error": "image_too_large"}

        fname, url = save_bytes_to_spaces_or_local(chosen_bytes, prefix=f"variation_{uuid.uuid4().hex[:6]}")
        if not fname:
            return {"success": False, "error": "save_failed"}
        return {"success": True, "url": url, "filename": fname, "debug_text_parts": text_parts[:3] if text_parts else []}
    except Exception as e:
        logger.exception("image_call_single_variation failed")
        return {"success": False, "error": "exception", "details": str(e), "trace": traceback.format_exc()}

# ---------------- Main route ----------------
@app.route("/api/v1/generate-from-workspace", methods=["POST", "OPTIONS"])
def generate_from_workspace():
    """
    Accepts:
      - multipart/form-data or JSON
      - fields: prompt (string), workspace_details (string JSON), optional logo (file or logo_url)
    Flow:
      1) Call planner text model once with prompt + workspace_details verbatim.
      2) Use resulting planner_text and call image model 3x with appended instructions:
            - "Generate image for FIRST THEME"
            - "Generate image for SECOND THEME"
            - "Generate image for THIRD THEME"
      3) Save images and return urls.
    """
    if request.method == "OPTIONS":
        return ("", 200)

    if GENAI_CLIENT is None:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    try:
        # parse input
        prompt = ""
        workspace_details = ""
        logo_bytes = None
        logo_mime = None
        logo_url = None

        if request.content_type and request.content_type.startswith("multipart/form-data"):
            prompt = request.form.get("prompt") or request.form.get("text") or ""
            workspace_details = request.form.get("workspace_details") or ""
            logo_file = request.files.get("logo")
            if logo_file:
                logo_mime = logo_file.mimetype or "image/png"
                logo_bytes = logo_file.read()
                if len(logo_bytes) > MAX_LOGO_BYTES:
                    return jsonify({"success": False, "error": "logo_file_too_large"}), 400
            logo_url = request.form.get("logo_url") or request.form.get("image_url")
        else:
            data = request.get_json(silent=True) or {}
            prompt = data.get("prompt") or data.get("text") or ""
            workspace_details = data.get("workspace_details") or ""
            logo_url = data.get("logo_url") or data.get("image_url")
            if data.get("logo_bytes"):
                try:
                    logo_bytes = base64.b64decode(data.get("logo_bytes"))
                    logo_mime = data.get("logo_mime_type") or "image/png"
                    if len(logo_bytes) > MAX_LOGO_BYTES:
                        return jsonify({"success": False, "error": "logo_file_too_large"}), 400
                except Exception:
                    return jsonify({"success": False, "error": "invalid_logo_base64"}), 400

        if not prompt:
            return jsonify({"success": False, "error": "prompt_required"}), 400

        # ---- Step 1: call planner text model (forward prompt + workspace verbatim) ----
        planner_parts = []
        planner_parts.append(types.Part.from_text(text=prompt))
        if workspace_details:
            planner_parts.append(types.Part.from_text(text=f"WORKSPACE_DETAILS_JSON:\n{workspace_details}"))

        if logo_bytes:
            planner_parts.insert(0, types.Part.from_bytes(data=logo_bytes, mime_type=logo_mime or "image/png"))
        elif logo_url:
            planner_parts.insert(0, types.Part.from_uri(file_uri=logo_url))

        planner_content = types.Content(role="user", parts=planner_parts)
        planner_cfg = types.GenerateContentConfig(
            temperature=0.9,
            top_p=0.95,
            max_output_tokens=4096,
            response_modalities=["TEXT"],
            candidate_count=1,
        )

        try:
            planner_resp = GENAI_CLIENT.models.generate_content(
                model=PLANNER_TEXT_MODEL,
                contents=[planner_content],
                config=planner_cfg,
            )
        except Exception:
            logger.exception("planner model call failed")
            return jsonify({"success": False, "error": "planner_model_failed"}), 500

        planner_text = ""
        try:
            if hasattr(planner_resp, "candidates") and planner_resp.candidates:
                c = planner_resp.candidates[0]
                if getattr(c, "content", None) and getattr(c.content, "parts", None):
                    for p in c.content.parts:
                        if getattr(p, "text", None):
                            planner_text += p.text
                else:
                    planner_text = getattr(c, "text", "") or str(c)
            else:
                planner_text = str(planner_resp)
        except Exception:
            planner_text = str(planner_resp)

        if not planner_text:
            planner_text = prompt  # fallback: use original prompt

        # ---- Step 2: call image model 3 times with appended simple instructions ----
        instructions = [
            "Generate image for FIRST THEME",
            "Generate image for SECOND THEME",
            "Generate image for THIRD THEME",
        ]

        # run serially or concurrently (we'll run concurrently but limit workers)
        results = []
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, 3)) as ex:
            futures = {
                ex.submit(image_call_single_variation, planner_text, inst, logo_bytes, logo_mime): idx + 1
                for idx, inst in enumerate(instructions)
            }
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    logger.exception("image future failed")
                    res = {"success": False, "error": "future_exception", "details": traceback.format_exc()}
                # attach theme index
                res_out = {"theme": idx, **res}
                results.append(res_out)

        # preserve deterministic ordering theme 1..3
        results_sorted = sorted(results, key=lambda r: r.get("theme", 0))

        # collate urls
        urls = [r.get("url") for r in results_sorted if r.get("success") and r.get("url")]
        logger.debug(f"Generated {len(urls)} image URLs")
        logger.info(urls)

        return jsonify({"success": True, "planner_text": planner_text, "results": results_sorted, "urls": urls}), 200

    except Exception:
        logger.exception("generate_from_workspace unexpected error")
        return jsonify({"success": False, "error": "internal", "details": traceback.format_exc()}), 500


import os
import re
from flask import Blueprint, request, jsonify
from google import genai
from google.genai import types


# Small helper to strip links/URLs from any nested string fields
URL_PATTERN = re.compile(r"https?://\S+")

def scrub_links(obj):
    if isinstance(obj, dict):
        return {k: scrub_links(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_links(v) for v in obj]
    if isinstance(obj, str):
        # remove URLs from the string
        return URL_PATTERN.sub("", obj).strip()
    return obj

@app.route("/api/suggest-prompt", methods=["POST"])
def suggest_prompt():
    try:
        data = request.get_json() or {}
        params = data.get("params") or {}
        base_prompt = data.get("prompt")
        template = data.get("template", "post")
        theme = data.get("theme")
        workspace_details_raw = data.get("workspace_details")
        hint = data.get("hint") or "create a meta ad creative that well describes"

        # Normalize workspace_details
        if isinstance(workspace_details_raw, str):
            try:
                workspace_details = json.loads(workspace_details_raw)
            except json.JSONDecodeError:
                current_app.logger.exception("Invalid workspace_details JSON")
                return jsonify({"error": "workspace_details must be valid JSON"}), 400
        elif isinstance(workspace_details_raw, dict):
            workspace_details = workspace_details_raw
        else:
            workspace_details = {}

        # Extract fields - NO HARDCODED FALLBACKS
        business_name = workspace_details.get("business_name", "the brand")
        usp = workspace_details.get("usp", "")
        audience_description = workspace_details.get("audience_description", "")
        description = workspace_details.get("description", "")
        website = workspace_details.get("website", "")

        num_candidates = int(params.get("num_candidates", 1) or 1)
        aspect_ratio = params.get("aspect_ratio", "1:1")

        if not base_prompt:
            base_prompt = (
                "Generate a single short prompt idea for creating engaging social media content for this business."
            )

        # DYNAMIC PROMPT GENERATION - Use actual business details
        suggested_prompt = (
            f"High-converting Meta ad visual for '{business_name}'. "
            f"{description} "
            f"USP: {usp}. "
            f"Show a compelling scene that highlights the brand's premium quality and seamless user experience. "
            f"The visual should appeal to {audience_description}, "
            f"emphasizing innovation, design aesthetics, and lifestyle integration. "
            f"Clean, modern, premium aesthetic, {aspect_ratio} aspect ratio."
        )

        prompts = [suggested_prompt] * num_candidates

        response_payload = {
            "prompts": prompts,
            "count": len(prompts),
            "template": template,
            "theme": theme,
            "meta": {
                "aspect_ratio": aspect_ratio,
                "hint": hint,
                "business_name": business_name,
                "website": website,
                "base_prompt": base_prompt,
                "description": description,
                "audience_description": audience_description,
            },
        }

        return jsonify(response_payload), 200

    except Exception as e:
        current_app.logger.exception("Error in /api/suggest-prompt")
        return jsonify(
            {
                "error": "Internal server error in /api/suggest-prompt",
                "detail": str(e),
            }
        ), 500

import os
import time
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import request, jsonify, current_app
from dotenv import load_dotenv

from models import (
    db,
    User,
    Workspace,
    SocialAccount,
    AssistantThread,
    AssistantMessage,
    Workflow,
    WorkflowRun,
)

from google import genai  # google-genai SDK

# -------------------------------------------------
# ENV & GEMINI SETUP
# -------------------------------------------------

load_dotenv()

# You already have an init_client() somewhere in your app
client = init_client()
GENAI_CLIENT = client

SUPPORT_EMAIL = "contact@sociovia.com"

# -------------------------------------------------
# SMALL HELPERS
# -------------------------------------------------
import smtplib
from email.message import EmailMessage

# SMTP CONFIG (set in .env)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

# Support both naming conventions
SMTP_USERNAME = os.getenv("SMTP_USERNAME") or os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") or os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM") or os.getenv("MAIL_FROM") or SMTP_USERNAME


def _build_email(subject: str, body: str, to: list[str]) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    return msg


def send_email(subject: str, body: str, to: list[str]) -> None:
    """
    Generic SMTP sender.
    Will log and fail gracefully; you can replace this with SendGrid/Resend/etc later.
    """
    if not to:
        current_app.logger.warning("[EMAIL] No recipients provided, skipping send.")
        return

    if not SMTP_HOST or not SMTP_FROM:
        current_app.logger.warning("[EMAIL] SMTP not configured, skipping send.")
        return

    msg = _build_email(subject, body, to)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        current_app.logger.info("[EMAIL] Sent email to %s", to)
    except Exception as e:
        current_app.logger.exception("[EMAIL] Failed to send email: %s", e)


def send_support_email(workspace_name: str, user_email: str | None, description: str) -> None:
    """
    Real support email: to SUPPORT_EMAIL (admin), optional reply-to user.
    """
    subject = f"[Sociovia Support] Bug / Issue reported for workspace: {workspace_name}"
    body_lines = [
        f"Workspace: {workspace_name}",
        f"Reported by: {user_email or 'Unknown user'}",
        "",
        "User description:",
        description or "(no additional details provided)",
    ]
    body = "\n".join(body_lines)
    send_email(subject, body, [SUPPORT_EMAIL])


def send_weekly_report_email(
    workspace_name: str,
    recipients: list[str],
    simulated_metrics: dict[str, float],
) -> None:
    """
    Real email for the Weekly Performance workflow.
    Metrics are still mock (zeros) for now.
    """
    subject = f"[Sociovia] Weekly Performance Summary – {workspace_name}"

    body_lines = [
        f"Hi there,",
        "",
        f"Here is your weekly performance summary for {workspace_name}.",
        "",
        "Note: These metrics are currently simulated (0) until real-time analytics",
        "integration with your ad accounts and tracking is completed.",
        "",
        f"ROAS:        {simulated_metrics.get('roas', 0):.2f}",
        f"Spend:       {simulated_metrics.get('spend', 0):.2f}",
        f"Conversions: {simulated_metrics.get('conversions', 0):.0f}",
        f"Clicks:      {simulated_metrics.get('clicks', 0):.0f}",
        "",
        "Once analytics are wired, this email will start showing your actual campaign performance.",
        "",
        "— Sociovia AI",
    ]
    body = "\n".join(body_lines)

    # Filter empties and duplicates
    recips = sorted({r.strip() for r in recipients if r and r.strip()})
    if not recips:
        current_app.logger.warning("[EMAIL] Weekly report has no recipients, skipping send.")
        return

    send_email(subject, body, recips)


def _safe_get(data: Dict, key: str, default: Any = None) -> Any:
    return data.get(key, default)


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _mock_analytics_metrics(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    For now: treat analytics values as ZERO / placeholder.
    Later you will replace this with real numbers from your DB / Meta API.
    """
    ws = context.get("workspace", {})
    ws_name = ws.get("business_name") or "your workspace"

    return {
        "workspace": ws_name,
        "time_window": "last_7_days",
        "total_spend": 0.0,
        "total_conversions": 0,
        "avg_roas": 0.0,
        "avg_ctr": 0.0,
        "avg_cpc": 0.0,
        "note": "These are mock analytics; real metrics are not wired yet.",
    }


def build_db_context(user_id: int, workspace_id: int) -> Dict[str, Any]:
    """
    Load User, Workspace, SocialAccounts, and any basic analytics-like context
    from your existing models.
    """
    user = User.query.get(user_id)
    if not user:
        raise ValueError("User not found")

    workspace = Workspace.query.filter_by(id=workspace_id, user_id=user.id).first()
    if not workspace:
        raise ValueError("Workspace not found for this user")

    social_accounts = SocialAccount.query.filter_by(user_id=user.id).all()

    # Simplified social account summary
    social_summary = [
        {
            "id": sa.id,
            "provider": sa.provider,
            "account_name": sa.account_name,
            "instagram_business_id": sa.instagram_business_id,
            "has_token": bool(sa.access_token),
        }
        for sa in social_accounts
    ]

    # 👉 Mock analytics: treat all numeric KPIs as 0 for now
    analytics = {
        "has_real_analytics": False,
        "summary": (
            "Using mock analytics for now. Treat all numeric metrics as 0 until real "
            "tracking is connected. You can still define and test automations."
        ),
        "notes": [
            "Later you can compute total ad spend, leads, CTR, etc. from your campaign tables.",
            "For now, assume all KPIs are 0 and focus on designing workflows.",
        ],
    }

    context = {
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "business_name": user.business_name,
            "industry": user.industry,
            "status": user.status,
            "email_verified": user.email_verified,
            "phone_verified": user.phone_verified,
        },
        "workspace": {
            "id": workspace.id,
            "business_name": workspace.business_name,
            "business_type": workspace.business_type,
            "registered_address": workspace.registered_address,
            "b2b_b2c": workspace.b2b_b2c,
            "industry": workspace.industry,
            "description": workspace.description,
            "audience_description": workspace.audience_description,
            "website": workspace.website,
            "usp": workspace.usp,
            "competitors": {
                "direct_1": workspace.competitor_direct_1,
                "direct_2": workspace.competitor_direct_2,
                "indirect_1": workspace.competitor_indirect_1,
                "indirect_2": workspace.competitor_indirect_2,
            },
            "logo_path": workspace.logo_path,
        },
        "social_accounts": social_summary,
        "analytics": analytics,
    }

    return context

SYSTEM_PROMPT = f"""You are Sociovia AI, an assistant that lives inside the Sociovia growth & CRM platform.

You ALWAYS receive:
- Authenticated user profile (name, email, phone, verification status, business_name, industry).
- Current workspace details (business name, type, industry, B2B/B2C, audience, USP, website, competitors).
- Connected social accounts (Facebook/Instagram/pages, etc).
- A basic analytics context dict.

VERY IMPORTANT:
- If analytics.has_real_analytics is False, you MUST behave as if all KPIs exist but are currently 0.
- You should STILL propose and configure automations (budget rules, reports, alerts, etc.) and may run dry-run simulations.
- When the user asks for exact numbers (ROAS, spend, leads, etc.), say clearly that:
  "Right now I'm using simulated metrics set to 0 until tracking is wired, but I can still create and run dry-run workflows for you."

Your behavior:
- Use the given context to personalize recommendations for this specific user and workspace.
- Don't hallucinate unknown numbers (spend, leads, ROAS, etc.). If not present in analytics, say they’re 0 / simulated and explain why.
- When suggesting actions, tie them to the user’s industry, audience and USP.
- If the user asks “my performance”, explain that analytics are simulated (0 for now) and how Sociovia will track real data later.
- If the user asks for help/support, you may mention that they can reach Sociovia support at {SUPPORT_EMAIL}.
- You can also suggest relevant docs and guides like:
  - Sociovia CRM quickstart
  - Workflow Builder quickstart
  - Email automation guide
- Keep responses concise, practical, and friendly.
"""


def build_prompt_with_context(
    messages: List[Dict[str, Any]],
    context: Dict[str, Any],
    summary: Optional[str] = None,
) -> str:
    user = context["user"]
    ws = context["workspace"]
    analytics = context["analytics"]
    social_accounts = context["social_accounts"]

    # --- Context block ---
    lines: List[str] = [SYSTEM_PROMPT, "", "CONTEXT:"]

    # User
    lines.append(
        f"- User: {user.get('name') or 'Unknown'} "
        f"({user.get('email') or 'no-email'}) | phone: {user.get('phone') or 'N/A'}"
    )
    lines.append(
        f"- User status: {user.get('status')} | "
        f"email_verified={user.get('email_verified')} | phone_verified={user.get('phone_verified')}"
    )

    # Workspace
    lines.append(
        f"- Workspace: {ws.get('business_name') or 'Unnamed business'} "
        f"(Industry: {ws.get('industry') or 'N/A'}, Type: {ws.get('business_type') or 'N/A'}, "
        f"Model: {ws.get('b2b_b2c') or 'N/A'})"
    )
    lines.append(f"- Audience: {ws.get('audience_description') or 'Not specified'}")
    lines.append(f"- USP: {ws.get('usp') or 'Not specified'}")
    lines.append(f"- Website: {ws.get('website') or 'N/A'}")

    # Competitors
    comp = ws.get("competitors") or {}
    competitor_list = [
        comp.get("direct_1"),
        comp.get("direct_2"),
        comp.get("indirect_1"),
        comp.get("indirect_2"),
    ]
    competitor_list = [c for c in competitor_list if c]
    if competitor_list:
        lines.append(f"- Competitors: {', '.join(competitor_list)}")
    else:
        lines.append("- Competitors: Not provided")

    # Social accounts
    if social_accounts:
        lines.append("- Connected social accounts:")
        for sa in social_accounts:
            lines.append(
                f"  • {sa['provider']} - {sa.get('account_name') or sa.get('provider_user_id') or 'N/A'} "
                f"(token_present={sa['has_token']})"
            )
    else:
        lines.append("- Connected social accounts: none")

    # Analytics
    lines.append("")
    lines.append("Analytics context:")
    lines.append(f"- has_real_analytics: {analytics.get('has_real_analytics')}")
    if "summary" in analytics:
        lines.append(f"- summary: {analytics['summary']}")
    if "notes" in analytics and isinstance(analytics["notes"], list):
        for note in analytics["notes"]:
            lines.append(f"  • {note}")

    if summary:
        lines.append("")
        lines.append("High-level summary of previous conversation:")
        lines.append(summary)
        lines.append("")

    # --- Conversation history ---
    lines.append("")
    lines.append("Conversation so far:")

    # Only last 10 messages to keep prompt small
    for msg in messages[-10:]:
        role = msg.get("from") or msg.get("from_role") or "user"
        role_label = {
            "user": "User",
            "bot": "Assistant",
            "system": "System",
        }.get(role, "User")

        text = msg.get("text", "")
        lines.append(f"{role_label}: {text}")

    lines.append("")
    lines.append("Assistant:")

    return "\n".join(lines)


def generate_ai_reply(
    messages: List[Dict[str, Any]],
    context: Dict[str, Any],
    summary: Optional[str] = None,
) -> str:
    prompt = build_prompt_with_context(messages, context, summary=summary)

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
    except Exception as e:
        current_app.logger.exception("Gemini API error")
        raise RuntimeError(f"Gemini API error: {e}")

    text = getattr(response, "text", None)
    if not text:
        raise RuntimeError("Empty response from Gemini")

    return text.strip()


# -------------------------------------------------
# DEMO TASKS / CALENDAR / NOTIFS
# -------------------------------------------------


def build_demo_tasks(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    ws = context["workspace"]
    name = ws.get("business_name") or "your business"

    now = int(time.time())
    one_day = 24 * 3600

    return [
        {
            "id": "task-1",
            "title": f"Review last week's campaigns for {name}",
            "description": "Check CTR, cost per lead, and pause any underperforming ad sets.",
            "status": "pending",
            "priority": "high",
            "dueDate": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now + one_day)),
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)),
            "assignedTo": "Sociovia AI",
        },
        {
            "id": "task-2",
            "title": "Create content calendar for next 7 days",
            "description": "Plan posts for awareness, engagement, and conversion.",
            "status": "in_progress",
            "priority": "medium",
            "dueDate": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now + 3 * one_day)
            ),
            "createdAt": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now - one_day)
            ),
            "assignedTo": "Marketing Team",
        },
        {
            "id": "task-3",
            "title": "Verify pixel / tracking setup",
            "description": "Confirm that events are firing correctly for key funnels.",
            "status": "pending",
            "priority": "urgent",
            "dueDate": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now + one_day)
            ),
            "createdAt": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now - 2 * one_day)
            ),
            "assignedTo": "Tech Team",
        },
    ]


def build_demo_calendar_events(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    ws = context["workspace"]
    name = ws.get("business_name") or "your brand"

    now = int(time.time())
    one_hour = 3600
    one_day = 24 * 3600

    return [
        {
            "id": "event-1",
            "title": "Weekly performance review",
            "description": f"Review ad performance and leads for {name}.",
            "startTime": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now + one_day + 10 * one_hour)
            ),
            "endTime": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now + one_day + 11 * one_hour)
            ),
            "type": "meeting",
            "status": "scheduled",
        },
        {
            "id": "event-2",
            "title": "New campaign launch window",
            "description": f"Suggested window to launch next campaign for {name}.",
            "startTime": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now + 2 * one_day + 9 * one_hour)
            ),
            "endTime": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now + 2 * one_day + 10 * one_hour)
            ),
            "type": "campaign",
            "status": "scheduled",
        },
        {
            "id": "event-3",
            "title": "Lead nurturing follow-up",
            "description": "Follow up with warm leads from last week's campaigns.",
            "startTime": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(now + 3 * one_day + 15 * one_hour)
            ),
            "type": "reminder",
            "status": "scheduled",
        },
    ]


def build_demo_notifications(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    ws = context["workspace"]
    name = ws.get("business_name") or "your workspace"

    now = int(time.time())

    def ts(offset_seconds: int) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - offset_seconds))

    return [
        {
            "id": "notif-1",
            "title": "New leads detected",
            "message": f"{name} captured 12 new leads in the last 24 hours. Ask Sociovia AI for a quick summary.",
            "type": "info",
            "timestamp": ts(3600),
            "read": False,
        },
        {
            "id": "notif-2",
            "title": "High CPA on one campaign",
            "message": "One of your ad sets is showing a higher cost per acquisition than usual. Consider pausing or optimizing.",
            "type": "warning",
            "timestamp": ts(2 * 3600),
            "read": False,
        },
        {
            "id": "notif-3",
            "title": "Pixel event check",
            "message": "We haven't seen any 'Purchase' events in the last 48 hours. Make sure your tracking is working correctly.",
            "type": "error",
            "timestamp": ts(48 * 3600),
            "read": True,
        },
    ]


# -------------------------------------------------
# WORKFLOW TEMPLATE CATALOG (BACKEND VIEW)
# -------------------------------------------------

WORKFLOW_TEMPLATES = {
    "pause-underperformers": {
        "name": "Pause Underperformers",
        "description": "Auto-pause campaigns with ROAS < 1.5.",
        "category": "optimization",
        "estimated_impact": "Saves ~20% budget on low-ROAS campaigns",
        "nodes_count": 4,
    },
    "boost-winners": {
        "name": "Auto-Boost Winners",
        "description": "Increase budget for high performers (ROAS > 2.5).",
        "category": "optimization",
        "estimated_impact": "Increases spend on winners by ~25%",
        "nodes_count": 6,
    },
    "duplicate-scaling": {
        "name": "Duplicate Scaling",
        "description": "Scale winners by duplicating high-ROAS ad sets.",
        "category": "optimization",
        "estimated_impact": "Doubles effective spend on winners without new creatives",
        "nodes_count": 4,
    },
    "creative-refresh": {
        "name": "Creative Refresh",
        "description": "Swap low-CTR creatives with AI-generated winners.",
        "category": "optimization",
        "estimated_impact": "Boosts CTR by ~15% via fresh creatives",
        "nodes_count": 5,
    },
    "budget-reallocation": {
        "name": "Budget Reallocation",
        "description": "Shift budget from losers to winners dynamically.",
        "category": "optimization",
        "estimated_impact": "Optimizes spend distribution for 10–15% ROAS lift",
        "nodes_count": 6,
    },
    "weekly-report": {
        "name": "Weekly Performance Email",
        "description": "Send comprehensive weekly performance reports.",
        "category": "reporting",
        "estimated_impact": "Keeps team aligned with key metrics",
        "nodes_count": 4,
    },
    "monthly-audit": {
        "name": "Monthly Compliance Audit",
        "description": "Audit campaigns for policy violations and compliance.",
        "category": "reporting",
        "estimated_impact": "Reduces risk of ad account bans",
        "nodes_count": 5,
    },
    "ai-copy-gen": {
        "name": "AI Copy Generation",
        "description": "Generate and A/B test new ad copy every week.",
        "category": "creative",
        "estimated_impact": "Tests 10 new variations per week",
        "nodes_count": 4,
    },
    "audience-suggest": {
        "name": "AI Audience Suggestions",
        "description": "Suggest and target new audiences based on performance.",
        "category": "creative",
        "estimated_impact": "Expands reach to similar high-converters",
        "nodes_count": 5,
    },
    "webhook-integration": {
        "name": "Webhook Integration",
        "description": "Trigger workflows from external events (e.g., CRM lead).",
        "category": "manual",
        "estimated_impact": "Automates response to external signals",
        "nodes_count": 4,
    },
}


# -------------------------------------------------
# WORKFLOW BUILDERS (ReactFlow JSON)
# -------------------------------------------------


def build_weekly_report_workflow(
    context: Dict[str, Any], overrides: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """
    Build a ReactFlow-compatible workflow JSON for:
    'Create a workflow that emails me a weekly ad performance summary...'

    This version respects overrides.email_to and treats analytics as mock/zero-level
    in the description (real numbers will be wired later).
    """
    overrides = overrides or {}
    ws = context["workspace"]
    user = context["user"]

    ws_name = ws.get("business_name") or "Your Brand"
    user_email = user.get("email") or "you@example.com"

    # Schedule override, e.g. { "schedule": "0 10 * * MON" }
    schedule = overrides.get("schedule") or "0 9 * * MON"

    # Workflow name override
    name = overrides.get("name") or f"{ws_name} Weekly Ad Performance Summary"

    # 🔵 Recipient override: if AI specified additional emails, use them
    # expected shape: overrides["email_to"] = "owner@example.com, another@example.com"
    email_to = overrides.get("email_to") or user_email

    nodes: List[Dict[str, Any]] = [
        {
            "id": "trigger-weekly",
            "type": "workflow",
            "position": {"x": 100, "y": 100},
            "data": {
                "label": "Weekly Trigger (Mon 9 AM)",
                "nodeType": "trigger",
                "description": "Runs every Monday at 9 AM",
                "config": {
                    "schedule": schedule,
                    "frequency": "weekly",
                    "dayOfWeek": "MON",
                    "timeOfDay": "09:00",
                },
                "status": "idle",
            },
        },
        {
            "id": "fetch-metrics",
            "type": "workflow",
            "position": {"x": 360, "y": 100},
            "data": {
                "label": "Fetch Weekly Metrics (Mock)",
                "nodeType": "analytics",
                "description": (
                    "Pull ad set performance for the last 7 days. "
                    "Currently uses mock analytics (all metrics treated as 0) "
                    "until real-time analytics are wired."
                ),
                "config": {
                    "action": "fetch_metrics",
                    "timeframe": "last_7_days",
                    "granularity": "daily",
                    "platforms": ["facebook_ads", "google_ads"],
                    "metrics": ["roas", "cpa", "spend", "conversions", "revenue"],
                    # this flag is for your executor, to know it's a mock run
                    "useMockAnalytics": True,
                },
                "status": "idle",
            },
        },
        {
            "id": "classify-performance",
            "type": "workflow",
            "position": {"x": 620, "y": 100},
            "data": {
                "label": "Classify Top & Poor Ad Sets (Mock)",
                "nodeType": "analytics",
                "description": (
                    "Split into top and poor performers using ROAS & CPA. "
                    "Currently works on mock metrics (0) for simulation only."
                ),
                "config": {
                    "action": "classify_performance",
                    "topThreshold": overrides.get("topThreshold")
                    or {"roas_gt": 3.5, "cpa_lt": 40},
                    "poorThreshold": overrides.get("poorThreshold")
                    or {"roas_lt": 2.0, "cpa_gt": 75},
                    "minSpend": overrides.get("minSpend", 100),
                    "limitTop": overrides.get("limitTop", 5),
                    "limitPoor": overrides.get("limitPoor", 5),
                    "useMockAnalytics": True,
                },
                "status": "idle",
            },
        },
        {
            "id": "email-summary",
            "type": "workflow",
            "position": {"x": 880, "y": 100},
            "data": {
                "label": "Email Weekly Summary",
                "nodeType": "notification",
                "description": (
                    f"Send weekly performance summary to {email_to}. "
                    "For now, this will include simulated/placeholder metrics."
                ),
                "config": {
                    "channel": "email",
                    "to": email_to,
                    "subject": overrides.get("email_subject")
                    or f"{ws_name} – Weekly Ad Performance Summary",
                    "templateId": overrides.get("templateId")
                    or "weekly_ad_summary_v1",
                    "includeSections": ["top_performers", "poor_performers", "totals"],
                    "useMockAnalytics": True,
                },
                "status": "idle",
            },
        },
    ]

    edges: List[Dict[str, Any]] = [
        {
            "id": "e-trigger-metrics",
            "source": "trigger-weekly",
            "target": "fetch-metrics",
        },
        {
            "id": "e-metrics-classify",
            "source": "fetch-metrics",
            "target": "classify-performance",
        },
        {
            "id": "e-classify-email",
            "source": "classify-performance",
            "target": "email-summary",
        },
    ]

    return {
        "name": name,
        "nodes": nodes,
        "edges": edges,
    }


def build_budget_reallocation_workflow(
    context: Dict[str, Any], overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    overrides = overrides or {}
    ws = context["workspace"]
    ws_name = ws.get("business_name") or "Your Brand"

    # schedule override (default: daily at 09:00)
    schedule = overrides.get("schedule") or "0 9 * * *"

    name = overrides.get("name") or f"{ws_name} Dynamic Budget Reallocation"

    nodes: List[Dict[str, Any]] = [
        {
            "id": "trigger-daily",
            "type": "workflow",
            "position": {"x": 80, "y": 100},
            "data": {
                "label": "Daily Trigger (9 AM)",
                "nodeType": "trigger",
                "description": "Runs every day at 9 AM",
                "config": {
                    "schedule": schedule,
                    "frequency": "daily",
                    "timeOfDay": "09:00",
                },
                "status": "idle",
            },
        },
        {
            "id": "fetch-performance",
            "type": "workflow",
            "position": {"x": 320, "y": 100},
            "data": {
                "label": "Fetch Ad Set Performance",
                "nodeType": "analytics",
                "description": "Get ROAS, CPA, spend for active ad sets",
                "config": {
                    "action": "fetch_metrics",
                    "timeframe": "last_3_days",
                    "platforms": ["facebook_ads", "google_ads"],
                    "metrics": ["roas", "cpa", "spend", "conversions", "revenue"],
                    "filter": {"status": "active"},
                },
                "status": "idle",
            },
        },
        {
            "id": "classify-winners-losers",
            "type": "workflow",
            "position": {"x": 580, "y": 100},
            "data": {
                "label": "Classify Winners & Losers",
                "nodeType": "analytics",
                "description": "Tag ad sets as winners / losers using ROAS & CPA",
                "config": {
                    "action": "classify_winners_losers",
                    "winner": overrides.get("winnerThreshold")
                    or {"roas_gt": 3.0, "cpa_lt": 40},
                    "loser": overrides.get("loserThreshold")
                    or {"roas_lt": 1.5, "cpa_gt": 80},
                    "minSpend": overrides.get("minSpend", 100),
                },
                "status": "idle",
            },
        },
        {
            "id": "decrease-losers",
            "type": "workflow",
            "position": {"x": 840, "y": 40},
            "data": {
                "label": "Decrease Losers' Budgets",
                "nodeType": "action",
                "description": "Reduce budget for loss-making ad sets",
                "config": {
                    "action": "adjust_budget",
                    "target": "losers",
                    "operation": "decrease",
                    "byPercent": overrides.get("decreasePercent", 20),
                    "minDailyBudget": overrides.get("minDailyBudget", 10),
                },
                "status": "idle",
            },
        },
        {
            "id": "increase-winners",
            "type": "workflow",
            "position": {"x": 840, "y": 160},
            "data": {
                "label": "Increase Winners' Budgets",
                "nodeType": "action",
                "description": "Shift released budget to profitable ad sets",
                "config": {
                    "action": "adjust_budget",
                    "target": "winners",
                    "operation": "increase",
                    "byPercent": overrides.get("increasePercent", 15),
                    "maxDailyBudget": overrides.get("maxDailyBudget", 1000),
                    "useFreedBudget": True,
                },
                "status": "idle",
            },
        },
        {
            "id": "notify-summary",
            "type": "workflow",
            "position": {"x": 1100, "y": 100},
            "data": {
                "label": "Notify Budget Changes",
                "nodeType": "notification",
                "description": "Send summary of budget shifts",
                "config": {
                    "channel": "email",
                    "subject": overrides.get("summarySubject")
                    or f"{ws_name} – Daily Budget Reallocation Summary",
                    "templateId": overrides.get("summaryTemplateId")
                    or "budget_reallocation_summary_v1",
                    "includeDetails": True,
                },
                "status": "idle",
            },
        },
    ]

    edges: List[Dict[str, Any]] = [
        {"id": "e-trig-fetch", "source": "trigger-daily", "target": "fetch-performance"},
        {
            "id": "e-fetch-classify",
            "source": "fetch-performance",
            "target": "classify-winners-losers",
        },
        {
            "id": "e-classify-decrease",
            "source": "classify-winners-losers",
            "target": "decrease-losers",
        },
        {
            "id": "e-classify-increase",
            "source": "classify-winners-losers",
            "target": "increase-winners",
        },
        {
            "id": "e-decrease-notify",
            "source": "decrease-losers",
            "target": "notify-summary",
        },
        {
            "id": "e-increase-notify",
            "source": "increase-winners",
            "target": "notify-summary",
        },
    ]

    return {
        "name": name,
        "nodes": nodes,
        "edges": edges,
    }

def ai_suggest_workflow_template(
    user_text: str, context: Dict[str, Any]
) -> Dict[str, Any] | None:
    """
    Ask Gemini to pick the best workflow template (if any) based on the user's request
    and workspace context.

    Returns a dict like:
    {
      "template_id": "pause-underperformers",
      "confidence": 0.93,
      "reason": "...",
      "overrides": { "schedule": "0 2 * * *", ... }
    }
    or None if nothing fits.
    """
    if not user_text or not user_text.strip():
        return None

    ws = context.get("workspace", {})
    ws_name = ws.get("business_name") or "your workspace"
    ws_industry = ws.get("industry") or "unknown"
    ws_model = ws.get("b2b_b2c") or "N/A"

    # Compact template catalog for the model
    template_catalog = [
        {
            "id": tid,
            "name": t["name"],
            "category": t["category"],
            "description": t["description"],
            "estimated_impact": t.get("estimated_impact"),
        }
        for tid, t in WORKFLOW_TEMPLATES.items()
    ]

    # 👉 Build a SINGLE string prompt instead of role-based contents
    prompt = f"""
You are an automation planner for the Sociovia ads platform.

You must choose the SINGLE best workflow template from the provided catalog,
based on the user's request and workspace context.

IMPORTANT RULES:
- If none of the templates clearly match the user request, set "template_id" to null.
- If a template matches but needs customization (schedule, thresholds, email, etc.),
  put those in "overrides".
- Output STRICT JSON only, no markdown, no comments, no extra text.
- "confidence" is between 0.0 and 1.0.

WORKSPACE:
{json.dumps({
    "name": ws_name,
    "industry": ws_industry,
    "model": ws_model,
}, indent=2)}

TEMPLATE_CATALOG:
{json.dumps(template_catalog, indent=2)}

USER_REQUEST:
{user_text}

You must respond ONLY with a JSON object like:

{{
  "template_id": "pause-underperformers",
  "confidence": 0.92,
  "reason": "User wants to pause low ROAS campaigns daily.",
  "overrides": {{
    "schedule": "0 1 * * *",
    "thresholds": {{"roas_lt": 1.5}}
  }}
}}
"""

    try:
        resp = GENAI_CLIENT.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        # ---------- AI USAGE LOGGING ----------
        try:
            usage_meta = getattr(resp, "usage_metadata", None) or {}

            # Gemini / Vertex style fields
            input_tokens = int(
                getattr(usage_meta, "prompt_token_count", 0)
                or getattr(usage_meta, "input_token_count", 0)
                or 0
            )
            output_tokens = int(
                getattr(usage_meta, "candidates_token_count", 0)
                or getattr(usage_meta, "output_token_count", 0)
                or 0
            )
            total_tokens = input_tokens + output_tokens

            usage_dict = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
            }

            # Resolve user + workspace
            user_id = context.get("user", {}).get("id") or get_current_user_id_safe()
            workspace_id = context.get("workspace", {}).get("id")

            # Client IP (if running under Flask request context)
            try:
                client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            except Exception:
                client_ip = None

            if user_id:
                cost_dec = calculate_cost_inr(
                    "gemini-2.5-flash",
                    input_tokens,
                    output_tokens,
                )
                cost_inr = float(cost_dec)

                log_ai_usage(
                    user_id=int(user_id),
                    workspace_id=int(workspace_id) if workspace_id else None,
                    feature="ai_workflow_template_suggestion",
                    route_path="/api/v1/ai/workflow-template-suggest",
                    model="gemini-2.5-flash",
                    usage=usage_dict,
                    cost_inr=cost_inr,
                    ip_address=client_ip,
                )
        except Exception as log_err:
            current_app.logger.warning(
                f"[AI_USAGE] failed to log ai_workflow_template_suggestion usage: {log_err}"
            )
        # -------------------------------------

        raw = getattr(resp, "text", None)
        if not raw:
            return None

        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            raw = raw.lstrip("json").strip()

        parsed = json.loads(raw)

        template_id = parsed.get("template_id")
        if template_id is None:
            return None

        if template_id not in WORKFLOW_TEMPLATES:
            # Unknown template id; ignore
            return None

        return {
            "template_id": template_id,
            "confidence": float(parsed.get("confidence", 0.0)),
            "reason": parsed.get("reason", ""),
            "overrides": parsed.get("overrides") or {},
        }

    except Exception as e:
        current_app.logger.exception("ai_suggest_workflow_template error: %s", e)
        return None

def ai_suggest_navigation_action(
    user_text: str, context: Dict[str, Any]
) -> Dict[str, Any] | None:
    """
    Let Gemini decide if we should suggest navigation (open a specific page in the UI)
    based on the user's last message.
    """
    if not user_text or not user_text.strip():
        return None

    available_routes = [
        "/sociovia-ai",
        "/assistant",
        "/workflow-builder",
        "/fb_user",
        "/marketing-dashboard",
        "/dashboard",
        "/workspaces",
        "/workspace/create",
        "/settings",
        "/support",
        "/docs",
        "/guides",
    ]

    nav_prompt = f"""
You are a routing planner for the Sociovia web app.

Very important rules:
- Only choose `/workspace/create` if the user clearly talks about workspaces
  (e.g. "create workspace", "add workspace", "new workspace").
- Do NOT map generic phrases like "create again", "create it", or "do it" to `/workspace/create`.
- If you're not confident, set "navigate_to" to null.

Decide IF navigation is helpful.
Return:
{{
  "navigate_to": string | null,
  "label": string,
  "reason": string
}}

Routes:
{json.dumps(available_routes, indent=2)}

USER MESSAGE:
{user_text}
"""

    try:
        resp = GENAI_CLIENT.models.generate_content(
            model="gemini-2.5-flash",
            contents=nav_prompt,
        )

        # ---------- AI USAGE LOGGING ----------
        try:
            usage_meta = getattr(resp, "usage_metadata", {}) or {}
            input_tokens = int(
                getattr(usage_meta, "prompt_token_count", 0)
                or getattr(usage_meta, "input_token_count", 0)
                or 0
            )
            output_tokens = int(
                getattr(usage_meta, "candidates_token_count", 0)
                or getattr(usage_meta, "output_token_count", 0)
                or 0
            )
            total_tokens = input_tokens + output_tokens

            user_id = context.get("user", {}).get("id") or get_current_user_id_safe()
            workspace_id = context.get("workspace", {}).get("id")
            client_ip = None
            try:
                client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            except Exception:
                pass

            if user_id:
                cost_inr = float(
                    calculate_cost_inr(
                        "gemini-2.5-flash",
                        input_tokens,
                        output_tokens,
                    )
                )

                log_ai_usage(
                    user_id=int(user_id),
                    workspace_id=int(workspace_id) if workspace_id else None,
                    feature="ai_navigation_suggestion",
                    route_path="/api/v1/ai/navigation-suggest",
                    model="gemini-2.5-flash",
                    usage={
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "total_tokens": total_tokens,
                    },
                    cost_inr=cost_inr,
                    ip_address=client_ip,
                )

        except Exception as log_err:
            current_app.logger.warning(
                f"[AI_USAGE] failed to log ai_navigation_suggestion usage: {log_err}"
            )

        # ==== RESPONSE EXTRACTION ====
        raw = getattr(resp, "text", None)
        if not raw:
            return None

        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.strip("`").lstrip("json").strip()

        parsed = json.loads(raw)
        navigate_to = parsed.get("navigate_to")

        if not navigate_to or navigate_to not in available_routes:
            return None

        # 🔒 Guard: only allow /workspace/create when user explicitly talks about workspaces
        if navigate_to == "/workspace/create":
            lowered = user_text.lower()
            if not any(
                kw in lowered
                for kw in ["workspace", "create workspace", "new workspace", "add workspace"]
            ):
                return None

        return {
            "navigate_to": navigate_to,
            "label": parsed.get("label") or f"Open {navigate_to}",
            "reason": parsed.get("reason") or "",
        }

    except Exception as e:
        current_app.logger.exception("ai_suggest_navigation_action error: %s", e)
        return None

# -------------------------------------------------
# THREAD + SUMMARY HELPERS
# -------------------------------------------------

MAX_SUMMARY_LEN = 2000
MAX_HISTORY_MSGS = 12


def get_or_create_thread(
    user_id: int, workspace_id: int, title: Optional[str] = None
) -> AssistantThread:
    """
    For now: one 'current' thread per user/workspace.
    Later you can add explicit conversation_id support from frontend.
    """
    thread = (
        AssistantThread.query.filter_by(user_id=user_id, workspace_id=workspace_id)
        .order_by(AssistantThread.created_at.desc())
        .first()
    )

    if thread:
        return thread

    thread = AssistantThread(
        user_id=user_id,
        workspace_id=workspace_id,
        title=title or "New conversation",
        summary="",
    )
    db.session.add(thread)
    db.session.commit()
    return thread


def load_thread_messages(
    thread: AssistantThread, limit: int = MAX_HISTORY_MSGS
) -> List[Dict[str, Any]]:
    """
    Load last N messages from this thread, oldest → newest,
    and convert to the same structure your build_prompt_with_context expects.
    """
    q = (
        AssistantMessage.query.filter_by(thread_id=thread.id)
        .order_by(AssistantMessage.created_at.asc())
    )
    all_msgs = q.all()
    recent = all_msgs[-limit:]

    model_msgs: List[Dict[str, Any]] = []
    for m in recent:
        model_msgs.append(
            {
                "from": "bot" if m.role == "assistant" else m.role,
                "text": m.text or "",
            }
        )

    return model_msgs


def update_thread_summary(
    thread: AssistantThread,
    last_user_text: str,
    last_assistant_text: str,
) -> None:
    """
    Cheap token-friendly summary: append a compact 'what was asked / what was delivered'
    line and trim to MAX_SUMMARY_LEN characters.
    """
    last_user_text = (last_user_text or "").strip()
    last_assistant_text = (last_assistant_text or "").strip()

    last_user_text = (
        (last_user_text[:200] + "…") if len(last_user_text) > 200 else last_user_text
    )
    last_assistant_text = (
        (last_assistant_text[:300] + "…")
        if len(last_assistant_text) > 300
        else last_assistant_text
    )

    new_line = (
        f"- User asked: {last_user_text} | Assistant replied: {last_assistant_text}\n"
    )
    current_summary = thread.summary or ""

    combined = current_summary + new_line
    if len(combined) > MAX_SUMMARY_LEN:
        combined = combined[-MAX_SUMMARY_LEN:]

    thread.summary = combined
    thread.updated_at = datetime.utcnow()


# -------------------------------------------------
# WORKFLOW EXECUTION ENGINE (SIMULATION)
# -------------------------------------------------

def schedule_workflow(workflow: Workflow) -> None:
    """
    Stub: later you can hook this into Celery / APScheduler / Cloud Tasks.
    For now it just logs that a schedule exists.
    """
    if not workflow.schedule_cron:
        return

    current_app.logger.info(
        "Workflow %s scheduled with cron %s (stub)",
        workflow.id,
        workflow.schedule_cron,
    )


# ----------------- WORKFLOW EXECUTION (SIMULATED) -----------------


def _get_mock_analytics() -> Dict[str, Any]:
    """
    Central place to define fake metrics used across all simulations.
    You can replace this later with real DB/meta-api calls.
    """
    return {
        "has_real_analytics": False,
        "accounts": [
            {
                "id": "act_demo_1",
                "name": "Demo Ad Account 1",
                "campaigns": [
                    {
                        "id": "cmp_1",
                        "name": "Prospecting – India",
                        "roas": 0.0,
                        "spend": 0.0,
                        "conversions": 0,
                    },
                    {
                        "id": "cmp_2",
                        "name": "Retargeting – Warm Leads",
                        "roas": 0.0,
                        "spend": 0.0,
                        "conversions": 0,
                    },
                ],
            }
        ],
    }


def execute_budget_reallocation_workflow(
    workflow: Dict[str, Any],
    context: Dict[str, Any],
    simulate: bool = True,
) -> Dict[str, Any]:
    """
    Simulated execution for the Budget Reallocation workflow.
    For now, it:
    - Reads the config from nodes.
    - Uses mock analytics (ROAS, spend = 0).
    - Returns a summary of what would have been changed.
    """
    ws_name = context["workspace"].get("business_name") or "your workspace"
    analytics = _get_mock_analytics()

    # Extract key config from workflow
    nodes = {n["id"]: n for n in workflow.get("nodes", [])}
    classify_node = nodes.get("classify-winners-losers")
    decrease_node = nodes.get("decrease-losers")
    increase_node = nodes.get("increase-winners")

    winner_cfg = (classify_node or {}).get("data", {}).get("config", {}).get("winner", {})
    loser_cfg = (classify_node or {}).get("data", {}).get("config", {}).get("loser", {})
    dec_cfg = (decrease_node or {}).get("data", {}).get("config", {})
    inc_cfg = (increase_node or {}).get("data", {}).get("config", {})

    result = {
        "workspace": ws_name,
        "simulate": simulate,
        "analytics_used": analytics,
        "winner_threshold": winner_cfg,
        "loser_threshold": loser_cfg,
        "decrease_config": dec_cfg,
        "increase_config": inc_cfg,
        "affected_campaigns": [],  # stays empty until real metrics
        "notes": [
            "This is a dry-run execution using mock analytics (all metrics = 0).",
            "Once real Meta API + DB wiring is ready, this function can:",
            "- Pull real ROAS / spend / conversions for each ad set.",
            "- Decide winners / losers.",
            "- Call Meta Marketing API to adjust budgets.",
        ],
    }

    current_app.logger.info(
        "[WORKFLOW] Simulated budget reallocation for workspace=%s, config=%s",
        ws_name,
        {
            "winner": winner_cfg,
            "loser": loser_cfg,
            "decrease": dec_cfg,
            "increase": inc_cfg,
        },
    )
    return result


def execute_weekly_report_workflow(
    workflow: Dict[str, Any],
    context: Dict[str, Any],
    simulate: bool = True,
) -> Dict[str, Any]:
    """
    Simulated execution for the Weekly Performance Email workflow.
    For now it:
    - Uses mock metrics (0).
    - Sends a real email (via SMTP) with those simulated metrics.
    """
    ws = context["workspace"]
    user = context["user"]
    ws_name = ws.get("business_name") or "your workspace"
    user_email = user.get("email")

    analytics = _get_mock_analytics()
    simulated_metrics = {
        "roas": 0.0,
        "spend": 0.0,
        "conversions": 0.0,
        "clicks": 0.0,
    }

    # Find email node configuration
    nodes = {n["id"]: n for n in workflow.get("nodes", [])}
    email_node = nodes.get("email-summary")
    email_cfg = (email_node or {}).get("data", {}).get("config", {}) if email_node else {}

    # Recipients: from overrides (via node config) + user email fallback
    recipients_raw = email_cfg.get("to") or ""
    extra_recips = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    recipients: list[str] = []
    if user_email:
        recipients.append(user_email)
    recipients.extend(extra_recips)

    # Actually send an email (even in "simulate", we treat email as safe side effect)
    try:
        send_weekly_report_email(ws_name, recipients, simulated_metrics)
        email_status = "sent"
    except Exception as e:
        current_app.logger.exception("[WORKFLOW] Failed to send weekly report email: %s", e)
        email_status = f"failed: {e}"

    result = {
        "workspace": ws_name,
        "simulate": simulate,
        "analytics_used": analytics,
        "recipients": recipients,
        "email_status": email_status,
        "notes": [
            "Weekly performance report uses simulated metrics (zeros) for now.",
            "Email was sent using the SMTP configuration from environment variables.",
            "Once analytics are wired, replace `_get_mock_analytics` + `simulated_metrics` with real data.",
        ],
    }

    current_app.logger.info(
        "[WORKFLOW] Weekly report workflow executed. recipients=%s status=%s",
        recipients,
        email_status,
    )
    return result


def execute_workflow_from_template(
    template_id: str,
    workflow: Dict[str, Any],
    context: Dict[str, Any],
    simulate: bool = True,
) -> Dict[str, Any]:
    """
    Router: choose the correct executor based on template_id.
    """
    if template_id == "budget-reallocation":
        return execute_budget_reallocation_workflow(workflow, context, simulate=simulate)
    elif template_id == "weekly-report":
        return execute_weekly_report_workflow(workflow, context, simulate=simulate)
    else:
        ws_name = context["workspace"].get("business_name") or "your workspace"
        msg = f"No executor defined for template_id={template_id}. Workflow only created, not run."
        current_app.logger.info("[WORKFLOW] %s", msg)
        return {
            "workspace": ws_name,
            "simulate": simulate,
            "notes": [msg],
        }


def execute_workflow_json(
    workflow_json: Dict[str, Any],
    context: Dict[str, Any],
    run_mode: str = "simulate",
) -> Dict[str, Any]:
    """
    VERY SIMPLE engine:
    - Walk nodes in a naive graph traversal
    - For each node, simulate behavior and log it
    - Uses mock analytics (all zeros) for now
    """
    nodes = {n["id"]: n for n in workflow_json.get("nodes", [])}
    edges = workflow_json.get("edges", [])

    # Build adjacency map: source -> [targets]
    graph: Dict[str, List[str]] = {}
    incoming_count: Dict[str, int] = {node_id: 0 for node_id in nodes.keys()}

    for e in edges:
        src = e["source"]
        tgt = e["target"]
        graph.setdefault(src, []).append(tgt)
        incoming_count[tgt] = incoming_count.get(tgt, 0) + 1

    # Find start nodes: triggers first, else nodes with no incoming edges
    start_nodes = [
        nid
        for nid, node in nodes.items()
        if node.get("data", {}).get("nodeType") == "trigger"
    ]
    if not start_nodes:
        start_nodes = [nid for nid, cnt in incoming_count.items() if cnt == 0]

    mock_metrics = _mock_analytics_metrics(context)

    visited = set()
    exec_log: List[Dict[str, Any]] = []

    def process_node(node_id: str):
        if node_id in visited:
            return
        visited.add(node_id)

        node = nodes.get(node_id)
        if not node:
            return

        data = node.get("data", {})
        node_type = data.get("nodeType", "unknown")
        label = data.get("label", node_id)
        config = data.get("config", {}) or {}

        step = {
            "nodeId": node_id,
            "label": label,
            "nodeType": node_type,
            "status": "ok",
            "details": {},
        }

        # --- Dispatch per nodeType (very simple, just for logs) ---
        if node_type == "trigger":
            step["details"] = {
                "kind": "trigger",
                "schedule": config.get("schedule"),
                "frequency": config.get("frequency"),
                "note": "Trigger fired (simulation only).",
            }

        elif node_type == "selector":
            step["details"] = {
                "kind": "selector",
                "criteria": config,
                "selected_ids": [],
                "note": "Would select campaigns/adsets here; using empty list for now.",
            }

        elif node_type == "analytics":
            step["details"] = {
                "kind": "analytics",
                "action": config.get("action"),
                "metrics": mock_metrics,
                "note": "Using mock analytics metrics (all zeros).",
            }

        elif node_type == "condition":
            step["details"] = {
                "kind": "condition",
                "config": config,
                "result": True,
                "note": "Condition evaluated as True by default in simulation.",
            }

        elif node_type == "action":
            step["details"] = {
                "kind": "action",
                "config": config,
                "note": "Would call Meta API to pause/adjust budgets; simulation only, no real changes.",
            }

        elif node_type == "ai":
            step["details"] = {
                "kind": "ai",
                "config": config,
                "note": "Would call LLM to generate copy/audiences; not executed in dry-run.",
            }

        elif node_type == "notification":
            step["details"] = {
                "kind": "notification",
                "config": config,
                "note": "Would send email/slack/webhook; simulation only.",
            }

        elif node_type == "approval":
            step["details"] = {
                "kind": "approval",
                "config": config,
                "note": "Would create approval task; simulation only.",
            }

        else:
            step["details"] = {
                "kind": "unknown",
                "config": config,
                "note": "Unknown node type; skipped.",
            }

        exec_log.append(step)

        # Recurse into next nodes
        for nxt in graph.get(node_id, []):
            process_node(nxt)

    started_at = _now_iso()
    for s in start_nodes:
        process_node(s)
    finished_at = _now_iso()

    return {
        "workflowName": workflow_json.get("name"),
        "startedAt": started_at,
        "finishedAt": finished_at,
        "status": "success",
        "mode": run_mode,
        "stepsCount": len(exec_log),
        "steps": exec_log,
        "outputs": {
            "analytics": mock_metrics,
            "note": "This was a simulation; no real campaign changes were made.",
        },
    }


# -------------------------------------------------
# FLASK ROUTES (ASSISTANT)
# -------------------------------------------------
# NOTE: This assumes you have `app = Flask(__name__)` defined elsewhere
# and this file is imported. If you use blueprints, adapt decorators accordingly.
# -------------------------------------------------


@app.route(
    "/api/assistant/conversations/<int:thread_id>/messages",
    methods=["GET"],
)
def assistant_conversation_messages(thread_id: int):
    """
    Returns all messages for a given assistant thread, scoped by user + workspace.
    """
    user_id = request.args.get("userId", type=int)
    workspace_id = request.args.get("workspaceId", type=int)

    if not user_id or not workspace_id:
        return jsonify({"error": "userId and workspaceId are required"}), 400

    thread = (
        AssistantThread.query.filter_by(
            id=thread_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        .first()
    )

    if not thread:
        return (
            jsonify(
                {
                    "error": "Conversation not found for this user/workspace",
                    "messages": [],
                }
            ),
            404,
        )

    messages_payload = []
    for m in thread.messages:  # assuming relationship ordered by created_at
        role = m.role or "system"
        if role not in ("user", "bot", "system"):
            role = "system"

        created_ts = int(m.created_at.timestamp() * 1000) if m.created_at else 0

        messages_payload.append(
            {
                "id": f"{role}-{m.id}",
                "from": role,
                "text": m.text or "",
                "time": created_ts,
                "type": m.message_type or "text",
                "data": m.data_json or None,
                "actions": None,
            }
        )

    thread_payload = {
        "id": thread.id,
        "title": thread.title,
        "summary": thread.summary,
        "created_at": thread.created_at.isoformat()
        if thread.created_at
        else None,
        "updated_at": thread.updated_at.isoformat()
        if thread.updated_at
        else None,
    }

    return jsonify({"thread": thread_payload, "messages": messages_payload}), 200

@app.route("/api/assistant/chat", methods=["POST"])
def assistant_chat():
    """
    Body JSON expected:

    {
      "userId": 1,
      "workspaceId": 10,
      "messages": [...],       # frontend messages (at least last user message)
      "conversationId": 123    # OPTIONAL - for future multi-thread support
    }
    """
    data = request.get_json(force=True, silent=True) or {}

    user_id = _safe_get(data, "userId")
    workspace_id = _safe_get(data, "workspaceId")
    messages = _safe_get(data, "messages", [])
    conversation_id = _safe_get(data, "conversationId")

    if user_id is None or workspace_id is None:
        return jsonify({"error": "userId and workspaceId are required"}), 400

    if not isinstance(messages, list) or len(messages) == 0:
        return jsonify({"error": "messages[] is required"}), 400

    try:
        user_id_int = int(user_id)
        workspace_id_int = int(workspace_id)

        # Build DB context
        context = build_db_context(user_id_int, workspace_id_int)

        # ---- 1) Resolve / create thread (conversation) ----
        first_user_msg = next(
            (m for m in messages if m.get("from") == "user"),
            messages[0],
        )
        first_text = (first_user_msg.get("text") or "").strip()

        # For now: ignore conversationId and keep it 1-thread-per user/workspace.
        thread = get_or_create_thread(
            user_id_int,
            workspace_id_int,
            title=(first_text[:60] if first_text else "New conversation"),
        )

        # ---- 2) Build history for model (token friendly) ----
        # Load last messages from DB
        history_from_db = load_thread_messages(thread, limit=MAX_HISTORY_MSGS)

        # Current last user message (from request)
        last_user_msg = next(
            (m for m in reversed(messages) if m.get("from") == "user"),
            messages[-1],
        )
        last_text_raw = last_user_msg.get("text") or ""
        last_text = last_text_raw.lower()

        # Append current user turn to history so the model sees it
        messages_for_model = history_from_db + [
            {
                "from": "user",
                "text": last_user_msg.get("text") or "",
            }
        ]

        # ---- 3) Generate natural language reply using summary+history ----
        reply_text = generate_ai_reply(
            messages_for_model,
            context,
            summary=thread.summary,  # token-friendly memory
        )

        msg_type: str = "text"
        data_payload: Any = None
        actions: List[Dict[str, Any]] = []

        # ===== A) Simple keyword → visualization logic =====
        if any(
            kw in last_text
            for kw in ["performance", "overview", "report", "insights", "metrics"]
        ):
            msg_type = "chart"
            data_payload = {
                "title": "Last 7 days performance (demo, metrics=0)",
                "chartType": "line",
                "points": [
                    {"label": "Day 1", "value": 0},
                    {"label": "Day 2", "value": 0},
                    {"label": "Day 3", "value": 0},
                    {"label": "Day 4", "value": 0},
                    {"label": "Day 5", "value": 0},
                    {"label": "Day 6", "value": 0},
                    {"label": "Day 7", "value": 0},
                ],
            }

        # kpi summary (still mock metrics = 0)
        if any(kw in last_text for kw in ["kpi", "summary", "leads", "spend"]):
            msg_type = "kpi"
            data_payload = {
                "metrics": [
                    {
                        "label": "Leads (demo, simulated)",
                        "value": "0",
                        "trend": "simulated (no tracking yet)",
                        "trendDirection": "flat",
                    },
                    {
                        "label": "CTR (demo, simulated)",
                        "value": "0.0%",
                        "trend": "simulated (no tracking yet)",
                        "trendDirection": "flat",
                    },
                    {
                        "label": "CPL (demo, simulated)",
                        "value": "₹0",
                        "trend": "simulated (no tracking yet)",
                        "trendDirection": "flat",
                    },
                    {
                        "label": "Active campaigns (demo)",
                        "value": "0",
                        "trend": "simulated",
                        "trendDirection": "flat",
                    },
                ]
            }

        # calendar-style requests
        if any(
            kw in last_text
            for kw in ["calendar", "schedule", "meeting", "upcoming", "plan my week"]
        ):
            msg_type = "calendar"
            data_payload = {"events": build_demo_calendar_events(context)}

        # ===== B) AI-based workflow template selection =====
        selection = ai_suggest_workflow_template(last_text_raw, context)

        if selection:
            tpl_id = selection["template_id"]
            tpl = WORKFLOW_TEMPLATES[tpl_id]
            ws_name = context["workspace"].get("business_name") or "your workspace"

            workflow_json = None
            if tpl_id == "weekly-report":
                workflow_json = build_weekly_report_workflow(
                    context, selection.get("overrides") or {}
                )
            elif tpl_id == "budget-reallocation":
                workflow_json = build_budget_reallocation_workflow(
                    context, selection.get("overrides") or {}
                )

            msg_type = "workflow"
            data_payload = {
                "templateId": tpl_id,
                "templateName": tpl["name"],
                "category": tpl["category"],
                "estimatedImpact": tpl.get("estimated_impact"),
                "nodesCount": tpl.get("nodes_count"),
                "workspaceName": ws_name,
                "confidence": selection["confidence"],
                "overrides": selection.get("overrides") or {},
            }

            if workflow_json is not None:
                data_payload["workflow"] = workflow_json

            actions = [
                {
                    "id": f"create_workflow::{tpl_id}",
                    "label": f"Create & run \"{tpl['name']}\" workflow",
                    "variant": "primary",
                    "api": f"{request.url_root.rstrip('/')}/api/assistant/action",
                    "payload": {
                        "templateId": tpl_id,
                        "mode": "create_and_activate",
                        "overrides": selection.get("overrides") or {},
                    },
                },
                {
                    "id": f"open_workflow_builder::{tpl_id}",
                    "label": "Open in workflow builder",
                    "variant": "secondary",
                    "payload": {
                        "templateId": tpl_id,
                        "mode": "open_in_builder",
                        "overrides": selection.get("overrides") or {},
                        "navigate": "workflow-builder",
                    },
                },
            ]

            reason = selection.get("reason") or ""

            # 🔥 Overwrite the generic LLM reply completely when a template is selected
            reply_text = (
                f"I've mapped your request to the **{tpl['name']}** automation template "
                f"(_{tpl['category']}_). {reason}\n\n"
                "Right now I'm using **simulated analytics** with all numeric metrics treated as **0** "
                "until tracking is wired. This still lets us fully configure and **dry-run** the workflow.\n\n"
                "Click **Create & run** to let me create this workflow and execute a **simulation only** "
                "(no real campaign changes yet)."
            )

        # ===== C) AI-based navigation suggestion =====
        nav_suggestion = ai_suggest_navigation_action(last_text_raw, context)

        if nav_suggestion and nav_suggestion.get("navigate_to"):
            target = nav_suggestion["navigate_to"]
            label = nav_suggestion.get("label") or f"Open {target}"
            reason = nav_suggestion.get("reason") or ""

            existing_ids = {a.get("id") for a in (actions or [])}
            nav_id = f"navigate::{target.lstrip('/')}"
            if nav_id not in existing_ids:
                if not actions:
                    actions = []
                actions.append(
                    {
                        "id": nav_id,
                        "label": label,
                        "variant": "secondary",
                        "payload": {
                            "navigate": target,
                            "reason": reason,
                        },
                    }
                )

            if reason:
                reply_text += f"\n\nI've also added a quick button: **{label}** — {reason}"
            else:
                reply_text += f"\n\nI've added a quick button: **{label}**."

        # ===== D) Support / docs explicit keyword helpers =====
        if any(
            kw in last_text
            for kw in ["support", "help", "issue", "bug", "problem", "contact", "ticket"]
        ):
            actions.append(
                {
                    "id": "contact_support",
                    "label": f"Send support email ({SUPPORT_EMAIL})",
                    "variant": "primary",
                    "api": f"{request.url_root.rstrip('/')}/api/assistant/action",
                    "payload": {
                        "type": "support",
                        "reason": last_text_raw,
                        "navigate": "support",
                    },
                }
            )
            actions.append(
                {
                    "id": "open_docs_crm_quickstart",
                    "label": "Open CRM quickstart docs",
                    "variant": "secondary",
                    "payload": {"navigate": "docs/crm-quickstart"},
                }
            )
            actions.append(
                {
                    "id": "open_docs_email_automation",
                    "label": "Open email automation docs",
                    "variant": "secondary",
                    "payload": {"navigate": "docs/email-automation"},
                }
            )

            reply_text += (
                f"\n\nIf this looks like a support question, you can also reach our team at **{SUPPORT_EMAIL}**. "
                "I've added a button to send a support email on your behalf (once wired) plus relevant docs."
            )

        # ===== E) Approval / review actions =====
        if any(
            kw in last_text
            for kw in ["approve", "approval", "review", "draft", "campaign"]
        ):
            if not actions:
                actions = []
            actions.extend(
                [
                    {
                        "id": "approve_campaigns",
                        "label": "Approve all safe drafts (simulated)",
                        "variant": "primary",
                        "api": f"{request.url_root.rstrip('/')}/api/assistant/action",
                        "payload": {
                            "scope": "campaigns",
                            "decision": "approve",
                        },
                    },
                    {
                        "id": "reject_risky",
                        "label": "Reject risky or non-compliant (simulated)",
                        "variant": "destructive",
                        "payload": {
                            "scope": "campaigns",
                            "decision": "reject_non_compliant",
                        },
                    },
                    {
                        "id": "open_dashboard",
                        "label": "Open in dashboard",
                        "variant": "secondary",
                        "payload": {"navigate": "campaigns"},
                    },
                ]
            )

        # ---- 4) Save this turn to DB: user + assistant messages ----
        try:
            # store user message
            user_msg_model = AssistantMessage(
                thread_id=thread.id,
                role="user",
                text=last_user_msg.get("text") or "",
                message_type="text",   # request is always text for now
                data_json=None,
            )
            db.session.add(user_msg_model)

            # store assistant message
            assistant_msg_model = AssistantMessage(
                thread_id=thread.id,
                role="assistant",
                text=reply_text,
                message_type=msg_type,
                data_json=data_payload,
            )
            db.session.add(assistant_msg_model)

            # update summary (token-friendly high-level memory)
            update_thread_summary(
                thread,
                last_user_text=last_user_msg.get("text") or "",
                last_assistant_text=reply_text,
            )

            db.session.commit()
        except Exception as save_err:
            current_app.logger.warning(f"Failed to persist assistant messages: {save_err}")
            db.session.rollback()

        # ---- 5) Final message back to frontend ----
        reply_message = {
            "id": f"bot-{int(time.time() * 1000)}",
            "from": "bot",
            "text": reply_text,
            "time": int(time.time() * 1000),
            "type": msg_type,
            "data": data_payload,
            "actions": actions,
        }

        return jsonify({
            "message": reply_message,
            "conversationId": thread.id,  # frontend can store like ChatGPT
        }), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404
    except Exception as e:
        current_app.logger.exception("Error in assistant_chat")
        return jsonify({"error": str(e)}), 500

# -------------------------------------------------
# TASKS / CALENDAR / NOTIFICATIONS ENDPOINTS
# -------------------------------------------------


@app.route("/api/assistant/tasks", methods=["GET"])
def assistant_tasks():
    user_id = request.args.get("userId")
    workspace_id = request.args.get("workspaceId")
    if not user_id or not workspace_id:
        return jsonify({"error": "userId and workspaceId are required"}), 400

    try:
        context = build_db_context(int(user_id), int(workspace_id))
        tasks = build_demo_tasks(context)
        return jsonify({"tasks": tasks}), 200
    except ValueError as ve:
        return jsonify({"error": str(ve), "tasks": []}), 404
    except Exception as e:
        current_app.logger.exception("Error in assistant_tasks")
        return jsonify({"error": str(e), "tasks": []}), 500


@app.route("/api/assistant/calendar", methods=["GET"])
def assistant_calendar():
    user_id = request.args.get("userId")
    workspace_id = request.args.get("workspaceId")
    if not user_id or not workspace_id:
        return jsonify({"error": "userId and workspaceId are required"}), 400

    try:
        context = build_db_context(int(user_id), int(workspace_id))
        events = build_demo_calendar_events(context)
        return jsonify({"events": events}), 200
    except ValueError as ve:
        return jsonify({"error": str(ve), "events": []}), 404
    except Exception as e:
        current_app.logger.exception("Error in assistant_calendar")
        return jsonify({"error": str(e), "events": []}), 500


@app.route("/api/assistant/notifications", methods=["GET"])
def assistant_notifications():
    user_id = request.args.get("userId")
    workspace_id = request.args.get("workspaceId")
    if not user_id or not workspace_id:
        return jsonify({"error": "userId and workspaceId are required"}), 400

    try:
        context = build_db_context(int(user_id), int(workspace_id))
        notifications = build_demo_notifications(context)
        return jsonify({"notifications": notifications}), 200
    except ValueError as ve:
        return jsonify({"error": str(ve), "notifications": []}), 404
    except Exception as e:
        current_app.logger.exception("Error in assistant_notifications")
        return jsonify({"error": str(e), "notifications": []}), 500


# -------------------------------------------------
# ACTION HANDLER (INCLUDES WORKFLOW CREATE + RUN + SUPPORT)
# -------------------------------------------------

@app.route("/api/assistant/action", methods=["POST"])
def assistant_action():
    """
    Expects body:

    {
      "userId": 1,
      "workspaceId": 10,
      "actionId": "approve_campaigns" | "create_workflow::budget-reallocation" | ...,
      "sourceMessageId": "bot-...",
      "payload": {...}
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    user_id = _safe_get(data, "userId")
    workspace_id = _safe_get(data, "workspaceId")
    action_id = _safe_get(data, "actionId")
    payload = _safe_get(data, "payload", {}) or {}

    if not user_id or not workspace_id or not action_id:
        return jsonify({"error": "userId, workspaceId, and actionId are required"}), 400

    try:
        context = build_db_context(int(user_id), int(workspace_id))
        ws = context["workspace"]
        user = context["user"]
        ws_name = ws.get("business_name") or "your workspace"
        user_email = user.get("email")

        status = "ok"
        result_text: str = ""
        message_type: str = "text"
        data_payload: Any = None

        aid_lower = str(action_id).lower()

        # -------- A) CREATE & RUN WORKFLOW FROM TEMPLATE --------
        if aid_lower.startswith("create_workflow::"):
            # actionId is like: create_workflow::budget-reallocation
            tpl_id = action_id.split("::", 1)[1]
            overrides = payload.get("overrides") or {}

            workflow_json = None
            if tpl_id == "weekly-report":
                workflow_json = build_weekly_report_workflow(context, overrides)
            elif tpl_id == "budget-reallocation":
                workflow_json = build_budget_reallocation_workflow(context, overrides)
            else:
                # Unknown template but still respond gracefully
                result_text = (
                    f"I received a request to create a workflow from template `{tpl_id}`, "
                    "but I don't yet have a builder configured for that template."
                )
                reply_message = {
                    "id": f"bot-action-{int(time.time() * 1000)}",
                    "from": "bot",
                    "text": result_text,
                    "time": int(time.time() * 1000),
                    "type": message_type,
                    "data": data_payload,
                }
                return jsonify({"status": "ok", "result": result_text, "message": reply_message}), 200

            # Execute workflow in simulated mode (but with real email for weekly-report)
            exec_result = execute_workflow_from_template(
                tpl_id,
                workflow_json,
                context,
                simulate=True,
            )

            if tpl_id == "budget-reallocation":
                result_text = (
                    f"I've created a workflow \"{workflow_json['name']}\" from template "
                    f"**{WORKFLOW_TEMPLATES[tpl_id]['name']}** for **{ws_name}**, "
                    f"scheduled with {workflow_json['nodes'][0]['data']['config'].get('schedule', '0 9 * * *')} "
                    "and executed a simulation run.\n\n"
                    "No real campaign changes were made yet — this is a dry run using mock analytics."
                )
            elif tpl_id == "weekly-report":
                recips = exec_result.get("recipients") or []
                result_text = (
                    f"I've created a workflow \"{workflow_json['name']}\" from template "
                    f"**{WORKFLOW_TEMPLATES[tpl_id]['name']}** for **{ws_name}**, "
                    "scheduled weekly, and sent a simulated performance email.\n\n"
                    f"Recipients: {', '.join(recips) or 'none'}\n"
                    "Metrics inside the email are currently simulated (0) until real analytics are wired."
                )
            else:
                result_text = (
                    f"I've created a workflow \"{workflow_json['name']}\" for **{ws_name}** "
                    "and executed it in simulated mode."
                )

            message_type = "workflow_run"
            data_payload = {
                "templateId": tpl_id,
                "workflow": workflow_json,
                "execution": exec_result,
            }

        # -------- B) Approvals --------
        elif "approve" in aid_lower:
            result_text = (
                f"I've (virtually) approved the safe campaigns for **{ws_name}**. "
                "Once the real backend wiring is ready, this button can trigger actual approvals."
            )

        # -------- C) Rejections --------
        elif "reject" in aid_lower:
            result_text = (
                f"I've (virtually) rejected risky/non-compliant campaigns for **{ws_name}**. "
                "You can later connect this to a true moderation workflow."
            )

        # -------- D) Navigation (e.g. navigate::sociovia-ai) --------
        elif aid_lower.startswith("navigate::"):
            target_slug = aid_lower.split("navigate::", 1)[1].strip() or ""

            nav_map = {
                "sociovia-ai": "/sociovia-ai",
                "assistant": "/assistant",
                "workflow-builder": "/workflow-builder",
                "workflows": "/workflow-builder",
                "campaigns": "/marketing-dashboard",
                "marketing-dashboard": "/marketing-dashboard",
                "fb_user": "/fb_user",
                "bind-meta": "/fb_user",
                "meta": "/fb_user",
                "crm": "/dashboard",
                "dashboard": "/dashboard",
                "workspaces": "/workspaces",
                "workspace-create": "/workspace/create",
                "workspace/create": "/workspace/create",
                "settings": "/settings",
                "support": "/support",
                "docs": "/docs",
                "guides": "/guides",
            }

            target_path = nav_map.get(
                target_slug,
                f"/{target_slug}" if target_slug else "/dashboard"
            )

            result_text = f"Navigate to **{target_path}** in the Sociovia UI."
            message_type = "navigation"
            data_payload = {"navigate": target_path}

        # -------- E) Support / ticket / contact (REAL EMAIL) --------
        elif "support" in aid_lower or "ticket" in aid_lower or "contact" in aid_lower:
            reason = payload.get("reason") or "User raised a support request via Sociovia AI."

            # Send real support email
            try:
                send_support_email(ws_name, user_email, reason)
                email_status = "sent"
            except Exception as e:
                current_app.logger.exception("[SUPPORT] Failed to send support email: %s", e)
                email_status = f"failed: {e}"

            result_text = (
                f"I've recorded a support request for **{ws_name}** and forwarded details "
                f"to our support team at **{SUPPORT_EMAIL}**.\n\n"
                f"Email status: {email_status}\n\n"
                "Once ticketing is fully wired, this can also create a ticket in your support system."
            )

        # -------- F) Generic "open" actions --------
        elif "open_dashboard" in aid_lower or ("open" in aid_lower and "workflow" in aid_lower):
            result_text = (
                "Opening the campaigns or workflow view in your dashboard would happen here. "
                "For now, use the navigation button in the UI."
            )

        # -------- G) Fallback --------
        else:
            result_text = (
                f"Action `{action_id}` received. "
                "You can extend the backend to perform real side effects here."
            )

        reply_message = {
            "id": f"bot-action-{int(time.time() * 1000)}",
            "from": "bot",
            "text": result_text,
            "time": int(time.time() * 1000),
            "type": message_type,
            "data": data_payload,
        }

        return (
            jsonify(
                {
                    "status": status,
                    "result": result_text,
                    "message": reply_message,
                }
            ),
            200,
        )

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404
    except Exception as e:
        current_app.logger.exception("Error in assistant_action")
        return jsonify({"error": str(e)}), 500

# -------------------------------------------------
# RE-RUN WORKFLOW ENDPOINT
# -------------------------------------------------

@app.route("/api/assistant/workflows/execute", methods=["POST"])
def assistant_execute_workflow():
    """
    Body options:

    Option 1:
    {
      "userId": 1,
      "workspaceId": 10,
      "workflowId": 5
    }

    Option 2:
    {
      "userId": 1,
      "workspaceId": 10,
      "workflowJson": { ... ReactFlow JSON ... }
    }
    """
    data = request.get_json(force=True, silent=True) or {}

    user_id = _safe_get(data, "userId")
    workspace_id = _safe_get(data, "workspaceId")
    workflow_id = _safe_get(data, "workflowId")
    workflow_json = _safe_get(data, "workflowJson")

    if not user_id or not workspace_id:
        return jsonify({"error": "userId and workspaceId are required"}), 400

    try:
        user_id_int = int(user_id)
        workspace_id_int = int(workspace_id)

        context = build_db_context(user_id_int, workspace_id_int)

        wf_model: Optional[Workflow] = None
        if workflow_id:
            wf_model = Workflow.query.filter_by(
                id=int(workflow_id),
                user_id=user_id_int,
                workspace_id=workspace_id_int,
            ).first()
            if not wf_model:
                return jsonify({"error": "Workflow not found for this user/workspace"}), 404
            workflow_json = wf_model.json

        if not workflow_json:
            return jsonify({"error": "Either workflowId or workflowJson is required"}), 400

        run_report = execute_workflow_json(workflow_json, context, run_mode="simulate")

        if wf_model:
            run_model = WorkflowRun(
                workflow_id=wf_model.id,
                started_at=datetime.utcnow(),
                finished_at=datetime.utcnow(),
                status=run_report.get("status", "success"),
                report_json=run_report,
            )
            db.session.add(run_model)
            db.session.commit()

        return jsonify({"runReport": run_report}), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404
    except Exception as e:
        current_app.logger.exception("Error in assistant_execute_workflow")
        return jsonify({"error": str(e)}), 500


# -------------------------------------------------
# HEALTHCHECK
# -------------------------------------------------

@app.route("/api/assistant/health", methods=["GET"])
def assistant_health():
    return jsonify({"status": "ok", "model": "gemini-2.5-flash"}), 200


from typing import Any, Dict, Optional
from decimal import Decimal
from datetime import datetime
import uuid

def log_ai_usage(
    *,
    user_id: int,
    workspace_id: Optional[int],
    feature: str,
    route_path: str,
    model: str,
    usage: Dict[str, Any],
    cost_inr: float,
    request_id: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Generic AI usage logger.

    - For text models: expect true token counts in usage.
    - For image models: we can treat num_images as "tokens" if needed.
    """

    usage = usage or {}

    # ---- 1) Extract tokens safely ----
    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)

    # Fallback: if this is an image call and caller only sent num_images
    if output_tokens == 0 and "num_images" in usage:
        try:
            output_tokens = int(usage.get("num_images") or 0)
        except Exception:
            output_tokens = 0

    total_tokens = int(usage.get("total_tokens") or (input_tokens + output_tokens) or 0)

    # ---- 2) Normalize cost to Decimal/float as your model expects ----
    try:
        # if your AIUsage.cost_inr is Numeric/Decimal, it's better to convert:
        cost_inr_value = float(cost_inr)
    except Exception:
        cost_inr_value = 0.0

    # ---- 3) Ensure we always have a request_id if column is non-nullable ----
    if request_id is None:
        request_id = uuid.uuid4().hex

    # ---- 4) Debug log (optional but super helpful) ----
    current_app.logger.info(
        f"[AI_USAGE_DEBUG] feature={feature} model={model} "
        f"input_tokens={input_tokens} output_tokens={output_tokens} "
        f"total_tokens={total_tokens} usage={usage}"
    )

    # ---- 5) Persist ----
    record = AIUsage(
        user_id=user_id,
        workspace_id=workspace_id,
        feature=feature,
        route_path=route_path,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        cost_inr=cost_inr_value,
        request_id=request_id,
        ip_address=ip_address,
    )
    db.session.add(record)
    db.session.commit()


from datetime import timedelta
from sqlalchemy import func
from flask import request, jsonify, session
from datetime import datetime, timedelta
from sqlalchemy import func

@app.route("/api/usage/summary", methods=["GET"])
def get_usage_summary():
    try:
        # --------------------------------
        # Resolve user_id (session-based)
        # --------------------------------
        user_id = session.get("user_id")
        if not user_id:
            # optionally also allow header-based user id
            hdr_uid = request.headers.get("X-User-Id")
            if hdr_uid:
                try:
                    user_id = int(hdr_uid)
                except Exception:
                    user_id = None

        if not user_id:
            return jsonify({"ok": False, "error": "not_authenticated"}), 401

        try:
            user_id = int(user_id)
        except Exception:
            return jsonify({"ok": False, "error": "invalid_user_id"}), 400

        # --------------------------------
        # Query window + optional workspace
        # --------------------------------
        days = request.args.get("days", type=int) or 30
        workspace_id = request.args.get("workspace_id", type=int)

        since = datetime.utcnow() - timedelta(days=days)

        q = AIUsage.query.filter(
            AIUsage.user_id == user_id,
            AIUsage.created_at >= since,
        )

        if workspace_id:
            q = q.filter(AIUsage.workspace_id == workspace_id)

        # --------------------------------
        # Overall totals
        # --------------------------------
        total_row = q.with_entities(
            func.count(AIUsage.id),
            func.coalesce(func.sum(AIUsage.input_tokens), 0),
            func.coalesce(func.sum(AIUsage.output_tokens), 0),
            func.coalesce(func.sum(AIUsage.total_tokens), 0),
            func.coalesce(func.sum(AIUsage.cost_inr), 0),
        ).first()

        total_calls = int(total_row[0] or 0)
        total_input_tokens = int(total_row[1] or 0)
        total_output_tokens = int(total_row[2] or 0)
        total_tokens = int(total_row[3] or 0)
        total_cost_inr = float(total_row[4] or 0)

        # --------------------------------
        # Breakdown by feature
        # --------------------------------
        feature_rows = (
            q.with_entities(
                AIUsage.feature,
                func.count(AIUsage.id),
                func.coalesce(func.sum(AIUsage.input_tokens), 0),
                func.coalesce(func.sum(AIUsage.output_tokens), 0),
                func.coalesce(func.sum(AIUsage.total_tokens), 0),
                func.coalesce(func.sum(AIUsage.cost_inr), 0),
            )
            .group_by(AIUsage.feature)
            .order_by(func.sum(AIUsage.cost_inr).desc())
            .all()
        )

        by_feature = []
        for feature, cnt, in_tok, out_tok, tot_tok, cost in feature_rows:
            by_feature.append({
                "feature": feature,
                "calls": int(cnt or 0),
                "input_tokens": int(in_tok or 0),
                "output_tokens": int(out_tok or 0),
                "total_tokens": int(tot_tok or 0),
                "cost_inr": float(cost or 0),
            })

        return jsonify({
            "ok": True,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "window_days": days,
            "total": {
                "calls": total_calls,
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
                "total_tokens": total_tokens,
                "cost_inr": total_cost_inr,
            },
            "by_feature": by_feature,
        }), 200

    except Exception as e:
        app.logger.exception("get_usage_summary error")
        return jsonify({"ok": False, "error": str(e)}), 500

from datetime import datetime, timedelta
from flask import jsonify, request
from sqlalchemy import func

@app.route("/api/usage/detailed", methods=["GET"])
def get_usage_detailed():
    """
    Public-ish internal route for the admin dashboard.
    No auth check for now – just returns ai_usage rows.

    Query params:
      - days: lookback window (default 30)
      - user_id: optional filter
      - workspace_id: optional filter
      - limit: max records (default 500)
    """
    try:
        days = request.args.get("days", type=int) or 30
        user_id = request.args.get("user_id", type=int)
        workspace_id = request.args.get("workspace_id", type=int)
        limit = request.args.get("limit", type=int) or 500

        since = datetime.utcnow() - timedelta(days=days)

        q = AIUsage.query.filter(AIUsage.created_at >= since)

        if user_id:
            q = q.filter(AIUsage.user_id == user_id)

        if workspace_id:
            q = q.filter(AIUsage.workspace_id == workspace_id)

        q = q.order_by(AIUsage.created_at.desc()).limit(limit)
        rows = q.all()

        records = []
        for row in rows:
            records.append({
                "id": row.id,
                "created_at": row.created_at.replace(tzinfo=None).isoformat() + "Z",
                "feature": row.feature,
                "model": row.model,
                "input_tokens": row.input_tokens,
                "output_tokens": row.output_tokens,
                "total_tokens": row.total_tokens,
                "cost_inr": float(row.cost_inr or 0),
                "workspace_id": row.workspace_id,
                "user_id": row.user_id,
            })

        return jsonify({"ok": True, "records": records}), 200

    except Exception as e:
        app.logger.exception("get_usage_detailed error")
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        debug_flag = os.getenv("FLASK_ENV", "development") != "production"
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)),debug=True, use_reloader=False)
        
