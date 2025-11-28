import os
import re
import json
import random
import logging
from datetime import datetime, timedelta
from flask import Flask, request, render_template, redirect, url_for, jsonify, session, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from sqlalchemy.orm import DeclarativeBase

from config import Config
from models import db, User, Admin, AuditLog
from mailer import send_mail
from tokens import make_action_token, load_action_token
from utils import log_action, valid_password, generate_code, load_email_template

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Load environment variables
load_dotenv()

class Base(DeclarativeBase):
    pass

# Create Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = os.environ.get("SESSION_SECRET", app.config['SECRET_KEY'])
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
CORS(app, resources={r"/*": {"origins": "*"}})
# Initialize database
db.init_app(app)

with app.app_context():
    db.create_all()
    
    # Create default admin if none exists
    if not Admin.query.first():
        admin_email = "admin@sociovia.com"
        admin_password = "admin123"  # Change this in production
        admin = Admin(
            email=admin_email,
            password_hash=generate_password_hash(admin_password),
            is_superadmin=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Created default admin: {admin_email} / {admin_password}")

# ---------- Public Routes ----------

@app.route("/")
def home():
    return redirect(url_for("signup"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # Get form data
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        business_name = request.form.get("business_name", "").strip()
        industry = request.form.get("industry", "").strip()
        password = request.form.get("password", "")
        
        # Validation
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
            
        # Check if email already exists
        if email and User.query.filter_by(email=email).first():
            errors.append("Email already registered")
            
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("signup.html")
            
        # Create user
        verification_code = generate_code()
        user = User(
            name=name,
            email=email,
            phone=phone,
            business_name=business_name,
            industry=industry,
            password_hash=generate_password_hash(password),
            verification_code_hash=generate_password_hash(verification_code),
            verification_expires_at=datetime.utcnow() + timedelta(minutes=app.config['VERIFY_TTL_MIN'])
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log action
        log_action("system", "user_signup", user.id, {"email": email})
        
        # Send verification email
        try:
            email_body = load_email_template("user_verify.txt", {
                "name": name,
                "code": verification_code
            })
            send_mail(email, "Verify your Sociovia account", email_body)
            
            session['pending_email'] = email
            flash("Verification code sent to your email", "success")
            return redirect(url_for("verify_email"))
            
        except Exception as e:
            print(f"Failed to send email: {e}")
            flash("Account created but failed to send verification email. Please contact support.", "warning")
            
    return render_template("signup.html")

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        code = request.form.get("code", "").strip()
        
        if not email or not code:
            flash("Email and verification code are required", "error")
            return render_template("verify_email.html")
            
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("User not found", "error")
            return render_template("verify_email.html")
            
        if user.email_verified:
            flash("Email already verified", "info")
            return redirect(url_for("under_review"))
            
        if not user.verification_code_hash:
            flash("No verification code found", "error")
            return render_template("verify_email.html")
            
        if user.verification_expires_at < datetime.utcnow():
            flash("Verification code has expired", "error")
            return render_template("verify_email.html")
            
        if not check_password_hash(user.verification_code_hash, code):
            flash("Invalid verification code", "error")
            return render_template("verify_email.html")
            
        # Verification successful
        user.email_verified = True
        user.status = "under_review"
        user.verification_code_hash = None
        user.verification_expires_at = None
        db.session.commit()
        
        # Log action
        log_action("system", "email_verified", user.id)
        log_action("system", "moved_to_review", user.id)
        
        # Send admin notification
        try:
            admin_emails = app.config['ADMIN_EMAILS']
            if admin_emails:
                # Create action tokens
                approve_token = make_action_token({
                    "user_id": user.id,
                    "action": "approve",
                    "issued_at": datetime.utcnow().isoformat()
                })
                reject_token = make_action_token({
                    "user_id": user.id,
                    "action": "reject",
                    "issued_at": datetime.utcnow().isoformat()
                })
                
                email_body = load_email_template("admin_notify.txt", {
                    "name": user.name,
                    "email": user.email,
                    "business_name": user.business_name,
                    "industry": user.industry,
                    "approve_url": f"{app.config['APP_BASE_URL']}/admin/action?token={approve_token}",
                    "reject_url": f"{app.config['APP_BASE_URL']}/admin/action?token={reject_token}"
                })
                
                send_mail(admin_emails, f"New account to review – {user.business_name}", email_body)
                
        except Exception as e:
            print(f"Failed to send admin notification: {e}")
            
        session.pop('pending_email', None)
        return redirect(url_for("under_review"))
        
    # Pre-fill email from session
    email = session.get('pending_email', '')
    return render_template("verify_email.html", email=email)

@app.route("/under-review")
def under_review():
    return render_template("under_review.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        if not email or not password:
            flash("Email and password are required", "error")
            return render_template("login.html")
            
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password", "error")
            return render_template("login.html")
            
        if user.status != "approved":
            if user.status == "pending_verification":
                flash("Please verify your email first", "warning")
                return redirect(url_for("verify_email"))
            elif user.status == "under_review":
                flash("Your account is still under review", "info")
                return redirect(url_for("under_review"))
            elif user.status == "rejected":
                flash("Your account has been rejected", "error")
                return render_template("login.html")
                
        session['user_id'] = user.id
        flash("Login successful", "success")
        return redirect(url_for("dashboard"))
        
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for("login"))
        
    user = User.query.get(session['user_id'])
    if not user or user.status != "approved":
        session.pop('user_id', None)
        return redirect(url_for("login"))
        
    return render_template("dashboard.html", user=user)

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))

@app.route("/resend-code", methods=["POST"])
def resend_code():
    email = request.form.get("email", "").strip().lower()
    
    if not email:
        flash("Email is required", "error")
        return redirect(url_for("verify_email"))
        
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found", "error")
        return redirect(url_for("verify_email"))
        
    if user.email_verified:
        flash("Email already verified", "info")
        return redirect(url_for("under_review"))
        
    # Generate new code
    verification_code = generate_code()
    user.verification_code_hash = generate_password_hash(verification_code)
    user.verification_expires_at = datetime.utcnow() + timedelta(minutes=app.config['VERIFY_TTL_MIN'])
    db.session.commit()
    
    # Send email
    try:
        email_body = load_email_template("user_verify.txt", {
            "name": user.name,
            "code": verification_code
        })
        send_mail(email, "Verify your Sociovia account", email_body)
        flash("New verification code sent", "success")
        
    except Exception as e:
        print(f"Failed to send email: {e}")
        flash("Failed to send verification code", "error")
        
    return redirect(url_for("verify_email"))

# ---------- Admin Routes ----------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        if not email or not password:
            flash("Email and password are required", "error")
            return render_template("admin/login.html")
            
        admin = Admin.query.filter_by(email=email).first()
        if not admin or not check_password_hash(admin.password_hash, password):
            flash("Invalid credentials", "error")
            return render_template("admin/login.html")
            
        session['admin_id'] = admin.id
        return redirect(url_for("admin_review"))
        
    return render_template("admin/login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop('admin_id', None)
    return redirect(url_for("admin_login"))

@app.route("/admin/review")
def admin_review():
    if 'admin_id' not in session:
        return redirect(url_for("admin_login"))
        
    users = User.query.filter_by(status="under_review").order_by(User.created_at.desc()).all()
    return render_template("admin/review.html", users=users)

@app.route("/admin/approve/<int:user_id>", methods=["POST"])
def admin_approve_user(user_id):
    if 'admin_id' not in session:
        return redirect(url_for("admin_login"))
        
    admin = Admin.query.get(session['admin_id'])
    user = User.query.get_or_404(user_id)
    
    if not admin:
        flash("Admin not found", "error")
        return redirect(url_for("admin_login"))
    
    if user.status != "under_review":
        flash("User is not in review status", "error")
        return redirect(url_for("admin_review"))
        
    user.status = "approved"
    db.session.commit()
    
    # Log action
    log_action(admin.email, "approved", user.id)
    
    # Send approval email
    try:
        email_body = load_email_template("user_approved.txt", {
            "name": user.name
        })
        send_mail(user.email, "Your Sociovia account is approved", email_body)
    except Exception as e:
        print(f"Failed to send approval email: {e}")
        
    flash(f"User {user.name} has been approved", "success")
    return redirect(url_for("admin_review"))

@app.route("/admin/reject/<int:user_id>", methods=["POST"])
def admin_reject_user(user_id):
    if 'admin_id' not in session:
        return redirect(url_for("admin_login"))
        
    admin = Admin.query.get(session['admin_id'])
    user = User.query.get_or_404(user_id)
    reason = request.form.get("reason", "").strip()
    
    if not admin:
        flash("Admin not found", "error")
        return redirect(url_for("admin_login"))
    
    if user.status != "under_review":
        flash("User is not in review status", "error")
        return redirect(url_for("admin_review"))
        
    if not reason:
        flash("Rejection reason is required", "error")
        return redirect(url_for("admin_review"))
        
    user.status = "rejected"
    user.rejection_reason = reason
    db.session.commit()
    
    # Log action
    log_action(admin.email, "rejected", user.id, {"reason": reason})
    
    # Send rejection email
    try:
        email_body = load_email_template("user_rejected.txt", {
            "name": user.name,
            "reason": reason
        })
        send_mail(user.email, "Update on your Sociovia account", email_body)
    except Exception as e:
        print(f"Failed to send rejection email: {e}")
        
    flash(f"User {user.name} has been rejected", "success")
    return redirect(url_for("admin_review"))

@app.route("/admin/action")
def admin_action():
    token = request.args.get("token")
    if not token:
        abort(400)
        
    try:
        payload = load_action_token(token, app.config['ADMIN_LINK_TTL_HOURS'] * 3600)
        user_id = payload.get("user_id")
        action = payload.get("action")
        reason = payload.get("reason", "Rejected via admin link")
        
        user = User.query.get_or_404(user_id)
        
        if user.status != "under_review":
            return f"Error: User {user.name} is no longer under review", 400
            
        if action == "approve":
            user.status = "approved"
            db.session.commit()
            
            # Log action
            log_action("admin_link", "approved", user.id)
            
            # Send approval email
            try:
                email_body = load_email_template("user_approved.txt", {
                    "name": user.name
                })
                send_mail(user.email, "Your Sociovia account is approved", email_body)
            except Exception as e:
                print(f"Failed to send approval email: {e}")
                
            return f"✅ User {user.name} has been approved successfully!"
            
        elif action == "reject":
            user.status = "rejected"
            user.rejection_reason = reason
            db.session.commit()
            
            # Log action
            log_action("admin_link", "rejected", user.id, {"reason": reason})
            
            # Send rejection email
            try:
                email_body = load_email_template("user_rejected.txt", {
                    "name": user.name,
                    "reason": reason
                })
                send_mail(user.email, "Update on your Sociovia account", email_body)
            except Exception as e:
                print(f"Failed to send rejection email: {e}")
                
            return f"❌ User {user.name} has been rejected"
            
        else:
            abort(400)
            
    except Exception as e:
        print(f"Token validation failed: {e}")
        abort(400)



@app.route("/api/status")
def api_status():
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
        
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user not found"}), 404
        
    return jsonify({"status": user.status})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
