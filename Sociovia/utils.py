import os
import re
import json
import random
from flask import current_app
from models import db, AuditLog


def log_action(actor, action, user_id=None, meta=None):
    """Log an action to the audit trail"""
    log_entry = AuditLog(
        actor=actor,
        action=action,
        user_id=user_id,
        meta=json.dumps(meta or {})
    )
    db.session.add(log_entry)
    db.session.commit()


def valid_password(password: str) -> bool:
    """Validate password meets minimum requirements"""
    if not password:
        return False
    return len(password) >= 8


def generate_code(length=6):
    """Generate random numeric verification code"""
    return "".join(str(random.randint(0, 9)) for _ in range(length))


def load_email_template(template_name, context):
    """Load and render email template with context variables"""
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(base_dir, "templates", "emails", template_name)

        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()

        # Replace {{ key }} (with optional spaces) with context values
        for key, value in context.items():
            pattern = r"\{\{\s*" + re.escape(key) + r"\s*\}\}"
            template_content = re.sub(pattern, str(value), template_content)

        return template_content
    except FileNotFoundError:
        print(f"Email template {template_name} not found at {template_path}")
        return f"Template {template_name} not found"
