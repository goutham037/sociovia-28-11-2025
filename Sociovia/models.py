from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

from datetime import datetime, timezone

class User(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(30))
    business_name = db.Column(db.String(255))
    industry = db.Column(db.String(120))
    password_hash = db.Column(db.String(256), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(32), default="pending_verification")  # pending_verification, under_review, approved, rejected

    # Verification (email)
    verification_code_hash = db.Column(db.String(256))
    verification_expires_at = db.Column(db.DateTime)

    # OTP (phone) fields — newly added
    phone_otp_hash = db.Column(db.String(512), nullable=True)               # store hashed OTP
    phone_otp_expires_at = db.Column(db.DateTime, nullable=True)           # expiry datetime (UTC-aware preferred)
    phone_last_sent_at = db.Column(db.DateTime, nullable=True)             # when OTP was last sent (for cooldown)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)  # whether phone is verified

    rejection_reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    def __repr__(self):
        return f'<User {self.email}>'

class Admin(db.Model):
    __tablename__ = "admins"
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_superadmin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Admin {self.email}>'

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(255))  # system, admin email, admin_link
    action = db.Column(db.String(64))  # user_signup, email_verified, moved_to_review, approved, rejected
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    meta = db.Column(db.Text)  # JSON string for additional data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.actor}>'
class Workspace(db.Model):
    __tablename__ = "workspaces2"
    __table_args__ = {"extend_existing": True}   # temporary: allows redefinition during debugging

    id = db.Column(db.Integer, primary_key=True)
    # important: reference 'users.id' if your User __tablename__ == 'users'
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    business_name = db.Column(db.String(255), nullable=True)
    business_type = db.Column(db.String(100), nullable=True)
    registered_address = db.Column(db.String(500), nullable=True)
    b2b_b2c = db.Column(db.String(20), nullable=True)
    industry = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    audience_description = db.Column(db.Text, nullable=True)
    website = db.Column(db.String(255), nullable=True)
    competitor_direct_1 = db.Column(db.String(255), nullable=True)
    competitor_direct_2 = db.Column(db.String(255), nullable=True)
    competitor_indirect_1 = db.Column(db.String(255), nullable=True)
    competitor_indirect_2 = db.Column(db.String(255), nullable=True)
    social_links = db.Column(db.Text, nullable=True)  # JSON or CSV
    usp = db.Column(db.Text, nullable=True)
    logo_path = db.Column(db.String(500), nullable=True)
    creatives_path = db.Column(db.String(500), nullable=True)
    remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = db.relationship("User", backref="workspaces2")
    
    
# models.py
class SocialAccount(db.Model):
    __tablename__ = "social_accounts"
    __table_args__ = {"extend_existing": True}
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    provider_user_id = db.Column(db.String(255), nullable=False, index=True)
    account_name = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    access_token = db.Column(db.Text, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)
    profile = db.Column(db.JSON, nullable=True)
    scopes = db.Column(db.String(1024), nullable=True)
    instagram_business_id = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    def serialize(self):
        return {
            "id": self.id,
            "provider": self.provider,
            "provider_user_id": self.provider_user_id,
            "account_name": self.account_name,
            "user_id": self.user_id,
            "access_token": self.access_token,
            "token_expires_at": self.token_expires_at.isoformat() if self.token_expires_at else None,
            "profile": self.profile,
            "scopes": self.scopes,
            "instagram_business_id": self.instagram_business_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


from datetime import date

class AIUsage(db.Model):
    __tablename__ = "ai_usage"

    id = db.Column(db.BigInteger, primary_key=True)

    # Who / where
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces2.id"), nullable=True, index=True)

    # What
    feature = db.Column(db.String(100), nullable=False)       # e.g. "ai_suggest_audience"
    route_path = db.Column(db.String(255), nullable=True)     # e.g. "/api/workspace/<id>/ai-suggest-audience"
    model = db.Column(db.String(100), nullable=False)         # e.g. "gemini-flash-latest"

    # Tokens
    input_tokens = db.Column(db.Integer, nullable=False, default=0)
    output_tokens = db.Column(db.Integer, nullable=False, default=0)
    total_tokens = db.Column(db.Integer, nullable=False, default=0)

    # Money (₹)
    cost_inr = db.Column(db.Numeric(12, 4), nullable=False, default=0)  # up to 999,999,999.9999

    # Meta
    request_id = db.Column(db.String(100), nullable=True)     # trace id / correlation id
    ip_address = db.Column(db.String(45), nullable=True)      # IPv4 / IPv6 as string
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = db.relationship("User", backref=db.backref("ai_usages", lazy="dynamic"))
    workspace = db.relationship("Workspace", backref=db.backref("ai_usages", lazy="dynamic"))

    def __repr__(self):
        return f"<AIUsage user={self.user_id} feature={self.feature} model={self.model} cost_inr={self.cost_inr}>"


class AssistantThread(db.Model):
    __tablename__ = "assistant_threads"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    workspace_id = db.Column(
        db.Integer,
        db.ForeignKey("workspaces2.id"),   # <-- FIXED HERE
        nullable=False,
    )

    # Optional title – you can show this in sidebar like ChatGPT
    title = db.Column(db.String(255))

    summary = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    messages = db.relationship(
        "AssistantMessage",
        backref="thread",
        lazy=True,
        order_by="AssistantMessage.created_at",
        cascade="all, delete-orphan",
    )
    
class AssistantMessage(db.Model):
    __tablename__ = "assistant_messages"

    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey("assistant_threads.id"), nullable=False)


    role = db.Column(db.String(16), nullable=False)


    text = db.Column(db.Text, nullable=False)

    message_type = db.Column(db.String(32))

    
    data_json = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AIUsageDailySummary(db.Model):
    __tablename__ = "ai_usage_daily_summary"

    id = db.Column(db.BigInteger, primary_key=True)

    day = db.Column(db.Date, nullable=False, index=True)     # date (no time)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces2.id"), nullable=True, index=True)
    feature = db.Column(db.String(100), nullable=False)

    total_calls = db.Column(db.Integer, nullable=False, default=0)
    total_input_tokens = db.Column(db.BigInteger, nullable=False, default=0)
    total_output_tokens = db.Column(db.BigInteger, nullable=False, default=0)
    total_tokens = db.Column(db.BigInteger, nullable=False, default=0)
    total_cost_inr = db.Column(db.Numeric(14, 4), nullable=False, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", backref=db.backref("ai_usage_daily", lazy="dynamic"))
    workspace = db.relationship("Workspace", backref=db.backref("ai_usage_daily", lazy="dynamic"))

    __table_args__ = (
        db.UniqueConstraint("day", "user_id", "workspace_id", "feature", name="uq_ai_usage_daily_user_ws_feature_day"),
    )

    def __repr__(self):
        return f"<AIUsageDailySummary day={self.day} user={self.user_id} feature={self.feature} cost={self.total_cost_inr}>"



# models.py (example)

from sqlalchemy.dialects.postgresql import JSONB

class Workflow(db.Model):
    __tablename__ = "workflows"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces2.id"), nullable=False)

    name = db.Column(db.String(255), nullable=False)
    template_id = db.Column(db.String(100), nullable=True)
    json = db.Column(JSONB, nullable=False)          # ReactFlow graph
    schedule_cron = db.Column(db.String(64), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    runs = db.relationship("WorkflowRun", backref="workflow", lazy=True)


class WorkflowRun(db.Model):
    __tablename__ = "workflow_runs"

    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey("workflows.id"), nullable=False)

    started_at = db.Column(db.DateTime, nullable=False)
    finished_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default="success")

    report_json = db.Column(JSONB, nullable=False)   # full exec_report dict

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
