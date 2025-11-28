# app.py
import os
import uuid
import json
import re
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.sqlite import JSON as SQLITE_JSON

# ---------------- Config ----------------
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'dev.db')}")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ---------------- Helpers ----------------
def now_iso(dt: Optional[datetime] = None):
    if dt is None:
        dt = datetime.utcnow()
    # return naive UTC ISO with Z
    return dt.replace(microsecond=0).isoformat() + "Z"

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

# ---------------- Models ----------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String, unique=True, nullable=True)
    name = db.Column(db.String, nullable=True)

class Objective(db.Model):
    __tablename__ = "objectives"
    id = db.Column(db.String, primary_key=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)
    metaMapping = db.Column(db.String, nullable=True)
    icon = db.Column(db.String, nullable=True)
    color = db.Column(db.String, nullable=True)

class Campaign(db.Model):
    __tablename__ = "campaigns"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=True)
    title = db.Column(db.String, nullable=True)
    objective = db.Column(db.String, nullable=True)
    meta_objective = db.Column(db.String, nullable=True)
    step = db.Column(db.Integer, default=1)
    status = db.Column(db.String, default="DRAFT")
    # Budget
    budget_type = db.Column(db.String, nullable=True)   # daily | lifetime
    budget_amount = db.Column(db.Numeric(12, 2), nullable=True)
    currency = db.Column(db.String(8), default="INR")
    start_date = db.Column(db.DateTime, nullable=True)
    end_date = db.Column(db.DateTime, nullable=True)
    optimization = db.Column(db.String, nullable=True)
    # placements: JSON
    placements = db.Column(SQLITE_JSON, default=lambda: {"automatic": True, "manual": []})
    meta_campaign_id = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

class Audience(db.Model):
    __tablename__ = "audiences"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = db.Column(db.String, db.ForeignKey("campaigns.id"), nullable=False, unique=True)
    mode = db.Column(db.String, default="MANUAL")  # AI | MANUAL
    location = db.Column(SQLITE_JSON, default=lambda: {"country": None, "region": None, "city": None})
    age_min = db.Column(db.Integer, default=18)
    age_max = db.Column(db.Integer, default=65)
    gender = db.Column(db.String, default="all")
    interests = db.Column(SQLITE_JSON, default=list)
    estimate_lower = db.Column(db.Integer, nullable=True)
    estimate_upper = db.Column(db.Integer, nullable=True)
    estimate_updated_at = db.Column(db.DateTime, nullable=True)
    ai_suggestion_id = db.Column(db.String, db.ForeignKey("ai_suggestions.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AISuggestion(db.Model):
    __tablename__ = "ai_suggestions"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = db.Column(db.String, db.ForeignKey("campaigns.id"), nullable=False)
    input_payload = db.Column(SQLITE_JSON)
    suggestion = db.Column(SQLITE_JSON, nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    confidence = db.Column(db.Float, nullable=True)
    status = db.Column(db.String, default="PENDING")   # PENDING | READY | FAILED
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

class Creative(db.Model):
    __tablename__ = "creatives"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = db.Column(db.String, db.ForeignKey("campaigns.id"), nullable=False)
    type = db.Column(db.String, default="IMAGE")  # IMAGE | VIDEO
    image_url = db.Column(db.String, nullable=True)
    preview_image_url = db.Column(db.String, nullable=True)
    primary_text = db.Column(db.Text, default="")
    headline = db.Column(db.String, default="")
    description = db.Column(db.String, default="")
    cta = db.Column(db.String, default="")
    url = db.Column(db.String, default="")
    status = db.Column(db.String, default="PENDING")  # PROCESSING | READY | FAILED
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ObjectiveSuggestion(db.Model):
    __tablename__ = "objective_suggestions"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = db.Column(db.String, db.ForeignKey("campaigns.id"), nullable=True)
    input_payload = db.Column(SQLITE_JSON)
    suggestions = db.Column(SQLITE_JSON, nullable=True)
    status = db.Column(db.String, default="PENDING")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

class CreativeSuggestion(db.Model):
    __tablename__ = "creative_suggestions"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = db.Column(db.String, db.ForeignKey("campaigns.id"), nullable=False)
    creative_id = db.Column(db.String, db.ForeignKey("creatives.id"), nullable=True)
    input_payload = db.Column(SQLITE_JSON)
    candidates = db.Column(SQLITE_JSON, nullable=True)  # list of candidate dicts
    status = db.Column(db.String, default="PENDING")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

# Create DB + seed objectives
with app.app_context():
    db.create_all()
    if Objective.query.count() == 0:
        objs = [
            {"id":"BRAND_AWARENESS","title":"Brand Awareness","description":"Increase awareness of your brand","metaMapping":"BRAND_AWARENESS","icon":"Target","color":"text-primary"},
            {"id":"REACH","title":"Reach","description":"Show your ad to the maximum number of people","metaMapping":"REACH","icon":"Users","color":"text-accent"},
            {"id":"ENGAGEMENT","title":"Engagement","description":"Get more messages, video views, post engagement","metaMapping":"ENGAGEMENT","icon":"Heart","color":"text-pink-500"},
            {"id":"LEAD_GENERATION","title":"Lead Generation","description":"Collect leads for your business","metaMapping":"LEAD_GENERATION","icon":"TrendingUp","color":"text-green-500"},
            {"id":"TRAFFIC","title":"Traffic","description":"Send people to your website or app","metaMapping":"TRAFFIC","icon":"MousePointer","color":"text-blue-500"},
            {"id":"CONVERSIONS","title":"Sales","description":"Drive sales and conversions","metaMapping":"CONVERSIONS","icon":"ShoppingBag","color":"text-orange-500"},
        ]
        for o in objs:
            db.session.add(Objective(**o))
        db.session.commit()

# ---------------- Simple auth stub ----------------
def get_user_from_request(require: bool = False) -> Optional[User]:
    """
    Very small auth stub: returns the first user, creating one if missing.
    Replace with real JWT-based auth in production.
    """
    user = User.query.first()
    if not user:
        user = User(email="demo@example.com", name="Demo User")
        db.session.add(user)
        db.session.commit()
    return user

# ---------------- AI wrapper (fallback-enabled) ----------------
GENAI_CLIENT = None
TEXT_MODEL = "text-model-placeholder"

class GenerateContentConfig:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

def _generate_text_from_prompt(prompt_text: str, model_id: str = TEXT_MODEL, *, response_modalities: List[str] = ["TEXT"], candidate_count: int = 1, timeout_seconds: Optional[int] = None) -> Dict[str, Any]:
    """
    Wrapper to call GENAI text model. If GENAI_CLIENT is None, produce a deterministic fallback.
    """
    if GENAI_CLIENT:
        cfg_kwargs = {
            "response_modalities": response_modalities,
            "candidate_count": max(1, int(candidate_count or 1)),
        }
        cfg = GenerateContentConfig(**cfg_kwargs)
        resp = GENAI_CLIENT.models.generate_content(
            model=model_id,
            contents=[prompt_text],
            config=cfg,
        )
        return resp

    # Local deterministic fallback for dev/testing
    # Heuristic: pick keyword chunks and format candidate text
    tokens = [t.strip(",. ") for t in prompt_text.split() if len(t) > 3][:40]
    primary = " ".join(tokens[:12]) or "Amazing product for customers"
    headline = (tokens[0].title() if tokens else "Limited Offer") + " — Buy Now"
    explanation = f"Generated from prompt: {prompt_text[:200]}"
    content_text = f"{primary}\n\n{headline}\n\n{explanation}"
    return {
        "candidates": [
            {"content": {"text": content_text}, "metadata": {"model": model_id}}
        ],
        "meta": {"fallback": True}
    }

# ---------------- Utility parsers / heuristics ----------------
def serialize_campaign(c: Campaign) -> Dict[str, Any]:
    return {
        "id": c.id,
        "owner_id": c.owner_id,
        "title": c.title,
        "objective": c.objective,
        "meta_objective": c.meta_objective,
        "step": c.step,
        "status": c.status,
        "budget_type": c.budget_type,
        "budget_amount": float(c.budget_amount) if c.budget_amount is not None else None,
        "currency": c.currency,
        "start_date": c.start_date.isoformat()+"Z" if c.start_date else None,
        "end_date": c.end_date.isoformat()+"Z" if c.end_date else None,
        "optimization": c.optimization,
        "placements": c.placements or {"automatic": True, "manual": []},
        "meta_campaign_id": c.meta_campaign_id,
        "created_at": now_iso(c.created_at),
        "updated_at": now_iso(c.updated_at) if c.updated_at else None,
    }

def serialize_audience(a: Audience) -> Dict[str, Any]:
    label = None
    if a.estimate_lower and a.estimate_upper:
        # present more human-friendly label
        def fmt(n):
            if n >= 1_000_000:
                return f"{n//1_000_000}M"
            if n >= 1000:
                return f"{n//1000}K"
            return str(n)
        label = f"{fmt(a.estimate_lower)} - {fmt(a.estimate_upper)}"
    return {
        "id": a.id,
        "campaign_id": a.campaign_id,
        "mode": a.mode,
        "location": a.location or {"country": None},
        "age": [a.age_min, a.age_max],
        "age_min": a.age_min,
        "age_max": a.age_max,
        "gender": a.gender,
        "interests": a.interests or [],
        "estimate": {"lower": a.estimate_lower, "upper": a.estimate_upper, "label": label} if a.estimate_lower else None,
        "estimate_updated_at": now_iso(a.estimate_updated_at) if a.estimate_updated_at else None,
        "ai_suggestion_id": a.ai_suggestion_id
    }

def simple_audience_estimate(location: dict, age: List[int], gender: str, interests: List[str]) -> dict:
    base = 1_000_000
    if location and location.get("country") and location.get("country").lower() == "india":
        base = 1_200_000
    mult = 1.0 + min(0.5, 0.05 * len(interests or []))
    lower = int(base * mult * 0.9)
    upper = int(base * mult * 1.1)
    label = f"{lower//1000}K - {upper//1000}K"
    return {"lower": lower, "upper": upper, "label": label, "method": "heuristic", "calculated_at": now_iso()}

def parse_creative_candidates_from_text(text: str, candidate_count: int = 1) -> List[Dict[str, Any]]:
    """
    Heuristic parser to extract primaryText, headline, description from generated text.
    Prefer instructing model to return JSON in prod.
    """
    blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
    candidates = []
    for i in range(candidate_count):
        block = blocks[i] if i < len(blocks) else (blocks[0] if blocks else text)
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        primary = lines[0][:125] if len(lines) > 0 else block[:125]
        headline = lines[1][:40] if len(lines) > 1 else (primary.split(".")[0][:40])
        description = lines[2][:30] if len(lines) > 2 else primary[:30]
        candidates.append({"primaryText": primary, "headline": headline, "description": description, "score": 0.8})
    return candidates

# ---------------- Upload config ----------------
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ensure_dir(UPLOAD_DIR)

# ---------------- Routes ----------------

# Health
@app.route("/api/v1/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok", "db": "ok", "queue": "local-sync"}), 200

# Objectives
@app.route("/api/v1/objectives", methods=["GET"])
def api_objectives():
    objectives = Objective.query.all()
    result = []
    for o in objectives:
        result.append({
            "id": o.id,
            "title": o.title,
            "description": o.description,
            "metaMapping": o.metaMapping,
            "icon": o.icon,
            "color": o.color
        })
    return jsonify({"success": True, "objectives": result}), 200

# Campaigns
@app.route("/api/v1/campaigns", methods=["POST"])
def api_create_campaign():
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    data = request.get_json() or {}
    campaign = Campaign(
        owner_id=user.id,
        title=data.get("title") or data.get("name") or "Untitled Campaign",
        objective=data.get("objective"),
        meta_objective=data.get("meta_objective") or data.get("objective")
    )
    db.session.add(campaign)
    db.session.commit()
    return jsonify({"success": True, "campaign": serialize_campaign(campaign)}), 201

@app.route("/api/v1/campaigns", methods=["GET"])
def api_list_campaigns():
    user = get_user_from_request(require=False)
    q = Campaign.query
    if user:
        q = q.filter_by(owner_id=user.id)
    items = q.all()
    return jsonify({"success": True, "items": [serialize_campaign(i) for i in items], "total": len(items)}), 200

@app.route("/api/v1/campaigns/<campaign_id>", methods=["GET"])
def api_get_campaign(campaign_id):
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    aud = Audience.query.filter_by(campaign_id=campaign_id).first()
    creatives = Creative.query.filter_by(campaign_id=campaign_id).all()
    data = serialize_campaign(c)
    data["audience"] = serialize_audience(aud) if aud else None
    data["creatives"] = [{
        "id": cr.id, "type": cr.type, "image_url": cr.image_url, "primaryText": cr.primary_text,
        "headline": cr.headline, "description": cr.description, "cta": cr.cta, "url": cr.url, "status": cr.status
    } for cr in creatives]
    return jsonify({"success": True, "campaign": data}), 200

@app.route("/api/v1/campaigns/<campaign_id>/step", methods=["PATCH"])
def api_patch_campaign_step(campaign_id):
    data = request.get_json() or {}
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    step = data.get("step")
    if step is None:
        return jsonify({"success": False, "error": "missing_step"}), 400
    c.step = int(step)
    db.session.commit()
    return jsonify({"success": True, "step": c.step}), 200

# Audience
@app.route("/api/v1/campaigns/<campaign_id>/audience", methods=["GET"])
def api_get_audience(campaign_id):
    a = Audience.query.filter_by(campaign_id=campaign_id).first()
    if not a:
        return jsonify({"success": True, "audience": None}), 200
    return jsonify({"success": True, "audience": serialize_audience(a)}), 200

@app.route("/api/v1/campaigns/<campaign_id>/audience", methods=["PUT"])
def api_put_audience(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    data = request.get_json() or {}
    a = Audience.query.filter_by(campaign_id=campaign_id).first()
    if not a:
        a = Audience(campaign_id=campaign_id)
        db.session.add(a)
    age = data.get("age")
    if isinstance(age, list) and len(age) == 2:
        a.age_min = int(age[0]); a.age_max = int(age[1])
    elif data.get("age_min") is not None and data.get("age_max") is not None:
        a.age_min = int(data.get("age_min")); a.age_max = int(data.get("age_max"))
    a.mode = data.get("mode", a.mode)
    a.location = data.get("location", a.location)
    a.gender = data.get("gender", a.gender)
    interests = data.get("interests")
    if isinstance(interests, str):
        interests = [i.strip() for i in interests.split(",") if i.strip()]
    a.interests = interests or a.interests or []
    a.estimate_updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True, "message": "Audience saved", "audience": serialize_audience(a)}), 200

@app.route("/api/v1/campaigns/<campaign_id>/audience", methods=["PATCH"])
def api_patch_audience(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    data = request.get_json() or {}
    a = Audience.query.filter_by(campaign_id=campaign_id).first()
    if not a:
        return jsonify({"success": False, "error": "audience_not_found"}), 404
    if "age" in data:
        age = data["age"]
        if isinstance(age, list) and len(age) == 2:
            a.age_min = int(age[0]); a.age_max = int(age[1])
    if "location" in data:
        a.location = data["location"]
    if "gender" in data:
        a.gender = data["gender"]
    if "interests" in data:
        inter = data["interests"]
        if isinstance(inter, str):
            inter = [i.strip() for i in inter.split(",") if i.strip()]
        a.interests = inter
    a.estimate_updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True, "audience": serialize_audience(a)}), 200

# AI audience generation (synchronous fallback)
@app.route("/api/v1/campaigns/<campaign_id>/audience/generate", methods=["POST"])
def api_generate_audience(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    payload = request.get_json() or {}
    industry = payload.get("industry") or payload.get("business") or ""
    creative_desc = payload.get("creative_desc") or payload.get("prompt") or ""
    prompt_text = f"Generate audience suggestion for industry: {industry}. Creative: {creative_desc}.\nReturn: location (country/region/city), age range, gender, interests (list), short explanation and confidence (0-1)."
    sug = AISuggestion(campaign_id=campaign_id, input_payload={"industry": industry, "creative_desc": creative_desc})
    db.session.add(sug)
    db.session.commit()
    resp = _generate_text_from_prompt(prompt_text, candidate_count=1)
    suggestion_text = resp.get("candidates", [{}])[0].get("content", {}).get("text", "") if isinstance(resp, dict) else str(resp)
    # Simple heuristic structured suggestion
    suggestion_struct = {
        "location": {"country": "India", "region": "Karnataka", "city": "Bengaluru"},
        "age": [18, 30],
        "gender": "all",
        "interests": ["Sneakers", "Streetwear", "Athleisure"],
    }
    sug.suggestion = suggestion_struct
    sug.explanation = suggestion_text[:200]
    sug.confidence = 0.8
    sug.status = "READY"
    sug.completed_at = datetime.utcnow()
    db.session.commit()
    # Attach to audience
    aud = Audience.query.filter_by(campaign_id=campaign_id).first()
    if not aud:
        aud = Audience(campaign_id=campaign_id)
        db.session.add(aud)
    aud.ai_suggestion_id = sug.id
    db.session.commit()
    return jsonify({"success": True, "suggestion_id": sug.id, "status": sug.status}), 201

@app.route("/api/v1/ai_suggestions/<suggestion_id>", methods=["GET"])
def api_get_ai_suggestion(suggestion_id):
    s = AISuggestion.query.filter_by(id=suggestion_id).first()
    if not s:
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({
        "success": True,
        "id": s.id,
        "campaign_id": s.campaign_id,
        "status": s.status,
        "input_payload": s.input_payload,
        "suggestion": s.suggestion,
        "confidence": s.confidence,
        "explanation": s.explanation,
        "created_at": now_iso(s.created_at),
        "completed_at": now_iso(s.completed_at) if s.completed_at else None
    }), 200

@app.route("/api/v1/campaigns/<campaign_id>/audience/apply_suggestion", methods=["POST"])
def api_apply_suggestion(campaign_id):
    body = request.get_json() or {}
    suggestion_id = body.get("suggestion_id")
    if not suggestion_id:
        return jsonify({"success": False, "error": "missing_suggestion_id"}), 400
    s = AISuggestion.query.filter_by(id=suggestion_id).first()
    if not s or s.status != "READY":
        return jsonify({"success": False, "error": "suggestion_not_ready"}), 400
    aud = Audience.query.filter_by(campaign_id=campaign_id).first()
    if not aud:
        aud = Audience(campaign_id=campaign_id)
        db.session.add(aud)
    sug = s.suggestion or {}
    loc = sug.get("location") or {}
    age = sug.get("age") or [18, 65]
    aud.mode = "AI"
    aud.location = loc
    aud.age_min = int(age[0]); aud.age_max = int(age[1])
    aud.gender = sug.get("gender", aud.gender)
    aud.interests = sug.get("interests", aud.interests)
    aud.ai_suggestion_id = s.id
    db.session.commit()
    return jsonify({"success": True, "audience": serialize_audience(aud)}), 200

@app.route("/api/v1/campaigns/<campaign_id>/audience/estimate", methods=["POST"])
def api_audience_estimate(campaign_id):
    data = request.get_json() or {}
    aud = Audience.query.filter_by(campaign_id=campaign_id).first()
    if not aud and not data:
        return jsonify({"success": False, "error": "no_audience_data"}), 400
    loc = data.get("location") if data.get("location") is not None else (aud.location if aud else {})
    age = data.get("age") if data.get("age") is not None else ([aud.age_min, aud.age_max] if aud else [18, 65])
    gender = data.get("gender") if data.get("gender") is not None else (aud.gender if aud else "all")
    interests = data.get("interests") if data.get("interests") is not None else (aud.interests if aud else [])
    res = simple_audience_estimate(loc, age, gender, interests)
    if aud:
        aud.estimate_lower = res["lower"]
        aud.estimate_upper = res["upper"]
        aud.estimate_updated_at = datetime.utcnow()
        db.session.commit()
    return jsonify({"success": True, "lower": res["lower"], "upper": res["upper"], "label": res["label"], "method": res["method"]}), 200

# ---------------- Budget ----------------
@app.route("/api/v1/campaigns/<campaign_id>/budget", methods=["GET"])
def api_get_budget(campaign_id):
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({"success": True, "budget": {
        "campaign_id": c.id,
        "type": c.budget_type,
        "amount": float(c.budget_amount) if c.budget_amount is not None else None,
        "currency": c.currency,
        "start_date": c.start_date.isoformat()+"Z" if c.start_date else None,
        "end_date": c.end_date.isoformat()+"Z" if c.end_date else None,
        "optimization": c.optimization
    }}), 200

@app.route("/api/v1/campaigns/<campaign_id>/budget", methods=["PUT"])
def api_put_budget(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    data = request.get_json() or {}
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    typ = data.get("type")
    amt = data.get("amount")
    start = data.get("start_date")
    end = data.get("end_date")
    c.budget_type = typ or c.budget_type
    c.budget_amount = float(amt) if amt is not None else c.budget_amount
    c.currency = data.get("currency") or c.currency
    if start:
        # allow ISO string with Z
        c.start_date = datetime.fromisoformat(start.replace("Z", ""))
    if end:
        c.end_date = datetime.fromisoformat(end.replace("Z", ""))
    c.optimization = data.get("optimization") or c.optimization
    if c.budget_type == "daily" and c.budget_amount is not None and float(c.budget_amount) < 100:
        return jsonify({"success": False, "error": "min_daily_budget", "message": "Minimum budget is ₹100 per day"}), 400
    if c.start_date and c.end_date and c.end_date < c.start_date:
        return jsonify({"success": False, "error": "invalid_dates", "message": "end_date must be after start_date"}), 400
    db.session.commit()
    return jsonify({"success": True, "message": "Budget saved", "budget": {
        "type": c.budget_type, "amount": float(c.budget_amount) if c.budget_amount else None,
        "currency": c.currency, "start_date": c.start_date.isoformat()+"Z" if c.start_date else None,
        "end_date": c.end_date.isoformat()+"Z" if c.end_date else None, "optimization": c.optimization
    }}), 200

@app.route("/api/v1/campaigns/<campaign_id>/budget/recommend", methods=["POST"])
def api_budget_recommend(campaign_id):
    c = Campaign.query.filter_by(id=campaign_id).first()
    aud = Audience.query.filter_by(campaign_id=campaign_id).first()
    if aud and aud.estimate_lower:
        rec_daily = max(100, int((aud.estimate_lower / 1_000_000) * 500))
        rec_lifetime = rec_daily * 14
        rationale = f"For estimated audience {aud.estimate_lower}-{aud.estimate_upper}, recommended daily={rec_daily}"
    else:
        rec_daily = 500
        rec_lifetime = rec_daily * 14
        rationale = "Default recommendation based on generic heuristics"
    return jsonify({"success": True, "recommended_daily": rec_daily, "recommended_lifetime": rec_lifetime, "rationale": rationale}), 200

@app.route("/api/v1/campaigns/<campaign_id>/validate_before_launch", methods=["POST"])
def api_validate_before_launch(campaign_id):
    errors = []
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "errors": [{"field":"campaign","message":"Campaign not found"}]}), 404
    if c.budget_type == "daily" and (c.budget_amount is None or float(c.budget_amount) < 100):
        errors.append({"field":"budget.amount","message":"Minimum daily budget is ₹100"})
    if c.start_date and c.end_date and c.end_date < c.start_date:
        errors.append({"field":"budget.dates","message":"Start date must be before end date"})
    creatives = Creative.query.filter_by(campaign_id=campaign_id).all()
    if len(creatives) == 0:
        errors.append({"field":"creatives","message":"At least one creative required"})
    ok = len(errors) == 0
    return jsonify({"success": ok, "valid": ok, "errors": errors}), 200 if ok else 400

# ---------------- Placements ----------------
@app.route("/api/v1/placements", methods=["GET"])
def api_get_placements():
    placements_list = [
        {"id":"facebook_feed","name":"Facebook Feed","description":"Show ads in Facebook News Feed","requires_vertical": False},
        {"id":"instagram_feed","name":"Instagram Feed","description":"Show ads in Instagram Feed","requires_vertical": False},
        {"id":"stories","name":"Stories & Reels","description":"Full-screen vertical ads","requires_vertical": True},
        {"id":"messenger","name":"Messenger","description":"Ads in Messenger conversations","requires_vertical": False},
        {"id":"audience_network","name":"Audience Network","description":"Extend reach to partner apps","requires_vertical": False}
    ]
    return jsonify({"success": True, "placements": placements_list}), 200

@app.route("/api/v1/campaigns/<campaign_id>/placements", methods=["GET"])
def api_get_campaign_placements(campaign_id):
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({"success": True, "placements": c.placements or {"automatic": True, "manual": []}}), 200

@app.route("/api/v1/campaigns/<campaign_id>/placements", methods=["PUT"])
def api_put_campaign_placements(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    data = request.get_json() or {}
    automatic = bool(data.get("automatic", False))
    manual = data.get("manual", [])
    if not automatic and (not isinstance(manual, list) or len(manual) == 0):
        return jsonify({"success": False, "error": "no_placements", "message": "Please select at least one placement or use automatic placements"}), 400
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    c.placements = {"automatic": automatic, "manual": manual}
    db.session.commit()
    return jsonify({"success": True, "message": "Placements updated", "placements": c.placements}), 200

# ---------------- Creatives ----------------
@app.route("/api/v1/campaigns/<campaign_id>/creatives", methods=["GET"])
def api_get_creatives(campaign_id):
    cs = Creative.query.filter_by(campaign_id=campaign_id).all()
    items = [{
        "id": c.id,
        "campaign_id": c.campaign_id,
        "type": c.type,
        "image_url": c.image_url,
        "preview_image_url": c.preview_image_url,
        "primaryText": c.primary_text,
        "headline": c.headline,
        "description": c.description,
        "cta": c.cta,
        "url": c.url,
        "status": c.status
    } for c in cs]
    return jsonify({"success": True, "creatives": items}), 200

@app.route("/uploads/<path:filename>", methods=["GET"])
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route("/api/v1/campaigns/<campaign_id>/creatives", methods=["POST"])
def api_post_creative(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    f = request.files.get("file")
    primaryText = request.form.get("primaryText", "") or request.form.get("primary_text", "")
    headline = request.form.get("headline", "")
    description = request.form.get("description", "")
    cta = request.form.get("cta", "")
    url_field = request.form.get("url", "")
    typ = request.form.get("type", "IMAGE")
    if not f:
        return jsonify({"success": False, "error": "missing_file"}), 400
    filename = f"{uuid.uuid4().hex}_{f.filename}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    f.save(filepath)
    cr = Creative(campaign_id=campaign_id, type=typ, image_url=f"/uploads/{filename}", preview_image_url=f"/uploads/{filename}", primary_text=primaryText, headline=headline, description=description, cta=cta, url=url_field, status="READY")
    db.session.add(cr)
    db.session.commit()
    return jsonify({"success": True, "creative_id": cr.id, "image_url": cr.image_url}), 201

@app.route("/api/v1/campaigns/<campaign_id>/creatives/generate", methods=["POST"])
def api_generate_creative(campaign_id):
    body = request.get_json() or {}
    prompt = body.get("prompt") or ""
    gen = _generate_text_from_prompt(prompt)
    text = gen.get("candidates", [{}])[0].get("content", {}).get("text", "Generated creative")
    cr = Creative(campaign_id=campaign_id, type="IMAGE", image_url=None, preview_image_url=None, primary_text=text[:125], headline=(text[:40]), description=(text[:30]), cta="", url="", status="READY")
    db.session.add(cr)
    db.session.commit()
    return jsonify({"success": True, "creative_id": cr.id, "primaryText": cr.primary_text, "headline": cr.headline}), 201

@app.route("/api/v1/creatives/<creative_id>/autogenerate_copy", methods=["POST"])
def api_autogenerate_copy(creative_id):
    c = Creative.query.filter_by(id=creative_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    body = request.get_json() or {}
    prompt = f"Generate primary text and short headline for: {c.headline or c.primary_text or 'product'}"
    gen = _generate_text_from_prompt(prompt)
    text = gen.get("candidates", [{}])[0].get("content", {}).get("text", "")
    primary = text.strip().split("\n\n")[0][:125]
    headline = text.strip().split("\n\n")[1] if len(text.strip().split("\n\n")) > 1 else text[:40]
    c.primary_text = primary
    c.headline = headline[:40]
    c.description = c.description or (text[:30])
    c.status = "READY"
    db.session.commit()
    return jsonify({"success": True, "creative": {"id": c.id, "primaryText": c.primary_text, "headline": c.headline, "description": c.description}}), 200

# ---------------- Preview & Launch ----------------
@app.route("/api/v1/campaigns/<campaign_id>/preview", methods=["GET"])
def api_campaign_preview(campaign_id):
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    aud = Audience.query.filter_by(campaign_id=campaign_id).first()
    creatives = Creative.query.filter_by(campaign_id=campaign_id).all()
    preview = {
        "campaign": serialize_campaign(c),
        "audience": serialize_audience(aud) if aud else None,
        "budget": {
            "type": c.budget_type, "amount": float(c.budget_amount) if c.budget_amount else None, "currency": c.currency,
            "start_date": c.start_date.isoformat()+"Z" if c.start_date else None, "end_date": c.end_date.isoformat()+"Z" if c.end_date else None,
            "optimization": c.optimization
        },
        "placements": c.placements,
        "creative": {
            "id": creatives[0].id if creatives else None,
            "image_url": creatives[0].image_url if creatives else None,
            "primaryText": creatives[0].primary_text if creatives else None,
            "headline": creatives[0].headline if creatives else None,
            "description": creatives[0].description if creatives else None,
            "cta_label": (creatives[0].cta.replace("_"," ") if creatives and creatives[0].cta else None),
            "destination_url": creatives[0].url if creatives else None
        } if creatives else None,
        "ad_preview": {
            "image_url": creatives[0].preview_image_url if creatives else None,
            "primaryText": creatives[0].primary_text if creatives else None,
            "headline": creatives[0].headline if creatives else None,
            "cta_label": creatives[0].cta if creatives else None,
            "destination_url": creatives[0].url if creatives else None
        } if creatives else None
    }
    return jsonify({"success": True, "preview": preview}), 200

@app.route("/api/v1/campaigns/<campaign_id>/launch", methods=["POST"])
def api_campaign_launch(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    errors = []
    if c.budget_type == "daily" and (c.budget_amount is None or float(c.budget_amount) < 100):
        errors.append({"field":"budget.amount","message":"Minimum daily budget is ₹100"})
    creatives = Creative.query.filter_by(campaign_id=campaign_id).all()
    if len(creatives) == 0:
        errors.append({"field":"creatives","message":"At least one creative required"})
    if errors:
        return jsonify({"success": False, "errors": errors}), 400
    c.meta_campaign_id = f"meta_{uuid.uuid4().hex[:8]}"
    c.status = "LAUNCHED"
    c.step = 7
    db.session.commit()
    return jsonify({"success": True, "job_id": f"job_{uuid.uuid4().hex}", "meta_campaign_id": c.meta_campaign_id}), 202

@app.route("/api/v1/campaigns/<campaign_id>/status", methods=["GET"])
def api_campaign_status(campaign_id):
    c = Campaign.query.filter_by(id=campaign_id).first()
    if not c:
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({"success": True, "campaign_id": c.id, "status": c.status, "meta_campaign_id": c.meta_campaign_id, "last_updated": now_iso(c.updated_at) if c.updated_at else now_iso(c.created_at)}), 200

# ---------------- AI suggestions: objective & creative copy ----------------
@app.route("/api/v1/suggest/objective", methods=["POST"])
def api_suggest_objective():
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    body = request.get_json() or {}
    business = body.get("business", "")
    goal = body.get("goal", "")
    audience_summary = body.get("audience_summary", {})
    campaign_id = body.get("campaign_id")
    prompt = (
        f"Given the business: {business}. Goal: {goal}. Audience: {json.dumps(audience_summary)}.\n"
        "Recommend 3 ad objectives from [BRAND_AWARENESS, REACH, ENGAGEMENT, LEAD_GENERATION, TRAFFIC, CONVERSIONS]. "
        "For each return: objective id, short explanation (1-2 sentences), and confidence 0-1."
    )
    rec = ObjectiveSuggestion(campaign_id=campaign_id, input_payload={"business": business, "goal": goal, "audience_summary": audience_summary})
    db.session.add(rec); db.session.commit()
    gen = _generate_text_from_prompt(prompt, candidate_count=1)
    text = gen.get("candidates", [{}])[0].get("content", {}).get("text", "")
    suggestions = []
    for para in [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()][:5]:
        parts = para.split(":")
        if len(parts) >= 2:
            obj = parts[0].strip().upper()
            rest = ":".join(parts[1:]).strip()
            m = re.search(r"([01](?:\.\d+)?)", rest)
            score = float(m.group(1)) if m else 0.8
            suggestions.append({"objective": obj, "score": round(score, 2), "explanation": rest})
    if not suggestions:
        g = goal.lower()
        if "traffic" in g or "visit" in g or "website" in g:
            suggestions = [{"objective":"TRAFFIC","score":0.8,"explanation":"Goal mentions driving people to website."}]
        elif "sale" in g or "buy" in g or "purchase" in g:
            suggestions = [{"objective":"CONVERSIONS","score":0.9,"explanation":"Goal indicates sales/conversions."}]
        else:
            suggestions = [{"objective":"BRAND_AWARENESS","score":0.7,"explanation":"Default pick for awareness/generic goals."}]
    rec.suggestions = suggestions; rec.status = "READY"; rec.completed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True, "suggestion_id": rec.id, "suggestions": suggestions}), 201

@app.route("/api/v1/objective_suggestions/<suggestion_id>", methods=["GET"])
def api_get_objective_suggestion(suggestion_id):
    s = ObjectiveSuggestion.query.filter_by(id=suggestion_id).first()
    if not s:
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({"success": True, "id": s.id, "status": s.status, "suggestions": s.suggestions, "created_at": now_iso(s.created_at), "completed_at": now_iso(s.completed_at) if s.completed_at else None}), 200

@app.route("/api/v1/campaigns/<campaign_id>/creative/copy/generate", methods=["POST"])
def api_generate_creative_copy(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    body = request.get_json() or {}
    prompt = body.get("prompt", "")
    tone = body.get("tone", "friendly")
    candidate_count = int(body.get("candidate_count", 3))
    cs = CreativeSuggestion(campaign_id=campaign_id, input_payload={"prompt": prompt, "tone": tone, "candidate_count": candidate_count})
    db.session.add(cs); db.session.commit()
    ai_prompt = (f"Create {candidate_count} ad copy candidates in {tone} tone for: {prompt}\n"
                 "For each candidate return primary text (<=125), headline (<=40), description (<=30). Separate by double newlines.")
    resp = _generate_text_from_prompt(ai_prompt, candidate_count=1)
    text = resp.get("candidates", [{}])[0].get("content", {}).get("text", "") or ""
    candidates = parse_creative_candidates_from_text(text, candidate_count=candidate_count)
    cs.candidates = candidates; cs.status = "READY"; cs.completed_at = datetime.utcnow(); db.session.commit()
    return jsonify({"success": True, "suggestion_id": cs.id, "candidates": candidates}), 201

@app.route("/api/v1/creative_suggestions/<suggestion_id>", methods=["GET"])
def api_get_creative_suggestion(suggestion_id):
    s = CreativeSuggestion.query.filter_by(id=suggestion_id).first()
    if not s:
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({"success": True, "id": s.id, "status": s.status, "candidates": s.candidates, "created_at": now_iso(s.created_at), "completed_at": now_iso(s.completed_at) if s.completed_at else None}), 200

@app.route("/api/v1/suggestions/<suggestion_id>/apply", methods=["POST"])
def api_apply_suggestion(suggestion_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    body = request.get_json() or {}
    cs = CreativeSuggestion.query.filter_by(id=suggestion_id).first()
    if cs:
        idx = int(body.get("candidate_index", 0))
        if not cs.candidates or idx >= len(cs.candidates):
            return jsonify({"success": False, "error": "invalid_candidate_index"}), 400
        cand = cs.candidates[idx]
        target_creative_id = body.get("target_id")
        if target_creative_id:
            cr = Creative.query.filter_by(id=target_creative_id).first()
        else:
            cr = Creative(campaign_id=cs.campaign_id, type="IMAGE", status="READY")
            db.session.add(cr)
            db.session.commit()
        cr.primary_text = cand.get("primaryText", cr.primary_text)
        cr.headline = cand.get("headline", cr.headline)
        cr.description = cand.get("description", cr.description)
        cr.status = "READY"
        db.session.commit()
        return jsonify({"success": True, "creative_id": cr.id, "creative": {"id": cr.id, "primaryText": cr.primary_text, "headline": cr.headline, "description": cr.description}}), 200
    osug = ObjectiveSuggestion.query.filter_by(id=suggestion_id).first()
    if osug:
        idx = int(body.get("candidate_index", 0))
        choices = osug.suggestions or []
        if idx >= len(choices):
            return jsonify({"success": False, "error": "invalid_candidate_index"}), 400
        sel = choices[idx]
        if osug.campaign_id:
            c = Campaign.query.filter_by(id=osug.campaign_id).first()
            if c:
                c.objective = sel.get("objective")
                c.meta_objective = sel.get("objective")
                db.session.commit()
                return jsonify({"success": True, "campaign_id": c.id, "applied_objective": sel}), 200
        return jsonify({"success": False, "error": "no_campaign_attached"}), 400
    ais = AISuggestion.query.filter_by(id=suggestion_id).first()
    if ais and ais.suggestion:
        aud = Audience.query.filter_by(campaign_id=ais.campaign_id).first()
        if not aud:
            aud = Audience(campaign_id=ais.campaign_id)
            db.session.add(aud)
        sug = ais.suggestion
        aud.mode = "AI"
        aud.location = sug.get("location", aud.location)
        age = sug.get("age", [aud.age_min, aud.age_max])
        aud.age_min = int(age[0]); aud.age_max = int(age[1])
        aud.gender = sug.get("gender", aud.gender)
        aud.interests = sug.get("interests", aud.interests or [])
        aud.ai_suggestion_id = ais.id
        db.session.commit()
        return jsonify({"success": True, "audience": serialize_audience(aud)}), 200
    return jsonify({"success": False, "error": "suggestion_not_found"}), 404

@app.route("/api/v1/campaigns/<campaign_id>/suggest_all", methods=["POST"])
def api_suggest_all(campaign_id):
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    body = request.get_json() or {}
    business = body.get("business", "")
    goal = body.get("goal", "")
    creative_brief = body.get("creative_brief", "")
    candidate_count = int(body.get("candidate_count", 3))
    # objective
    o_prompt = f"Recommend objectives for business: {business}. Goal: {goal}."
    o_rec = ObjectiveSuggestion(campaign_id=campaign_id, input_payload={"business": business, "goal": goal})
    db.session.add(o_rec); db.session.commit()
    o_gen = _generate_text_from_prompt(o_prompt)
    o_text = o_gen.get("candidates", [{}])[0].get("content", {}).get("text", "")
    o_sugs = []
    for para in [p.strip() for p in re.split(r"\n\s*\n", o_text) if p.strip()][:3]:
        parts = para.split(":")
        obj = parts[0].strip().upper() if parts else "BRAND_AWARENESS"
        score = 0.8
        explanation = para
        o_sugs.append({"objective": obj, "score": score, "explanation": explanation})
    o_rec.suggestions = o_sugs; o_rec.status="READY"; o_rec.completed_at = datetime.utcnow(); db.session.commit()
    # audience
    ais = AISuggestion(campaign_id=campaign_id, input_payload={"industry": business, "creative_brief": creative_brief})
    db.session.add(ais); db.session.commit()
    aud_prompt = f"Generate audience suggestion for industry: {business}. Creative: {creative_brief}."
    aud_gen = _generate_text_from_prompt(aud_prompt)
    aud_text = aud_gen.get("candidates", [{}])[0].get("content", {}).get("text", "")
    aud_struct = {"location": {"country": "India"}, "age": [18,30], "gender": "all", "interests": ["Sneakers","Streetwear"]}
    ais.suggestion = aud_struct; ais.explanation = aud_text[:1000]; ais.confidence = 0.8; ais.status="READY"; ais.completed_at = datetime.utcnow(); db.session.commit()
    # creatives
    cs = CreativeSuggestion(campaign_id=campaign_id, input_payload={"prompt": creative_brief, "candidate_count": candidate_count})
    db.session.add(cs); db.session.commit()
    cr_prompt = f"Create {candidate_count} ad copy candidates for: {creative_brief}"
    cr_gen = _generate_text_from_prompt(cr_prompt)
    cr_text = cr_gen.get("candidates", [{}])[0].get("content", {}).get("text", "")
    cr_cands = parse_creative_candidates_from_text(cr_text, candidate_count)
    cs.candidates = cr_cands; cs.status = "READY"; cs.completed_at = datetime.utcnow(); db.session.commit()
    return jsonify({
        "success": True,
        "objective_suggestion_id": o_rec.id,
        "audience_suggestion_id": ais.id,
        "creative_suggestion_id": cs.id,
        "objective_suggestions": o_sugs,
        "audience_suggestion": ais.suggestion,
        "creative_candidates": cr_cands
    }), 201

# ---------------- Run ----------------
if __name__ == "__main__":
    ensure_dir(UPLOAD_DIR)
    app.run(debug=True, port=int(os.getenv("PORT", 5000)))
