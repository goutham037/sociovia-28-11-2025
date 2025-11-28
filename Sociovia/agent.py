# agent_ads_optimizer.py
# --------------------------------------------------------------
#  Ads Optimization Agent – ALWAYS emails sharan1114411@gmail.com
#  Run: python agent_ads_optimizer.py
# --------------------------------------------------------------

import os, json, re, uuid, hmac, hashlib, threading, traceback, logging, random, time, smtplib
from datetime import datetime, timedelta
from urllib.parse import urljoin
from typing import List

import requests
from flask import Flask, request, jsonify, abort
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ---------- CONFIG ----------
FLASK_BASE_URL      = os.getenv("FLASK_BASE_URL", "http://127.0.0.1:5000")
AGENT_API_KEY       = os.getenv("AGENT_API_KEY", "dev-key")
POLL_SECONDS        = int(os.getenv("POLL_SECONDS", "300"))
MAX_ACTIONS_PER_RUN = int(os.getenv("MAX_ACTIONS_PER_RUN", "6"))
DRY_RUN             = os.getenv("DRY_RUN", "true").lower() in ("1","true","yes")
CANARY_PCT          = int(os.getenv("CANARY_PCT", "10"))
COOLDOWN_HOURS      = int(os.getenv("COOLDOWN_HOURS", "6"))
FOLLOWUP_HOURS      = int(os.getenv("FOLLOWUP_HOURS", "6"))

# SMTP – Hardcoded for reliability
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "noreply.sociovia@gmail.com"
SMTP_PASS = "mgvr uwsc eymh prxo"  # ← Your App Password
APPROVER_EMAIL = "sharan1114411@gmail.com"  # ← ALWAYS THIS EMAIL

AGENT_PUBLIC_HOST   = "http://127.0.0.1:8000"
APP_SIGNING_KEY     = os.getenv("APP_SIGNING_KEY", "dev-signing-key")
DATABASE_URL        = "postgresql://dbuser:StrongPasswordHere@34.10.193.3:5432/postgres"

# ---------- LOGGING ----------
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# ---------- DB ----------
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

class ActionLog(Base):
    __tablename__ = "action_logs"
    id                = Column(String, primary_key=True)
    campaign_id       = Column(String, index=True)
    action            = Column(String)
    params            = Column(JSON)
    reason            = Column(String)
    applied           = Column(Boolean, default=False)
    dry_run           = Column(Boolean, default=True)
    created_at        = Column(DateTime, default=datetime.utcnow)
    applied_response  = Column(JSON, nullable=True)
    device_token      = Column(String, nullable=True)

class PendingAction(Base):
    __tablename__ = "pending_actions"
    id          = Column(String, primary_key=True)
    payload     = Column(JSON)
    expires_at  = Column(DateTime)
    created_at  = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ---------- HELPERS ----------
def now_iso(): return datetime.utcnow().isoformat()

def sign_token(campaign_id, action_id, ttl=86400):
    exp = int(time.time()) + ttl
    payload = f"{campaign_id}|{action_id}|{exp}"
    sig = hmac.new(APP_SIGNING_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{exp}:{sig}"

def verify_token(campaign_id, action_id, token):
    try:
        exp, sig = token.split(":")
        if int(exp) < int(time.time()): return False
        expected = hmac.new(APP_SIGNING_KEY.encode(), f"{campaign_id}|{action_id}|{exp}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception: return False

# ---------- EMAIL ----------
def get_approver_email() -> List[str]:
    """Always return sharan1114411@gmail.com"""
    return [APPROVER_EMAIL]

def send_email(subj: str, html: str, to: List[str]):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS): 
        log.warning("[EMAIL] SMTP not configured")
        return False
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subj
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(to)
    msg.attach(MIMEText(html, "html"))
    try:
        s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_USER, to, msg.as_string())
        s.quit()
        log.info(f"[EMAIL SENT] → {', '.join(to)}")
        return True
    except Exception as e:
        log.error(f"[EMAIL_ERR] {e}")
        return False

def approval_email(name, cid, aid, payload):
    approve = f"{AGENT_PUBLIC_HOST}/approve?action=approve&campaign_id={cid}&action_id={aid}&token={sign_token(cid,aid)}"
    reject  = f"{AGENT_PUBLIC_HOST}/approve?action=reject&campaign_id={cid}&action_id={aid}&token={sign_token(cid,aid)}"
    return f"""
    <h3>Approval Required</h3>
    <p><b>{name}</b> (ID: <code>{cid}</code>)</p>
    <p><strong>Action:</strong> {payload['action']} {payload.get('params','')}</p>
    <p><strong>Reason:</strong> {payload.get('reason')} | Conf: {payload.get('conf'):.2f}</p>
    <p>
      <a href="{approve}" style="background:#0b74de;color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;margin-right:8px;">Approve</a>
      <a href="{reject}"  style="background:#e53e3e;color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Reject</a>
    </p>
    <hr><small>Agent: {AGENT_PUBLIC_HOST}</small>
    """

# ---------- MOCK DATA ----------
def generate_gemini_mock_simulation(variety="balanced", num_rows=5):
    mul = {"low": 0.3, "high": 2.0, "balanced": 1.0}.get(variety, 1.0)
    rows = []
    for i in range(num_rows):
        imp = int(10000 * mul * (1 + random.uniform(-0.2, 0.2)))
        rows.append({
            "campaign_id": f"sim_{i+1}",
            "campaign_name": f"Sim Campaign {i+1}",
            "impressions": imp,
            "clicks": max(1, int(imp * random.uniform(0.01, 0.05))),
            "spend": round(random.uniform(imp * 0.005, imp * 0.02), 2),
            "roas": round(random.uniform(0.5, 3.5), 2),
            "conversions": random.randint(0, 12),
            "frequency": round(random.uniform(1.0, 6.0), 2),
            "ctr": round(random.uniform(0.5, 5.0), 2),
            "daily_budget": round(random.uniform(50, 300), 2),
            "spend_today": round(random.uniform(30, 280), 2)
        })
    return {"metrics_rows": rows}

THRESH = {
    "min_imp": 1000, "ctr_pause": 0.5, "freq_max": 6,
    "roas_scale": 2.0, "scale_pct": 20, "budget_overrun": 1.2,
    "high_impact_pct": 20
}

def decide_action_for_campaign(c):
    imp = c.get("impressions", 0)
    ctr = c.get("ctr", 0)
    roas = c.get("roas", 0)
    freq = c.get("frequency", 0)
    conv = c.get("conversions", 0)
    spend = c.get("spend_today", 0)
    budget = c.get("daily_budget", 0)

    if freq >= THRESH["freq_max"] and imp > 500:
        return {"action": "pause", "reason": "high_freq", "confidence": 0.97, "params": {}, "needsApproval": False}

    if imp >= THRESH["min_imp"] and ctr < THRESH["ctr_pause"] and conv == 0:
        return {"action": "pause", "reason": "low_ctr", "confidence": 0.95, "params": {}, "needsApproval": False}

    if budget > 0 and spend > budget * THRESH["budget_overrun"]:
        return {"action": "decrease_budget", "reason": "overspend", "confidence": 0.9, "params": {"pct": 20}, "needsApproval": False}

    if roas >= THRESH["roas_scale"] and conv >= 3:
        pct = THRESH["scale_pct"]
        needs_approval = pct >= THRESH["high_impact_pct"]
        return {
            "action": "increase_budget",
            "reason": "high_roas",
            "confidence": 0.85,
            "params": {"pct": pct, "canary_pct": 10},
            "needsApproval": needs_approval
        }
    return None

# ---------- API CALLS ----------
def apply_via_api(item, dry=DRY_RUN):
    url = urljoin(FLASK_BASE_URL, "/api/campaigns/action")
    headers = {"Content-Type": "application/json", "X-API-KEY": AGENT_API_KEY}
    body = {k: item.get(k) for k in ["campaign_id", "action", "params", "reason", "dry_run"]}
    body["dry_run"] = dry
    try:
        r = requests.post(url, json=body, headers=headers, timeout=15)
        return {"ok": r.ok, "code": r.status_code, "txt": r.text}
    except Exception as e:
        return {"ok": False, "txt": str(e)}

# ---------- FLASK APP ----------
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/approve": {"origins": "*"}})

@app.route("/approve", methods=["GET"])
def approve():
    a = request.args.get("action")
    cid = request.args.get("campaign_id")
    aid = request.args.get("action_id")
    tok = request.args.get("token")
    if not all([a, cid, aid, tok]): abort(400)
    if not verify_token(cid, aid, tok): return "Invalid token", 403
    pa = session.query(PendingAction).filter(PendingAction.id == aid).first()
    if not pa: return "Not found or expired", 404
    payload = pa.payload
    if a == "approve":
        resp = apply_via_api(payload, DRY_RUN)
        alog = session.query(ActionLog).filter(ActionLog.id == aid).first()
        if alog:
            alog.applied = (not DRY_RUN and resp.get("ok"))
            alog.applied_response = resp
            session.add(alog); session.commit()
        session.delete(pa); session.commit()
        return "Approved & applied", 200
    if a == "reject":
        alog = session.query(ActionLog).filter(ActionLog.id == aid).first()
        if alog:
            alog.applied = False
            alog.applied_response = {"rejected": True}
            session.add(alog); session.commit()
        session.delete(pa); session.commit()
        return "Rejected", 200
    abort(400)

# ---------- SIMULATE + AUTO EMAIL ----------
@app.route("/api/simulate", methods=["GET"])
def simulate():
    try:
        rows = int(request.args.get("rows", 5))
        variety = request.args.get("variety", "balanced")

        mock = generate_gemini_mock_simulation(variety=variety, num_rows=rows)
        sim_rows = mock["metrics_rows"]
        decisions = []
        queued = 0

        for i, c in enumerate(sim_rows):
            d = decide_action_for_campaign(c) or {}
            decisions.append({
                "action": d.get("action", "none"),
                "reason": d.get("reason", ""),
                "conf": d.get("confidence", 0),
                "params": d.get("params", {}),
                "needs_approval": d.get("needsApproval", False)
            })

            if not d.get("needsApproval", False):
                continue

            aid = hashlib.sha1(f"{c['campaign_id']}|{time.time()+i}".encode()).hexdigest()
            item = {
                "campaign_id": c["campaign_id"],
                "action": d["action"],
                "params": d["params"],
                "reason": d["reason"],
                "conf": d["confidence"],
                "impact": "high",
                "needs_approval": True,
                "metrics": c
            }

            alog = ActionLog(id=aid, campaign_id=c["campaign_id"], action=d["action"],
                             params=d["params"], reason=d["reason"], dry_run=DRY_RUN)
            session.add(alog)
            pa = PendingAction(id=aid, payload=item, expires_at=datetime.utcnow() + timedelta(hours=24))
            session.add(pa)
            session.commit()

            html = approval_email(c["campaign_name"], c["campaign_id"], aid, item)
            send_email(f"[SIM] Approve: {d['action']} {c['campaign_id']}", html, get_approver_email())
            queued += 1

        return jsonify({
            "rows": sim_rows,
            "decisions": decisions,
            "queued_for_approval": queued,
            "email_sent_to": APPROVER_EMAIL
        })

    except Exception as e:
        log.error(f"[SIMULATE ERROR] {e}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# ---------- MANUAL ACTION ----------
@app.route("/api/add-action", methods=["POST"])
def add_action():
    data = request.get_json() or {}
    if "campaign_id" not in data or "action" not in data:
        return jsonify({"error": "missing campaign_id or action"}), 400

    item = {
        "campaign_id": data["campaign_id"],
        "action": data["action"],
        "params": data.get("params", {}),
        "reason": data.get("reason", "manual"),
        "conf": data.get("confidence", 0.99),
        "needs_approval": data.get("needs_approval", True),  # ← Force approval
        "metrics": data.get("metrics", {})
    }

    aid = hashlib.sha1(f"{item['campaign_id']}|{time.time()}".encode()).hexdigest()
    alog = ActionLog(id=aid, campaign_id=item["campaign_id"], action=item["action"],
                     params=item["params"], reason=item["reason"], dry_run=DRY_RUN)
    session.add(alog); session.commit()

    if item["needs_approval"]:
        pa = PendingAction(id=aid, payload=item, expires_at=datetime.utcnow() + timedelta(hours=24))
        session.add(pa); session.commit()
        html = approval_email(item["metrics"].get("campaign_name", item["campaign_id"]), item["campaign_id"], aid, item)
        send_email(f"[MANUAL] Approve: {item['action']}", html, get_approver_email())
        return jsonify({"status": "pending", "action_id": aid}), 202
    else:
        resp = apply_via_api(item, DRY_RUN)
        alog.applied = (not DRY_RUN and resp.get("ok"))
        alog.applied_response = resp
        session.add(alog); session.commit()
        return jsonify({"status": "applied", "response": resp}), 200

# ---------- PENDING / LOGS ----------
@app.route("/api/pending", methods=["GET"])
def list_pending():
    pend = session.query(PendingAction).all()
    return jsonify([{
        "id": p.id,
        "campaign_id": p.payload.get("campaign_id"),
        "action": p.payload.get("action"),
        "created": p.created_at.isoformat()
    } for p in pend])

@app.route("/api/logs", methods=["GET"])
def list_logs():
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 20))
    logs = session.query(ActionLog).order_by(ActionLog.created_at.desc()).offset((page-1)*size).limit(size).all()
    return jsonify([{
        "id": l.id, "campaign_id": l.campaign_id, "action": l.action,
        "applied": l.applied, "reason": l.reason, "created": l.created_at.isoformat()
    } for l in logs])

@app.route("/test-email", methods=["GET"])
def test_email():
    sent = send_email(
        "TEST EMAIL – Ads Agent",
        "<h2>SMTP Works!</h2><p>This is a test from your agent.</p>",
        get_approver_email()
    )
    return jsonify({"sent": sent, "to": APPROVER_EMAIL})

# ---------- REQUIRED ENDPOINTS ----------
@app.route("/api/campaigns/action", methods=["POST"])
def apply_action():
    data = request.get_json() or {}
    log.info(f"[MAIN APP] Action: {data}")
    return jsonify({"success": True, "message": "Action applied", "received": data})

@app.route("/api/campaigns/metrics", methods=["POST"])
def get_metrics():
    return jsonify({"campaigns": [{
        "campaign_id": "c123", "campaign_name": "Test Campaign",
        "impressions": 5000, "clicks": 120, "spend_today": 85.0,
        "daily_budget": 100.0, "roas": 2.8, "conversions": 5,
        "frequency": 3.2, "ctr": 2.4
    }]})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": now_iso(), "dry_run": DRY_RUN})

# ---------- SCHEDULER ----------
scheduler = BackgroundScheduler()
scheduler.add_job(lambda: None, "interval", seconds=POLL_SECONDS, id="agent_run")  # placeholder
scheduler.start()

if __name__ == "__main__":
    log.info(f"[STARTUP] Agent running on {AGENT_PUBLIC_HOST}")
    log.info(f"[EMAIL] All approvals → {APPROVER_EMAIL}")
    app.run(host="0.0.0.0", port=8000, debug=False)