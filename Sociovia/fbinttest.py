# fb_manager_api.py
"""
FB Manager API - exposes /api/* endpoints for the React UI.

Features:
  - Create Campaign -> AdSet -> upload image -> Creative -> Ad
  - List campaigns / adsets / creatives / ads
  - Pause / resume / delete ads
  - Update adset
  - Insights proxy
  - CORS enabled (allow all origins) for dev convenience

Setup:
  pip install flask requests flask-cors
  export FB_ACCESS_TOKEN="EAAZ..." 
  export FB_AD_ACCOUNT_ID="act_XXXXXXXXXXXX"
  export FB_PAGE_ID="1234567890"
  python fb_manager_api.py
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import requests

# ---------------- Config ----------------
FB_API_VERSION = os.getenv("FB_API_VERSION", "v17.0")
FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "EAAZAVAy1umqcBPlzb3eKWh9xtAdafi3nDF9DAu0xrVjSUhTlb2zZB2xV5ZAuLkeiISzSye85SZC3LTwLrsVZAAerce0YOqQllvirE04ihZBIKXfJY3V0h0mZAtMUxGTrQ8CB2qW5Ahkdsv1k8D7nIHcAU73wTApQeq3ZCWvDZAe1umrqjBREvlaqioDn6aYBniJeDSr5KFKgdCdNUiww7vcs8OowYOG4XHRvHaHAS")  # set this
FB_AD_ACCOUNT_ID = os.getenv("FB_AD_ACCOUNT_ID", "act_785545867549907")
FB_PAGE_ID = os.getenv("FB_PAGE_ID", "826620477192551")
DEFAULT_IMAGE_HASH = os.getenv("DEFAULT_IMAGE_HASH", "706094911862292")
MIN_DAILY_BUDGET = int(os.getenv("MIN_DAILY_BUDGET", "10000"))

if not FB_ACCESS_TOKEN:
    logging.warning("FB_ACCESS_TOKEN not set. Set FB_ACCESS_TOKEN env var before using live API calls.")

GRAPH_BASE = f"https://graph.facebook.com/{FB_API_VERSION}"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# allow all origins for development; for prod limit to your domains
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"])

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

def create_adset(ad_account_id: str, campaign_id: str, name: str, daily_budget: int, start_time: str, end_time: str, page_id: str, country: str = "US", status: str = "PAUSED") -> Optional[str]:
    acct = _acct_id(ad_account_id)
    if daily_budget < MIN_DAILY_BUDGET:
        logger.info("bumping daily_budget %s -> %s", daily_budget, MIN_DAILY_BUDGET)
        daily_budget = MIN_DAILY_BUDGET
    params = {
        "name": name,
        "campaign_id": campaign_id,
        "daily_budget": int(daily_budget),
        "billing_event": "IMPRESSIONS",
        "optimization_goal": "LINK_CLICKS",
        "bid_amount": max(1, int(daily_budget // 1000)),
        "promoted_object": json.dumps({"page_id": page_id}),
        "targeting": json.dumps({"geo_locations": {"countries": [country]}}),
        "start_time": start_time,
        "end_time": end_time,
        "status": status
    }
    resp = fb_post(f"act_{acct}/adsets", data=params)
    if "id" in resp:
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
@app.route("/api/creatives", methods=["GET"])
def api_creatives():
    acct = _acct_id(FB_AD_ACCOUNT_ID)
    resp = fb_get(f"act_{acct}/adcreatives", params={"fields": "id,name,object_story_spec"})
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

# Simple convenience route to return "last created" and UI
@app.route("/api/last", methods=["GET"])
def api_last():
    return jsonify(LAST)

# Also provide the minimal manager UI for convenience (same as earlier)
@app.route("/", methods=["GET"])
def index_ui():
    html = "<h1>FB Manager API</h1><p>Use the React UI -> call the /api endpoints.</p><pre>{}</pre>".format(json.dumps({
        "api_campaigns": "/api/campaigns",
        "api_publish": "/api/publish",
        "api_insights": "/api/insights"
    }, indent=2))
    return render_template_string(html)


@app.after_request
def add_cors_headers(response):
    response.headers.setdefault("Access-Control-Allow-Origin", "*")
    response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT")
    response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
    return response

# Optional: explicit OPTIONS handler if you want to ensure 200 for unknown routes:
@app.route('/api/<path:any>', methods=['OPTIONS'])
def options(any):
    # Return 200 with CORS headers — browser preflight will succeed
    resp = app.make_response(('', 200))
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, DELETE, PUT'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return resp
















# ---------------- Run ----------------
if __name__ == "__main__":
    logger.info("Starting FB Manager API on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
