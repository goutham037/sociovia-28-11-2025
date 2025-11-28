# fb_manager_full.py
"""
Full FB sandbox manager + publish Flask app.

Features:
- Create campaign -> adset -> upload image -> creative -> ad
- Upload image by URL or file (returns image hash)
- List campaigns / adsets / creatives / ads
- Pause / resume / delete objects
- Update adset fields (daily_budget, end_time)
- Insights endpoint
- Simple UI to view/manage and run actions from browser
- Optional AI suggest endpoint (calls _generate_text_from_prompt if you wire it in)

Requirements:
  pip install flask requests
Run:
  export FB_ACCESS_TOKEN="..."   # or set in script defaults
  python fb_manager_full.py
"""
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify, render_template_string
import requests
import flask_cors
from flask_cors import CORS

# ---------------- Config ----------------
FB_API_VERSION = os.getenv("FB_API_VERSION", "v17.0")
FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "EAAZAVAy1umqcBPlzb3eKWh9xtAdafi3nDF9DAu0xrVjSUhTlb2zZB2xV5ZAuLkeiISzSye85SZC3LTwLrsVZAAerce0YOqQllvirE04ihZBIKXfJY3V0h0mZAtMUxGTrQ8CB2qW5Ahkdsv1k8D7nIHcAU73wTApQeq3ZCWvDZAe1umrqjBREvlaqioDn6aYBniJeDSr5KFKgdCdNUiww7vcs8OowYOG4XHRvHaHAS")  # set this
FB_AD_ACCOUNT_ID = os.getenv("FB_AD_ACCOUNT_ID", "act_785545867549907")
FB_PAGE_ID = os.getenv("FB_PAGE_ID", "826620477192551")
DEFAULT_IMAGE_HASH = os.getenv("DEFAULT_IMAGE_HASH", "706094911862292")
MIN_DAILY_BUDGET = int(os.getenv("MIN_DAILY_BUDGET", "10000"))

GRAPH_BASE = f"https://graph.facebook.com/{FB_API_VERSION}"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) 

# keep most-recent objects for UI convenience
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
        return {"error": str(e), "raw": getattr(e, "response", None) and e.response.text}

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
        # Graph API returns JSON with {"success": true} for deletes
        return r.json()
    except Exception as e:
        logger.exception("FB DELETE %s failed: %s", path, e)
        return {"error": str(e)}

# ---------------- FB helpers ----------------
def upload_image_by_url(ad_account_id: str, image_url: str) -> Optional[str]:
    logger.info("Uploading image by URL: %s", image_url)
    acct = ad_account_id.split("act_")[-1]
    resp = fb_post(f"act_{acct}/adimages", data={"url": image_url})
    if "images" in resp:
        for v in resp["images"].values():
            if "hash" in v:
                logger.info("image hash: %s", v["hash"])
                return v["hash"]
    logger.warning("upload_by_url failed: %s", resp)
    return None

def upload_image_file(ad_account_id: str, file_field) -> Optional[str]:
    logger.info("Uploading image file via multipart: %s", getattr(file_field, "filename", None))
    acct = ad_account_id.split("act_")[-1]
    files = {"source": (file_field.filename, file_field.stream, file_field.mimetype)}
    resp = fb_post(f"act_{acct}/adimages", data={}, files=files)
    if "images" in resp:
        for v in resp["images"].values():
            if "hash" in v:
                logger.info("image hash: %s", v["hash"])
                return v["hash"]
    logger.warning("upload_file failed: %s", resp)
    return None

def create_campaign(ad_account_id: str, name: str, objective: str = "OUTCOME_TRAFFIC", status: str = "PAUSED") -> Optional[str]:
    acct = ad_account_id.split("act_")[-1]
    resp = fb_post(f"act_{acct}/campaigns", data={"name": name, "objective": objective, "status": status, "special_ad_categories": json.dumps([])})
    if "id" in resp:
        return resp["id"]
    logger.warning("create_campaign failed: %s", resp)
    return None

def create_adset(ad_account_id: str, campaign_id: str, name: str, daily_budget: int, start_time: str, end_time: str, page_id: str, country: str = "US", status: str = "PAUSED") -> Optional[str]:
    acct = ad_account_id.split("act_")[-1]
    if daily_budget < MIN_DAILY_BUDGET:
        logger.info("bumping budget %s -> %s", daily_budget, MIN_DAILY_BUDGET)
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
        "status": status,
    }
    resp = fb_post(f"act_{acct}/adsets", data=params)
    if "id" in resp:
        return resp["id"]
    logger.warning("create_adset failed: %s", resp)
    return None

def create_adcreative(ad_account_id: str, page_id: str, image_hash: str, link: str, message: str, name: str = "Auto Creative") -> Optional[str]:
    acct = ad_account_id.split("act_")[-1]
    object_story_spec = {"page_id": page_id, "link_data": {"image_hash": image_hash, "link": link, "message": message}}
    resp = fb_post(f"act_{acct}/adcreatives", data={"name": name, "object_story_spec": json.dumps(object_story_spec)})
    if "id" in resp:
        return resp["id"]
    logger.warning("create_adcreative failed: %s", resp)
    return None

def create_ad(ad_account_id: str, adset_id: str, creative_id: str, name: str = "Auto Ad", status: str = "PAUSED") -> Optional[str]:
    acct = ad_account_id.split("act_")[-1]
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
        logger.exception("fetch_insights failed: %s", e)
        return {"error": str(e)}

# ---------------- Management / CRUD endpoints ----------------
@app.route("/", methods=["GET"])
def index_ui():
    """Simple UI to manage sandbox objects."""
    html = """
    <!doctype html><html><head><meta charset="utf-8"><title>FB Manager</title>
    <style>body{font-family:Arial;margin:18px;max-width:1000px}label{display:block;margin-top:8px}input,select,textarea{width:100%;padding:6px;margin-top:4px}button{padding:8px 12px;margin-top:8px}</style></head>
    <body>
    <h1>FB Sandbox Manager</h1>
    <p>Ad Account: <strong>{{ad_account}}</strong> | Page: <strong>{{page}}</strong></p>
    <section>
      <h2>Create (Publish) Campaign → AdSet → Creative → Ad</h2>
      <form id="publishForm" enctype="multipart/form-data">
        <label>Image URL (optional)</label><input name="image_url" />
        <label>or Upload Image File</label><input type="file" name="image_file" />
        <label>Campaign name</label><input name="campaign_name" value="Sandbox Campaign UI" />
        <label>AdSet name</label><input name="adset_name" value="Sandbox AdSet UI" />
        <label>Ad name</label><input name="ad_name" value="Sandbox Ad UI" />
        <label>Link</label><input name="link" value="https://www.sociovia.com" />
        <label>Message</label><textarea name="message">Check this out!</textarea>
        <div style="display:flex;gap:8px"><div style="flex:1"><label>Start In Days</label><input name="start_in_days" value="0"/></div><div style="flex:1"><label>Duration Days</label><input name="duration_days" value="2"/></div></div>
        <label>Daily budget (smallest unit)</label><input name="daily_budget" value="100000" />
        <button type="button" onclick="publish()">Publish (create)</button>
      </form>
      <pre id="publishOut">--</pre>
    </section>

    <section>
      <h2>List & Manage</h2>
      <div style="display:flex;gap:10px">
        <div style="flex:1">
          <h3>Campaigns</h3>
          <button onclick="listCampaigns()">Refresh campaigns</button>
          <ul id="campaignList"></ul>
        </div>
        <div style="flex:1">
          <h3>AdSets</h3>
          <button onclick="listAdSets()">Refresh adsets</button>
          <ul id="adsetList"></ul>
        </div>
        <div style="flex:1">
          <h3>Creatives</h3>
          <button onclick="listCreatives()">Refresh creatives</button>
          <ul id="creativeList"></ul>
        </div>
        <div style="flex:1">
          <h3>Ads</h3>
          <button onclick="listAds()">Refresh ads</button>
          <ul id="adList"></ul>
        </div>
      </div>
    </section>

    <section>
      <h2>Insights</h2>
      <label>Level</label><input id="ins_level" value="campaign" />
      <label>Object ID (for campaign/adset/ad)</label><input id="ins_obj" placeholder="object id" />
      <label>Fields (comma separated)</label><input id="ins_fields" placeholder="impressions,clicks,spend" />
      <button onclick="getInsights()">Get Insights</button>
      <pre id="insOut">--</pre>
    </section>

    <script>
      async function publish(){
        const form = document.getElementById('publishForm');
        const fd = new FormData(form);
        document.getElementById('publishOut').innerText = 'Publishing...';
        try{
          const res = await fetch('/publish', {method:'POST', body: fd});
          const j = await res.json();
          document.getElementById('publishOut').innerText = JSON.stringify(j,null,2);
        }catch(e){
          document.getElementById('publishOut').innerText = 'Error: '+e;
        }
      }

      async function listCampaigns(){
        const r = await fetch('/list/campaigns');
        const j = await r.json();
        const ul = document.getElementById('campaignList');
        ul.innerHTML = '';
        (j.data||[]).forEach(c => {
          const li = document.createElement('li');
          li.innerText = c.id + ' | ' + (c.name || '');
          li.innerHTML += ' <button onclick="manageObj(\\'campaign\\',\\''+c.id+'\\',\\'pause\\')">Pause</button>';
          li.innerHTML += ' <button onclick="manageObj(\\'campaign\\',\\''+c.id+'\\',\\'resume\\')">Resume</button>';
          li.innerHTML += ' <button onclick="deleteObj(\\'campaign\\',\\''+c.id+'\\')">Delete</button>';
          ul.appendChild(li);
        });
      }

      async function listAdSets(){
        const r = await fetch('/list/adsets');
        const j = await r.json();
        const ul = document.getElementById('adsetList');
        ul.innerHTML = '';
        (j.data||[]).forEach(a => {
          const li = document.createElement('li');
          li.innerText = a.id + ' | ' + (a.name || '');
          li.innerHTML += ' <button onclick="manageObj(\\'adset\\',\\''+a.id+'\\',\\'pause\\')">Pause</button>';
          li.innerHTML += ' <button onclick="manageObj(\\'adset\\',\\''+a.id+'\\',\\'resume\\')">Resume</button>';
          li.innerHTML += ' <button onclick="deleteObj(\\'adset\\',\\''+a.id+'\\')">Delete</button>';
          ul.appendChild(li);
        });
      }

      async function listCreatives(){
        const r = await fetch('/list/creatives');
        const j = await r.json();
        const ul = document.getElementById('creativeList');
        ul.innerHTML = '';
        (j.data||[]).forEach(c => {
          const li = document.createElement('li');
          li.innerText = c.id + ' | ' + (c.name||'');
          ul.appendChild(li);
        });
      }

      async function listAds(){
        const r = await fetch('/list/ads');
        const j = await r.json();
        const ul = document.getElementById('adList');
        ul.innerHTML = '';
        (j.data||[]).forEach(a => {
          const li = document.createElement('li');
          li.innerText = a.id + ' | ' + (a.name||'');
          li.innerHTML += ' <button onclick="manageObj(\\'ad\\',\\''+a.id+'\\',\\'pause\\')">Pause</button>';
          li.innerHTML += ' <button onclick="manageObj(\\'ad\\',\\''+a.id+'\\',\\'resume\\')">Resume</button>';
          li.innerHTML += ' <button onclick="deleteObj(\\'ad\\',\\''+a.id+'\\')">Delete</button>';
          ul.appendChild(li);
        });
      }

      async function manageObj(level,id,action){
        const res = await fetch('/object/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({level, id, action})});
        alert(JSON.stringify(await res.json(),null,2));
      }
      async function deleteObj(level,id){
        if(!confirm('Delete '+level+' '+id+'?')) return;
        const res = await fetch('/object/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({level,id})});
        alert(JSON.stringify(await res.json(),null,2));
      }

      async function getInsights(){
        const level = document.getElementById('ins_level').value;
        const id = document.getElementById('ins_obj').value;
        const fields = document.getElementById('ins_fields').value;
        let q = '?level='+encodeURIComponent(level);
        if(id) q += '&id=' + encodeURIComponent(id);
        if(fields) q += '&fields=' + encodeURIComponent(fields);
        const r = await fetch('/insights'+q);
        document.getElementById('insOut').innerText = JSON.stringify(await r.json(),null,2);
      }
    </script>
    </body></html>
    """
    return render_template_string(html, ad_account=FB_AD_ACCOUNT_ID, page=FB_PAGE_ID)

@app.route("/publish", methods=["POST"])
def publish():
    """
    Create campaign -> adset -> upload image -> creative -> ad (all paused).
    Accepts multipart form (image_file) OR image_url field in form.
    """
    try:
        # form or multipart
        body = request.form.to_dict() or {}
        # prefer file upload if present
        image_file = request.files.get("image_file")
        image_url = body.get("image_url", "").strip()

        # fields (fallback to defaults)
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

        # create campaign
        campaign_id = create_campaign(FB_AD_ACCOUNT_ID, campaign_name)
        if not campaign_id:
            return jsonify({"error": "campaign_create_failed"}), 500
        LAST["campaign_id"] = campaign_id

        # create adset
        adset_id = create_adset(FB_AD_ACCOUNT_ID, campaign_id, adset_name, daily_budget, start_time, end_time, FB_PAGE_ID)
        if not adset_id:
            return jsonify({"error": "adset_create_failed"}), 500
        LAST["adset_id"] = adset_id

        # upload image
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

        # create creative
        creative_id = create_adcreative(FB_AD_ACCOUNT_ID, FB_PAGE_ID, image_hash, link, message, name="Auto Creative")
        if not creative_id:
            return jsonify({"error": "creative_create_failed"}), 500
        LAST["creative_id"] = creative_id

        # create ad
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

# List endpoints
@app.route("/list/campaigns", methods=["GET"])
def list_campaigns():
    acct = FB_AD_ACCOUNT_ID.split("act_")[-1]
    resp = fb_get(f"act_{acct}/campaigns", params={"fields": "id,name,status,objective"})
    return jsonify(resp)

@app.route("/list/adsets", methods=["GET"])
def list_adsets():
    acct = FB_AD_ACCOUNT_ID.split("act_")[-1]
    # optional campaign filter
    campaign_id = request.args.get("campaign_id")
    params = {"fields": "id,name,status,campaign_id,daily_budget,start_time,end_time"}
    if campaign_id:
        params["filtering"] = json.dumps([{"field":"campaign.id","operator":"EQUAL","value":campaign_id}])
    resp = fb_get(f"act_{acct}/adsets", params=params)
    return jsonify(resp)

@app.route("/list/creatives", methods=["GET"])
def list_creatives():
    acct = FB_AD_ACCOUNT_ID.split("act_")[-1]
    resp = fb_get(f"act_{acct}/adcreatives", params={"fields":"id,name,object_story_spec"})
    return jsonify(resp)

@app.route("/list/ads", methods=["GET"])
def list_ads():
    acct = FB_AD_ACCOUNT_ID.split("act_")[-1]
    adset_id = request.args.get("adset_id")
    params = {"fields": "id,name,status,adset_id,creative"}
    if adset_id:
        params["filtering"] = json.dumps([{"field":"adset.id","operator":"EQUAL","value":adset_id}])
    resp = fb_get(f"act_{acct}/ads", params=params)
    return jsonify(resp)

# Pause / resume / generic object actions
@app.route("/object/action", methods=["POST"])
def object_action():
    """
    JSON { level: 'campaign'|'adset'|'ad', id: '<id>', action: 'pause'|'resume' }
    """
    body = request.get_json(force=True, silent=True) or {}
    level = body.get("level")
    obj_id = body.get("id")
    action = body.get("action")
    if not level or not obj_id or not action:
        return jsonify({"error": "level,id,action required"}), 400
    status = "PAUSED" if action == "pause" else "ACTIVE" if action == "resume" else None
    if not status:
        return jsonify({"error":"unknown action"}), 400
    resp = fb_post(f"{obj_id}", data={"status": status})
    return jsonify(resp)

@app.route("/object/delete", methods=["POST"])
def object_delete():
    """JSON { level, id } - deletes given object id (campaign/adset/ad/creative)"""
    body = request.get_json(force=True, silent=True) or {}
    obj_id = body.get("id")
    if not obj_id:
        return jsonify({"error":"id required"}), 400
    resp = fb_delete(obj_id)
    return jsonify(resp)

@app.route("/object/update/adset", methods=["POST"])
def update_adset():
    """Update adset fields: { adset_id, daily_budget (optional), end_time (YYYY-MM-DDTHH:MM:SS-0000) }"""
    body = request.get_json(force=True, silent=True) or {}
    adset_id = body.get("adset_id")
    if not adset_id:
        return jsonify({"error":"adset_id required"}), 400
    data = {}
    if "daily_budget" in body:
        data["daily_budget"] = int(body["daily_budget"])
    if "end_time" in body:
        data["end_time"] = body["end_time"]
    if not data:
        return jsonify({"error":"nothing to update"}), 400
    resp = fb_post(adset_id, data=data)
    return jsonify(resp)

@app.route("/image/upload_url", methods=["POST"])
def image_upload_url():
    body = request.get_json(force=True, silent=True) or {}
    image_url = (body.get("image_url") or "").strip()
    if not image_url:
        return jsonify({"error":"image_url required"}), 400
    h = upload_image_by_url(FB_AD_ACCOUNT_ID, image_url)
    if not h:
        return jsonify({"error":"upload_failed"}), 500
    return jsonify({"hash": h})

# Insights
@app.route("/insights", methods=["GET"])
def insights():
    """
    Query params:
       - level: account|campaign|adset|ad (default campaign)
       - id: object id for campaign/adset/ad (required if not account)
       - since, until YYYY-MM-DD (optional)
       - fields comma separated (optional)
    """
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
            return jsonify({"error":"id required for campaign/adset/ad level"}), 400
        object_id = obj
    data = fetch_insights_for(object_id, fields=fields_list, since=since, until=until)
    return jsonify(data)

# Optional AI suggest endpoint (calls _generate_text_from_prompt if you wire it in)
# If you have a function _generate_text_from_prompt(prompt_text, model_id, response_modalities, candidate_count)
# import it and this route will call it. Otherwise returns NOT-AVAILABLE.
try:
    # user can modify to import the actual function
    from genai_wrapper import _generate_text_from_prompt  # optional: create this wrapper in project
    AI_AVAILABLE = True
except Exception:
    AI_AVAILABLE = False

@app.route("/ai/suggest", methods=["POST"])
def ai_suggest():
    body = request.get_json(force=True, silent=True) or {}
    prompt = body.get("prompt")
    model = body.get("model_id", "text-bison")  # placeholder
    candidates = int(body.get("candidate_count", 1))
    if not prompt:
        return jsonify({"error":"prompt required"}), 400
    if not AI_AVAILABLE:
        return jsonify({"error":"AI client not configured (server-side). Implement _generate_text_from_prompt and import it)"}), 501
    try:
        resp = _generate_text_from_prompt(prompt, model, response_modalities=["TEXT"], candidate_count=candidates)
        return jsonify({"resp": resp})
    except Exception as e:
        logger.exception("ai_suggest failed: %s", e)
        return jsonify({"error": str(e)}), 500

# ---------------- Run ----------------
if __name__ == "__main__":
    if not FB_ACCESS_TOKEN:
        logger.warning("FB_ACCESS_TOKEN not set. Set env var FB_ACCESS_TOKEN to run API calls.")
    logger.info("Starting FB Manager on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
