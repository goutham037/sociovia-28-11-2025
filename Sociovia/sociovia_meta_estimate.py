# sociovia_meta_estimate.py
"""
Robust single-file Flask app implementing /api/meta/estimate.

Features included:
- Accepts payload either flat or wrapper:
    {"workspace": {...}, "audience": {...}, "budget": {...}, "run": true}
- Builds Meta targeting_spec (targetingsearch lookups for interests).
- Calls Graph API reachestimate and extracts bounds robustly.
- Auto-fixes single-invalid-interest-id errors by removing offending id and retrying once.
- Retries reachestimate without interests if necessary.
- Deterministic fallback math when Meta errors or returns zero (configurable).
- Short-term caching to avoid repeated Meta calls.
- CORS preflight (OPTIONS) support and small /health endpoint.
- Config via environment variables.

Usage:
    export FB_ACCESS_TOKEN, FB_AD_ACCOUNT_ID (optional: FB_API_VERSION, MIN_DAILY_BUDGET, FALLBACK_COUNTRY)
    python sociovia_meta_estimate.py
    POST JSON with {"run": true, ...} to http://127.0.0.1:5000/api/meta/estimate
"""

import os
import time
import json
import hashlib
import re
import logging
from typing import Dict, Any,Optional, List
import requests
from flask import Flask, request, jsonify, Response, current_app

# ---------- Config ----------
FB_API_VERSION = os.getenv("FB_API_VERSION", "v17.0")
FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "")
FB_AD_ACCOUNT_ID = os.getenv("FB_AD_ACCOUNT_ID", "") 
MIN_DAILY_BUDGET = int(os.getenv("MIN_DAILY_BUDGET", "10000"))
FALLBACK_COUNTRY = os.getenv("FALLBACK_COUNTRY", "IN")
USE_META_FALLBACK = os.getenv("USE_META_FALLBACK", "true").lower() in ("1", "true", "yes")

GRAPH_API_BASE = "https://graph.facebook.com"
GRAPH_API_VERSION = FB_API_VERSION

MAX_INTEREST_LOOKUPS = int(os.getenv("MAX_INTEREST_LOOKUPS", "5"))
TARGETINGSEARCH_LIMIT = int(os.getenv("TARGETINGSEARCH_LIMIT", "3"))
META_CACHE_TTL = float(os.getenv("META_CACHE_TTL_SECONDS", str(60 * 5)))  # default 5 minutes

# caches
_META_ESTIMATE_CACHE: Dict[str, Any] = {}

# Flask + logging
app = Flask(__name__)
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.DEBUG)
logger = logging.getLogger("sociovia_meta_estimate")

FB_API_VERSION = os.getenv("FB_API_VERSION", "v17.0")
FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "EAAZAVAy1umqcBPlzb3eKWh9xtAdafi3nDF9DAu0xrVjSUhTlb2zZB2xV5ZAuLkeiISzSye85SZC3LTwLrsVZAAerce0YOqQllvirE04ihZBIKXfJY3V0h0mZAtMUxGTrQ8CB2qW5Ahkdsv1k8D7nIHcAU73wTApQeq3ZCWvDZAe1umrqjBREvlaqioDn6aYBniJeDSr5KFKgdCdNUiww7vcs8OowYOG4XHRvHaHAS")  # set this
FB_AD_ACCOUNT_ID = os.getenv("FB_AD_ACCOUNT_ID", "act_785545867549907")
FB_PAGE_ID = os.getenv("FB_PAGE_ID", "826620477192551")
DEFAULT_IMAGE_HASH = os.getenv("DEFAULT_IMAGE_HASH", "706094911862292")

MAX_INTEREST_LOOKUPS = int(os.getenv("MAX_INTEREST_LOOKUPS", "5"))
TARGETINGSEARCH_LIMIT = int(os.getenv("TARGETINGSEARCH_LIMIT", "3"))
META_CACHE_TTL = float(os.getenv("META_CACHE_TTL_SECONDS", str(60 * 5)))  # default 5 minutes

# caches
_META_ESTIMATE_CACHE: Dict[str, Any] = {}


# normalize FB_AD_ACCOUNT_ID (remove act_ prefix if present)
if isinstance(FB_AD_ACCOUNT_ID, str) and FB_AD_ACCOUNT_ID.startswith("act_"):
    FB_AD_ACCOUNT_ID = FB_AD_ACCOUNT_ID.split("act_")[-1]

# ---------------- Helpers ----------------
def _is_sane_interest_id(id_val: str) -> bool:
    s = str(id_val).strip()
    return s.isdigit() and 4 <= len(s) <= 15


def _meta_targetingsearch(query: str, limit: int = TARGETINGSEARCH_LIMIT) -> list:
    """Call Meta targetingsearch for adinterest candidates (best-effort). Raises RuntimeError on HTTP error."""
    if not FB_AD_ACCOUNT_ID or not FB_ACCESS_TOKEN:
        return []
    url = f"{GRAPH_API_BASE}/{FB_API_VERSION}/act_{FB_AD_ACCOUNT_ID}/targetingsearch"
    params = {"type": "adinterest", "q": query, "limit": limit, "access_token": FB_ACCESS_TOKEN}
    r = requests.get(url, params=params, timeout=10)
    if not r.ok:
        raise RuntimeError(f"targetingsearch HTTP {r.status_code}: {r.text}")
    try:
        data = r.json()
    except Exception:
        raise RuntimeError(f"targetingsearch invalid JSON: {r.text}")
    return data.get("data", [])


def _do_reach_request(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Single reachestimate HTTP request -> parsed JSON or raise RuntimeError with body."""
    if not FB_AD_ACCOUNT_ID or not FB_ACCESS_TOKEN:
        raise RuntimeError("FB_AD_ACCOUNT_ID and FB_ACCESS_TOKEN must be configured")
    url = f"{GRAPH_API_BASE}/{FB_API_VERSION}/act_{FB_AD_ACCOUNT_ID}/reachestimate"
    params = {"access_token": FB_ACCESS_TOKEN, "targeting_spec": json.dumps(spec, ensure_ascii=False)}
    r = requests.get(url, params=params, timeout=15)
    if not r.ok:
        raise RuntimeError(f"reachestimate HTTP {r.status_code}: {r.text}")
    try:
        return r.json()
    except Exception:
        raise RuntimeError(f"reachestimate invalid JSON: {r.text}")


def _meta_reachestimate(targeting_spec: Dict[str, Any], warnings: Optional[List[str]] = None, errors: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Call reachestimate; on HTTP error inspect body for an invalid-interest id and retry once
    after removing the offending id. If that still fails, retry once with no interests.
    Raises RuntimeError if unrecoverable.
    Adds messages to warnings/errors lists if provided.
    """
    warnings = warnings if warnings is not None else []
    errors = errors if errors is not None else []
    try:
        return _do_reach_request(targeting_spec)
    except RuntimeError as e:
        body = str(e)
        json_part = None
        try:
            m = re.search(r"(\{.*\})", body, flags=re.DOTALL)
            if m:
                json_part = json.loads(m.group(1))
        except Exception:
            json_part = None

        msg_text = None
        if isinstance(json_part, dict):
            err = json_part.get("error", {})
            msg_text = err.get("message") or err.get("error_user_msg") or body
        else:
            msg_text = body

        # More robust regex to capture interest id mentions in various formats
        m_id = (
            re.search(r"Interests with ID\s+(\d+)", msg_text) or
            re.search(r"Interest id\s*[:=]?\s*(\d+)", msg_text, re.IGNORECASE) or
            re.search(r"ID\s+(\d+)\s+is\s+invalid", msg_text, re.IGNORECASE) or
            re.search(r"\"?(\d{6,16})\"?\s+is\s+invalid", msg_text) or
            re.search(r"interests.*?(\d{6,16})", msg_text, re.IGNORECASE)
        )
        bad_id = m_id.group(1) if m_id else None

        if bad_id:
            errors.append(f"Meta invalid interest id detected: {bad_id}")
            warnings.append(f"Meta reported bad interest id {bad_id} — attempting removal & retry")
            logger.debug("Meta reported bad interest id %s — removing & retrying", bad_id)
            try:
                fs = targeting_spec.get("flexible_spec") or []
                changed = False
                new_fs = []
                for block in fs:
                    if not isinstance(block, dict):
                        new_fs.append(block)
                        continue
                    if "interests" in block and isinstance(block["interests"], list):
                        filtered = [it for it in block["interests"] if str(it.get("id")) != bad_id]
                        if len(filtered) != len(block["interests"]):
                            changed = True
                        if filtered:
                            nb = dict(block)
                            nb["interests"] = filtered
                            new_fs.append(nb)
                    else:
                        new_fs.append(block)
                if changed:
                    new_spec = dict(targeting_spec)
                    new_spec["flexible_spec"] = new_fs
                    warnings.append(f"Retrying reachestimate after removing bad id {bad_id}")
                    return _do_reach_request(new_spec)
                else:
                    errors.append(f"Detected invalid interest id {bad_id} but failed to remove it from flexible_spec")
            except Exception:
                logger.exception("failed to remove bad interest id and retry")
                errors.append("Failed to remove invalid interest id during retry")
        else:
            logger.debug("reachestimate error did not identify a single bad interest id")

        # Retry once more with no interests
        try:
            if targeting_spec.get("flexible_spec"):
                warnings.append("Retrying reachestimate with flexible_spec=[] (no interests)")
                no_interest_spec = dict(targeting_spec)
                no_interest_spec["flexible_spec"] = []
                return _do_reach_request(no_interest_spec)
        except Exception:
            logger.exception("failed reachestimate retry without interests")
            errors.append("Failed to retry reachestimate without interests")

        # Not recoverable -> re-raise original
        raise


# ---------------- Targeting spec builders ----------------
_country_name_map = {
    "india": "IN",
    "united states": "US",
    "united states of america": "US",
    "usa": "US",
    "uk": "GB",
    "united kingdom": "GB",
    "great britain": "GB",
    "australia": "AU",
    "canada": "CA",
    "germany": "DE",
    "france": "FR",
    "spain": "ES",
    "italy": "IT",
    "brazil": "BR",
    "mexico": "MX",
    "china": "CN",
    "japan": "JP",
    "russia": "RU",
    "global": "GLOBAL",
    "world": "GLOBAL",
    "worldwide": "GLOBAL",
}


def _normalize_country_to_iso2(country_val: Any) -> Optional[str]:
    """Return ISO2 uppercase code (e.g. 'IN') for many inputs. Return None if cannot normalize."""
    if not country_val:
        return None
    s = str(country_val).strip()
    if not s:
        return None
    # already ISO2?
    if len(s) == 2 and s.isalpha():
        return s.upper()
    # ISO3 -> try to map
    if len(s) == 3 and s.isalpha():
        try:
            import pycountry as _pc
            c = _pc.countries.get(alpha_3=s.upper())
            if c and getattr(c, "alpha_2", None):
                return c.alpha_2.upper()
        except Exception:
            pass
        s2 = s.upper()
        if s2 == "IND": return "IN"
        if s2 == "USA": return "US"
        if s2 == "GBR": return "GB"

    low = s.lower()
    if low in _country_name_map:
        return _country_name_map[low]

    low_clean = re.sub(r"[^a-z\s]", "", low)
    low_clean = low_clean.replace("republic of ", "").replace("kingdom of ", "").strip()
    if low_clean in _country_name_map:
        return _country_name_map[low_clean]

    try:
        import pycountry as _pc
        c = _pc.countries.get(name=s)
        if not c:
            for cc in _pc.countries:
                n = getattr(cc, "name", "")
                common = getattr(cc, "common_name", None)
                if common and common.lower() == low:
                    c = cc
                    break
                if n and n.lower() == low:
                    c = cc
                    break
        if c and getattr(c, "alpha_2", None):
            return c.alpha_2.upper()
    except Exception:
        pass

    if len(low) >= 2:
        return low[:2].upper()
    return None


def _build_targeting_spec_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a Meta-style targeting_spec with robust country normalization.
    """
    audience = payload.get("audience") or {}
    workspace = payload.get("workspace") or {}

    # GEO: prefer explicit audience.location.country -> workspace.location.country -> workspace.address -> FALLBACK_COUNTRY
    country_raw = None
    loc = audience.get("location") or workspace.get("location") or {}
    if isinstance(loc, dict):
        country_raw = loc.get("country") or None
    elif isinstance(loc, str):
        country_raw = loc

    if not country_raw:
        addr = workspace.get("address") if isinstance(workspace.get("address"), str) else None
        if addr:
            last = addr.split(",")[-1].strip()
            if last:
                country_raw = last

    iso2 = _normalize_country_to_iso2(country_raw)
    if not iso2:
        iso2 = str(FALLBACK_COUNTRY).strip().upper()
        logger.debug("Could not normalize country '%s' -> falling back to %s", country_raw, iso2)

    # If GLOBAL, avoid empty countries list (Meta rejects it); use fallback country instead
    if iso2 == "GLOBAL":
        fallback_iso = _normalize_country_to_iso2(FALLBACK_COUNTRY) or "IN"
        logger.debug("GLOBAL requested — using fallback country %s for Meta targeting_spec", fallback_iso)
        geo_locations = {"countries": [fallback_iso]}
    else:
        geo_locations = {"countries": [iso2]}

    logger.debug("Using country for Meta targeting_spec: raw=%r normalized=%r", country_raw, iso2)

    # age
    age = audience.get("age") or workspace.get("age") or [18, 65]
    try:
        age_min = max(13, int(age[0] if isinstance(age, (list, tuple)) and len(age) > 0 else age))
        age_max = int(age[1] if isinstance(age, (list, tuple)) and len(age) > 1 else 65)
    except Exception:
        age_min, age_max = 18, 65

    # genders mapping
    genders = None
    gender = (audience.get("gender") or workspace.get("gender") or "all")
    if isinstance(gender, str):
        g = gender.lower()
        if g in ("male", "m", "1"):
            genders = [1]
        elif g in ("female", "f", "2"):
            genders = [2]

    # interests -> lookups (accept both 'adinterest' and 'interests' types)
    interests = audience.get("interests") or workspace.get("interests") or []
    interest_ids = []
    if isinstance(interests, list) and len(interests) > 0:
        seen = set()
        for it in interests[:MAX_INTEREST_LOOKUPS]:
            if not isinstance(it, str) or not it.strip():
                continue
            try:
                candidates = _meta_targetingsearch(it, limit=TARGETINGSEARCH_LIMIT)
            except RuntimeError:
                # bubble up to caller (they'll fallback)
                raise
            except Exception:
                continue
            if not candidates:
                continue

            # pick first *adinterest* or *interests* candidate, skip behaviors/devices/demographics
            chosen_cid = None
            for cand in candidates:
                ctype = cand.get("type") or cand.get("category") or ""
                # Accept both 'adinterest' and 'interests' types returned by targetingsearch
                if isinstance(ctype, str) and ctype.lower() not in ("adinterest", "interests"):
                    logger.debug("Skipping targetingsearch candidate because type not accepted: %s", cand)
                    continue
                cid = cand.get("id")
                if cid:
                    cid_s = str(cid).strip()
                    if _is_sane_interest_id(cid_s) and cid_s not in seen:
                        chosen_cid = cid_s
                        break
            if chosen_cid:
                seen.add(chosen_cid)
                interest_ids.append({"id": chosen_cid})
            else:
                logger.debug("No suitable adinterest/interests candidate found for query %r (candidates=%r)", it, candidates)

    spec: Dict[str, Any] = {"age_min": age_min, "age_max": age_max, "geo_locations": geo_locations}
    if genders:
        spec["genders"] = genders
    # If interest_ids empty, flexible_spec will be empty list (we add warning later in handler)
    spec["flexible_spec"] = [{"interests": interest_ids}] if interest_ids else []

    logger.debug("Built targeting_spec: %s", spec)
    return spec


def _deterministic_fallback_estimate(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic math fallback (used when Meta fails and fallback enabled).
    Mirrors earlier behavior.
    """
    audience = payload.get("audience") or payload.get("workspace", {}) or {}
    workspace = payload.get("workspace") or {}

    interests = audience.get("interests") or workspace.get("interests") or []
    interest_count = len(interests) if isinstance(interests, list) else 0

    country = (audience.get("location") or {}).get("country") or (workspace.get("location") or {}).get("country") or FALLBACK_COUNTRY
    c = str(country).upper() if country else FALLBACK_COUNTRY

    BASE_POP_MAP = {"US": 25000000, "IN": 80000000, "GB": 10000000, "AU": 5000000, "CA": 8000000, "GLOBAL": 1000000000}
    base_pop = BASE_POP_MAP.get(c, 1000000)

    interest_mul = 1.0 + min(interest_count * 0.12, 1.5)

    age = audience.get("age") or workspace.get("age") or [18, 65]
    try:
        age_min = int(age[0]); age_max = int(age[1])
    except Exception:
        age_min, age_max = 18, 65
    age_span = max(1, age_max - age_min)
    age_mul = max(0.6, min(1.6, 50.0 / age_span))

    budget = payload.get("budget") or workspace.get("budget") or {}
    try:
        amount = float(budget.get("amount") or budget.get("value") or MIN_DAILY_BUDGET)
    except Exception:
        amount = float(MIN_DAILY_BUDGET)
    budget_mul = max(0.2, min(10.0, amount / 10000.0))

    obj_mul = 1.0
    objective = (payload.get("objective") or workspace.get("objective") or "TRAFFIC").upper()
    if objective in ("OUTCOME_SALES", "CONVERSIONS"):
        obj_mul = 0.8
    elif objective in ("OUTCOME_AWARENESS",):
        obj_mul = 1.2

    estimated_reach = int(base_pop * 0.05 * interest_mul * age_mul * budget_mul * obj_mul)
    estimated_daily_impressions = int(max(1, estimated_reach * 2.5))
    estimated_daily_clicks = int(max(0, estimated_daily_impressions * 0.03))
    estimated_conversions_per_week = int(max(0, (estimated_daily_clicks * 7) * 0.02))
    estimated_leads = int(max(0, estimated_conversions_per_week * 0.25))

    est_cpc = (amount / max(1.0, estimated_daily_clicks)) if estimated_daily_clicks > 0 else float(amount)
    est_cpa = (amount / max(1.0, estimated_conversions_per_week)) if estimated_conversions_per_week > 0 else float(amount)
    confidence = min(0.95, max(0.25, 0.5 + (interest_count * 0.05)))

    predicted_audience = {
        "location": audience.get("location") or workspace.get("location") or {"country": c},
        "age": [age_min, age_max],
        "gender": audience.get("gender") or workspace.get("gender") or "all",
        "interests": interests if isinstance(interests, list) else [],
    }

    resp = {
        "ok": True,
        "estimated_reach": estimated_reach,
        "estimated_daily_impressions": estimated_daily_impressions,
        "estimated_daily_clicks": estimated_daily_clicks,
        "estimated_cpc": float(round(est_cpc, 2)),
        "estimated_cpa": float(round(est_cpa, 2)),
        "estimated_conversions_per_week": estimated_conversions_per_week,
        "estimated_leads": estimated_leads,
        "confidence": float(round(confidence, 2)),
        "predicted_audience": predicted_audience,
        "breakdown": {"by_country": {c: estimated_reach}},
        "meta_raw": None,
    }
    return resp


def _check_account_active(warnings: List[str], errors: List[str]) -> Optional[int]:
    """
    Query account metadata and return numeric amount_spent (major units or string) if available.
    Append warnings/errors messages to lists passed.
    """
    if not FB_AD_ACCOUNT_ID or not FB_ACCESS_TOKEN:
        errors.append("FB_AD_ACCOUNT_ID and/or FB_ACCESS_TOKEN not configured")
        return None
    try:
        url = f"{GRAPH_API_BASE}/{FB_API_VERSION}/act_{FB_AD_ACCOUNT_ID}"
        params = {"fields": "account_id,currency,timezone_name,amount_spent,business", "access_token": FB_ACCESS_TOKEN}
        r = requests.get(url, params=params, timeout=10)
        if not r.ok:
            errors.append(f"Account metadata HTTP {r.status_code}: {r.text}")
            return None
        data = r.json()
        amount_spent = data.get("amount_spent")
        try:
            if amount_spent is None:
                return 0
            return int(float(amount_spent))
        except Exception:
            warnings.append(f"Could not parse account.amount_spent: {amount_spent}")
            return 0
    except Exception as exc:
        errors.append(f"Failed to fetch account metadata: {str(exc)}")
        return None


# ---------------- Route / CORS ----------------
@app.after_request
def _set_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return resp


@app.route("/api/meta/estimate", methods=["POST", "OPTIONS"])
def meta_estimate():
    """
    Compute a single deterministic or Meta-based estimate only when client sends {"run": true}.
    Accepts payload either flat or with wrapper { "workspace": {...}, ... }.
    """
    # CORS preflight
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
            # return cached if fresh
            if cached and (now - cached["ts"] < META_CACHE_TTL):
                app.logger.info("meta_estimate: returning cached estimate (no run requested)")
                return jsonify(cached["data"])
            return jsonify({
                "ok": False,
                "error": "No cached estimate available. Set {\"run\": true} in the request body to compute now."
            }), 400

        # Build targeting_spec (may raise RuntimeError)
        warnings: List[str] = []
        errors: List[str] = []
        try:
            targeting_spec = _build_targeting_spec_from_payload(payload)
        except RuntimeError as e:
            app.logger.error("targeting_spec build error: %s", str(e))
            errors.append(str(e))
            if USE_META_FALLBACK:
                app.logger.info("Falling back to deterministic estimate due to targetingsearch error")
                resp = _deterministic_fallback_estimate(payload)
                resp["meta_raw"] = None
                resp["warnings"] = warnings
                resp["errors"] = errors
                _META_ESTIMATE_CACHE[key] = {"ts": now, "data": resp}
                return jsonify(resp)
            return jsonify({"ok": False, "error": "targeting_spec build failed", "meta_raw": str(e)}), 400
        except Exception as e:
            app.logger.exception("Failed to build targeting_spec")
            errors.append(str(e))
            return jsonify({"ok": False, "error": f"Failed to build targeting_spec: {str(e)}"}), 500

        # If flexible_spec is empty, warn caller (no interests resolved)
        if not targeting_spec.get("flexible_spec"):
            warnings.append("No interests resolved from payload; flexible_spec is empty.")

        # Optional: check account activity to surface a clear message when account has never spent.
        account_spend = _check_account_active(warnings, errors)
        if account_spend is not None and account_spend == 0:
            warnings.append("Ad account has no spend. Meta will not return delivery curves (daily_outcomes_curve) until the account has run at least one paid campaign. Run a small test ad (₹100–₹500) to unlock curves.")

        # Call Meta reachestimate (robust)
        try:
            meta_resp = _meta_reachestimate(targeting_spec, warnings=warnings, errors=errors)

            # --- robust bounds extraction (explicitly prefer data.users_*) ---
            lower_n = None
            upper_n = None
            try:
                data = meta_resp.get("data") if isinstance(meta_resp, dict) else None
                if isinstance(data, dict):
                    lower_candidate = data.get("users_lower_bound") or data.get("lower_bound")
                    upper_candidate = data.get("users_upper_bound") or data.get("upper_bound")
                    if lower_candidate is not None:
                        lower_n = int(lower_candidate)
                    if upper_candidate is not None:
                        upper_n = int(upper_candidate)

                # fallbacks
                if lower_n is None:
                    cand = meta_resp.get("users_lower_bound") or meta_resp.get("lower_bound")
                    if cand is not None:
                        lower_n = int(cand)
                if upper_n is None:
                    cand = meta_resp.get("users_upper_bound") or meta_resp.get("upper_bound")
                    if cand is not None:
                        upper_n = int(cand)

                est = meta_resp.get("estimate") if isinstance(meta_resp, dict) else None
                if (lower_n is None or upper_n is None) and isinstance(est, dict):
                    if lower_n is None:
                        cand = est.get("users_lower_bound") or est.get("lower_bound")
                        if cand is not None:
                            lower_n = int(cand)
                    if upper_n is None:
                        cand = est.get("users_upper_bound") or est.get("upper_bound")
                        if cand is not None:
                            upper_n = int(cand)
            except Exception:
                logger.exception("error extracting numeric bounds from meta_resp")
                errors.append("Failed to extract numeric bounds from Meta response")

            logger.debug("meta bounds extracted: lower_n=%s upper_n=%s", lower_n, upper_n)

            if lower_n and upper_n:
                estimated_reach = int((lower_n + upper_n) / 2)
            elif upper_n:
                estimated_reach = int(upper_n)
            elif lower_n:
                estimated_reach = int(lower_n)
            else:
                estimated_reach = int(meta_resp.get("estimate", {}).get("users", 0) or meta_resp.get("users", 0) or 0)

            # If Meta returned zero reach or delivery curve is zeros, treat as fallback candidate
            data_field = meta_resp.get("data")
            # detect a zero / empty daily_outcomes_curve
            curve_all_zero = False
            try:
                if isinstance(data_field, list) and len(data_field) > 0:
                    first = data_field[0]
                    doc = first.get("daily_outcomes_curve")
                    if isinstance(doc, list) and len(doc) > 0:
                        # all-zero check
                        curve_all_zero = all((item.get("impressions", 0) == 0 and item.get("spend", 0) == 0) for item in doc)
                    else:
                        curve_all_zero = True
                elif isinstance(data_field, dict):
                    doc = data_field.get("daily_outcomes_curve")
                    if isinstance(doc, list) and len(doc) > 0:
                        curve_all_zero = all((item.get("impressions", 0) == 0 and item.get("spend", 0) == 0) for item in doc)
                    else:
                        curve_all_zero = True
                else:
                    curve_all_zero = True
            except Exception:
                curve_all_zero = True

            if estimated_reach == 0 or curve_all_zero:
                warnings.append("Meta returned zero/empty delivery curve or estimated reach=0.")
                # if account has no spend, add a very explicit instruction
                if account_spend is not None and account_spend == 0:
                    warnings.append("This account's amount_spent=0. Meta hides delivery curves for accounts with no spend. Run a small paid campaign (₹100-₹500) and retry to get delivery curves.")
                if USE_META_FALLBACK:
                    resp = _deterministic_fallback_estimate(payload)
                    resp["meta_raw"] = meta_resp
                    resp["warnings"] = warnings
                    resp["errors"] = errors
                    _META_ESTIMATE_CACHE[key] = {"ts": now, "data": resp}
                    return jsonify(resp)
                # else continue and return the zero result (with meta_raw)

            # derive other metrics similar to deterministic fallback
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
                "warnings": warnings,
                "errors": errors,
            }

            # Cache & return
            _META_ESTIMATE_CACHE[key] = {"ts": now, "data": resp}
            app.logger.info("meta_estimate: Meta computed estimate reach=%s for key=%s", estimated_reach, key[:8])
            return jsonify(resp)

        except RuntimeError as e:
            app.logger.error("Meta reachestimate error: %s", str(e))
            errors.append(str(e))
            if USE_META_FALLBACK:
                app.logger.info("Falling back to deterministic estimate due to Meta error")
                resp = _deterministic_fallback_estimate(payload)
                resp["meta_raw"] = {"error": str(e)}
                resp["warnings"] = warnings
                resp["errors"] = errors
                _META_ESTIMATE_CACHE[key] = {"ts": now, "data": resp}
                return jsonify(resp)
            return jsonify({"ok": False, "error": "Meta reachestimate failed", "meta_raw": str(e), "warnings": warnings, "errors": errors}), 502

        except Exception as exc:
            app.logger.exception("Meta estimate failed")
            return jsonify({"ok": False, "error": str(exc), "warnings": warnings, "errors": errors}), 500

    except Exception as exc:
        app.logger.exception("meta_estimate failed early")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": int(time.time())})
