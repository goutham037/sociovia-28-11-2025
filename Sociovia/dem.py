#!/usr/bin/env python3
import requests, json, sys, traceback

# ----------------- CONFIG -----------------
ACCESS_TOKEN = "EAAZAVAy1umqcBPlzb3eKWh9xtAdafi3nDF9DAu0xrVjSUhTlb2zZB2xV5ZAuLkeiISzSye85SZC3LTwLrsVZAAerce0YOqQllvirE04ihZBIKXfJY3V0h0mZAtMUxGTrQ8CB2qW5Ahkdsv1k8D7nIHcAU73wTApQeq3ZCWvDZAe1umrqjBREvlaqioDn6aYBniJeDSr5KFKgdCdNUiww7vcs8OowYOG4XHRvHaHAS"
AD_ACCOUNT = "785545867549907"     # no 'act_'
API_VERSION = "v17.0"
API_BASE = f"https://graph.facebook.com/{API_VERSION}"

TARGETING_SPEC = {
    "age_min": 18,
    "age_max": 55,
    "geo_locations": {
        "countries": [
            "US","GB","CA","AU","IN","DE","FR","JP","KR","BR","MX","ES","IT","NL",
            "SE","CH","BE","AT","NO","DK","IE","SG","HK","TW","ZA","AE","SA","TR",
            "PL","ID"
        ]
    },
    "publisher_platforms": ["instagram", "facebook"]
}

DAILY_BUDGET_MINOR = 1000000
MINOR_TO_MAJOR = 100.0   # paise → rupees
ASSUMED_CTR = 0.01   # 1%

# ------------------------------------------

def safe_get_json(r):
    try:
        return r.json()
    except Exception:
        # fallback to raw text
        return {"_raw_text": r.text}

def call_reachestimate():
    params = {
        "access_token": ACCESS_TOKEN,
        "targeting_spec": json.dumps(TARGETING_SPEC)
    }
    url = f"{API_BASE}/act_{AD_ACCOUNT}/reachestimate"
    r = requests.get(url, params=params)
    if r.status_code != 200:
        print("reachestimate HTTP", r.status_code)
        print("Response body:", r.text)
        # raise so caller can see
        r.raise_for_status()
    return safe_get_json(r)

def call_delivery_estimate():
    params = {
        "access_token": ACCESS_TOKEN,
        "targeting_spec": json.dumps(TARGETING_SPEC),
        "optimization_goal": "IMPRESSIONS",
        "daily_budget": DAILY_BUDGET_MINOR
    }
    url = f"{API_BASE}/act_{AD_ACCOUNT}/delivery_estimate"
    r = requests.get(url, params=params)
    if r.status_code != 200:
        print("delivery_estimate HTTP", r.status_code)
        print("Response body:", r.text)
        r.raise_for_status()
    return safe_get_json(r)

def first_data_element(data_field):
    """
    Normalize data_field into a dict:
      - if list: return first element or {}
      - if dict: return it
      - otherwise return {}
    """
    if data_field is None:
        return {}
    if isinstance(data_field, list):
        return data_field[0] if len(data_field) > 0 else {}
    if isinstance(data_field, dict):
        return data_field
    return {}

def parse_and_compute(reach_resp, delivery_resp):
    out = {}

    # --- Normalize reach_resp.data safely ---
    rd = first_data_element(reach_resp.get("data")) if isinstance(reach_resp, dict) else {}
    # If reach_resp has error, show it
    if isinstance(reach_resp, dict) and "error" in reach_resp:
        out["reach_error"] = reach_resp["error"]

    lower = rd.get("users_lower_bound") or rd.get("users_lower") or rd.get("users_lower_bound_estimate")
    upper = rd.get("users_upper_bound") or rd.get("users_upper") or rd.get("users_upper_bound_estimate")
    # fallback to other naming sometimes used
    if lower and upper:
        try:
            midpoint = (float(lower) + float(upper)) / 2.0
        except Exception:
            midpoint = None
    else:
        midpoint = None

    out["reach_lower"] = lower
    out["reach_upper"] = upper
    out["reach_midpoint"] = midpoint
    out["raw_reach_response"] = reach_resp  # include for debugging

    # --- Normalize delivery_resp.data safely ---
    dd = first_data_element(delivery_resp.get("data")) if isinstance(delivery_resp, dict) else {}
    if isinstance(delivery_resp, dict) and "error" in delivery_resp:
        out["delivery_error"] = delivery_resp["error"]

    curve = dd.get("daily_outcomes_curve", [])
    estimate_dau = dd.get("estimate_dau") or dd.get("estimate_daily_active_users") or dd.get("estimate_mau")
    out["estimate_dau"] = estimate_dau
    out["raw_delivery_response"] = delivery_resp  # include for debugging

    rows = []
    for row in (curve or []):
        # handle row types defensively
        try:
            spend_minor = float(row.get("spend", 0) or 0)
            impressions = float(row.get("impressions", 0) or 0)
            actions = float(row.get("actions", 0) or 0)
            clicks = row.get("clicks")
        except Exception:
            # if row isn't dict-like, skip
            continue

        spend_major = spend_minor / MINOR_TO_MAJOR if MINOR_TO_MAJOR else None
        cpm = (spend_major / impressions) * 1000 if impressions > 0 and spend_major is not None else None
        cpa = (spend_major / actions) if actions > 0 and spend_major is not None else None

        row_result = {
            "spend_minor": spend_minor,
            "spend_major": spend_major,
            "impressions": impressions,
            "actions": actions,
            "cpm": cpm,
            "cpa": cpa
        }

        if clicks is not None:
            try:
                clicks = float(clicks)
                ctr = (clicks / impressions) * 100 if impressions > 0 else None
                cpc = (spend_major / clicks) if clicks > 0 else None
                row_result.update({"clicks": clicks, "ctr_pct": ctr, "cpc": cpc})
            except Exception:
                pass
        elif ASSUMED_CTR:
            est_clicks = impressions * ASSUMED_CTR
            est_ctr_pct = ASSUMED_CTR * 100
            est_cpc = (spend_major / est_clicks) if est_clicks > 0 else None
            row_result.update({"est_clicks": est_clicks, "est_ctr_pct": est_ctr_pct, "est_cpc": est_cpc})

        rows.append(row_result)

    # fallback if rows empty or all impressions zero
    if not rows or all((r.get("impressions", 0) == 0) for r in rows):
        try:
            impressions = float(estimate_dau or 0)
        except Exception:
            impressions = 0
        spend_major = DAILY_BUDGET_MINOR / MINOR_TO_MAJOR if MINOR_TO_MAJOR else None
        cpm = (spend_major / impressions) * 1000 if impressions > 0 and spend_major is not None else None
        rows = [{
            "fallback": True,
            "impressions": impressions,
            "spend_major": spend_major,
            "cpm": cpm
        }]

    out["rows"] = rows
    return out

def main():
    try:
        print("Calling reachestimate...")
        reach = call_reachestimate()
        print("Calling delivery_estimate...")
        delivery = call_delivery_estimate()

        res = parse_and_compute(reach, delivery)
        print(json.dumps(res, indent=2))
    except requests.HTTPError as he:
        print("HTTP error caught:")
        traceback.print_exc()
    except Exception as e:
        print("Unexpected error:")
        traceback.print_exc()

if __name__ == "__main__":
    main()
