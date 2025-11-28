
import os
import re
import json
import base64
import time
import traceback
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

# google-genai
try:
    from google import genai
    from google.genai import types
except Exception:
    genai = None
    types = None

app = Flask(__name__)

# Config (prefer environment)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyDIcAh8KPAafF6Oii2thk2jGGMoRZZDW-c")  # set this
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")
SCRAPER_OUTPUT = os.environ.get("SCRAPER_OUTPUT", "scraper_output")
os.makedirs(SCRAPER_OUTPUT, exist_ok=True)

if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY environment variable required")

if genai is None:
    raise RuntimeError("google-genai SDK not installed. Run: pip install google-genai")

GENAI_CLIENT = genai.Client(api_key=GEMINI_API_KEY)


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


def upload_file(pth):
    try:
        uploaded = GENAI_CLIENT.files.upload(file=pth)
        return {"local_path": pth, "uploaded_name": getattr(uploaded, "name", None), "id": getattr(uploaded, "name", None)}, uploaded
    except Exception as e:
        return {"local_path": pth, "error": str(e)}, None


GENAI_PROMPT = """
SYSTEM: You are a grounded web researcher + ad campaign suggester. Use ONLY the inputs provided and do NOT hallucinate.
INPUT:
page_url: {page_url}
json_ld: {json_ld}
og_meta: {og_meta}
title: {title}
description: {description}
detected_price: {price}
images: {images}
snapshots_summary: {snapshots_summary}

TASK:
Produce a single JSON object (NO surrounding text) exactly with this shape:

{{
  "status":"ok" | "blocked" | "error",
  "product": {{
    "title": string | null,
    "short_description": string | null,
    "price_raw": string | null,
    "currency": string | null,
    "availability": string | null,
    "brand": string | null,
    "images": [{{"url": string}}] | [],
    "source_url": string
  }},
  "ad_campaign_ready": {{
    "one_sentence_tagline": string | null,
    "top_3_usps": [string] | [],
    "recommended_ad_formats": [ "static_image", "carousel", "video_15s", "video_30s", "stories", "reels" ] | [],
    "audience_suggestions": [{{"name":string,"age_range":string|null,"interests":[string]}}] | [],
    "kpi_suggestions": {{ "ctr_target_pct": number | null, "cpa_target": number | null, "roas_target": number | null }}
  }},
  "notes": string | null
}}

Rules:
- Use only supplied structured inputs.
- snapshots_summary is a small list of snapshot index/timestamp; the actual images are uploaded separately to GenAI Files and are available to the model as file objects passed in the request.
- If missing fields, set to null/[].
- Output must be pure JSON only.
"""

def extract_json_block(text: str):
    m = re.search(r"```json\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if m:
        return m.group(1)
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return text[first:last+1]
    return None


@app.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True) or {}
    url = body.get("url")
    max_snapshots = int(body.get("max_snapshots", 4))
    if not url or not is_valid_url(url):
        return jsonify({"ok": False, "error": "missing/invalid 'url'"}), 400

    snapshots_paths = []
    uploaded_files_meta = []
    screenshot_data_urls_count = 0
    metadata = {}
    model_text = None
    parsed_json = None

    try:
        with sync_playwright() as p:
            # Launch headless to speed up (no visual rendering)
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = browser.new_context(viewport={"width": 1200, "height": 900}, user_agent="Mozilla/5.0")
            page = context.new_page()
            # Use domcontentloaded for faster load, fallback from networkidle
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=10000)
                # Brief wait for dynamic content
                page.wait_for_timeout(1000)
            except PWTimeout:
                page.goto(url, wait_until="load", timeout=5000)

            metadata = extract_basic_metadata_from_page(page)

            # Scroll & capture multiple snapshots (optimized waits)
            screenshot_data_urls = []
            snapshots_summary = []
            viewport_h = page.evaluate("() => window.innerHeight")
            scroll_y = 0
            scroll_height = page.evaluate("() => document.documentElement.scrollHeight")
            snaps = 0

            while snaps < max_snapshots and scroll_y < scroll_height:
                page.wait_for_timeout(200)  # Reduced wait for lazy loads
                shot = page.screenshot(type="png", full_page=False)
                local_path = save_snapshot(shot, url, snaps)
                snapshots_paths.append(local_path)
                # Removed base64 encoding as it's unused downstream
                snapshots_summary.append({"index": snaps, "y": int(scroll_y), "file": os.path.basename(local_path)})
                snaps += 1
                # Scroll down by viewport height (or more aggressively if needed)
                scroll_y += viewport_h * 0.8  # Slight overlap to avoid gaps
                page.evaluate(f"window.scrollTo(0, {scroll_y});")
                scroll_height = page.evaluate("() => document.documentElement.scrollHeight")
                page.wait_for_timeout(150)  # Reduced post-scroll wait

            browser.close()

        screenshot_data_urls_count = len(screenshot_data_urls)  # This is 0 now, but kept for compatibility

        # Parallel upload of snapshots to GenAI files
        uploaded_files = []
        with ThreadPoolExecutor(max_workers=min(4, len(snapshots_paths))) as executor:
            futures = [executor.submit(upload_file, pth) for pth in snapshots_paths]
            for future in futures:
                meta, uploaded = future.result()
                uploaded_files_meta.append(meta)
                if uploaded:
                    uploaded_files.append(uploaded)

        # Build prompt (compact)
        prompt_text = GENAI_PROMPT.format(
            page_url=url,
            json_ld=json.dumps(metadata.get("json_ld"), ensure_ascii=False) if metadata.get("json_ld") else "null",
            og_meta=json.dumps(metadata.get("og", {}), ensure_ascii=False),
            title=json.dumps(metadata.get("title"), ensure_ascii=False),
            description=json.dumps(metadata.get("description"), ensure_ascii=False),
            price=json.dumps(metadata.get("detected_price"), ensure_ascii=False),
            images=json.dumps(metadata.get("images", []), ensure_ascii=False),
            snapshots_summary=json.dumps(snapshots_summary, ensure_ascii=False),
        )

        # Build contents: include uploaded files first then the prompt
        contents_for_model = [f for f in uploaded_files if f]  # Filter None

        # Add textual content last
        contents_for_model.append(types.Content(role="user", parts=[types.Part.from_text(text=prompt_text + "\n\nNote: snapshots are attached as files.")]))

        # Call model (non-streaming)
        cfg = types.GenerateContentConfig(candidate_count=1)
        resp = GENAI_CLIENT.models.generate_content(model=GEMINI_MODEL, contents=contents_for_model, config=cfg)

        # Extract candidate text
        try:
            cand = resp.candidates[0]
            if cand and getattr(cand, "content", None) and getattr(cand.content, "parts", None):
                pieces = [getattr(p, "text", "") for p in cand.content.parts if getattr(p, "text", None)]
                model_text = "\n".join(pieces).strip()
        except Exception:
            model_text = None

        if model_text:
            block = extract_json_block(model_text)
            if block:
                try:
                    parsed_json = json.loads(block)
                except Exception:
                    parsed_json = None

        return jsonify({
            "ok": True,
            "page_url": url,
            "snapshots": snapshots_paths,
            "uploaded_files_meta": uploaded_files_meta,
            "screenshot_data_urls_count": screenshot_data_urls_count,
            "extracted_metadata": metadata,
            "model_text": model_text,
            "parsed_json": parsed_json,
        })

    except Exception as exc:
        tb = traceback.format_exc()
        return jsonify({"ok": False, "error": "internal", "detail": str(exc), "trace": tb}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)