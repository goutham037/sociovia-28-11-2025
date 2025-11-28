from flask import request, jsonify, current_app as app
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import json
import time
import test
# Assumptions:
# - GENAI_CLIENT exists as a global client (your existing code defines it).
# - generate_image_candidates(prompt, model_id=model, n=num) exists and returns "candidates" or similar.
# - save_images_from_response(candidates, prefix=...) exists and returns list of saved filenames.
# If your helpers have different names/signatures, adapt the calls in gen_for_theme below.

TEXT_MODEL = "gemini-2.5-flash-preview-09-2025"  # model to use for generating theme prompts
IMAGE_MODEL = os.getenv("IMAGE_MODEL", "gemini-2.5-flash-image")
DEFAULT_NUM_THEMES = 3
MAX_THEMES = 6  # safety cap


def generate_theme_prompts_via_llm(base_prompt: str, workspace_details: dict, n: int = 3, timeout_seconds: int = 15):
    """
    Ask the LLM to create `n` distinct theme prompts derived from base_prompt + workspace_details.
    Returns list[str] length n (or fewer on failure).
    NOTE: adapt parsing if your GENAI_CLIENT returns a different shape.
    """
    n = max(1, min(n, MAX_THEMES))
    # Compose an instruction prompt for the text model
    system_instruction = (
        "You are a creative marketing assistant. Given the base ad brief and workspace metadata, "
        "produce exactly {n} concise and distinct image-generation prompts (each 1-2 sentences) suitable "
        "for a photorealistic Meta feed ad (1:1). Number them 1..N. Keep brand colors and tone in mind. "
        "Do NOT include backticks or code fences. Do not include any external URLs."
    ).replace("{n}", str(n))

    user_block = f"Base brief: {base_prompt}\nWorkspace (JSON): {json.dumps(workspace_details or {}, default=str)}\n\nReturn only numbered prompts."

    try:
        # Use your existing global GENAI_CLIENT if available
        if "GENAI_CLIENT" in globals():
            client = GENAI_CLIENT
        else:
            # Fallback: try to create a client locally (this may duplicate your global client)
            from google import genai
            client = genai.Client(vertexai=True, api_key=os.environ.get("GOOGLE_CLOUD_API_KEY"))

        call = client.models.generate_content(
            model=TEXT_MODEL,
            # single content piece with system/user structure if your client supports it
            contents=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_block},
            ],
            # keep output short and deterministic-ish
            temperature=0.7,
            max_output_tokens=512,
            # response_modalities may be optional for text-only
        )

        # Many client libs return an object with `candidates` or `response.output[0].content[0].text`.
        # Try a few common shapes defensively:
        raw_text = None
        if hasattr(call, "candidates") and len(call.candidates) > 0:
            # some SDKs: call.candidates[0].content or .message or .output
            cand = call.candidates[0]
            raw_text = getattr(cand, "content", None) or getattr(cand, "text", None) or getattr(cand, "message", None)
        else:
            # try string conversion
            raw_text = str(call)

        if not raw_text:
            raw_text = ""

        # Heuristic: split by lines, pick numbered lines "1. ..." or "- "
        lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
        prompts = []
        for ln in lines:
            # Accept lines starting with "1." or "1)" or similar, or fallback to every line
            if ln[0].isdigit() and (ln[1:3].startswith(".") or ln[1:3].startswith(")")):
                # remove leading "1." or "1)"
                prompts.append(ln.split(".", 1)[1].strip() if "." in ln else ln.split(")", 1)[1].strip())
            else:
                prompts.append(ln)

            if len(prompts) >= n:
                break

        # If we don't have enough, try splitting by double newline blocks
        if len(prompts) < n:
            blocks = [b.strip() for b in raw_text.split("\n\n") if b.strip()]
            for b in blocks:
                if b not in prompts:
                    prompts.append(b)
                if len(prompts) >= n:
                    break

        # Clean prompts (truncate to a reasonable length)
        prompts = [p.replace('"', '').strip() for p in prompts if p.strip()]
        return prompts[:n]

    except Exception as e:
        app.logger.exception("generate_theme_prompts_via_llm failed")
        # Fallback: generate simple deterministic themes
        fallback = [
            f"{base_prompt} — Theme: Connectivity & Lifestyle Integration. Photorealistic people-centric scene, 1:1.",
            f"{base_prompt} — Theme: Technological Advancement & Network Power. Futuristic map of India, 1:1.",
            f"{base_prompt} — Theme: JioApps Ecosystem & Digital Life. Devices and app icons, 1:1.",
        ]
        return fallback[:n]


@app.route("/api/v1/generate-3-themes-ai", methods=["POST"])
def generate_3_themes_ai():
    """
    Generates `num_themes` theme prompts using the LLM, then creates images for each theme concurrently.

    Payload (JSON):
    {
      "prompt": "Base prompt / brief for the ad",
      "workspace_details": { ... },    # optional
      "num_themes": 3,                 # optional, default 3
      "num_candidates": 1,             # candidates per theme image
      "image_model": "gemini-2.5-flash-image"  # optional
    }

    Response:
    {
      "success": True,
      "themes": [
         {"theme_prompt": "...", "results": {...}}
      ]
    }
    """
    try:
        body = request.get_json(silent=True) or {}
        base_prompt = (body.get("prompt") or "").strip() or "Create a Meta ad creative that well describes this business."
        workspace_details = body.get("workspace_details") or {}
        num_themes = int(body.get("num_themes") or DEFAULT_NUM_THEMES)
        num_themes = max(1, min(num_themes, MAX_THEMES))
        num_candidates = int(body.get("num_candidates") or 1)
        image_model = body.get("image_model") or IMAGE_MODEL

        # 1) Ask the LLM to produce the theme prompts
        themes = generate_theme_prompts_via_llm(base_prompt, workspace_details, n=num_themes)

        # Safety: ensure we have at least 1 theme
        if not themes:
            themes = generate_theme_prompts_via_llm(base_prompt, workspace_details, n=DEFAULT_NUM_THEMES)

        # prepare worker for each theme
        def gen_for_theme(idx: int, theme_prompt: str):
            start = time.time()
            try:
                # Use existing helper generate_image_candidates if present
                if "generate_image_candidates" in globals():
                    candidates = generate_image_candidates(theme_prompt, model_id=image_model, n=num_candidates)
                else:
                    # Minimal fallback: call GENAI_CLIENT directly (adapt to your SDK)
                    if "GENAI_CLIENT" in globals():
                        client = GENAI_CLIENT
                    else:
                        from google import genai
                        client = genai.Client(vertexai=True, api_key=os.environ.get("GOOGLE_CLOUD_API_KEY"))

                    # Build a content payload suitable for image generation model in your environment
                    contents = [
                        {"role": "user", "content": theme_prompt}
                    ]
                    gen_call = client.models.generate_content(
                        model=image_model,
                        contents=contents,
                        response_modalities=["IMAGE", "TEXT"],
                        max_output_tokens=32768,
                        temperature=1.0
                    )
                    candidates = getattr(gen_call, "candidates", [gen_call])

                # Save results using your helper if available
                saved_files = []
                urls = []
                if "save_images_from_response" in globals():
                    saved_files = save_images_from_response(candidates, prefix=f"ai_theme_{idx}")
                    # optionally derive CDN URLs if you have SPACE_CDN / SPACE_BASE configured
                    if 'SPACE_CDN' in globals() and saved_files:
                        urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved_files]
                else:
                    # Fallback: try to extract image bytes from candidates and write to disk
                    saved_files = []
                    if hasattr(candidates, "__iter__"):
                        for i, c in enumerate(candidates):
                            # common pattern: c.output[0].content (base64) OR c.binary
                            b64 = None
                            # defensive attribute checks
                            if getattr(c, "image_base64", None):
                                b64 = c.image_base64
                            else:
                                # try content text that contains base64
                                text = getattr(c, "content", None) or getattr(c, "text", None) or str(c)
                                if "data:image" in text or "base64" in text:
                                    # crude extractions - find first base64 blob
                                    import re
                                    m = re.search(r"base64,([A-Za-z0-9+/=]+)", text)
                                    if m:
                                        b64 = m.group(1)
                            if b64:
                                fn = f"ai_theme_{idx}_{i}.png"
                                with open(fn, "wb") as fh:
                                    fh.write(base64.b64decode(b64))
                                saved_files.append(fn)
                    # no urls in fallback
                duration = time.time() - start
                return {"ok": True, "theme_index": idx, "prompt": theme_prompt, "files": saved_files, "urls": urls, "duration_s": duration}
            except Exception as exc:
                app.logger.exception("gen_for_theme failed for idx=%s", idx)
                return {"ok": False, "theme_index": idx, "prompt": theme_prompt, "error": str(exc)}

        # 2) Run image generation concurrently (cap workers)
        results = []
        with ThreadPoolExecutor(max_workers=min(len(themes), 6)) as ex:
            futures = {ex.submit(gen_for_theme, i, t): i for i, t in enumerate(themes)}
            for fut in as_completed(futures):
                results.append(fut.result())

        # Attach themes + results in order
        # Map results by index to preserve original order
        results_by_idx = {r.get("theme_index", i): r for i, r in enumerate(results)}
        ordered = [results_by_idx.get(i, {"ok": False, "theme_index": i, "prompt": themes[i]}) for i in range(len(themes))]

        return jsonify({"success": True, "themes": [{"prompt": themes[i], "result": ordered[i]} for i in range(len(themes))]}), 200

    except Exception as e:
        app.logger.exception("generate_3_themes_ai failed")
        return jsonify({"success": False, "error": str(e)}), 500
