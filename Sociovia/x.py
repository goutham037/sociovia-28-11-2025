"""
save_streamed_images_full.py

Usage:
  export GOOGLE_CLOUD_API_KEY="your_key_here"
  # Optional (if using service account file):
  # export GOOGLE_APPLICATION_CREDENTIALS="/path/to/creds.json"
  python save_streamed_images_full.py

This script:
 - Calls genai.Client(...).models.generate_content_stream(...)
 - Inspects each chunk for image data (bytes, base64 strings, nested fields)
 - Supports assembling multi-part images if chunks include an "image_id" and "part_index" / "is_final" style fields
 - Writes images to outputs/ with unique filenames and prints saved paths
"""

import os
import base64
import uuid
import json
import sys
from typing import Optional

# genai import may raise if not installed
try:
    from google import genai
    from google.genai import types
    # HttpOptions for explicit client options
    from google.genai.types import HttpOptions
except Exception as e:
    print("Failed to import google.genai. Install official SDK and ensure Python environment is correct.")
    print("Exception:", e)
    sys.exit(1)


OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _save_bytes(data: bytes, prefix="image", ext=".png") -> str:
    """Write raw bytes to a uniquely named file and return its path."""
    fname = f"{prefix}_{uuid.uuid4().hex[:8]}{ext}"
    path = os.path.join(OUTPUT_DIR, fname)
    with open(path, "wb") as f:
        f.write(data)
    print("Saved:", path)
    return path


def _try_decode_base64(s: str) -> Optional[bytes]:
    """Attempt to decode a base64 string; supports data:<mime>;base64,... prefixes."""
    if not isinstance(s, str):
        return None
    try:
        if s.startswith("data:") and "base64," in s:
            s = s.split("base64,", 1)[1]
        # strip whitespace/newlines
        s_clean = "".join(s.split())
        return base64.b64decode(s_clean)
    except Exception:
        return None


def _infer_extension_from_mime(mime: Optional[str]) -> str:
    if not mime:
        return ".png"
    mime = mime.lower()
    if "png" in mime:
        return ".png"
    if "jpeg" in mime or "jpg" in mime:
        return ".jpg"
    if "webp" in mime:
        return ".webp"
    if "gif" in mime:
        return ".gif"
    return ".png"


class StreamImageSaver:
    """
    Stateful helper to accumulate multi-part images if needed.
    """

    def __init__(self):
        # accumulators: image_id -> dict with {'parts': {index: bytes}, 'mime': str}
        self.accumulators = {}

    def _save_or_accumulate(self, candidate, meta=None):
        if candidate is None:
            return False

        # If meta provides image_id and part_index, assemble
        if meta and meta.get("image_id") and ("part_index" in meta or "is_final" in meta):
            image_id = str(meta["image_id"])
            part_index = int(meta.get("part_index", 0))
            mime = meta.get("mime_type") or meta.get("mime") or None
            acc = self.accumulators.setdefault(image_id, {"parts": {}, "mime": mime})
            acc["parts"][part_index] = candidate
            if mime and not acc.get("mime"):
                acc["mime"] = mime
            # if flagged final, write assembled file
            if meta.get("is_final") or meta.get("final", False):
                ordered_bytes = bytearray()
                for idx in sorted(acc["parts"].keys()):
                    ordered_bytes.extend(acc["parts"][idx])
                ext = _infer_extension_from_mime(acc.get("mime"))
                _save_bytes(bytes(ordered_bytes), prefix=f"image_{image_id}", ext=ext)
                del self.accumulators[image_id]
            return True

        # No accumulation metadata — save immediately
        _save_bytes(candidate)
        return True

    def inspect_and_handle_chunk(self, chunk) -> bool:
        """
        Inspect chunk (proto-like object), find image bytes/base64, and save/accumulate.
        Returns True if any image was saved/queued from this chunk.
        """
        common_field_names = [
            "image", "image_bytes", "bytes", "b64", "base64", "blob", "content", "data",
            "parts", "output", "image_data", "image_base64", "raw"
        ]

        def try_extract_bytes(val):
            if isinstance(val, (bytes, bytearray)):
                return bytes(val)
            if isinstance(val, str):
                decoded = _try_decode_base64(val)
                if decoded:
                    return decoded
                try:
                    parsed = json.loads(val)
                    found = walk_and_find(parsed)
                    if isinstance(found, (bytes, bytearray)):
                        return bytes(found)
                except Exception:
                    pass
                return None
            if isinstance(val, dict):
                found = walk_and_find(val)
                if isinstance(found, (bytes, bytearray)):
                    return bytes(found)
            if hasattr(val, "__dict__"):
                try:
                    found = walk_and_find(vars(val))
                    if isinstance(found, (bytes, bytearray)):
                        return bytes(found)
                except Exception:
                    pass
            return None

        def walk_and_find(obj):
            if obj is None:
                return None
            if isinstance(obj, (bytes, bytearray)):
                return bytes(obj)
            if isinstance(obj, str):
                dec = _try_decode_base64(obj)
                if dec:
                    return dec
                return None
            if isinstance(obj, dict):
                for key in ("image", "image_base64", "b64", "data", "blob", "content"):
                    if key in obj:
                        res = walk_and_find(obj[key])
                        if res:
                            return res
                for k, v in obj.items():
                    res = walk_and_find(v)
                    if res:
                        return res
                return None
            if isinstance(obj, (list, tuple)):
                for it in obj:
                    res = walk_and_find(it)
                    if res:
                        return res
                return None
            try:
                for a in dir(obj):
                    if a.startswith("_"):
                        continue
                    try:
                        v = getattr(obj, a)
                        res = walk_and_find(v)
                        if res:
                            return res
                    except Exception:
                        pass
            except Exception:
                pass
            return None

        # try common fields
        for fld in common_field_names:
            if hasattr(chunk, fld):
                val = getattr(chunk, fld)
                if val is None:
                    continue
                if isinstance(val, (list, tuple)):
                    for item in val:
                        candidate = try_extract_bytes(item)
                        if candidate:
                            meta = _extract_meta_from_obj(item)
                            if self._save_or_queue(candidate, meta):
                                return True
                else:
                    candidate = try_extract_bytes(val)
                    if candidate:
                        meta = _extract_meta_from_obj(val)
                        if self._save_or_queue(candidate, meta):
                            return True

        # try to_dict / __dict__ / str
        try:
            payload = None
            if hasattr(chunk, "to_dict"):
                payload = chunk.to_dict()
            else:
                payload = getattr(chunk, "__dict__", None) or str(chunk)
            found = walk_and_find(payload)
            if found:
                meta = _extract_meta_from_obj(payload)
                if self._save_or_queue(found, meta):
                    return True
        except Exception:
            pass

        # try chunk.text (some streams include base64 or JSON in text)
        try:
            if hasattr(chunk, "text") and isinstance(chunk.text, str) and chunk.text.strip():
                txt = chunk.text.strip()
                dec = _try_decode_base64(txt)
                if dec:
                    if self._save_or_queue(dec, None):
                        return True
                try:
                    parsed = json.loads(txt)
                    found = walk_and_find(parsed)
                    if found:
                        meta = _extract_meta_from_obj(parsed)
                        if self._save_or_queue(found, meta):
                            return True
                except Exception:
                    pass
        except Exception:
            pass

        return False

    def _save_or_queue(self, candidate_bytes: bytes, meta_obj: Optional[dict]):
        meta = {}
        if isinstance(meta_obj, dict):
            meta = meta_obj
        elif hasattr(meta_obj, "__dict__"):
            meta = vars(meta_obj)
        normalized_meta = {}
        for k, v in meta.items():
            normalized_meta[str(k).lower()] = v
        meta_info = {
            "image_id": normalized_meta.get("image_id") or normalized_meta.get("id") or normalized_meta.get("imageid"),
            "part_index": normalized_meta.get("part_index") or normalized_meta.get("index") or normalized_meta.get("chunk_index"),
            "is_final": normalized_meta.get("is_final") or normalized_meta.get("final") or normalized_meta.get("islast"),
            "mime_type": normalized_meta.get("mime_type") or normalized_meta.get("mime") or normalized_meta.get("contenttype"),
        }
        return self._save_or_accumulate(candidate_bytes, meta=meta_info)


def _extract_meta_from_obj(obj):
    if obj is None:
        return {}
    if isinstance(obj, dict):
        keys = {}
        for candidate in ("image_id", "imageId", "id", "part_index", "partIndex", "index", "chunk_index", "is_final", "final", "mime_type", "mime", "content_type"):
            if candidate in obj:
                keys[candidate] = obj[candidate]
        return keys
    meta = {}
    for attr in ("image_id", "imageId", "id", "part_index", "partIndex", "index", "chunk_index", "is_final", "final", "mime_type", "mime", "content_type"):
        if hasattr(obj, attr):
            try:
                meta[attr] = getattr(obj, attr)
            except Exception:
                pass
    return meta


def init_client(api_key: Optional[str]):
    project = os.environ.get("GCP_PROJECT") or os.environ.get("PROJECT_ID") or "angular-sorter-473216-k8"
    location = os.environ.get("GOOGLE_CLOUD_LOCATION") or "global"
    adc_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    print("[env] GCP_PROJECT:", project)
    print("[env] LOCATION:", location)
    print("[env] ADC PATH SET:", bool(adc_path))
    try:
        # Provide api_key explicitly (if SDK supports it); else SDK will use ADC.
        client_kwargs = {"vertexai": True}
        if api_key:
            client_kwargs["api_key"] = api_key
        # optional http options example (not required)
        client = genai.Client(
            http_options=HttpOptions(api_version="v1"),
            **client_kwargs,
            project=project,
            location=location,
        )
        print("[startup] genai.Client initialized (Vertex mode).")
        return client
    except Exception as e:
        print("[startup] genai.Client init FAILED:", e)
        return None


def generate_and_save():
    """
    Main function: builds the client and streams from the model, saving images.
    """
    api_key = os.environ.get("GOOGLE_CLOUD_API_KEY")
    if not api_key:
        print("WARNING: GOOGLE_CLOUD_API_KEY not set. The client will attempt to use ADC (service account) if available.")
    client = init_client(api_key)

    if client is None:
        print("Client initialization failed; exiting.")
        return

    # Clean prompt text (avoid broken JSON fragments). Use only textual workspace context.
    msg_text = (
        "create a meta ad creative that well describes my business\n"
        "Workspace Details (JSON): "
        "{\"audience_description\":"
        "\"The target audience consists of aspiring software developers, engineering students, and "
        "professional coders who are actively preparing for technical interviews at technology companies, "
        "seeking structured guidance and comprehensive DSA training.\","
        "\"business_name\":\"Smart Interviews\","
        "\"created_at\":\"2025-11-14T11:05:06.890279\","
        "\"creatives_path\":[],"
        "\"description\":\"Smart Interviews is an ed-tech platform that provides comprehensive courses "
        "designed to help coders crack technical interviews and secure their dream jobs. The primary offering "
        "mentioned is the 'Smart Coder (DSA)' course, focusing on data structures and algorithms necessary for "
        "competitive coding interviews.\","
        "\"usp\":\"Helps coders ace their next coding interview by providing comprehensive Data Structures and "
        "Algorithms (DSA) training.\","
        "\"website\":\"https://smartinterviews.in\"}\n"
        "ignore the link specified just use the textual data\n"
        "Please use the workspace context above when generating."
    )

    msg_part = types.Part.from_text(text=msg_text)

    contents = [
        types.Content(
            role="user",
            parts=[msg_part]
        )
    ]

    generate_content_config = types.GenerateContentConfig(
        temperature=1,
        top_p=0.95,
        max_output_tokens=32768,
        response_modalities=["IMAGE"],
        # Keep safety settings as appropriate to your environment.
        safety_settings=[
            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="OFF"),
        ],
    )

    model = "gemini-2.5-flash-image"
    saver = StreamImageSaver()

    print("Starting stream from model:", model)
    stream = client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    )

    count = 0
    for chunk in stream:
        count += 1
        # small diagnostics
        if hasattr(chunk, "delta") and getattr(chunk, "delta"):
            print(f"[chunk {count}] delta:", getattr(chunk, "delta", "") or getattr(chunk, "text", "") or "")
        else:
            if hasattr(chunk, "text"):
                txt = (chunk.text or "")[:160]
                if txt:
                    print(f"[chunk {count}] text snippet:", txt.replace("\n", " ")[:160])

        handled = False
        try:
            handled = saver.inspect_and_handle_chunk(chunk)
        except Exception as e:
            print("Error inspecting chunk:", e)

        if not handled:
            try:
                r = repr(chunk)
                print(f"[chunk {count}] No image found in chunk. repr (truncated): {r[:400]}")
            except Exception:
                print(f"[chunk {count}] No image found in chunk; unable to repr this chunk.")

    print("Stream completed.")


if __name__ == "__main__":
    generate_and_save()
