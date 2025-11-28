# assistant_ai.py

import os
import time
from typing import Any, Dict, List
from flask import Blueprint, request, jsonify, current_app
from dotenv import load_dotenv
from models import db, User, Workspace, SocialAccount
from test import init_client
from google import genai  # google-genai SDK

# ----------------- ENV & GEMINI SETUP -----------------

load_dotenv()

client = init_client()
# ----------------- BLUEPRINT -----------------

assistant_bp = Blueprint("assistant", __name__)

# ----------------- HELPERS -----------------


def _safe_get(data: Dict, key: str, default: Any = None) -> Any:
    return data.get(key, default)


def build_db_context(user_id: int, workspace_id: int) -> Dict[str, Any]:
    """
    Load User, Workspace, SocialAccounts, and any basic analytics-like context
    from your existing models.
    """
    user = User.query.get(user_id)
    if not user:
        raise ValueError("User not found")

    workspace = (
        Workspace.query.filter_by(id=workspace_id, user_id=user.id).first()
    )
    if not workspace:
        raise ValueError("Workspace not found for this user")

    social_accounts = SocialAccount.query.filter_by(user_id=user.id).all()

    # Simplified social account summary
    social_summary = [
        {
            "id": sa.id,
            "provider": sa.provider,
            "account_name": sa.account_name,
            "instagram_business_id": sa.instagram_business_id,
            "has_token": bool(sa.access_token),
        }
        for sa in social_accounts
    ]

    # 👉 Placeholder analytics:
    # Right now we don't have campaigns/leads tables in the models you shared.
    # This block is designed so you can later plug in real analytics (campaign stats, leads etc.)
    analytics = {
        "has_real_analytics": False,
        "summary": "Analytics models not wired yet. You can extend this to pull campaign/funnel metrics.",
        "notes": [
            "You can compute total ad spend, leads, CTR, etc. from your campaign tables here.",
            "Use this dict to feed real numbers into the prompt once those models exist."
        ],
    }

    context = {
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "business_name": user.business_name,
            "industry": user.industry,
            "status": user.status,
            "email_verified": user.email_verified,
            "phone_verified": user.phone_verified,
        },
        "workspace": {
            "id": workspace.id,
            "business_name": workspace.business_name,
            "business_type": workspace.business_type,
            "registered_address": workspace.registered_address,
            "b2b_b2c": workspace.b2b_b2c,
            "industry": workspace.industry,
            "description": workspace.description,
            "audience_description": workspace.audience_description,
            "website": workspace.website,
            "usp": workspace.usp,
            "competitors": {
                "direct_1": workspace.competitor_direct_1,
                "direct_2": workspace.competitor_direct_2,
                "indirect_1": workspace.competitor_indirect_1,
                "indirect_2": workspace.competitor_indirect_2,
            },
            "logo_path": workspace.logo_path,
        },
        "social_accounts": social_summary,
        "analytics": analytics,
    }

    return context


SYSTEM_PROMPT = """You are Sociovia AI, an assistant that lives inside the Sociovia growth & CRM platform.

You ALWAYS receive:
- Authenticated user profile (name, email, phone, verification status, business_name, industry).
- Current workspace details (business name, type, industry, B2B/B2C, audience, USP, website, competitors).
- Connected social accounts (Facebook/Instagram/pages, etc).
- A basic analytics context dict (can later include real metrics like spend, leads, CTR, etc.).

Your behavior:
- Use the given context to personalize recommendations for this specific user and workspace.
- Don't hallucinate unknown numbers (spend, leads, ROAS, etc.). If not present in analytics, say that data isn't available yet.
- When suggesting actions, tie them to user’s industry, audience and USP.
- If the user asks “my performance”, explain what data is needed and how Sociovia can track it.
- Keep responses concise, practical, and friendly.
"""


def build_prompt_with_context(messages: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
    user = context["user"]
    ws = context["workspace"]
    analytics = context["analytics"]
    social_accounts = context["social_accounts"]

    # --- Context block ---
    lines: List[str] = [SYSTEM_PROMPT, "", "CONTEXT:"]

    # User
    lines.append(
        f"- User: {user.get('name') or 'Unknown'} "
        f"({user.get('email') or 'no-email'}) | phone: {user.get('phone') or 'N/A'}"
    )
    lines.append(
        f"- User status: {user.get('status')} | "
        f"email_verified={user.get('email_verified')} | phone_verified={user.get('phone_verified')}"
    )

    # Workspace
    lines.append(
        f"- Workspace: {ws.get('business_name') or 'Unnamed business'} "
        f"(Industry: {ws.get('industry') or 'N/A'}, Type: {ws.get('business_type') or 'N/A'}, "
        f"Model: {ws.get('b2b_b2c') or 'N/A'})"
    )
    lines.append(f"- Audience: {ws.get('audience_description') or 'Not specified'}")
    lines.append(f"- USP: {ws.get('usp') or 'Not specified'}")
    lines.append(f"- Website: {ws.get('website') or 'N/A'}")

    # Competitors
    comp = ws.get("competitors") or {}
    competitor_list = [
        comp.get("direct_1"),
        comp.get("direct_2"),
        comp.get("indirect_1"),
        comp.get("indirect_2"),
    ]
    competitor_list = [c for c in competitor_list if c]
    if competitor_list:
        lines.append(f"- Competitors: {', '.join(competitor_list)}")
    else:
        lines.append("- Competitors: Not provided")

    # Social accounts
    if social_accounts:
        lines.append("- Connected social accounts:")
        for sa in social_accounts:
            lines.append(
                f"  • {sa['provider']} - {sa.get('account_name') or sa['provider_user_id']} "
                f"(token_present={sa['has_token']})"
            )
    else:
        lines.append("- Connected social accounts: none")

    # Analytics (placeholder for now)
    lines.append("")
    lines.append("Analytics context:")
    lines.append(f"- has_real_analytics: {analytics.get('has_real_analytics')}")
    if "summary" in analytics:
        lines.append(f"- summary: {analytics['summary']}")
    if "notes" in analytics and isinstance(analytics["notes"], list):
        for note in analytics["notes"]:
            lines.append(f"  • {note}")

    # --- Conversation history ---
    lines.append("")
    lines.append("Conversation so far:")

    # Only last 10 messages to keep prompt small
    for msg in messages[-10:]:
        role = msg.get("from") or msg.get("from_role") or "user"
        role_label = {
            "user": "User",
            "bot": "Assistant",
            "system": "System",
        }.get(role, "User")

        text = msg.get("text", "")
        lines.append(f"{role_label}: {text}")

    lines.append("")
    lines.append("Assistant:")

    return "\n".join(lines)


def generate_ai_reply(messages: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
    prompt = build_prompt_with_context(messages, context)

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            generation_config={
                "temperature": 0.55,
                "max_output_tokens": 512,
            },
        )
    except Exception as e:
        current_app.logger.exception("Gemini API error")
        raise RuntimeError(f"Gemini API error: {e}")

    text = getattr(response, "text", None)
    if not text:
        raise RuntimeError("Empty response from Gemini")

    return text.strip()


# ----------------- ROUTES -----------------


@assistant_bp.route("/api/assistant/chat", methods=["POST"])
def assistant_chat():
    """
    Body JSON expected:

    {
      "userId": 1,
      "workspaceId": 10,
      "messages": [
        {
          "id": "user-123",
          "from": "user",
          "text": "hey explain my performance",
          "time": 123456789,
          "type": "text",
          "data": null
        },
        ...
      ]
    }
    """
    data = request.get_json(force=True, silent=True) or {}

    user_id = _safe_get(data, "userId")
    workspace_id = _safe_get(data, "workspaceId")
    messages = _safe_get(data, "messages", [])

    if user_id is None or workspace_id is None:
        return jsonify({"error": "userId and workspaceId are required"}), 400

    if not isinstance(messages, list) or len(messages) == 0:
        return jsonify({"error": "messages[] is required"}), 400

    try:
        # Build DB context
        context = build_db_context(int(user_id), int(workspace_id))

        # Generate reply from Gemini
        reply_text = generate_ai_reply(messages, context)

        # Build a ChatMessage-like object for frontend
        reply_message = {
            "id": f"bot-{int(time.time() * 1000)}",
            "from": "bot",
            "text": reply_text,
            "time": int(time.time() * 1000),
            "type": "text",  # later you can output "chart"/"kpi" and extra data
            "data": None,
        }

        return jsonify({"message": reply_message}), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404
    except Exception as e:
        current_app.logger.exception("Error in assistant_chat")
        return jsonify({"error": str(e)}), 500


@assistant_bp.route("/api/assistant/health", methods=["GET"])
def assistant_health():
    return jsonify({"status": "ok", "model": "gemini-2.5-flash"}), 200
