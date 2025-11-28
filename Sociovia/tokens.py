from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app

def get_serializer():
    """Get URLSafeTimedSerializer with current app's secret key"""
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

def make_action_token(payload: dict) -> str:
    """
    Create a signed token containing the payload data
    """
    return get_serializer().dumps(payload)

def load_action_token(token: str, max_age_seconds: int):
    """
    Load and verify a signed token, raising exception if invalid or expired
    """
    try:
        return get_serializer().loads(token, max_age=max_age_seconds)
    except SignatureExpired:
        raise Exception("Token has expired")
    except BadSignature:
        raise Exception("Invalid token signature")
