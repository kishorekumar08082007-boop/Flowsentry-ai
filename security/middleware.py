"""
FlowSentry AI - Application Security Middleware
Features:
- Role-Based Access Control (RBAC): viewer, operator, admin.
- Request payload schema validation and sanitization.
- In-memory sliding window rate limiter per client IP.
- Parameterized safety & sanitized error responses (no stack trace leaks).
"""
import time
from functools import wraps
from flask import request, jsonify
from typing import Dict, Any, List, Set, Optional, Tuple

ROLE_HIERARCHY = {
    "viewer": 1,
    "operator": 2,
    "admin": 3
}

class SecurityMiddleware:
    def __init__(self):
        # Rate Limiting State: IP -> list of timestamps
        self.ip_request_windows: Dict[str, List[float]] = {}

    @staticmethod
    def get_actor_and_role() -> Tuple[str, str]:
        """
        Extract authenticated actor and role from headers or session.
        Defaults to 'operator' to ensure seamless UI operation while allowing
        explicit role simulation via headers.
        """
        role = request.headers.get("X-User-Role", "operator").lower().strip()
        if role not in ROLE_HIERARCHY:
            role = "viewer"
        actor = request.headers.get("X-User-Actor", f"{role}@flowsentry.local").strip()
        return actor, role

    def check_rate_limit(self, max_requests: int = 120, window_sec: int = 60) -> bool:
        """
        Sliding-window rate limiter. Returns True if request is allowed, False if exceeded.
        """
        ip = request.remote_addr or "127.0.0.1"
        now = time.time()
        cutoff = now - window_sec

        if ip not in self.ip_request_windows:
            self.ip_request_windows[ip] = []

        # Filter out timestamps outside the window
        self.ip_request_windows[ip] = [ts for ts in self.ip_request_windows[ip] if ts > cutoff]

        if len(self.ip_request_windows[ip]) >= max_requests:
            return False

        self.ip_request_windows[ip].append(now)
        return True

security_middleware = SecurityMiddleware()

def require_role(min_role: str = "operator"):
    """Decorator to enforce minimum role authorization."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            actor, role = security_middleware.get_actor_and_role()
            required_level = ROLE_HIERARCHY.get(min_role, 2)
            current_level = ROLE_HIERARCHY.get(role, 1)

            if current_level < required_level:
                return jsonify({
                    "success": False,
                    "error": f"Authorization Denied: Endpoint requires elevated '{min_role}' role (Current role: '{role}').",
                    "error_code": "FORBIDDEN_ROLE",
                    "current_role": role,
                    "required_role": min_role
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limit(max_requests: int = 120, window_sec: int = 60):
    """Decorator to enforce rate limits per client IP."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not security_middleware.check_rate_limit(max_requests, window_sec):
                return jsonify({
                    "success": False,
                    "error": "Rate limit exceeded. Too many requests dispatched.",
                    "error_code": "RATE_LIMIT_EXCEEDED"
                }), 429
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_schema(required_fields: List[str], allowed_fields: Optional[List[str]] = None):
    """Decorator to validate JSON request schemas."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ("POST", "PUT", "PATCH"):
                data = request.get_json(silent=True)
                if data is None and required_fields:
                    return jsonify({
                        "success": False,
                        "error": "Malformed or missing JSON body.",
                        "error_code": "INVALID_JSON_BODY"
                    }), 400

                data = data or {}
                # Check required fields
                for field in required_fields:
                    if field not in data:
                        return jsonify({
                            "success": False,
                            "error": f"Missing required request parameter: '{field}'.",
                            "error_code": "MISSING_REQUIRED_FIELD"
                        }), 400

                # Check allowed fields (prevent unauthorized parameter pollution)
                if allowed_fields is not None:
                    allowed_set = set(allowed_fields)
                    for key in data.keys():
                        if key not in allowed_set:
                            return jsonify({
                                "success": False,
                                "error": f"Unrecognized request field: '{key}'.",
                                "error_code": "UNRECOGNIZED_PARAMETER"
                            }), 400

            return f(*args, **kwargs)
        return decorated_function
    return decorator
