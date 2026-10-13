"""
FlowSentry AI - System Configuration
Centralized configuration for transaction simulator, detection engine,
AI root-cause detective, and recovery agent.
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.environ.get("FLOWSENTRY_DB_PATH", str(BASE_DIR / "flowsentry.db"))

# Server & Environment Settings
ENV = os.environ.get("FLOWSENTRY_ENV", "production").lower()
HOST = os.environ.get("FLOWSENTRY_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLOWSENTRY_PORT", "5000"))
# Production safety: Disable debug mode by default unless explicitly in development
DEBUG = (ENV == "development") and os.environ.get("FLOWSENTRY_DEBUG", "False").lower() in ("true", "1")

# Rate Limiting & Security Controls
RATE_LIMIT_MAX_PER_MINUTE = int(os.environ.get("FLOWSENTRY_RATE_LIMIT", "120"))
CSRF_ENABLED = True

# AI Settings
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash").strip()
AI_TIMEOUT_SECONDS = 8

# SLA & Latency Thresholds (in milliseconds)
SLA_THRESHOLDS_MS = {
    "auth": 400,
    "cart": 500,
    "inventory": 800,
    "payment_auth": 1200,
    "payment_confirm": 1500,
    "order_create": 1000,
    "default": 1200
}

# Failure Scenarios definitions
SCENARIOS = {
    "NONE": {
        "id": "NONE",
        "name": "Healthy Checkout (Baseline)",
        "description": "All 6 transaction services operate within optimal SLA (<250ms total).",
        "category": "Normal",
        "severity": "NORMAL"
    },
    "PAYMENT_TIMEOUT": {
        "id": "PAYMENT_TIMEOUT",
        "name": "Payment Confirmation Gateway Timeout",
        "description": "Payment authorization succeeds, but payment confirmation hangs (>2500ms) with 504 Gateway Timeout while infrastructure pings remain 200 OK.",
        "category": "Third-Party Integration / Async Lock",
        "severity": "CRITICAL",
        "target_step": "payment_confirm"
    },
    "INVENTORY_FAILURE": {
        "id": "INVENTORY_FAILURE",
        "name": "Inventory Lock Contention / SKU Depleted",
        "description": "Concurrent checkout requests cause reservation lock timeout (409 Conflict) on inventory fulfillment node.",
        "category": "Distributed State / Concurrency",
        "severity": "HIGH",
        "target_step": "inventory"
    },
    "DB_LATENCY": {
        "id": "DB_LATENCY",
        "name": "Order Persistence Database Bottleneck",
        "description": "Order creation step suffers 2400ms latency exceeding strict 1000ms SLA due to unindexed connection pool exhaustion.",
        "category": "Infrastructure Performance",
        "severity": "MEDIUM",
        "target_step": "order_create"
    },
    "INTERMITTENT_API": {
        "id": "INTERMITTENT_API",
        "name": "Intermittent Gateway 503 Service Unavailable",
        "description": "Payment authorization microservice rejects request with transient 503 Bad Gateway due to upstream token revocation.",
        "category": "Microservice Resilience",
        "severity": "HIGH",
        "target_step": "payment_auth"
    },
    "AUTH_FAILURE": {
        "id": "AUTH_FAILURE",
        "name": "User Login & Identity Provider Failure",
        "description": "User authentication session rejected due to expired OAuth credentials / Identity Provider authentication signature mismatch (HTTP 401).",
        "category": "Identity & Access Management",
        "severity": "HIGH",
        "target_step": "auth"
    }
}

# Recovery Safeguards
MAX_RETRIES = 3
CIRCUIT_BREAKER_RESET_SEC = 30
IDEMPOTENCY_PREFIX = "fs_idem_"
