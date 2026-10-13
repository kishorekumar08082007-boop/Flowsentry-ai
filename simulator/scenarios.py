"""
FlowSentry AI - Scenario Definitions
Defines reproducible business transactions, failure vectors, and simulated logs.
"""
from typing import Dict, Any

SCENARIO_PROFILES: Dict[str, Dict[str, Any]] = {
    "NONE": {
        "id": "NONE",
        "name": "Healthy Checkout (Baseline)",
        "description": "Standard eCommerce checkout with all 6 microservices responding well within SLA (<250ms total).",
        "category": "Baseline",
        "severity": "NORMAL",
        "steps": {
            "auth": {
                "latency_range": (30, 45),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/auth/verify - 200 OK",
                    "User session valid: usr_sentry_889 (token exp: 3600s)",
                    "Customer KYC & risk tier: Tier-1 Verified"
                ],
                "metadata": {"user_id": "usr_sentry_889", "session_id": "sess_89182"}
            },
            "cart": {
                "latency_range": (20, 35),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/cart/lock - 200 OK",
                    "Cart items verified: [SKU-PRO-981, SKU-ACC-110]",
                    "Subtotal: $149.00 USD, Tax: $12.50 USD, Total: $161.50 USD"
                ],
                "metadata": {"cart_id": "cart_9918", "total_amount": 161.50, "currency": "USD"}
            },
            "inventory": {
                "latency_range": (40, 60),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/inventory/reserve - 200 OK",
                    "Node US-EAST-1 reserved SKU-PRO-981 (qty: 1)",
                    "Reservation lock acquired: lock_inv_7721 (ttl: 600s)"
                ],
                "metadata": {"reservation_lock": "lock_inv_7721", "warehouse": "US-EAST-1"}
            },
            "payment_auth": {
                "latency_range": (35, 50),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/payments/authorize - 200 OK",
                    "Card verification: Visa ending in 4242",
                    "Pre-auth token issued: tok_auth_9102 (held $161.50)"
                ],
                "metadata": {"preauth_token": "tok_auth_9102", "authorized_amount": 161.50}
            },
            "payment_confirm": {
                "latency_range": (25, 40),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/payments/capture - 200 OK",
                    "Idempotency-Key: fs_idem_baseline_01",
                    "Settlement acknowledgment received: tx_chrg_88190",
                    "Payment capture confirmed in 32ms"
                ],
                "metadata": {"charge_id": "tx_chrg_88190", "status": "captured"}
            },
            "order_create": {
                "latency_range": (15, 25),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/orders/commit - 201 Created",
                    "Order created: ORD-2026-90412",
                    "Dispatched async message: order.created to Fulfillment Queue",
                    "Confirmation notification sent to user"
                ],
                "metadata": {"order_id": "ORD-2026-90412", "status": "CONFIRMED"}
            }
        }
    },

    "PAYMENT_TIMEOUT": {
        "id": "PAYMENT_TIMEOUT",
        "name": "Payment Confirmation Gateway Timeout",
        "description": "Payment authorization succeeds, but payment confirmation hangs (>2500ms) with 504 Gateway Timeout while infrastructure pings remain 200 OK.",
        "category": "Third-Party Integration / Async Lock",
        "severity": "CRITICAL",
        "target_step": "payment_confirm",
        "steps": {
            "auth": {
                "latency_range": (30, 45),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/auth/verify - 200 OK",
                    "User session valid: usr_sentry_889",
                    "Customer KYC verified"
                ],
                "metadata": {"user_id": "usr_sentry_889"}
            },
            "cart": {
                "latency_range": (25, 38),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/cart/lock - 200 OK",
                    "Cart lock acquired: $149.00 USD total"
                ],
                "metadata": {"cart_id": "cart_9918", "total_amount": 149.00}
            },
            "inventory": {
                "latency_range": (45, 65),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/inventory/reserve - 200 OK",
                    "Reservation lock acquired: lock_inv_8820"
                ],
                "metadata": {"reservation_lock": "lock_inv_8820"}
            },
            "payment_auth": {
                "latency_range": (40, 55),
                "status": "SUCCESS",
                "logs": [
                    "POST /api/v1/payments/authorize - 200 OK",
                    "Card token verified: tok_auth_88291",
                    "Pre-auth hold registered for $149.00 USD"
                ],
                "metadata": {"preauth_token": "tok_auth_88291", "amount": 149.00}
            },
            "payment_confirm": {
                "latency_range": (2400, 2600),
                "status": "FAILED",
                "error_code": "GATEWAY_CONFIRMATION_TIMEOUT",
                "error_message": "HTTP 504 Gateway Timeout: Upstream payment capture socket timed out after 2500ms",
                "logs": [
                    "POST /api/v1/payments/capture - Dispatching capture request...",
                    "Idempotency-Key sent: fs_idem_timeout_981",
                    "Healthcheck ping to gateway host api.stripe.mock: 200 OK (latency: 14ms)",
                    "WARN: Upstream capture worker unacknowledged after 1500ms (SLA breach)",
                    "ERROR: TCP socket read timeout exceeded at 2500ms threshold",
                    "FATAL: Gateway returned HTTP 504 Gateway Timeout. Funds state in limbo!"
                ],
                "metadata": {
                    "idempotency_key": "fs_idem_timeout_981",
                    "preauth_token": "tok_auth_88291",
                    "upstream_health": "200_OK_SHALLOW",
                    "transaction_state": "UNCERTAIN_CAPTURE"
                }
            },
            "order_create": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_PRECONDITION_FAILED",
                "error_message": "Order creation aborted because payment confirmation failed.",
                "logs": [
                    "SKIP: Precondition failed - payment confirmation status is FAILED",
                    "Rollback trigger withheld pending idempotent reconciliation"
                ],
                "metadata": {}
            }
        }
    },

    "INVENTORY_FAILURE": {
        "id": "INVENTORY_FAILURE",
        "name": "Inventory Lock Contention / SKU Depleted",
        "description": "Concurrent checkout requests cause reservation lock timeout (409 Conflict) on inventory fulfillment node.",
        "category": "Distributed State / Concurrency",
        "severity": "HIGH",
        "target_step": "inventory",
        "steps": {
            "auth": {
                "latency_range": (30, 42),
                "status": "SUCCESS",
                "logs": ["POST /api/v1/auth/verify - 200 OK", "User session valid: usr_sentry_889"],
                "metadata": {"user_id": "usr_sentry_889"}
            },
            "cart": {
                "latency_range": (22, 35),
                "status": "SUCCESS",
                "logs": ["POST /api/v1/cart/lock - 200 OK", "Cart items: [SKU-PRO-981]"],
                "metadata": {"cart_id": "cart_9918", "total_amount": 149.00}
            },
            "inventory": {
                "latency_range": (750, 950),
                "status": "FAILED",
                "error_code": "INVENTORY_LOCK_CONFLICT",
                "error_message": "HTTP 409 Conflict: Row-level lock contention on SKU-PRO-981. Warehouse node busy.",
                "logs": [
                    "POST /api/v1/inventory/reserve - Requesting lock on SKU-PRO-981",
                    "Acquiring distributed lock on cluster node Redis-INV-02",
                    "WARN: Lock acquisition blocked by competing worker thread tx_lock_441",
                    "ERROR: Distributed lock acquisition timeout reached (850ms)",
                    "HTTP 409 Conflict: Unable to reserve inventory units safely"
                ],
                "metadata": {"sku": "SKU-PRO-981", "lock_cluster": "Redis-INV-02"}
            },
            "payment_auth": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_INVENTORY_UNAVAILABLE",
                "error_message": "Payment authorization aborted: inventory not secured.",
                "logs": ["SKIP: Cannot authorize payment without inventory reservation"],
                "metadata": {}
            },
            "payment_confirm": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_INVENTORY_UNAVAILABLE",
                "error_message": "Payment confirmation skipped.",
                "logs": ["SKIP: Step aborted"],
                "metadata": {}
            },
            "order_create": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_INVENTORY_UNAVAILABLE",
                "error_message": "Order creation skipped.",
                "logs": ["SKIP: Step aborted"],
                "metadata": {}
            }
        }
    },

    "DB_LATENCY": {
        "id": "DB_LATENCY",
        "name": "Order Persistence Database Latency Breach",
        "description": "Order creation step suffers 2400ms latency exceeding strict 1000ms SLA due to connection pool saturation.",
        "category": "Infrastructure Performance",
        "severity": "MEDIUM",
        "target_step": "order_create",
        "steps": {
            "auth": {"latency_range": (30, 42), "status": "SUCCESS", "logs": ["Session valid"], "metadata": {}},
            "cart": {"latency_range": (20, 32), "status": "SUCCESS", "logs": ["Cart locked"], "metadata": {}},
            "inventory": {"latency_range": (45, 55), "status": "SUCCESS", "logs": ["Inventory reserved"], "metadata": {}},
            "payment_auth": {"latency_range": (38, 48), "status": "SUCCESS", "logs": ["Payment authorized"], "metadata": {}},
            "payment_confirm": {"latency_range": (32, 45), "status": "SUCCESS", "logs": ["Payment captured: tx_chrg_7781"], "metadata": {}},
            "order_create": {
                "latency_range": (2300, 2550),
                "status": "DEGRADED",
                "error_code": "LATENCY_SLA_BREACH",
                "error_message": "SLA Violation: Order persistence took 2410ms (Threshold: 1000ms). Database connection pool queue saturation.",
                "logs": [
                    "POST /api/v1/orders/commit - Opening SQL transaction...",
                    "WARN: Database connection pool 'orders_cluster_rw' 100% saturated (50/50 active connections)",
                    "Wait time in connection queue: 1980ms",
                    "Transaction committed after 2410ms total latency",
                    "ALERT: SLA threshold 1000ms breached. Transaction flagged for recovery triage."
                ],
                "metadata": {"pool_saturation": "100%", "queue_wait_ms": 1980, "order_id": "ORD-DEGRADED-102"}
            }
        }
    },

    "INTERMITTENT_API": {
        "id": "INTERMITTENT_API",
        "name": "Intermittent Gateway 503 Service Unavailable",
        "description": "Payment authorization microservice rejects request with transient 503 due to upstream gateway worker restart.",
        "category": "Microservice Resilience",
        "severity": "HIGH",
        "target_step": "payment_auth",
        "steps": {
            "auth": {"latency_range": (30, 42), "status": "SUCCESS", "logs": ["Session valid"], "metadata": {}},
            "cart": {"latency_range": (20, 32), "status": "SUCCESS", "logs": ["Cart locked"], "metadata": {}},
            "inventory": {"latency_range": (45, 55), "status": "SUCCESS", "logs": ["Inventory reserved"], "metadata": {}},
            "payment_auth": {
                "latency_range": (280, 360),
                "status": "FAILED",
                "error_code": "SERVICE_503_UNAVAILABLE",
                "error_message": "HTTP 503 Service Unavailable: Payment routing worker restarting. Connection dropped.",
                "logs": [
                    "POST /api/v1/payments/authorize - Routing to gateway node gw-east-04",
                    "HTTP/1.1 503 Service Unavailable (Retry-After: 2s)",
                    "Upstream server error: Pod memory limit reached, restarting pod",
                    "Downstream client transaction aborted prematurely"
                ],
                "metadata": {"target_gateway": "gw-east-04", "retry_after": 2}
            },
            "payment_confirm": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_PAYMENT_UNAUTHORIZED",
                "error_message": "Payment confirmation skipped.",
                "logs": ["SKIP: Preceding auth step failed"],
                "metadata": {}
            },
            "order_create": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_PAYMENT_UNAUTHORIZED",
                "error_message": "Order creation skipped.",
                "logs": ["SKIP: Preceding auth step failed"],
                "metadata": {}
            }
        }
    },

    "AUTH_FAILURE": {
        "id": "AUTH_FAILURE",
        "name": "User Login & Identity Provider Failure",
        "description": "User authentication session rejected due to expired OAuth credentials / Identity Provider authentication signature mismatch (HTTP 401).",
        "category": "Identity & Access Management",
        "severity": "HIGH",
        "target_step": "auth",
        "steps": {
            "auth": {
                "latency_range": (380, 480),
                "status": "FAILED",
                "error_code": "AUTH_CREDENTIALS_INVALID",
                "error_message": "HTTP 401 Unauthorized: User login session expired or JWT signature mismatch in Identity Provider.",
                "logs": [
                    "POST /api/v1/auth/login - Processing login request for usr_sentry_889",
                    "Connecting to OAuth Identity Provider (IdP) auth.sentry.internal...",
                    "WARN: Token verification failed: RSA-256 JWT signature verification failure",
                    "ERROR: HTTP 401 Unauthorized - Invalid credentials or revoked token",
                    "FATAL: User login rejected. Business transaction pipeline aborted at step 01 (Auth)"
                ],
                "metadata": {
                    "attempted_user": "usr_sentry_889",
                    "auth_protocol": "OIDC/OAuth2",
                    "http_status": 401,
                    "idp_cluster": "auth-idp-01.internal"
                }
            },
            "cart": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_UNAUTHENTICATED",
                "error_message": "Cart locking skipped: User unauthenticated.",
                "logs": ["SKIP: Cannot initialize shopping cart for unauthenticated session"],
                "metadata": {}
            },
            "inventory": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_UNAUTHENTICATED",
                "error_message": "Inventory check skipped.",
                "logs": ["SKIP: Preceding auth step failed"],
                "metadata": {}
            },
            "payment_auth": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_UNAUTHENTICATED",
                "error_message": "Payment authorization skipped.",
                "logs": ["SKIP: Preceding auth step failed"],
                "metadata": {}
            },
            "payment_confirm": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_UNAUTHENTICATED",
                "error_message": "Payment confirmation skipped.",
                "logs": ["SKIP: Preceding auth step failed"],
                "metadata": {}
            },
            "order_create": {
                "latency_range": (0, 0),
                "status": "SKIPPED",
                "error_code": "ABORTED_UNAUTHENTICATED",
                "error_message": "Order creation skipped.",
                "logs": ["SKIP: Preceding auth step failed"],
                "metadata": {}
            }
        }
    }
}
