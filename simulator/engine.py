"""
FlowSentry AI - Transaction Simulator Engine
Executes synthetic business transactions across 6 microservice steps.
Records timings, step logs, diagnostic metadata, and persists to SQLite.
"""
import time
import random
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from simulator.scenarios import SCENARIO_PROFILES
from database import get_db_connection, init_db
from config import SLA_THRESHOLDS_MS

STEP_SEQUENCE = [
    ("auth", 1, "User Authentication"),
    ("cart", 2, "Shopping Cart"),
    ("inventory", 3, "Inventory Validation"),
    ("payment_auth", 4, "Payment Authorization"),
    ("payment_confirm", 5, "Payment Confirmation"),
    ("order_create", 6, "Order Creation")
]

class TransactionSimulator:
    def __init__(self):
        pass

    def run_transaction(
        self, 
        scenario_id: str = "NONE", 
        custom_latency_ms: Optional[int] = None,
        is_replay: bool = False,
        parent_run_id: Optional[str] = None,
        recovery_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a 6-step synthetic business transaction.
        If recovery_context is provided (e.g. during verified replay),
        the failed steps execute healthy recovery logic.
        """
        scenario = SCENARIO_PROFILES.get(scenario_id, SCENARIO_PROFILES["NONE"])
        now_utc = datetime.now(timezone.utc)
        run_id = f"run_{now_utc.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        created_at_iso = now_utc.isoformat()

        steps_result: List[Dict[str, Any]] = []
        overall_status = "SUCCESS"
        total_latency = 0.0
        error_step_name = None

        has_failed = False

        for step_name, step_order, step_label in STEP_SEQUENCE:
            step_profile = scenario["steps"].get(step_name, {})
            step_time = datetime.now(timezone.utc).isoformat()

            # Check if this is a replay with successful recovery applied
            if is_replay and recovery_context and recovery_context.get("applied_recovery"):
                # Replay executes successfully
                step_latency = float(random.randint(25, 45))
                step_status = "SUCCESS"
                step_err_code = None
                step_err_msg = None
                
                # Contextual logs for recovery replay
                if step_name == "payment_confirm" and scenario_id == "PAYMENT_TIMEOUT":
                    step_logs = [
                        f"POST /api/v1/payments/capture - Replaying with Idempotency-Key: {recovery_context.get('idempotency_key')}",
                        "RECONCILIATION: Querying existing gateway capture journal...",
                        "Gateway returned HTTP 200 OK: Existing pre-authorization captured successfully without duplicate charge.",
                        f"Audit trail verified: Charge tx_rec_{uuid.uuid4().hex[:6]} confirmed in {step_latency}ms"
                    ]
                    step_meta = {
                        "idempotency_key": recovery_context.get("idempotency_key"),
                        "reconciled": True,
                        "duplicate_prevented": True
                    }
                elif step_name == "inventory" and scenario_id == "INVENTORY_FAILURE":
                    step_logs = [
                        "POST /api/v1/inventory/reserve - Routing to secondary fulfillment node US-EAST-02",
                        "Backoff window elapsed: Stale lock contention cleared",
                        f"Inventory lock acquired: lock_failover_{uuid.uuid4().hex[:4]}",
                        "SKU-PRO-981 reserved successfully"
                    ]
                    step_meta = {"failover_node": "US-EAST-02", "lock_renewed": True}
                elif step_name == "order_create" and scenario_id == "DB_LATENCY":
                    step_logs = [
                        "POST /api/v1/orders/commit - Read/Write connection pool buffer flushed",
                        "Active connection acquired from refreshed pool in 12ms",
                        f"Order committed: ORD-REC-{uuid.uuid4().hex[:6].upper()}",
                        "Transaction SLA verified: 28ms (Optimal)"
                    ]
                    step_meta = {"pool_repaired": True, "order_id": f"ORD-REC-{uuid.uuid4().hex[:6].upper()}"}
                elif step_name == "payment_auth" and scenario_id == "INTERMITTENT_API":
                    step_logs = [
                        "POST /api/v1/payments/authorize - Circuit Breaker: HALF-OPEN trial query",
                        "Exponential backoff retry attempt #1 with jitter (latency: 35ms)",
                        "Upstream gateway pod restarted & healthy: HTTP 200 OK",
                        "Pre-auth token issued: tok_recovered_990"
                    ]
                    step_meta = {"circuit_state": "CLOSED", "retry_count": 1}
                elif step_name == "auth" and scenario_id == "AUTH_FAILURE":
                    step_logs = [
                        "POST /api/v1/auth/refresh - Refreshing OAuth credentials with Identity Provider...",
                        "Stale session token purged from Redis session cache",
                        "New OAuth JWT token issued: tok_refreshed_8921 (exp: 3600s)",
                        "User identity verified successfully: usr_sentry_889 (Tier-1 Verified)"
                    ]
                    step_meta = {"token_refreshed": True, "auth_status": "AUTHENTICATED", "user_id": "usr_sentry_889"}
                else:
                    step_logs = [f"{step_label} executed successfully during recovery replay"]
                    step_meta = {"recovery_replay": True}

            elif has_failed:
                # If a prior step failed, subsequent steps are skipped
                step_latency = 0.0
                step_status = "SKIPPED"
                step_err_code = "ABORTED_CASCADE"
                step_err_msg = f"Step skipped due to preceding failure in {error_step_name}"
                step_logs = [f"SKIP: Precondition failed because {error_step_name} step encountered an unhandled error."]
                step_meta = {"skipped_reason": f"Cascade from {error_step_name}"}

            else:
                # Normal or injected failure execution
                configured_status = step_profile.get("status", "SUCCESS")
                min_lat, max_lat = step_profile.get("latency_range", (20, 40))
                
                # Apply custom latency if injected for this target step
                if custom_latency_ms is not None and scenario.get("target_step") == step_name:
                    step_latency = float(custom_latency_ms)
                else:
                    step_latency = float(random.randint(min_lat, max_lat))

                step_err_code = step_profile.get("error_code")
                step_err_msg = step_profile.get("error_message")
                step_logs = list(step_profile.get("logs", []))
                step_meta = dict(step_profile.get("metadata", {}))

                # Check for SLA breach detection
                step_sla = SLA_THRESHOLDS_MS.get(step_name, SLA_THRESHOLDS_MS["default"])
                if step_latency > step_sla and configured_status == "SUCCESS":
                    step_status = "DEGRADED"
                    step_err_code = "LATENCY_SLA_BREACH"
                    step_err_msg = f"SLA Violation: Latency {step_latency}ms breached threshold ({step_sla}ms)"
                else:
                    step_status = configured_status

                if step_status in ("FAILED", "DEGRADED"):
                    has_failed = (step_status == "FAILED")
                    if not error_step_name:
                        error_step_name = step_name
                        overall_status = step_status

            total_latency += step_latency
            steps_result.append({
                "step_name": step_name,
                "step_order": step_order,
                "step_label": step_label,
                "status": step_status,
                "latency_ms": round(step_latency, 1),
                "error_code": step_err_code,
                "error_message": step_err_msg,
                "logs": step_logs,
                "metadata": step_meta,
                "created_at": step_time
            })

        if is_replay and recovery_context and recovery_context.get("applied_recovery"):
            overall_status = "RECOVERED"

        # Persist to SQLite
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO workflow_runs (id, scenario, status, total_latency_ms, error_step, is_replay, parent_run_id, is_seed, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (run_id, scenario_id, overall_status, round(total_latency, 1), error_step_name, 1 if is_replay else 0, parent_run_id, created_at_iso))

        for s in steps_result:
            cursor.execute("""
                INSERT INTO workflow_steps (run_id, step_name, step_order, status, latency_ms, error_code, error_message, logs_json, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (run_id, s["step_name"], s["step_order"], s["status"], s["latency_ms"], s["error_code"], s["error_message"], json.dumps(s["logs"]), json.dumps(s["metadata"]), s["created_at"]))

        conn.commit()
        conn.close()

        return {
            "run_id": run_id,
            "scenario": scenario_id,
            "scenario_name": scenario["name"],
            "status": overall_status,
            "total_latency_ms": round(total_latency, 1),
            "error_step": error_step_name,
            "is_replay": is_replay,
            "parent_run_id": parent_run_id,
            "created_at": created_at_iso,
            "steps": steps_result
        }

    def reset_demo(self) -> Dict[str, Any]:
        """Reset database to initial pristine seed demonstration state."""
        init_db(reset=True)
        return {"status": "SUCCESS", "message": "Demo state successfully reset to seed baseline"}

# Global singleton simulator instance
simulator = TransactionSimulator()
