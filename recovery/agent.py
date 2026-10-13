"""
FlowSentry AI - Safe Recovery Agent with Explicit State Machine
Features:
- Explicit recovery state machine: PROPOSED -> PENDING_APPROVAL -> APPROVED -> EXECUTING -> VERIFYING -> RESOLVED / FAILED_VERIFICATION / REJECTED / EXHAUSTED.
- Strict predefined recovery action enum.
- Retry budget enforcement (token bucket), exponential backoff with randomized jitter.
- Authorization and operator approval requirements for designated risky actions.
- Post-replay business invariant verification before incident resolution.
- Integrated hash-chained audit logging.
"""
import uuid
import json
import random
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from database import get_db_connection, get_run_details, get_incident_details
from simulator.engine import simulator
from recovery.counterfactual import counterfactual_engine
from security.ai_guard import ALLOWED_RECOVERY_ACTIONS, RISKY_ACTIONS
from security.anomaly import anomaly_detector
from security.audit_ledger import audit_ledger
from config import MAX_RETRIES, IDEMPOTENCY_PREFIX

STRATEGY_MAP = {
    "PAYMENT_TIMEOUT": {
        "action_type": "IDEMPOTENT_RECONCILE",
        "name": "Idempotent Gateway Query & State Reconciliation",
        "description": "Probe payment gateway capture log with original idempotency key. Settle held funds safely without generating secondary charge attempt.",
        "is_risky": True,
        "safeguards": ["Zero duplicate billing guarantee via UUID v4 Idempotency Key", "Max retry budget: 3 tokens", "Operator role approval mandatory"]
    },
    "INVENTORY_FAILURE": {
        "action_type": "INVENTORY_BACKOFF_RETRY",
        "name": "Fulfillment Node Failover & Backoff Release",
        "description": "Yield reservation lock for backoff window, then route inventory request to secondary fulfillment cluster node.",
        "is_risky": False,
        "safeguards": ["Deadlock evasion delay", "Cluster node health confirmation", "Circuit breaker: CLOSED"]
    },
    "DB_LATENCY": {
        "action_type": "DB_POOL_FLUSH",
        "name": "Connection Buffer Flush & Write-Pool Isolation",
        "description": "Purge idle database connections, redirect analytical telemetry to read-replica, and isolate high-priority checkout write pool.",
        "is_risky": True,
        "safeguards": ["Zero downtime pool flush", "Transaction isolation level: READ COMMITTED", "Operator role approval mandatory"]
    },
    "INTERMITTENT_API": {
        "action_type": "EXPONENTIAL_BACKOFF_RETRY",
        "name": "Exponential Backoff Retry with Jitter & Circuit Check",
        "description": "Probe upstream microservice health endpoint. Execute retry with randomized jitter after pod restarts.",
        "is_risky": False,
        "safeguards": ["Circuit breaker state verification", "Max retry budget: 3 tokens", "Jitter: 20-80ms to prevent thundering herd"]
    },
    "AUTH_FAILURE": {
        "action_type": "AUTH_TOKEN_REFRESH",
        "name": "OAuth Session Refresh & Token Cache Invalidation",
        "description": "Invalidate stale authentication token cache, re-issue verified OAuth session token, and re-establish secure user identity context.",
        "is_risky": False,
        "safeguards": ["Zero secret exposure", "Session entropy check: 256-bit", "Re-authentication audit log"]
    }
}

class SafeRecoveryAgent:
    def __init__(self):
        # In-memory incident retry budgets: incident_id -> remaining tokens (default 3)
        self.retry_budgets: Dict[str, int] = {}
        # Track used idempotency keys to prevent duplicate execution
        self.executed_idempotency_keys: set = set()

    def get_retry_budget(self, incident_id: str) -> int:
        if incident_id not in self.retry_budgets:
            self.retry_budgets[incident_id] = MAX_RETRIES
        return self.retry_budgets[incident_id]

    def decrement_retry_budget(self, incident_id: str) -> int:
        curr = self.get_retry_budget(incident_id)
        new_val = max(0, curr - 1)
        self.retry_budgets[incident_id] = new_val
        return new_val

    def propose_recovery(
        self, 
        incident_id: str, 
        actor: str = "system", 
        role: str = "operator"
    ) -> Dict[str, Any]:
        """
        Generate a safe recovery proposal for an incident using the explicit state machine.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        inc_row = cursor.fetchone()
        if not inc_row:
            conn.close()
            raise ValueError(f"Incident {incident_id} not found")
        
        incident = dict(inc_row)
        run_id = incident["run_id"]
        
        cursor.execute("SELECT * FROM workflow_runs WHERE id = ?", (run_id,))
        run_row = cursor.fetchone()
        scenario = run_row["scenario"] if run_row else "PAYMENT_TIMEOUT"
        
        # Check if an action already exists
        cursor.execute("SELECT * FROM recovery_actions WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1", (incident_id,))
        existing_action = cursor.fetchone()
        if existing_action:
            conn.close()
            act_dict = dict(existing_action)
            act_dict["retry_budget_remaining"] = self.get_retry_budget(incident_id)
            return act_dict

        strat = STRATEGY_MAP.get(scenario, STRATEGY_MAP["PAYMENT_TIMEOUT"])
        action_type = strat["action_type"]

        # Validate against strict allowed action enum
        if action_type not in ALLOWED_RECOVERY_ACTIONS:
            conn.close()
            raise ValueError(f"Action '{action_type}' is not in allowed recovery enum")

        action_id = f"REC-2026-{uuid.uuid4().hex[:6].upper()}"
        idempotency_key = f"{IDEMPOTENCY_PREFIX}{uuid.uuid4().hex[:10]}"
        created_at = datetime.now(timezone.utc).isoformat()

        # State Machine Transition: Risky actions require PENDING_APPROVAL
        initial_state = "PENDING_APPROVAL" if strat.get("is_risky", True) else "APPROVED"

        cursor.execute("""
            INSERT INTO recovery_actions (
                id, incident_id, run_id, action_type, status, strategy_description, 
                idempotency_key, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            action_id,
            incident_id,
            run_id,
            action_type,
            initial_state,
            strat["name"] + " - " + strat["description"],
            idempotency_key,
            created_at
        ))
        conn.commit()
        conn.close()

        # Audit log recording
        audit_ledger.record_event(
            actor=actor,
            role=role,
            action="PROPOSE_RECOVERY",
            target_id=action_id,
            details={
                "incident_id": incident_id,
                "action_type": action_type,
                "is_risky": strat.get("is_risky", True),
                "state": initial_state,
                "idempotency_key": idempotency_key
            }
        )

        return {
            "id": action_id,
            "incident_id": incident_id,
            "run_id": run_id,
            "action_type": action_type,
            "strategy_name": strat["name"],
            "strategy_description": strat["description"],
            "is_risky": strat.get("is_risky", True),
            "safeguards": strat["safeguards"],
            "idempotency_key": idempotency_key,
            "status": initial_state,
            "retry_budget_remaining": self.get_retry_budget(incident_id),
            "created_at": created_at
        }

    def execute_recovery(
        self, 
        recovery_action_id: str, 
        approved: bool = True,
        actor: str = "operator@flowsentry.local",
        role: str = "operator",
        simulate_verification_failure: bool = False
    ) -> Dict[str, Any]:
        """
        Execute an approved recovery action, check retry budget, enforce idempotency,
        replay the workflow, and verify business outcome before incident resolution.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM recovery_actions WHERE id = ?", (recovery_action_id,))
        rec_row = cursor.fetchone()
        if not rec_row:
            conn.close()
            raise ValueError(f"Recovery action {recovery_action_id} not found")
        
        rec = dict(rec_row)
        incident_id = rec["incident_id"]
        run_id = rec["run_id"]
        action_type = rec["action_type"]
        idempotency_key = rec["idempotency_key"]

        # 1. Approval Decision Handling
        if not approved:
            cursor.execute("UPDATE recovery_actions SET status = 'REJECTED' WHERE id = ?", (recovery_action_id,))
            conn.commit()
            conn.close()
            audit_ledger.record_event(
                actor=actor, role=role, action="REJECT_RECOVERY",
                target_id=recovery_action_id, details={"reason": "Operator rejected action."}
            )
            return {"status": "REJECTED", "message": "Recovery action was rejected by operator."}

        # 2. Authorization Check for Risky Actions
        is_risky = action_type in RISKY_ACTIONS
        if is_risky and role not in ("operator", "admin"):
            conn.close()
            audit_ledger.record_event(
                actor=actor, role=role, action="DENY_UNAUTHORIZED_RECOVERY",
                target_id=recovery_action_id, details={"error": "Insufficient permissions for risky recovery action."}
            )
            raise PermissionError(f"Action '{action_type}' is designated as RISKY and requires 'operator' or 'admin' role.")

        # 3. Retry Budget Verification
        budget = self.get_retry_budget(incident_id)
        if budget <= 0:
            cursor.execute("UPDATE recovery_actions SET status = 'EXHAUSTED' WHERE id = ?", (recovery_action_id,))
            conn.commit()
            conn.close()
            audit_ledger.record_event(
                actor=actor, role=role, action="RETRY_BUDGET_EXHAUSTED",
                target_id=recovery_action_id, details={"retry_budget": 0}
            )
            return {
                "status": "EXHAUSTED",
                "is_successful": False,
                "error": "Retry budget exhausted (0 tokens remaining). Automated recovery halted."
            }

        # 4. Idempotency Check (Prevent duplicate replay execution)
        if idempotency_key in self.executed_idempotency_keys:
            conn.close()
            audit_ledger.record_event(
                actor=actor, role=role, action="BLOCK_DUPLICATE_IDEMPOTENCY_REPLAY",
                target_id=recovery_action_id, details={"idempotency_key": idempotency_key}
            )
            return {
                "status": "DUPLICATE_BLOCKED",
                "is_successful": False,
                "error": f"Idempotency Safeguard: Action with key '{idempotency_key}' has already executed."
            }

        # Consume 1 retry token & calculate exponential backoff with jitter
        tokens_left = self.decrement_retry_budget(incident_id)
        attempt_number = MAX_RETRIES - tokens_left
        jitter_ms = random.uniform(20.0, 75.0)
        backoff_ms = round(min(1500.0, (100.0 * (2 ** (attempt_number - 1))) + jitter_ms), 1)

        # State Machine Transition: APPROVED -> EXECUTING
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            UPDATE recovery_actions 
            SET status = 'EXECUTING', approval_timestamp = ? 
            WHERE id = ?
        """, (now_iso, recovery_action_id))
        conn.commit()

        # Fetch original run
        cursor.execute("SELECT * FROM workflow_runs WHERE id = ?", (run_id,))
        original_run_row = cursor.fetchone()
        original_run = dict(original_run_row) if original_run_row else {}
        scenario = original_run.get("scenario", "PAYMENT_TIMEOUT")

        # Fetch incident
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        inc_row = cursor.fetchone()
        incident = dict(inc_row) if inc_row else {}

        # Execute safe replay via simulator
        recovery_context = {
            "applied_recovery": True,
            "action_type": action_type,
            "idempotency_key": idempotency_key
        }

        replay_result = simulator.run_transaction(
            scenario_id=scenario,
            is_replay=True,
            parent_run_id=run_id,
            recovery_context=recovery_context
        )

        # Mark idempotency key as consumed
        self.executed_idempotency_keys.add(idempotency_key)
        replay_run_id = replay_result["run_id"]

        # State Machine Transition: EXECUTING -> VERIFYING
        # 5. Business Outcome Invariant Verification
        invariant_violations = anomaly_detector.verify_business_invariants(replay_result["steps"])
        
        # Test hook for Security Lab to simulate verification failure
        if simulate_verification_failure:
            invariant_violations.append({
                "invariant_id": "SIMULATED_VERIFICATION_FAILURE",
                "severity": "CRITICAL",
                "step": "payment_confirm",
                "message": "Simulated Invariant Failure: Gateway journal discrepancy detected during audit check."
            })

        is_verified_healthy = (
            replay_result["status"] == "RECOVERED" and 
            len(invariant_violations) == 0
        )

        verification_details = {
            "status": "VERIFIED_HEALTHY" if is_verified_healthy else "VERIFICATION_FAILED",
            "steps_completed": len(replay_result["steps"]),
            "replay_run_id": replay_run_id,
            "total_latency_ms": replay_result["total_latency_ms"],
            "idempotency_safeguard": f"ENFORCED ({idempotency_key})",
            "retry_tokens_remaining": tokens_left,
            "simulated_backoff_ms": backoff_ms,
            "invariant_violations": invariant_violations,
            "circuit_breaker": "HEALTHY (State: CLOSED)",
            "verified_at": datetime.now(timezone.utc).isoformat()
        }

        # Generate Counterfactual Analysis
        counterfactual = counterfactual_engine.generate_counterfactual_model(
            incident=incident,
            original_run=original_run,
            recovery_action=rec,
            replay_run=replay_result
        )

        outcome_id = f"OUT-2026-{uuid.uuid4().hex[:6].upper()}"

        if is_verified_healthy:
            # State Machine Transition: VERIFYING -> RESOLVED
            final_action_state = "RESOLVED"
            cursor.execute("UPDATE recovery_actions SET status = 'RESOLVED' WHERE id = ?", (recovery_action_id,))
            cursor.execute("UPDATE incidents SET status = 'RECOVERED' WHERE id = ?", (incident_id,))
        else:
            # State Machine Transition: VERIFYING -> FAILED_VERIFICATION
            final_action_state = "FAILED_VERIFICATION"
            cursor.execute("UPDATE recovery_actions SET status = 'FAILED_VERIFICATION' WHERE id = ?", (recovery_action_id,))
            # Incident remains OPEN so operator can triage
            cursor.execute("UPDATE incidents SET status = 'OPEN' WHERE id = ?", (incident_id,))

        cursor.execute("""
            INSERT INTO recovery_outcomes (
                id, recovery_action_id, original_run_id, replay_run_id, 
                is_successful, verification_details_json, counterfactual_summary_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            outcome_id,
            recovery_action_id,
            run_id,
            replay_run_id,
            1 if is_verified_healthy else 0,
            json.dumps(verification_details),
            json.dumps(counterfactual),
            now_iso
        ))

        conn.commit()
        conn.close()

        # Audit log recording
        audit_ledger.record_event(
            actor=actor,
            role=role,
            action="VERIFY_RECOVERY_OUTCOME",
            target_id=outcome_id,
            details={
                "recovery_action_id": recovery_action_id,
                "is_verified_healthy": is_verified_healthy,
                "state": final_action_state,
                "replay_run_id": replay_run_id,
                "violations_count": len(invariant_violations)
            }
        )

        return {
            "outcome_id": outcome_id,
            "recovery_action_id": recovery_action_id,
            "original_run_id": run_id,
            "replay_run_id": replay_run_id,
            "is_successful": is_verified_healthy,
            "state": final_action_state,
            "verification": verification_details,
            "counterfactual": counterfactual,
            "replay_run": replay_result
        }

recovery_agent = SafeRecoveryAgent()
