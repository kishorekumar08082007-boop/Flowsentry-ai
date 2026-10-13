"""
FlowSentry AI - Failure Detection Engine with Rolling MAD Anomaly Detection
Features:
- Rolling-median and MAD-based (Median Absolute Deviation) latency anomaly detection.
- Sufficient-baseline sample size checks with automatic SLA fallback.
- Explicit business invariant checks.
- Audit trail recording for detected incidents.
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from config import SLA_THRESHOLDS_MS
from database import get_db_connection
from security.anomaly import anomaly_detector
from security.audit_ledger import audit_ledger

class FailureDetector:
    def __init__(self, sla_thresholds: Optional[Dict[str, int]] = None):
        self.sla_thresholds = sla_thresholds or SLA_THRESHOLDS_MS

    def _get_historical_latencies(self, step_name: str, limit: int = 15) -> List[float]:
        """Fetch historical latencies for a step from SQLite for rolling baseline."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT latency_ms FROM workflow_steps 
            WHERE step_name = ? AND status IN ('SUCCESS', 'RECOVERED')
            ORDER BY created_at DESC LIMIT ?
        """, (step_name, limit))
        rows = cursor.fetchall()
        conn.close()
        return [float(r["latency_ms"]) for r in rows if r["latency_ms"] is not None]

    def evaluate_run(self, run_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate a transaction execution for failures, statistical latency anomalies (MAD),
        and transactional business invariant breaches.
        """
        steps = run_result.get("steps", [])
        run_id = run_result["run_id"]
        scenario = run_result.get("scenario", "NONE")

        failed_step = None
        degraded_step = None
        sla_breach_step = None
        statistical_anomaly_step = None
        anomaly_meta = None
        error_type = None
        error_message = None

        # 1. Check explicit business invariants
        invariant_violations = anomaly_detector.verify_business_invariants(steps)

        # 2. Step-by-step evaluation
        for step in steps:
            s_name = step["step_name"]
            s_status = step["status"]
            s_latency = step["latency_ms"]
            s_sla = self.sla_thresholds.get(s_name, self.sla_thresholds["default"])

            # Check rolling MAD latency anomaly
            history = self._get_historical_latencies(s_name, limit=15)
            stat_eval = anomaly_detector.evaluate_latency_anomaly(s_latency, history, s_sla)

            if s_status == "FAILED" and not failed_step:
                failed_step = step
                error_type = step.get("error_code") or "GENERIC_EXECUTION_FAILURE"
                error_message = step.get("error_message") or "Microservice execution failed"
                anomaly_meta = stat_eval
                break
            elif s_status == "DEGRADED" and not degraded_step:
                degraded_step = step
                error_type = step.get("error_code") or "LATENCY_SLA_BREACH"
                error_message = step.get("error_message") or f"Latency {s_latency}ms breached threshold {s_sla}ms"
                anomaly_meta = stat_eval
            elif stat_eval.get("is_anomaly") and s_status == "SUCCESS" and not statistical_anomaly_step:
                statistical_anomaly_step = step
                error_type = "STATISTICAL_LATENCY_ANOMALY"
                error_message = stat_eval.get("reason")
                anomaly_meta = stat_eval

        target_issue_step = failed_step or degraded_step or statistical_anomaly_step
        if not target_issue_step and not invariant_violations:
            return None  # Nominal execution

        # Handle invariant violations as critical failure if no explicit step failed
        if invariant_violations and not target_issue_step:
            inv = invariant_violations[0]
            target_issue_step = {
                "step_name": inv["step"],
                "latency_ms": 0.0,
                "logs": [inv["message"]],
                "metadata": {"invariant": inv["invariant_id"]}
            }
            error_type = inv["invariant_id"]
            error_message = inv["message"]

        # Severity classification
        target_name = target_issue_step["step_name"]
        if target_name in ("payment_confirm", "payment_auth") or invariant_violations:
            severity = "CRITICAL"
        elif target_name in ("inventory", "cart"):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        incident_number = f"INC-2026-{uuid.uuid4().hex[:5].upper()}"
        detected_time = datetime.now(timezone.utc).isoformat()

        incident_summary = {
            "incident_id": incident_number,
            "run_id": run_id,
            "scenario": scenario,
            "failed_step": target_name,
            "severity": severity,
            "error_type": error_type,
            "error_message": error_message,
            "latency_ms": target_issue_step.get("latency_ms", 0.0),
            "sla_limit_ms": self.sla_thresholds.get(target_name, 1200),
            "step_logs": target_issue_step.get("logs", []),
            "step_metadata": target_issue_step.get("metadata", {}),
            "statistical_anomaly_eval": anomaly_meta,
            "invariant_violations": invariant_violations,
            "detected_at": detected_time
        }

        # Record security audit log event
        audit_ledger.record_event(
            actor="failure_detector",
            role="system",
            action="OPEN_INCIDENT",
            target_id=incident_number,
            details={
                "run_id": run_id,
                "failed_step": target_name,
                "severity": severity,
                "error_type": error_type,
                "is_statistical_anomaly": bool(anomaly_meta and anomaly_meta.get("is_anomaly"))
            }
        )

        return incident_summary

detector = FailureDetector()
