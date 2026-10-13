"""
FlowSentry AI - Statistical Anomaly Detection & Business Invariant Engine
Features:
- Rolling-median and MAD-based (Median Absolute Deviation) latency anomaly detection.
- Configurable thresholds and sufficient-baseline checks.
- Explicit business-invariant and HTTP status verification.
"""
import math
from typing import List, Dict, Any, Optional, Tuple

class AnomalyDetector:
    def __init__(self, min_baseline_samples: int = 5, mad_threshold: float = 3.5):
        self.min_baseline_samples = min_baseline_samples
        self.mad_threshold = mad_threshold

    @staticmethod
    def _compute_median(values: List[float]) -> float:
        """Compute the median of a numerical list."""
        if not values:
            return 0.0
        s = sorted(values)
        n = len(s)
        mid = n // 2
        if n % 2 == 1:
            return float(s[mid])
        return float((s[mid - 1] + s[mid]) / 2.0)

    def compute_mad(self, values: List[float]) -> Tuple[float, float]:
        """
        Compute Median and Median Absolute Deviation (MAD).
        Returns (median, mad).
        """
        if not values:
            return 0.0, 0.0
        med = self._compute_median(values)
        deviations = [abs(x - med) for x in values]
        mad = self._compute_median(deviations)
        return med, mad

    def evaluate_latency_anomaly(
        self, 
        current_latency_ms: float, 
        historical_latencies: List[float], 
        step_sla_ms: float
    ) -> Dict[str, Any]:
        """
        Evaluate if current latency is an anomaly using rolling MAD when sufficient
        baseline exists, or static SLA threshold as fallback.
        """
        sample_size = len(historical_latencies)
        has_sufficient_baseline = sample_size >= self.min_baseline_samples

        if has_sufficient_baseline:
            med, mad = self.compute_mad(historical_latencies)
            # Safe non-zero denominator
            effective_mad = max(mad, 1.0)
            # Boris Iglewicz and David Hoaglin modified Z-score
            modified_z_score = 0.6745 * (current_latency_ms - med) / effective_mad
            is_anomaly = modified_z_score > self.mad_threshold

            return {
                "detection_method": "rolling_mad",
                "is_anomaly": bool(is_anomaly),
                "modified_z_score": round(modified_z_score, 2),
                "threshold": self.mad_threshold,
                "median_ms": round(med, 1),
                "mad_ms": round(mad, 1),
                "baseline_sample_size": sample_size,
                "sufficient_baseline": True,
                "reason": (
                    f"Modified Z-score {modified_z_score:.2f} exceeded statistical threshold {self.mad_threshold}"
                    if is_anomaly else "Latency within normal statistical deviation bounds."
                )
            }
        else:
            # Fallback to deterministic SLA threshold check
            is_breached = current_latency_ms > step_sla_ms
            return {
                "detection_method": "static_sla",
                "is_anomaly": bool(is_breached),
                "modified_z_score": None,
                "threshold": step_sla_ms,
                "median_ms": None,
                "mad_ms": None,
                "baseline_sample_size": sample_size,
                "sufficient_baseline": False,
                "reason": (
                    f"Baseline sample size ({sample_size}) < required ({self.min_baseline_samples}). "
                    f"Fallback to static SLA: {current_latency_ms}ms vs {step_sla_ms}ms limit."
                )
            }

    @staticmethod
    def verify_business_invariants(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Explicitly verify transactional business invariants across the workflow trail.
        Returns a list of detected invariant violations.
        """
        violations = []
        step_dict = {s["step_name"]: s for s in steps}

        # Invariant 1: Payment Auth requires valid User Auth
        auth_step = step_dict.get("auth")
        pay_auth = step_dict.get("payment_auth")
        if pay_auth and pay_auth.get("status") == "SUCCESS":
            if not auth_step or auth_step.get("status") != "SUCCESS":
                violations.append({
                    "invariant_id": "INV_01_AUTH_REQUIRED",
                    "severity": "CRITICAL",
                    "step": "payment_auth",
                    "message": "Business Invariant Violation: Payment authorization succeeded without authenticated user session."
                })

        # Invariant 2: Payment Confirmation requires successful Payment Auth pre-auth token
        pay_confirm = step_dict.get("payment_confirm")
        if pay_confirm and pay_confirm.get("status") == "SUCCESS":
            if not pay_auth or pay_auth.get("status") != "SUCCESS":
                violations.append({
                    "invariant_id": "INV_02_AUTH_TOKEN_REQUIRED",
                    "severity": "CRITICAL",
                    "step": "payment_confirm",
                    "message": "Business Invariant Violation: Payment capture confirmed without valid pre-authorization hold."
                })

        # Invariant 3: Order Creation requires Payment Capture / Settlement
        order_step = step_dict.get("order_create")
        if order_step and order_step.get("status") == "SUCCESS":
            if not pay_confirm or pay_confirm.get("status") != "SUCCESS":
                violations.append({
                    "invariant_id": "INV_03_PAYMENT_CAPTURED_FOR_ORDER",
                    "severity": "CRITICAL",
                    "step": "order_create",
                    "message": "Business Invariant Violation: Order creation committed without verified payment settlement."
                })

        # Invariant 4: Success status must have non-failing HTTP codes
        for step in steps:
            s_name = step.get("step_name")
            s_status = step.get("status")
            err_code = step.get("error_code")
            if s_status == "SUCCESS" and err_code:
                violations.append({
                    "invariant_id": "INV_04_STATUS_INTEGRITY",
                    "severity": "HIGH",
                    "step": s_name,
                    "message": f"Integrity Violation: Step '{s_name}' is marked SUCCESS but holds error code '{err_code}'."
                })

        return violations

anomaly_detector = AnomalyDetector()
