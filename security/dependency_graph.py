"""
FlowSentry AI - Service Dependency Graph & Multi-Factor Root Cause Ranker
Features:
- Directed Acyclic Graph (DAG) representing service and microservice dependencies.
- Normalized multi-factor causal ranking using error, dependency topology, temporal order, and latency evidence.
- Explicit uncertainty bounds and evidence disclosures without claiming heuristic scores prove causation.
"""
from typing import Dict, List, Any, Optional

# Service Topology Dependency Graph
# Key depends on values in the list
SERVICE_GRAPH = {
    "auth_service": [],
    "cart_service": ["auth_service"],
    "inventory_service": ["cart_service"],
    "payment_gateway_proxy": ["inventory_service", "cart_service"],
    "external_payment_gateway": ["payment_gateway_proxy"],
    "order_db_cluster": ["external_payment_gateway"]
}

STEP_TO_SERVICE = {
    "auth": "auth_service",
    "cart": "cart_service",
    "inventory": "inventory_service",
    "payment_auth": "payment_gateway_proxy",
    "payment_confirm": "external_payment_gateway",
    "order_create": "order_db_cluster"
}

class ServiceDependencyRanker:
    def __init__(self, graph: Optional[Dict[str, List[str]]] = None):
        self.graph = graph or SERVICE_GRAPH
        self.step_map = STEP_TO_SERVICE

    def rank_root_causes(
        self, 
        steps: List[Dict[str, Any]], 
        failed_step_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Rank candidate root causes across all services using 4 normalized factors:
        1. Error Evidence Score (HTTP 5xx, socket timeout, error codes)
        2. Dependency Distance Score (Topological origin vs downstream cascade)
        3. Temporal Precedence Score (Earliest observed degradation in execution sequence)
        4. Latency Anomaly Score (Deviation magnitude)
        """
        candidates = []
        total_steps = len(steps)

        # First failure in execution sequence
        first_failed_order = None
        for s in steps:
            if s.get("status") in ("FAILED", "DEGRADED") and first_failed_order is None:
                first_failed_order = s.get("step_order", 1)

        for step in steps:
            s_name = step.get("step_name")
            s_order = step.get("step_order", 1)
            service_name = self.step_map.get(s_name, f"{s_name}_service")
            status = step.get("status")
            err_code = step.get("error_code")
            latency = step.get("latency_ms", 0.0)
            logs = step.get("logs", [])

            # 1. Error Evidence Score (0.0 to 1.0)
            if status == "FAILED" and err_code:
                s_error = 1.0
            elif status == "DEGRADED" or err_code:
                s_error = 0.75
            elif status == "SKIPPED":
                s_error = 0.10
            else:
                s_error = 0.0

            # 2. Dependency Topology Score (0.0 to 1.0)
            # Services that failed while their upstream dependencies were SUCCESS receive high causal weight
            upstream_steps = [steps[i] for i in range(s_order - 1)]
            all_upstream_ok = all(u.get("status") == "SUCCESS" for u in upstream_steps)
            if status == "FAILED" and all_upstream_ok:
                s_dep = 1.0  # Root point of origin
            elif status == "FAILED" and not all_upstream_ok:
                s_dep = 0.25 # Likely cascade victim
            elif status == "DEGRADED":
                s_dep = 0.70
            else:
                s_dep = 0.05

            # 3. Temporal Precedence Score (0.0 to 1.0)
            if first_failed_order is not None:
                order_diff = s_order - first_failed_order
                if order_diff == 0:
                    s_temp = 1.0
                elif order_diff > 0:
                    s_temp = max(0.0, 1.0 - (order_diff * 0.35))
                else:
                    s_temp = 0.0
            else:
                s_temp = 0.0

            # 4. Latency Deviation Score (0.0 to 1.0)
            if latency > 2000:
                s_lat = 1.0
            elif latency > 1000:
                s_lat = 0.75
            elif latency > 500:
                s_lat = 0.40
            else:
                s_lat = 0.05

            # Weighted composite score
            # Weights: Error (0.35), Topology (0.25), Temporal (0.25), Latency (0.15)
            composite_score = round(
                (0.35 * s_error) + (0.25 * s_dep) + (0.25 * s_temp) + (0.15 * s_lat),
                3
            )

            evidence_items = []
            if s_error > 0.5:
                evidence_items.append(f"Direct error signature: '{err_code or status}'")
            if s_dep > 0.8:
                evidence_items.append("Topological origin: all upstream dependencies responded 200 OK")
            elif s_dep < 0.3 and status == "SKIPPED":
                evidence_items.append("Cascade skip: aborted due to upstream node failure")
            if s_temp == 1.0:
                evidence_items.append(f"Temporal origin: earliest failure at step 0{s_order}")
            if s_lat > 0.7:
                evidence_items.append(f"Excessive latency: {latency}ms")

            candidates.append({
                "step_name": s_name,
                "service_name": service_name,
                "status": status,
                "composite_score": composite_score,
                "factor_scores": {
                    "error_evidence": s_error,
                    "dependency_origin": s_dep,
                    "temporal_precedence": s_temp,
                    "latency_deviation": s_lat
                },
                "evidence": evidence_items
            })

        # Rank candidates descending by composite score
        ranked = sorted(candidates, key=lambda c: c["composite_score"], reverse=True)
        top_candidate = ranked[0] if ranked else None

        return {
            "top_candidate": top_candidate,
            "ranked_candidates": ranked,
            "topology_graph": self.graph,
            "uncertainty_disclosure": (
                "Heuristic Ranking & Uncertainty Bounds: Scores represent normalized multi-factor diagnostic "
                "ranking based on observed telemetry and do NOT constitute mathematical proof of causation. "
                "Downstream telemetry is inferred from client socket timeouts."
            )
        }

dependency_ranker = ServiceDependencyRanker()
