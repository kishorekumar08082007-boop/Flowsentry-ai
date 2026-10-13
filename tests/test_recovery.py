"""
Tests for SafeRecoveryAgent & Counterfactual Replay
"""
import pytest
from simulator.engine import simulator
from detection.detector import detector
from investigation.ai_detective import detective
from recovery.agent import recovery_agent
from recovery.counterfactual import counterfactual_engine

def test_recovery_lifecycle_and_safeguards():
    # 1. Run failing workflow
    run = simulator.run_transaction(scenario_id="PAYMENT_TIMEOUT")
    incident_data = detector.evaluate_run(run)
    detective.analyze_incident(incident_data, run)
    
    # 2. Propose recovery
    proposal = recovery_agent.propose_recovery(incident_data["incident_id"])
    assert proposal["status"] == "PENDING_APPROVAL"
    assert proposal["action_type"] == "IDEMPOTENT_RECONCILE"
    assert proposal["idempotency_key"].startswith("fs_idem_")
    assert len(proposal["safeguards"]) > 0

    # 3. Execution rejected if approved=False
    rejected = recovery_agent.execute_recovery(proposal["id"], approved=False)
    assert rejected["status"] == "REJECTED"

    # Propose new action or approve
    proposal_2 = recovery_agent.propose_recovery(incident_data["incident_id"])
    executed = recovery_agent.execute_recovery(proposal_2["id"], approved=True)
    
    assert executed["is_successful"] is True
    assert executed["verification"]["status"] == "VERIFIED_HEALTHY"
    assert executed["verification"]["steps_completed"] == 6
    assert executed["replay_run"]["status"] == "RECOVERED"
    assert "counterfactual" in executed

def test_counterfactual_engine_comparison():
    run = simulator.run_transaction(scenario_id="PAYMENT_TIMEOUT")
    incident_data = detector.evaluate_run(run)
    detective.analyze_incident(incident_data, run)
    proposal = recovery_agent.propose_recovery(incident_data["incident_id"])
    
    cf = counterfactual_engine.generate_counterfactual_model(
        incident=incident_data,
        original_run=run,
        recovery_action=proposal
    )
    
    assert "unmitigated_simulation" in cf
    assert cf["unmitigated_simulation"]["abandonment_probability_pct"] > 80
    assert "strategy_rationale" in cf
    assert "rejected_alternatives" in cf["strategy_rationale"]
    assert len(cf["timeline"]) >= 4
