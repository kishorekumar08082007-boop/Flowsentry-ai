"""
Tests for RootCauseDetective (Gemini and Deterministic fallback)
"""
import pytest
from simulator.engine import simulator
from detection.detector import detector
from investigation.ai_detective import detective

def test_deterministic_investigation_payment_timeout():
    run = simulator.run_transaction(scenario_id="PAYMENT_TIMEOUT")
    incident = detector.evaluate_run(run)
    analysis = detective.analyze_incident(incident, run)
    
    assert "Payment Gateway" in analysis["most_likely_root_cause"]
    assert len(analysis["evidence"]) > 0
    assert 0.0 < analysis["confidence_score"] <= 1.0
    assert len(analysis["confidence_rationale"]) > 0
    assert "payment_confirm" in analysis["affected_steps"]
    assert len(analysis["downstream_impact"]) > 0
    assert analysis["recommended_action_type"] == "IDEMPOTENT_RECONCILE"
    assert len(analysis["alternative_causes"]) > 0
    # Must distinguish source honestly
    assert analysis["analysis_source"] in ("deterministic_rules", "gemini_ai")

def test_deterministic_investigation_inventory_conflict():
    run = simulator.run_transaction(scenario_id="INVENTORY_FAILURE")
    incident = detector.evaluate_run(run)
    analysis = detective.analyze_incident(incident, run)
    
    assert "Inventory" in analysis["most_likely_root_cause"]
    assert analysis["recommended_action_type"] == "INVENTORY_BACKOFF_RETRY"

def test_graceful_operation_without_api_key():
    # Detective works even if api_key is None
    from investigation.ai_detective import RootCauseDetective
    offline_detective = RootCauseDetective(api_key="")
    run = simulator.run_transaction(scenario_id="INTERMITTENT_API")
    incident = detector.evaluate_run(run)
    analysis = offline_detective.analyze_incident(incident, run)
    
    assert analysis["analysis_source"] == "deterministic_rules"
    assert analysis["confidence_score"] > 0
