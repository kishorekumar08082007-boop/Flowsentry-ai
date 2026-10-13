"""
Tests for TransactionSimulator Engine
"""
import pytest
from simulator.engine import simulator

def test_healthy_checkout_workflow():
    result = simulator.run_transaction(scenario_id="NONE")
    assert result["status"] == "SUCCESS"
    assert len(result["steps"]) == 6
    assert result["error_step"] is None
    for step in result["steps"]:
        assert step["status"] == "SUCCESS"
        assert step["latency_ms"] > 0
        assert len(step["logs"]) > 0

def test_payment_timeout_scenario():
    result = simulator.run_transaction(scenario_id="PAYMENT_TIMEOUT")
    assert result["status"] == "FAILED"
    assert result["error_step"] == "payment_confirm"
    steps = {s["step_name"]: s for s in result["steps"]}
    
    # Preceding steps must succeed
    assert steps["auth"]["status"] == "SUCCESS"
    assert steps["cart"]["status"] == "SUCCESS"
    assert steps["inventory"]["status"] == "SUCCESS"
    assert steps["payment_auth"]["status"] == "SUCCESS"
    
    # Target step must fail with 504 timeout
    assert steps["payment_confirm"]["status"] == "FAILED"
    assert steps["payment_confirm"]["error_code"] == "GATEWAY_CONFIRMATION_TIMEOUT"
    assert steps["payment_confirm"]["latency_ms"] >= 2000
    
    # Subsequent order create must be skipped
    assert steps["order_create"]["status"] == "SKIPPED"

def test_inventory_failure_scenario():
    result = simulator.run_transaction(scenario_id="INVENTORY_FAILURE")
    assert result["status"] == "FAILED"
    assert result["error_step"] == "inventory"
    steps = {s["step_name"]: s for s in result["steps"]}
    assert steps["inventory"]["status"] == "FAILED"
    assert steps["inventory"]["error_code"] == "INVENTORY_LOCK_CONFLICT"
    assert steps["payment_auth"]["status"] == "SKIPPED"
    assert steps["order_create"]["status"] == "SKIPPED"

def test_database_latency_scenario():
    result = simulator.run_transaction(scenario_id="DB_LATENCY")
    assert result["status"] == "DEGRADED"
    assert result["error_step"] == "order_create"
    steps = {s["step_name"]: s for s in result["steps"]}
    assert steps["order_create"]["status"] == "DEGRADED"
    assert steps["order_create"]["latency_ms"] > 1000

def test_intermittent_api_scenario():
    result = simulator.run_transaction(scenario_id="INTERMITTENT_API")
    assert result["status"] == "FAILED"
    assert result["error_step"] == "payment_auth"
    steps = {s["step_name"]: s for s in result["steps"]}
    assert steps["payment_auth"]["status"] == "FAILED"
    assert steps["payment_auth"]["error_code"] == "SERVICE_503_UNAVAILABLE"
    assert steps["payment_confirm"]["status"] == "SKIPPED"

def test_recovery_replay_execution():
    recovery_ctx = {
        "applied_recovery": True,
        "action_type": "IDEMPOTENT_RECONCILE",
        "idempotency_key": "fs_idem_test_replay_99"
    }
    result = simulator.run_transaction(
        scenario_id="PAYMENT_TIMEOUT",
        is_replay=True,
        parent_run_id="run_test_parent",
        recovery_context=recovery_ctx
    )
    assert result["status"] == "RECOVERED"
    assert result["is_replay"] is True
    assert result["parent_run_id"] == "run_test_parent"
    for step in result["steps"]:
        assert step["status"] == "SUCCESS"
