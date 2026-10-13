"""
Tests for FailureDetector Engine
"""
import pytest
from simulator.engine import simulator
from detection.detector import detector

def test_detect_healthy_run_returns_none():
    run = simulator.run_transaction(scenario_id="NONE")
    incident = detector.evaluate_run(run)
    assert incident is None

def test_detect_payment_timeout():
    run = simulator.run_transaction(scenario_id="PAYMENT_TIMEOUT")
    incident = detector.evaluate_run(run)
    assert incident is not None
    assert incident["failed_step"] == "payment_confirm"
    assert incident["severity"] == "CRITICAL"
    assert incident["error_type"] == "GATEWAY_CONFIRMATION_TIMEOUT"
    assert incident["run_id"] == run["run_id"]

def test_detect_inventory_conflict():
    run = simulator.run_transaction(scenario_id="INVENTORY_FAILURE")
    incident = detector.evaluate_run(run)
    assert incident is not None
    assert incident["failed_step"] == "inventory"
    assert incident["severity"] == "HIGH"
    assert incident["error_type"] == "INVENTORY_LOCK_CONFLICT"

def test_detect_database_latency_sla():
    run = simulator.run_transaction(scenario_id="DB_LATENCY")
    incident = detector.evaluate_run(run)
    assert incident is not None
    assert incident["failed_step"] == "order_create"
    assert incident["severity"] == "MEDIUM"
    assert incident["error_type"] == "LATENCY_SLA_BREACH"
