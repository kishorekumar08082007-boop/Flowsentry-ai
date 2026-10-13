"""
Tests for Flask REST API Endpoints
"""
import pytest
import json
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "HEALTHY"
    assert "ai_engine" in data

def test_metrics_endpoint(client):
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "total_runs" in data["data"]
    assert "success_rate" in data["data"]

def test_run_simulation_baseline(client):
    res = client.post("/api/simulator/run", json={"scenario": "NONE"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["run"]["status"] == "SUCCESS"
    assert data["incident"] is None

def test_run_simulation_payment_timeout(client):
    res = client.post("/api/simulator/run", json={"scenario": "PAYMENT_TIMEOUT"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["run"]["status"] == "FAILED"
    assert data["incident"] is not None
    assert data["incident"]["failed_step"] == "payment_confirm"

def test_one_click_demo_flow(client):
    res = client.post("/api/demo/one-click")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    demo = data["demo"]
    assert demo["step_1_healthy"]["status"] == "SUCCESS"
    assert demo["step_2_failed"]["status"] == "FAILED"
    assert demo["step_3_detection"]["failed_step"] == "payment_confirm"
    assert "most_likely_root_cause" in demo["step_4_analysis"]
    assert demo["step_5_proposal"]["status"] == "PENDING_APPROVAL"
    assert demo["step_6_recovery"]["is_successful"] is True
