"""
FlowSentry AI - Database Layer
SQLite schema, connection management, query helpers, and realistic demo seed data.
"""
import sqlite3
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
from config import DATABASE_PATH

def get_db_connection():
    """Create a thread-safe connection to SQLite with row factory enabled."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(reset: bool = False):
    """Initialize database tables. Optionally reset existing tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if reset:
        cursor.execute("DROP TABLE IF EXISTS recovery_outcomes")
        cursor.execute("DROP TABLE IF EXISTS recovery_actions")
        cursor.execute("DROP TABLE IF EXISTS incidents")
        cursor.execute("DROP TABLE IF EXISTS workflow_steps")
        cursor.execute("DROP TABLE IF EXISTS workflow_runs")

    # 1. Workflow Runs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workflow_runs (
            id TEXT PRIMARY KEY,
            scenario TEXT NOT NULL,
            status TEXT NOT NULL,
            total_latency_ms REAL NOT NULL,
            error_step TEXT,
            is_replay INTEGER DEFAULT 0,
            parent_run_id TEXT,
            is_seed INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    # 2. Workflow Steps
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workflow_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            step_name TEXT NOT NULL,
            step_order INTEGER NOT NULL,
            status TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            error_code TEXT,
            error_message TEXT,
            logs_json TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
        )
    """)

    # 3. Incidents
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            failed_step TEXT NOT NULL,
            severity TEXT NOT NULL,
            error_type TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            confidence REAL NOT NULL,
            confidence_rationale TEXT,
            analysis_source TEXT NOT NULL,
            full_analysis_json TEXT NOT NULL,
            status TEXT NOT NULL,
            is_seed INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
        )
    """)

    # 4. Recovery Actions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recovery_actions (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            status TEXT NOT NULL,
            strategy_description TEXT NOT NULL,
            idempotency_key TEXT,
            approval_timestamp TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
            FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
        )
    """)

    # 5. Recovery Outcomes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recovery_outcomes (
            id TEXT PRIMARY KEY,
            recovery_action_id TEXT NOT NULL,
            original_run_id TEXT NOT NULL,
            replay_run_id TEXT NOT NULL,
            is_successful INTEGER NOT NULL,
            verification_details_json TEXT NOT NULL,
            counterfactual_summary_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (recovery_action_id) REFERENCES recovery_actions(id) ON DELETE CASCADE,
            FOREIGN KEY (original_run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE,
            FOREIGN KEY (replay_run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
        )
    """)

    conn.commit()

    # Check if seed data exists; if not, seed realistic demonstration records
    cursor.execute("SELECT COUNT(*) as cnt FROM workflow_runs")
    count = cursor.fetchone()["cnt"]
    if count == 0:
        seed_demonstration_data(conn)

    conn.close()

def seed_demonstration_data(conn):
    """Seed realistic demonstration historical data clearly flagged with is_seed=1."""
    cursor = conn.cursor()
    base_time = datetime.now(timezone.utc) - timedelta(hours=8)

    # 1. Successful baseline run 1
    run1_id = "run-seed-101"
    t1 = (base_time + timedelta(minutes=15)).isoformat() + "Z"
    cursor.execute("""
        INSERT INTO workflow_runs (id, scenario, status, total_latency_ms, is_replay, is_seed, created_at)
        VALUES (?, 'NONE', 'SUCCESS', 214.5, 0, 1, ?)
    """, (run1_id, t1))

    # Steps for run 1
    steps_1 = [
        ("auth", 1, "SUCCESS", 42.1, None, None, ["User session valid: usr_88291", "JWT token signature verified"]),
        ("cart", 2, "SUCCESS", 31.4, None, None, ["Cart locked: 2 items", "Subtotal $149.00 computed"]),
        ("inventory", 3, "SUCCESS", 52.8, None, None, ["Inventory reserved: SKU-PRO-981 qty:1"]),
        ("payment_auth", 4, "SUCCESS", 48.2, None, None, ["Pre-auth token generated: tok_auth_909", "Risk score: 0.02 (Safe)"]),
        ("payment_confirm", 5, "SUCCESS", 25.0, None, None, ["Payment captured: tx_chrg_89211", "Gateway response 200 OK"]),
        ("order_create", 6, "SUCCESS", 15.0, None, None, ["Order generated: ORD-77401", "Confirmation email queued"])
    ]
    for sname, sorder, sstatus, slat, scode, smsg, logs in steps_1:
        cursor.execute("""
            INSERT INTO workflow_steps (run_id, step_name, step_order, status, latency_ms, error_code, error_message, logs_json, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run1_id, sname, sorder, sstatus, slat, scode, smsg, json.dumps(logs), json.dumps({"order_id": "ORD-77401"}), t1))

    # 2. Historical Payment Timeout Incident (Resolved)
    run2_id = "run-seed-102"
    t2 = (base_time + timedelta(hours=2)).isoformat() + "Z"
    cursor.execute("""
        INSERT INTO workflow_runs (id, scenario, status, total_latency_ms, error_step, is_replay, is_seed, created_at)
        VALUES (?, 'PAYMENT_TIMEOUT', 'FAILED', 2640.2, 'payment_confirm', 0, 1, ?)
    """, (run2_id, t2))

    steps_2 = [
        ("auth", 1, "SUCCESS", 38.5, None, None, ["Session verified"]),
        ("cart", 2, "SUCCESS", 29.0, None, None, ["Cart total: $289.00"]),
        ("inventory", 3, "SUCCESS", 61.2, None, None, ["Stock reserved"]),
        ("payment_auth", 4, "SUCCESS", 51.5, None, None, ["Payment authorized: tok_auth_441"]),
        ("payment_confirm", 5, "FAILED", 2460.0, "GATEWAY_CONFIRMATION_TIMEOUT", "HTTP 504 Gateway Timeout while awaiting capture acknowledgment", 
         ["Initiating capture request to Stripe/Adyen mock gateway", "TCP socket read timeout > 2000ms", "Received HTTP 504 Gateway Timeout"]),
        ("order_create", 6, "SKIPPED", 0.0, None, "Preceding step failed", ["Step aborted due to payment_confirm failure"])
    ]
    for sname, sorder, sstatus, slat, scode, smsg, logs in steps_2:
        cursor.execute("""
            INSERT INTO workflow_steps (run_id, step_name, step_order, status, latency_ms, error_code, error_message, logs_json, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run2_id, sname, sorder, sstatus, slat, scode, smsg, json.dumps(logs), json.dumps({"amount": 289.0}), t2))

    # Incident for run 2
    inc2_id = "INC-2026-SEED-01"
    analysis_2 = {
        "most_likely_root_cause": "Payment Gateway Confirmation Read Timeout (Asynchronous Capture Lock)",
        "evidence": [
            "payment_auth succeeded in 51.5ms with valid token tok_auth_441",
            "payment_confirm read socket timed out after 2460ms",
            "Upstream gateway health check ping returned 200 OK (silent endpoint stall)"
        ],
        "confidence_score": 0.94,
        "confidence_rationale": "High confidence derived from socket timeout log combined with valid preceding pre-auth token; not 1.0 because upstream gateway internal trace logs are proprietary.",
        "affected_steps": ["payment_confirm", "order_create"],
        "downstream_impact": "Customer card holds $289.00 authorization, but order ORD-PENDING never created. Risk of duplicate charge if naively retried without idempotency.",
        "recommended_action": "Execute idempotent capture reconciliation using token tok_auth_441 before retrying order creation.",
        "alternative_causes": ["Transient DNS resolution failure", "Transit TLS packet drop at payment gateway edge"]
    }
    cursor.execute("""
        INSERT INTO incidents (id, run_id, failed_step, severity, error_type, root_cause, confidence, confidence_rationale, analysis_source, full_analysis_json, status, is_seed, created_at)
        VALUES (?, ?, 'payment_confirm', 'CRITICAL', 'GATEWAY_CONFIRMATION_TIMEOUT', ?, 0.94, ?, 'deterministic_rules', ?, 'RECOVERED', 1, ?)
    """, (inc2_id, run2_id, analysis_2["most_likely_root_cause"], analysis_2["confidence_rationale"], json.dumps(analysis_2), t2))

    # Recovery Action for run 2
    rec2_id = "REC-2026-SEED-01"
    cursor.execute("""
        INSERT INTO recovery_actions (id, incident_id, run_id, action_type, status, strategy_description, idempotency_key, approval_timestamp, created_at)
        VALUES (?, ?, ?, 'IDEMPOTENT_RECONCILE', 'EXECUTED', 'Idempotent Gateway Query & State Reconciliation', 'fs_idem_seed_9981', ?, ?)
    """, (rec2_id, inc2_id, run2_id, t2, t2))

    # Replay Run for run 2
    replay2_id = "run-seed-102-replay"
    t2_rep = (base_time + timedelta(hours=2, minutes=3)).isoformat() + "Z"
    cursor.execute("""
        INSERT INTO workflow_runs (id, scenario, status, total_latency_ms, is_replay, parent_run_id, is_seed, created_at)
        VALUES (?, 'PAYMENT_TIMEOUT', 'RECOVERED', 231.0, 1, ?, 1, ?)
    """, (replay2_id, run2_id, t2_rep))

    steps_2_rep = [
        ("auth", 1, "SUCCESS", 35.0, None, None, ["Session re-validated from cache"]),
        ("cart", 2, "SUCCESS", 22.0, None, None, ["Cart verified"]),
        ("inventory", 3, "SUCCESS", 48.0, None, None, ["Inventory hold renewed"]),
        ("payment_auth", 4, "SUCCESS", 42.0, None, None, ["Existing auth token reused: tok_auth_441"]),
        ("payment_confirm", 5, "SUCCESS", 65.0, None, None, ["Idempotent query executed: capture verified", "State reconciled successfully"]),
        ("order_create", 6, "SUCCESS", 19.0, None, None, ["Order finalized: ORD-77402", "Customer notified"])
    ]
    for sname, sorder, sstatus, slat, scode, smsg, logs in steps_2_rep:
        cursor.execute("""
            INSERT INTO workflow_steps (run_id, step_name, step_order, status, latency_ms, error_code, error_message, logs_json, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (replay2_id, sname, sorder, sstatus, slat, scode, smsg, json.dumps(logs), json.dumps({"order_id": "ORD-77402"}), t2_rep))

    # Recovery Outcome for run 2
    out2_id = "OUT-2026-SEED-01"
    verification = {
        "status": "VERIFIED_HEALTHY",
        "steps_completed": 6,
        "total_latency_ms": 231.0,
        "idempotency_check": "PASSED - No duplicate charge detected",
        "order_status": "COMMITTED - ORD-77402"
    }
    counterfactual = {
        "unmitigated_outcome": "User abandoned checkout after 45s; $289.00 lost revenue; support ticket opened for pending card hold.",
        "recovered_outcome": "Automated idempotent reconciliation recovered checkout in 180ms. Order ORD-77402 confirmed with zero customer friction."
    }
    cursor.execute("""
        INSERT INTO recovery_outcomes (id, recovery_action_id, original_run_id, replay_run_id, is_successful, verification_details_json, counterfactual_summary_json, created_at)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
    """, (out2_id, rec2_id, run2_id, replay2_id, json.dumps(verification), json.dumps(counterfactual), t2_rep))

    # 3. Successful run 3
    run3_id = "run-seed-103"
    t3 = (base_time + timedelta(hours=4)).isoformat() + "Z"
    cursor.execute("""
        INSERT INTO workflow_runs (id, scenario, status, total_latency_ms, is_replay, is_seed, created_at)
        VALUES (?, 'NONE', 'SUCCESS', 198.0, 0, 1, ?)
    """, (run3_id, t3))

    for sname, sorder, sstatus, slat in [("auth",1,"SUCCESS",33.0), ("cart",2,"SUCCESS",28.0), ("inventory",3,"SUCCESS",45.0), ("payment_auth",4,"SUCCESS",41.0), ("payment_confirm",5,"SUCCESS",32.0), ("order_create",6,"SUCCESS",19.0)]:
        cursor.execute("""
            INSERT INTO workflow_steps (run_id, step_name, step_order, status, latency_ms, logs_json, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (run3_id, sname, sorder, sstatus, slat, json.dumps([f"{sname} passed successfully"]), json.dumps({}), t3))

    conn.commit()

# --- Query Helpers ---

def get_recent_runs(limit: int = 15) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.*, 
               (SELECT COUNT(*) FROM workflow_steps s WHERE s.run_id = r.id) as step_count
        FROM workflow_runs r
        ORDER BY r.created_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_run_details(run_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM workflow_runs WHERE id = ?", (run_id,))
    run_row = cursor.fetchone()
    if not run_row:
        conn.close()
        return None
    run = dict(run_row)

    cursor.execute("SELECT * FROM workflow_steps WHERE run_id = ? ORDER BY step_order ASC", (run_id,))
    steps = []
    for s in cursor.fetchall():
        step_dict = dict(s)
        try:
            step_dict["logs"] = json.loads(step_dict["logs_json"]) if step_dict["logs_json"] else []
        except Exception:
            step_dict["logs"] = []
        try:
            step_dict["metadata"] = json.loads(step_dict["metadata_json"]) if step_dict["metadata_json"] else {}
        except Exception:
            step_dict["metadata"] = {}
        steps.append(step_dict)
    run["steps"] = steps

    # Associated Incident
    cursor.execute("SELECT * FROM incidents WHERE run_id = ?", (run_id,))
    incident_row = cursor.fetchone()
    if incident_row:
        inc = dict(incident_row)
        try:
            inc["full_analysis"] = json.loads(inc["full_analysis_json"])
        except Exception:
            inc["full_analysis"] = {}
        run["incident"] = inc
    else:
        run["incident"] = None

    conn.close()
    return run

def get_incident_details(incident_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    inc_row = cursor.fetchone()
    if not inc_row:
        conn.close()
        return None
    inc = dict(inc_row)
    try:
        inc["full_analysis"] = json.loads(inc["full_analysis_json"])
    except Exception:
        inc["full_analysis"] = {}

    # Check for recovery action
    cursor.execute("SELECT * FROM recovery_actions WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1", (incident_id,))
    rec_row = cursor.fetchone()
    if rec_row:
        rec = dict(rec_row)
        cursor.execute("SELECT * FROM recovery_outcomes WHERE recovery_action_id = ?", (rec["id"],))
        out_row = cursor.fetchone()
        if out_row:
            rec["outcome"] = dict(out_row)
        else:
            rec["outcome"] = None
        inc["recovery_action"] = rec
    else:
        inc["recovery_action"] = None

    conn.close()
    return inc

def get_all_incidents(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT i.*, r.scenario, r.total_latency_ms 
        FROM incidents i
        JOIN workflow_runs r ON i.run_id = r.id
        ORDER BY i.created_at DESC
        LIMIT ?
    """, (limit,))
    incidents = []
    for row in cursor.fetchall():
        item = dict(row)
        try:
            item["full_analysis"] = json.loads(item["full_analysis_json"])
        except Exception:
            item["full_analysis"] = {}
        incidents.append(item)
    conn.close()
    return incidents

def get_system_metrics() -> Dict[str, Any]:
    """Calculate aggregated metrics for operations dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM workflow_runs")
    total_runs = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as successful FROM workflow_runs WHERE status IN ('SUCCESS', 'RECOVERED')")
    success_runs = cursor.fetchone()["successful"]

    cursor.execute("SELECT COUNT(*) as failed FROM workflow_runs WHERE status = 'FAILED'")
    failed_runs = cursor.fetchone()["failed"]

    cursor.execute("SELECT AVG(total_latency_ms) as avg_latency FROM workflow_runs")
    avg_lat = cursor.fetchone()["avg_latency"] or 0.0

    cursor.execute("SELECT COUNT(*) as total_incidents FROM incidents")
    total_incidents = cursor.fetchone()["total_incidents"]

    cursor.execute("SELECT COUNT(*) as recovered_incidents FROM incidents WHERE status = 'RECOVERED'")
    recovered_incidents = cursor.fetchone()["recovered_incidents"]

    # Recent runs for trend chart
    cursor.execute("""
        SELECT id, scenario, status, total_latency_ms, created_at 
        FROM workflow_runs 
        ORDER BY created_at ASC 
        LIMIT 20
    """)
    trend_runs = [dict(r) for r in cursor.fetchall()]

    # Failure scenario breakdown
    cursor.execute("""
        SELECT scenario, COUNT(*) as count 
        FROM workflow_runs 
        WHERE status = 'FAILED' 
        GROUP BY scenario
    """)
    scenario_breakdown = {row["scenario"]: row["count"] for row in cursor.fetchall()}

    conn.close()

    success_rate = round((success_runs / total_runs * 100), 1) if total_runs > 0 else 100.0
    mttr_simulated = "180 ms" if recovered_incidents > 0 else "N/A"

    return {
        "total_runs": total_runs,
        "success_runs": success_runs,
        "failed_runs": failed_runs,
        "success_rate": success_rate,
        "avg_latency_ms": round(avg_lat, 1),
        "total_incidents": total_incidents,
        "recovered_incidents": recovered_incidents,
        "recovery_rate": round((recovered_incidents / total_incidents * 100), 1) if total_incidents > 0 else 100.0,
        "simulated_mttr": mttr_simulated,
        "trend_runs": trend_runs,
        "scenario_breakdown": scenario_breakdown
    }
