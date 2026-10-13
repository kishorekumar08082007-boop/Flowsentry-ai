"""
FlowSentry AI - Tamper-Evident Hash-Chained Audit Ledger
Features:
- Cryptographically chained audit log (SHA-256 hash chain).
- Deterministic canonical serialization (sorted keys, strict separators).
- Records actor, action, role, target_id, approval decision, timestamp, and outcome.
- Complete chain verification utility and tamper detection.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from config import DATABASE_PATH

GENESIS_HASH = "0" * 64

class AuditLedger:
    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self._init_table()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_table(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log_chain (
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    @staticmethod
    def canonical_json(data: Any) -> str:
        """Deterministic canonical JSON serialization for cryptographically stable hashing."""
        return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

    def record_event(
        self, 
        actor: str, 
        role: str, 
        action: str, 
        target_id: str, 
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Record a new security audit event with cryptographic hash chaining.
        Computes entry_hash = SHA256(prev_hash + canonical_json(details)).
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Retrieve the hash of the latest entry
        cursor.execute("SELECT entry_hash FROM audit_log_chain ORDER BY sequence_number DESC LIMIT 1")
        last_row = cursor.fetchone()
        prev_hash = last_row["entry_hash"] if last_row else GENESIS_HASH

        now_iso = datetime.now(timezone.utc).isoformat()
        canonical_details = self.canonical_json(details)

        # Hash payload: prev_hash + actor + role + action + target_id + timestamp + canonical_details
        payload_to_hash = f"{prev_hash}|{actor}|{role}|{action}|{target_id}|{now_iso}|{canonical_details}"
        entry_hash = hashlib.sha256(payload_to_hash.encode('utf-8')).hexdigest()

        cursor.execute("""
            INSERT INTO audit_log_chain (
                actor, role, action, target_id, details_json, timestamp, prev_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (actor, role, action, target_id, canonical_details, now_iso, prev_hash, entry_hash))

        seq_num = cursor.lastrowid
        conn.commit()
        conn.close()

        return {
            "sequence_number": seq_num,
            "actor": actor,
            "role": role,
            "action": action,
            "target_id": target_id,
            "timestamp": now_iso,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash
        }

    def verify_audit_chain(self) -> Dict[str, Any]:
        """
        Walk from sequence 1 to N, recomputing cryptographic hashes to verify
        ledger integrity and detect any record tampering.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log_chain ORDER BY sequence_number ASC")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return {
                "valid": True,
                "total_records": 0,
                "message": "Audit ledger is currently empty."
            }

        expected_prev_hash = GENESIS_HASH

        for row in rows:
            seq = row["sequence_number"]
            # 1. Verify prev_hash linkage
            if row["prev_hash"] != expected_prev_hash:
                return {
                    "valid": False,
                    "tampered_sequence": seq,
                    "error_type": "CHAIN_LINKAGE_BROKEN",
                    "reason": f"Record #{seq} prev_hash '{row['prev_hash']}' does not match expected '{expected_prev_hash}'."
                }

            # 2. Recompute entry hash
            payload_to_hash = f"{row['prev_hash']}|{row['actor']}|{row['role']}|{row['action']}|{row['target_id']}|{row['timestamp']}|{row['details_json']}"
            recomputed_hash = hashlib.sha256(payload_to_hash.encode('utf-8')).hexdigest()

            if recomputed_hash != row["entry_hash"]:
                return {
                    "valid": False,
                    "tampered_sequence": seq,
                    "error_type": "ENTRY_HASH_MISMATCH",
                    "reason": f"Record #{seq} stored hash '{row['entry_hash']}' does not match recomputed hash '{recomputed_hash}'. Content has been altered!"
                }

            expected_prev_hash = row["entry_hash"]

        return {
            "valid": True,
            "total_records": len(rows),
            "latest_sequence": rows[-1]["sequence_number"],
            "latest_entry_hash": rows[-1]["entry_hash"],
            "message": "Cryptographic hash chain verified 100% intact with zero tampering detected."
        }

    def get_recent_audit_records(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Retrieve recent audit events for UI dashboard."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log_chain ORDER BY sequence_number DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        records = []
        for r in rows:
            item = dict(r)
            try:
                item["details"] = json.loads(item["details_json"])
            except Exception:
                item["details"] = {}
            records.append(item)
        return records

    def simulate_tamper(self, sequence_number: int, forged_action: str = "FORGED_ACTION") -> Dict[str, Any]:
        """
        Simulation helper for the Security Lab: intentionally mutates an existing
        audit record to demonstrate tamper detection.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log_chain WHERE sequence_number = ?", (sequence_number,))
        target = cursor.fetchone()
        if not target:
            conn.close()
            return {"success": False, "error": f"Record {sequence_number} not found"}

        # Modify details without updating entry_hash
        cursor.execute("""
            UPDATE audit_log_chain 
            SET action = ?, details_json = ? 
            WHERE sequence_number = ?
        """, (forged_action, json.dumps({"tampered": True, "attacker": "unauthorized_write"}), sequence_number))
        conn.commit()
        conn.close()

        # Run verification to catch the tamper
        verification = self.verify_audit_chain()
        return {
            "success": True,
            "tampered_sequence": sequence_number,
            "verification_result": verification
        }

audit_ledger = AuditLedger()
