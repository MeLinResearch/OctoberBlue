"""Local SQLite experiment store. Not a true security isolation boundary."""

import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path


class Store:
    def __init__(self, path: str):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(p))
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, partition TEXT NOT NULL, "
            "body_json TEXT NOT NULL, sha256 TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS memory (side TEXT NOT NULL, version INTEGER NOT NULL, "
            "parent_version INTEGER, body TEXT NOT NULL, evidence_run_id TEXT, "
            "status TEXT NOT NULL, PRIMARY KEY(side, version))"
        )
        self.conn.commit()

    def save(self, result):
        from .service_contracts import RunRecordV1

        ticket = result.evidence is not None or any(
            event["kind"] == "witness_acquisition_failed"
            or event["detail"].get("task_family") == "synthetic_support_ticket"
            for event in result.events
        )
        wire = RunRecordV1.from_outcome(result).to_wire() if ticket else asdict(result)
        body = json.dumps(wire, sort_keys=True, separators=(",", ":"))
        with self.conn:
            self.conn.execute(
                "INSERT INTO runs VALUES (?,?,?,?)",
                (result.run_id, result.partition, body, hashlib.sha256(body.encode()).hexdigest()),
            )

    def get(self, run_id):
        row = self.conn.execute(
            "SELECT body_json,sha256 FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        if not row:
            raise KeyError(run_id)
        if hashlib.sha256(row[0].encode()).hexdigest() != row[1]:
            raise ValueError("run hash mismatch")
        from .service_contracts import parse_contract_json

        value = parse_contract_json(row[0])
        if "schema_version" in value:
            from .service_contracts import RunRecordV1
            return RunRecordV1.from_wire(value).to_wire()
        # Explicit legacy read path: unversioned rows are historical observations,
        # not authenticated acquisition or an automatic contract migration.
        return value

    def close(self):
        self.conn.close()
