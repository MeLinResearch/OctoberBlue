"""Local SQLite experiment store. Not a true security isolation boundary."""
import sqlite3
import json
import hashlib
from dataclasses import asdict
from pathlib import Path

class Store:
    def __init__(self, path: str):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(p))
        self.conn.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, partition TEXT NOT NULL, body_json TEXT NOT NULL, sha256 TEXT NOT NULL)")
        self.conn.execute("CREATE TABLE IF NOT EXISTS memory (side TEXT NOT NULL, version INTEGER NOT NULL, parent_version INTEGER, body TEXT NOT NULL, evidence_run_id TEXT, status TEXT NOT NULL, PRIMARY KEY(side, version))")
        self.conn.commit()
    def save(self, result):
        body = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
        with self.conn:
            self.conn.execute("INSERT INTO runs VALUES (?,?,?,?)", (result.run_id, result.partition, body, hashlib.sha256(body.encode()).hexdigest()))
    def get(self, run_id):
        row = self.conn.execute("SELECT body_json,sha256 FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row: raise KeyError(run_id)
        if hashlib.sha256(row[0].encode()).hexdigest() != row[1]: raise ValueError("run hash mismatch")
        return json.loads(row[0])
    def close(self):
        self.conn.close()
