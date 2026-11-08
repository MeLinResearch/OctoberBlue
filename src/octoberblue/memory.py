"""Separate evidence-linked red/blue memory versions; not autonomous Dreaming."""

from .service_contracts import DreamProposalV1


class Memory:
    def __init__(self, store, side):
        if side not in ("red", "blue"):
            raise ValueError("side")
        self.store, self.side = store, side

    def latest(self):
        row = self.store.conn.execute(
            "SELECT version,body FROM memory WHERE side=? AND status='approved' "
            "ORDER BY version DESC LIMIT 1",
            (self.side,),
        ).fetchone()
        return {"version": row[0], "body": row[1]} if row else None

    def propose(self, run_id, lesson):
        old = self.latest()
        proposal = DreamProposalV1(
            "1.0", self.side, old["version"] if old else None, run_id, lesson,
        )
        return self.propose_wire(proposal.to_wire())

    def propose_wire(self, wire):
        proposal = DreamProposalV1.from_wire(wire)
        if proposal.side != self.side:
            raise PermissionError("memory side mismatch")
        old = self.latest()
        if proposal.parent_version != (old["version"] if old else None):
            raise ValueError("stale parent")
        run_id, lesson = proposal.evidence_run_id, proposal.lesson
        run = self.store.get(run_id)
        if run["partition"] != "development":
            raise PermissionError("no holdout learning")
        if run["verdict"] not in ("pass", "fail"):
            raise ValueError("unverified run")
        v = self.store.conn.execute(
            "SELECT COALESCE(MAX(version),0)+1 FROM memory WHERE side=?", (self.side,)
        ).fetchone()[0]
        with self.store.conn:
            self.store.conn.execute(
                "INSERT INTO memory VALUES (?,?,?,?,?,?)",
                (self.side, v, old["version"] if old else None, lesson, run_id, "proposed"),
            )
        return v

    def approve(self, version):
        row = self.store.conn.execute(
            "SELECT parent_version,status,evidence_run_id FROM memory WHERE side=? AND version=?",
            (self.side, version),
        ).fetchone()
        if not row or row[1] != "proposed" or not row[2]:
            raise ValueError("invalid proposal")
        current = self.latest()
        if row[0] != (current["version"] if current else None):
            raise ValueError("stale parent")
        with self.store.conn:
            self.store.conn.execute(
                "UPDATE memory SET status='approved' WHERE side=? AND version=?",
                (self.side, version),
            )
