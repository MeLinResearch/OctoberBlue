"""SQLite reservations serialized across connections; no actual API calls."""

from contextlib import contextmanager
from decimal import Decimal, InvalidOperation


class BudgetExceeded(RuntimeError):
    pass


def amount(raw):
    try:
        val = Decimal(str(raw))
    except InvalidOperation as exc:
        raise ValueError("invalid money") from exc
    if not val.is_finite() or val < 0:
        raise ValueError("invalid money")
    return val


class Budget:
    def __init__(self, conn, ceiling="0.00"):
        self.conn = conn
        self.ceiling = amount(ceiling)
        with self._transaction():
            conn.execute(
                "CREATE TABLE IF NOT EXISTS spend (id TEXT PRIMARY KEY, reserved TEXT NOT NULL, "
                "actual TEXT, state TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS spend_policy "
                "(id INTEGER PRIMARY KEY CHECK(id=1), ceiling TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT OR IGNORE INTO spend_policy VALUES (1,?)", (str(self.ceiling),)
            )
            stored = conn.execute("SELECT ceiling FROM spend_policy WHERE id=1").fetchone()[0]
            if amount(stored) != self.ceiling:
                raise ValueError("ledger ceiling mismatch")
            if self.committed() > self.ceiling:
                raise BudgetExceeded("existing commitments exceed ceiling")

    @contextmanager
    def _transaction(self):
        # Acquire the writer lock before reading any balance or reservation state.
        # Never commit unrelated caller work, including on autocommit connections.
        if self.conn.in_transaction:
            raise ValueError("budget requires an idle connection")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    def committed(self):
        return sum(
            (
                amount(r[0])
                for r in self.conn.execute(
                    "SELECT COALESCE(actual,reserved) FROM spend "
                    "WHERE state IN ('reserved','inflight','settled','unknown')"
                )
            ),
            Decimal("0"),
        )

    def reserve(self, key, upper_bound):
        v = amount(upper_bound)
        with self._transaction():
            self._require_no_unresolved_charge()
            if self.committed() + v > self.ceiling:
                raise BudgetExceeded("hard cap exceeded")
            self.conn.execute(
                "INSERT INTO spend (id,reserved,state) VALUES (?,?,'reserved')", (key, str(v))
            )

    def _require_no_unresolved_charge(self):
        unresolved = self.conn.execute(
            "SELECT 1 FROM spend WHERE state IN ('inflight','unknown') LIMIT 1"
        ).fetchone()
        if unresolved:
            raise BudgetExceeded("inflight or unknown charge; reconciliation required")

    def _transition(self, key, expected, state):
        changed = self.conn.execute(
            "UPDATE spend SET state=? WHERE id=? AND state=?", (state, key, expected)
        ).rowcount
        if changed != 1:
            raise ValueError("missing reservation or invalid spend transition")

    def begin_dispatch(self, key):
        """Persist before invoking; a crashed caller leaves the ledger frozen."""
        with self._transaction():
            self._require_no_unresolved_charge()
            self._transition(key, "reserved", "inflight")

    def fail_dispatch(self, key):
        """Retain the bound and freeze the ledger after ambiguous execution."""
        with self._transaction():
            self._transition(key, "inflight", "unknown")

    def settle_dispatch(self, key, actual):
        self._settle(key, actual, "inflight")

    def settle(self, key, actual):
        self._settle(key, actual, "reserved")

    def _settle(self, key, actual, expected):
        v = amount(actual)
        with self._transaction():
            row = self.conn.execute(
                "SELECT reserved,state FROM spend WHERE id=?", (key,)
            ).fetchone()
            if not row or row[1] != expected:
                raise ValueError("missing reservation")
            over = v > amount(row[0])
            if over:
                self.conn.execute("UPDATE spend SET state='unknown' WHERE id=?", (key,))
            else:
                self.conn.execute(
                    "UPDATE spend SET actual=?,state='settled' WHERE id=?", (str(v), key)
                )
        if over:
            raise BudgetExceeded("usage exceeded reserved bound; stop execution")
