"""Local single-connection hard-cap prototype; no actual API calls."""

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
        conn.execute(
            "CREATE TABLE IF NOT EXISTS spend (id TEXT PRIMARY KEY, reserved TEXT NOT NULL, "
            "actual TEXT, state TEXT NOT NULL)"
        )
        conn.commit()

    def committed(self):
        return sum(
            (
                amount(r[0])
                for r in self.conn.execute(
                    "SELECT COALESCE(actual,reserved) FROM spend "
                    "WHERE state IN ('reserved','settled','unknown')"
                )
            ),
            Decimal("0"),
        )

    def reserve(self, key, upper_bound):
        v = amount(upper_bound)
        with self.conn:
            if self.committed() + v > self.ceiling:
                raise BudgetExceeded("hard cap exceeded")
            self.conn.execute(
                "INSERT INTO spend (id,reserved,state) VALUES (?,?,'reserved')", (key, str(v))
            )

    def settle(self, key, actual):
        v = amount(actual)
        with self.conn:
            row = self.conn.execute(
                "SELECT reserved,state FROM spend WHERE id=?", (key,)
            ).fetchone()
            if not row or row[1] != "reserved":
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
