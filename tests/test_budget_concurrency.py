"""File-backed independent callers must share one fail-closed spend ledger."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from octoberblue.budget import Budget, BudgetExceeded


def test_inv18_concurrent_reservations_cannot_exceed_shared_ceiling(tmp_path):
    path = tmp_path / "spend.sqlite3"
    barrier = Barrier(8)

    def reserve(index):
        with sqlite3.connect(path, timeout=10) as conn:
            budget = Budget(conn, "0.10")
            barrier.wait(timeout=10)
            try:
                budget.reserve(str(index), "0.03")
                return True
            except BudgetExceeded:
                return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(reserve, range(8))) == 3
    with sqlite3.connect(path) as conn:
        assert str(Budget(conn, "0.10").committed()) == "0.09"


def test_inv18_persisted_ceiling_rejects_other_callers(tmp_path):
    path = tmp_path / "spend.sqlite3"
    with sqlite3.connect(path) as conn:
        Budget(conn)
    with sqlite3.connect(path) as conn:
        with pytest.raises(ValueError, match="ceiling mismatch"):
            Budget(conn, "100")
        with pytest.raises(BudgetExceeded):
            Budget(conn).reserve("paid", "0.01")


def test_inv18_unknown_charge_stops_new_calls_after_reopen(tmp_path):
    path = tmp_path / "spend.sqlite3"
    with sqlite3.connect(path) as conn:
        budget = Budget(conn, "1")
        budget.reserve("overrun", "0.01")
        with pytest.raises(BudgetExceeded):
            budget.settle("overrun", "0.02")
    with sqlite3.connect(path) as conn:
        with pytest.raises(BudgetExceeded, match="unknown charge"):
            Budget(conn, "1").reserve("next", "0.01")


def test_inv18_budget_rejects_nested_transactions_without_committing_them(tmp_path):
    with sqlite3.connect(tmp_path / "spend.sqlite3") as conn:
        budget = Budget(conn, "1")
        conn.execute("INSERT INTO spend VALUES ('pending','0.1',NULL,'reserved')")
        with pytest.raises(ValueError, match="idle connection"):
            budget.reserve("next", "0.1")
        assert conn.in_transaction
        conn.rollback()
        assert budget.committed() == 0


def test_inv18_duplicate_reservation_rolls_back_in_autocommit_mode(tmp_path):
    with sqlite3.connect(tmp_path / "spend.sqlite3", isolation_level=None) as conn:
        budget = Budget(conn, "1")
        budget.reserve("same", "0.1")
        with pytest.raises(sqlite3.IntegrityError):
            budget.reserve("same", "0.1")
        assert not conn.in_transaction
        budget.settle("same", "0.05")
        with pytest.raises(ValueError, match="missing reservation"):
            budget.settle("same", "0")
        assert str(budget.committed()) == "0.05"


def test_inv18_concurrent_settlement_releases_reservation_only_once(tmp_path):
    path = tmp_path / "spend.sqlite3"
    with sqlite3.connect(path) as conn:
        Budget(conn, "1").reserve("call", "0.5")
    barrier = Barrier(2)

    def settle(_):
        with sqlite3.connect(path, timeout=10) as conn:
            budget = Budget(conn, "1")
            barrier.wait(timeout=10)
            try:
                budget.settle("call", "0.2")
                return True
            except ValueError:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(settle, range(2))) == 1
    with sqlite3.connect(path) as conn:
        assert str(Budget(conn, "1").committed()) == "0.2"


def test_inv18_lock_timeout_admits_no_reservation(tmp_path):
    path = tmp_path / "spend.sqlite3"
    with sqlite3.connect(path) as owner, sqlite3.connect(path, timeout=0) as contender:
        budget = Budget(contender, "1")
        owner.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            budget.reserve("blocked", "0.1")
        owner.rollback()
        assert budget.committed() == 0
        budget.reserve("retry", "0.1")


def test_inv18_legacy_ledger_cannot_adopt_ceiling_below_commitments(tmp_path):
    with sqlite3.connect(tmp_path / "spend.sqlite3") as conn:
        conn.execute(
            "CREATE TABLE spend (id TEXT PRIMARY KEY, reserved TEXT NOT NULL, "
            "actual TEXT, state TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO spend VALUES ('old','0.5',NULL,'reserved')")
        conn.commit()
        with pytest.raises(BudgetExceeded, match="existing commitments"):
            Budget(conn)
        budget = Budget(conn, "1")
        assert str(budget.committed()) == "0.5"
