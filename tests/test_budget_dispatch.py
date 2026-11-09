"""INV-18: durable dispatch state survives a lost caller and prevents retries."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from octoberblue.budget import Budget, BudgetExceeded


def test_inv18_crashed_dispatch_freezes_ledger_and_retains_reservation(tmp_path):
    path = tmp_path / "spend.sqlite3"
    with sqlite3.connect(path) as conn:
        budget = Budget(conn, "1")
        budget.reserve("call", "0.3")
        budget.begin_dispatch("call")
    with sqlite3.connect(path) as conn:
        budget = Budget(conn, "1")
        assert str(budget.committed()) == "0.3"
        with pytest.raises(BudgetExceeded, match="inflight"):
            budget.reserve("new-call", "0")
        with pytest.raises(BudgetExceeded):
            budget.begin_dispatch("call")
        with pytest.raises(ValueError):
            budget.settle("call", "0")
        budget.fail_dispatch("call")
        with pytest.raises(BudgetExceeded, match="unknown"):
            budget.reserve("next", "0.1")
        with pytest.raises(ValueError):
            budget.settle_dispatch("call", "0")


def test_inv18_dispatch_settles_once_and_releases_only_unused_bound(tmp_path):
    with sqlite3.connect(tmp_path / "spend.sqlite3") as conn:
        budget = Budget(conn, "1")
        budget.reserve("call", "0.3")
        budget.begin_dispatch("call")
        budget.settle_dispatch("call", "0.2")
        assert str(budget.committed()) == "0.2"
        with pytest.raises(ValueError):
            budget.settle_dispatch("call", "0")
        with pytest.raises(ValueError):
            budget.begin_dispatch("call")
        budget.reserve("next", "0.8")


def test_inv18_dispatch_overrun_cannot_be_cleared_by_a_second_settlement(tmp_path):
    with sqlite3.connect(tmp_path / "spend.sqlite3") as conn:
        budget = Budget(conn, "1")
        budget.reserve("call", "0.1")
        budget.begin_dispatch("call")
        with pytest.raises(BudgetExceeded):
            budget.settle_dispatch("call", "0.2")
        assert str(budget.committed()) == "0.1"
        with pytest.raises(ValueError):
            budget.settle_dispatch("call", "0")
        with pytest.raises(BudgetExceeded):
            budget.reserve("free", "0")


def test_inv18_concurrent_dispatches_cannot_pass_unresolved_charge(tmp_path):
    path = tmp_path / "spend.sqlite3"
    with sqlite3.connect(path) as conn:
        budget = Budget(conn, "1")
        budget.reserve("a", "0.1")
        budget.reserve("b", "0.1")
    barrier = Barrier(2)

    def dispatch(key):
        with sqlite3.connect(path, timeout=10) as conn:
            budget = Budget(conn, "1")
            barrier.wait(timeout=10)
            try:
                budget.begin_dispatch(key)
                return True
            except BudgetExceeded:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(dispatch, ("a", "b"))) == 1
    with sqlite3.connect(path) as conn:
        assert str(Budget(conn, "1").committed()) == "0.2"


def test_inv18_missing_dispatch_does_not_manufacture_a_reservation(tmp_path):
    with sqlite3.connect(tmp_path / "spend.sqlite3") as conn:
        budget = Budget(conn, "1")
        with pytest.raises(ValueError):
            budget.begin_dispatch("missing")
        with pytest.raises(ValueError):
            budget.fail_dispatch("missing")
        assert budget.committed() == 0
