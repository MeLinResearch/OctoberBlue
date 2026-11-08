"""Write docs/governance/dbom.json: OctoberBlue's data bill of materials with file hashes.

Run after changing any file listed below:
    uv run python scripts/build_dbom.py
"""

import hashlib
import json
from pathlib import Path

from octoberblue import __version__

ROOT = Path(__file__).resolve().parents[1]
RIGHTS = "MIT, authored"

ASSETS = [
    ("D01", "synthetic_task", "Authored invoice task and expected total",
     "Task input and task-success check", ["src/octoberblue/contracts.py"]),
    ("D02", "synthetic_inputs", "Authored clean and injected inputs",
     "Demo workload; payloads hashed, never logged", ["src/octoberblue/cli.py"]),
    ("D03", "defense_markers", "Authored guard phrases",
     "Marker-based guard; frozen per run", ["src/octoberblue/contracts.py"]),
    ("D04", "run_records", "Produced by the harness and verifier at runtime",
     "Events, flags and verdicts; SHA-256 per record",
     ["src/octoberblue/engine.py", "src/octoberblue/store.py"]),
    ("D05", "memory_versions", "Proposed against development runs, approved by an operator",
     "Separate red/blue lessons with parent and evidence links", ["src/octoberblue/memory.py"]),
    ("D06", "spend_ledger", "Produced at runtime",
     "Reservations, settlements and unknown charges; $0.00 default",
     ["src/octoberblue/budget.py"]),
    ("D07", "source_and_lock", "Executing source and dependency lock",
     "Experiment identity", ["pyproject.toml", "uv.lock"]),
]


def sha(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main() -> None:
    doc = {
        "project": "octoberblue",
        "version": __version__,
        "human_records": False,
        "assets": [
            {"id": i, "name": n, "origin": o, "use": u, "rights": RIGHTS,
             "consent": "not_applicable_synthetic_or_authored", "human_records": False,
             "files": [{"path": f, "sha256": sha(f)} for f in files]}
            for i, n, o, u, files in ASSETS
        ],
        "not_included": ["personal data", "credentials", "external datasets",
                         "model weights", "model outputs"],
    }
    out = ROOT / "docs/governance/dbom.json"
    out.write_bytes((json.dumps(doc, indent=2) + "\n").encode("utf-8"))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
