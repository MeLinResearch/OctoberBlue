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
    ("D13", "provider_admission_contracts", "Operator-reviewed model pins and pricing records",
     "Offline identity/pricing admission and exact cost bounds; no provider transport",
     ["src/octoberblue/provider_contracts.py", "schemas/model-pin.v1.json",
      "schemas/price-quote.v1.json", "schemas/provider-call-request.v1.json"]),
    ("D12", "contained_ticket_acceptance", "Authored fixed-worker boundary and acceptance gate",
     "Pinned image launch, resource probes and reproducible zero-model acceptance",
     ["src/octoberblue/contained_runtime.py", "src/octoberblue/containment_probe.py",
      "src/octoberblue/phase1.py", "docker/target.Dockerfile", "docker/trusted.Dockerfile",
      "docker/trusted-requirements.txt", "schemas/run-manifest.v2.json"]),
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
    ("D11", "bounded_process_boundaries", "Authored bounded I/O and trusted-worker startup",
     "Finite process streams, deadlines, cleanup and sanitized verifier launch",
     ["src/octoberblue/process_boundary.py", "src/octoberblue/target_runtime.py",
      "src/octoberblue/verifier_process.py", "src/octoberblue/ticket_verifier_process.py"]),
    ("D10", "service_contract_catalog", "Authored service schemas and admission validators",
     "Versioned run, trace, guard, proposal and private service boundaries",
     ["src/octoberblue/service_contracts.py", "scripts/build_service_schemas.py",
      "schemas/run-request.v1.json", "schemas/run-record.v1.json", "schemas/trace.v1.json",
      "schemas/guard-decision.v1.json", "schemas/dream-proposal.v1.json",
      "schemas/service-message.v1.json", "schemas/witness-request.v1.json",
      "schemas/witness-response.v1.json"]),
    ("D09", "ticket_witness_evidence", "Produced by the trusted ticket witness subprocess",
     "Frozen manifest, chained events, action receipts and ephemeral acquisition authentication",
     ["src/octoberblue/ticket_evidence.py", "src/octoberblue/ticket_witness.py",
      "src/octoberblue/ticket_witness_worker.py", "schemas/run-manifest.v1.json",
      "src/octoberblue/ticket_audit.py", "src/octoberblue/ticket_audit_worker.py",
      "schemas/ticket-audit-pack.v1.json"]),
    ("D08", "synthetic_ticket_fixtures", "40 wholly authored support-ticket test cases",
     "Development-only ticket tasks, injections, task contracts and oracle",
     ["src/octoberblue/fixtures/tickets.v1.json",
      "src/octoberblue/ticket_contracts.py",
      "schemas/ticket-task.v1.json", "schemas/ticket-case.v1.json"]),
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
