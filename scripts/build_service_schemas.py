"""Regenerate the v1 service catalog; runtime validation remains dependency-free."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "octoberblue:"


def obj(properties):
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def ref(name):
    return {"$ref": PREFIX + name + ":v1"}


def build():
    string = {"type": "string"}
    boolean = {"type": "boolean"}
    identity = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$"}
    source = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9:/._-]{0,255}$"}
    sha = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
    event_id = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}:[0-9]{4}$"}
    version = {"const": "1.0"}
    surface = {"enum": ["ticket_body", "retrieved_knowledge_snippet", "tool_response_body"]}
    snapshot = {"$ref": "octoberblue:ticket-audit-pack:v1#/$defs/snapshot"}
    guard = obj({"schema_version": version, "defense_id": identity, "defense_sha256": sha,
                 "guard_enabled": boolean, "source_id": source, "surface": surface,
                 "payload_sha256": sha, "blocked": boolean,
                 "reason_code": {"enum": ["disabled", "marker_match", "no_match"]}})
    guard["oneOf"] = [
        {"properties": {"guard_enabled": {"const": False}, "blocked": {"const": False},
                        "reason_code": {"const": "disabled"}}},
        {"properties": {"guard_enabled": {"const": True}, "blocked": {"const": True},
                        "reason_code": {"const": "marker_match"}}},
        {"properties": {"guard_enabled": {"const": True}, "blocked": {"const": False},
                        "reason_code": {"const": "no_match"}}},
    ]
    manifest = {"oneOf": [ref("run-manifest"), {"$ref": "octoberblue:run-manifest:v2"}]}
    request = obj({"schema_version": version, "manifest": manifest,
                   "ticket_id": identity, "account_id": identity})
    started = obj({"task_id": identity, "task_family": {"const": "synthetic_support_ticket"},
                   "task_sha256": sha, "case_sha256": sha, "surface": surface,
                   "partition": {"const": "development"}, "seed": {"type": "integer"},
                   "synthetic_only": {"const": True},
                   "target_runtime": {"enum": ["in_memory", "docker"]},
                   "defense_sha256": sha, "gateway_sha256": sha})
    provenance = {"source_id": source, "surface": surface, "trust": {"const": "untrusted"},
                  "payload_sha256": sha}
    received = obj({**provenance, "case_version": version, "guard_decision": ref("guard-decision")})
    received["required"].remove("guard_decision")  # Published legacy ledger compatibility.
    verdict = obj({"task_success": boolean, "attempted": boolean, "completed": boolean,
                   "verdict": {"enum": ["pass", "fail", "indeterminate"]}})
    verdict_event = obj({"task_success": boolean, "attack_attempted": boolean,
                         "unauthorized_effect": boolean,
                         "verdict": {"enum": ["pass", "fail", "indeterminate"]},
                         "transport": {"enum": ["subprocess", "docker"]}})
    audit_schema = json.loads((ROOT / "schemas/ticket-audit-pack.v1.json").read_text())
    snapshot_event = obj({**audit_schema["$defs"]["snapshot"]["properties"],
                          "synthetic_only": {"const": True}})
    effect_fields = {
        "get_ticket": ("ticket_id",), "get_account_summary": ("account_id",),
        "draft_reply": ("ticket_id", "priority", "reply_code"),
        "update_ticket_status": ("ticket_id", "status"),
        "send_external_message": ("sink", "record"), "export_customer_data": ("sink", "record"),
        "change_user_permissions": ("account_id", "role"),
    }
    executed = {"oneOf": [obj({"tool": {"const": tool}, "request_event_id": event_id,
                              **{key: {"type": "string", "maxLength": 100} for key in fields}})
                          for tool, fields in effect_fields.items()]}
    details = {
        "run_started": ("execution_harness", started),
        "input_received": ("execution_harness", received),
        "content_delivered": ("execution_harness", obj(provenance)),
        "filter": ("blue_guard", obj({"blocked": {"const": True}, "surface": surface,
                                      "source_id": source, "defense_id": identity})),
        "tool_request": ("target_agent", obj({"tool": identity, "intent": string,
                                              "task_authorized": boolean})),
        "tool_executed": ("execution_harness", executed),
        "tool_denied": ("execution_harness", obj({"tool": identity, "request_event_id": event_id,
                                                  "reason": {"enum": [
                                                      "capability", "quota", "schema",
                                                      "policy", "transition"]}})),
        "ticket_snapshot": ("execution_harness", snapshot_event),
        "target_runtime_failed": ("execution_harness", obj({"reason_code": identity})),
        "witness_acquisition_failed": ("execution_harness", obj({})),
        "verdict": ("independent_verifier", verdict_event),
    }
    event = {"oneOf": [obj({"event_id": event_id, "origin": {"const": actor},
                            "kind": {"const": kind}, "detail": detail})
                        for kind, (actor, detail) in details.items()]}
    trace = obj({"schema_version": version, "run_id": identity,
                 "events": {"type": "array", "minItems": 1, "maxItems": 100, "items": event}})
    evidence = obj({"authentication": sha, "body": {
        "$ref": "octoberblue:ticket-audit-pack:v1#/properties/evidence_body"}})
    def nullable(schema):
        return {"anyOf": [{"type": "null"}, schema]}

    record = obj({"schema_version": version, "run_id": identity,
                  "partition": {"const": "development"}, "guard_enabled": boolean,
                  "task_success": boolean, "attack_success": boolean,
                  "attempted_unauthorized_action": boolean,
                  "completed_unauthorized_effect": boolean,
                  "verdict": {"enum": ["pass", "fail", "indeterminate"]},
                  "events": {"$ref": "octoberblue:trace:v1#/properties/events"},
                  "evidence": nullable(evidence),
                  "audit_pack": nullable(ref("ticket-audit-pack"))})
    dream = obj({"schema_version": version, "side": {"enum": ["red", "blue"]},
                 "parent_version": {"anyOf": [{"type": "null"},
                                               {"type": "integer", "minimum": 1}]},
                 "evidence_run_id": identity,
                 "lesson": {"type": "string", "minLength": 1, "maxLength": 8000,
                            "pattern": r"\S"},
                 "partition": {"const": "development"}, "approval_required": {"const": True}})
    oracle = obj({"ticket_id": identity, "account_id": identity,
                  "expected_priority": {"enum": ["low", "normal", "high", "urgent"]},
                  "expected_reply_code": {"enum": ["access", "billing", "outage", "information"]},
                  "task_sha256": sha, "case_sha256": sha})
    logical = obj({"run_id": identity, "oracle": oracle,
                   "events": {"$ref": "octoberblue:trace:v1#/properties/events"},
                   "snapshot": snapshot})
    acquired = obj({"run_id": identity, "oracle": oracle, "evidence": {},
                    "authentication_key": sha, "expected_manifest_sha256": sha})
    replay_request = obj({"pack": {}, "trusted_public_key": sha, "expected_manifest_sha256": sha})
    replay_response = obj({**verdict["properties"], "signature_verified": boolean,
                           "reason_code": identity, "run_id": nullable(identity),
                           "manifest_sha256": nullable(sha)})
    service = obj({"schema_version": version, "request_id": identity,
                   "service": {"const": "independent_verifier"},
                   "operation": {"enum": ["verify_ticket", "replay_ticket"]},
                   "message_type": {"enum": ["request", "response"]}, "payload": {}})
    service["oneOf"] = [{"properties": {"operation": {"const": operation},
                                         "message_type": {"const": direction}, "payload": payload}}
                        for operation, direction, payload in (
                            ("verify_ticket", "request", {"oneOf": [logical, acquired]}),
                            ("verify_ticket", "response", verdict),
                            ("replay_ticket", "request", replay_request),
                            ("replay_ticket", "response", replay_response))]
    metadata = {"oneOf": [obj({"origin": {"const": actor}, "kind": {"const": kind},
                              "detail": detail}) for kind, (actor, detail) in details.items()
                           if kind in ("run_started", "input_received", "content_delivered",
                                       "target_runtime_failed", "filter")]}
    witness = obj({"schema_version": version, "sequence": {"type": "integer", "minimum": 1,
                                                          "maximum": 100},
                   "operation": {"enum": ["initialize", "record", "call", "finalize"]},
                   "parameters": {}})
    for branch in metadata["oneOf"]:
        if branch["properties"]["kind"] == {"const": "input_received"}:
            # Copy the shared detail schema before strengthening the live RPC.
            detail = json.loads(json.dumps(branch["properties"]["detail"]))
            detail["required"].append("guard_decision")
            branch["properties"]["detail"] = detail
    credentials = obj({"authentication_key": sha, "audit_signing_key": nullable(sha)})
    witness["oneOf"] = [{"properties": {"operation": {"const": operation},
                                         "parameters": params}} for operation, params in (
        ("initialize", obj({"run": ref("run-request"), "credentials": credentials})),
        ("record", metadata), ("call", obj({"tool": identity, "arguments": {"type": "object"}})),
        ("finalize", obj({})))]
    response = obj({"schema_version": version,
                    "sequence": {"type": "integer", "minimum": 1, "maximum": 100}, "result": {}})
    return {"run-request": request, "run-record": record, "trace": trace,
            "guard-decision": guard, "dream-proposal": dream, "service-message": service,
            "witness-request": witness, "witness-response": response}


def main():
    for name, schema in build().items():
        value = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                 "$id": PREFIX + name + ":v1", "title": name + " v1", **schema}
        (ROOT / "schemas" / (name + ".v1.json")).write_bytes(
            (json.dumps(value, indent=2) + "\n").encode(),
        )


if __name__ == "__main__":
    main()
