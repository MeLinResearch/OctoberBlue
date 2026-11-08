"""Bounded offline replay entry point. No provider or target execution."""
import sys

from .service_contracts import service_message, service_payload
from .ticket_audit import replay_audit_pack
from .ticket_evidence import MAX_PACKET_BYTES, canonical, decode


def main() -> int:
    try:
        message = decode(sys.stdin.buffer.read(MAX_PACKET_BYTES + 1))
        request = service_payload(message, operation="replay_ticket")
        if type(request) is not dict or set(request) != {
            "pack", "trusted_public_key", "expected_manifest_sha256",
        }:
            return 2
        result = replay_audit_pack(
            request["pack"], trusted_public_key=bytes.fromhex(request["trusted_public_key"]),
            expected_manifest_sha256=request["expected_manifest_sha256"],
        )
        response = service_message("replay_ticket", message["request_id"], result.to_wire(),
                                   response=True)
        sys.stdout.buffer.write(canonical(response) + b"\n")
        return 0
    except (ValueError, TypeError, OSError, RecursionError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
