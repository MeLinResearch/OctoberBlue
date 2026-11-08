"""Bounded offline replay entry point. No provider or target execution."""
import sys

from .ticket_audit import replay_audit_pack
from .ticket_evidence import MAX_PACKET_BYTES, canonical, decode


def main() -> int:
    try:
        request = decode(sys.stdin.buffer.read(MAX_PACKET_BYTES + 1))
        if type(request) is not dict or set(request) != {
            "pack", "trusted_public_key", "expected_manifest_sha256",
        }:
            return 2
        result = replay_audit_pack(
            request["pack"], trusted_public_key=bytes.fromhex(request["trusted_public_key"]),
            expected_manifest_sha256=request["expected_manifest_sha256"],
        )
        sys.stdout.buffer.write(canonical(result.to_wire()) + b"\n")
        return 0
    except (ValueError, TypeError, OSError, RecursionError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
