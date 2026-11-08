"""Opt-in Ed25519 acquisition signatures and offline deterministic audit replay.

A supplied public key is a trust anchor, never a field borrowed from a pack.
Signatures attest to the configured trusted signer, not an honest host or model.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .service_contracts import service_message, service_payload
from .ticket_contracts import TicketOracle, digest, load_ticket_cases
from .ticket_evidence import (
    MAX_PACKET_BYTES,
    RunManifestV1,
    canonical,
    decode,
    implementation_digest,
    verify_witness_body,
)
from .verifier import Verification

DOMAIN = b"octoberblue.ticket.audit-pack.v1\x00"
_HEX = re.compile(r"[a-f0-9]{64}\Z")


class AuditError(ValueError):
    """Safe fixed error code; no key material or untrusted strings in errors."""


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        raise AuditError("audit_dependency_missing") from None
    return serialization, ed25519


def public_bytes(seed: bytes) -> bytes:
    serialization, ed25519 = _crypto()
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


def key_id(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise AuditError("invalid_public_key")
    return hashlib.sha256(public_key).hexdigest()


def _read_file(path: str | Path, limit: int, *, private: bool = False) -> bytes:
    # No symlink following; regular files only. Ancestor directories are operator-trusted.
    try:
        metadata = Path(path).lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise AuditError("invalid_audit_file")
        if private and os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AuditError("private_key_permissions")
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NONBLOCK", 0))
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise AuditError("audit_file_changed")
            if private and os.name != "nt" and stat.S_IMODE(opened.st_mode) & 0o077:
                raise AuditError("private_key_permissions")
            if not stat.S_ISREG(opened.st_mode):
                raise AuditError("invalid_audit_file")
            raw = handle.read(limit + 1)
        if not 0 < len(raw) <= limit:
            raise AuditError("audit_file_size")
        return raw
    except OSError:
        raise AuditError("audit_file_unavailable") from None


def write_new(path: str | Path, raw: bytes, *, private: bool = False) -> None:
    """Exclusive creation prevents replacement and symlink clobbering."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                     0o600 if private else 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise AuditError("audit_output_unavailable") from None


def generate_keypair(private_path: str | Path, public_path: str | Path) -> str:
    serialization, ed25519 = _crypto()
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.absolute() == public_path.absolute():
        raise AuditError("key_paths_must_differ")
    # Do not create either artifact when an output already exists (including a symlink).
    if os.path.lexists(private_path) or os.path.lexists(public_path):
        raise AuditError("key_output_exists")
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    write_new(private_path, private, private=True)
    write_new(public_path, public)
    return key_id(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw))


def load_signing_seed(path: str | Path) -> bytes:
    serialization, ed25519 = _crypto()
    try:
        key = serialization.load_pem_private_key(_read_file(path, 16_384, private=True), None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise AuditError("invalid_private_key")
        return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    except (ValueError, TypeError) as error:
        if isinstance(error, AuditError):
            raise
        raise AuditError("invalid_private_key") from None


def load_public_key(path: str | Path) -> bytes:
    serialization, ed25519 = _crypto()
    try:
        key = serialization.load_pem_public_key(_read_file(path, 16_384))
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise AuditError("invalid_public_key")
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except (ValueError, TypeError) as error:
        if isinstance(error, AuditError):
            raise
        raise AuditError("invalid_public_key") from None


def _sign_witness_body(body: dict, seed: bytes) -> dict:
    """Witness-internal acquisition operation; no CLI/API for post-hoc signing DB rows."""
    _, ed25519 = _crypto()
    payload = {"schema_version": "1.0", "algorithm": "ed25519",
               "key_id": key_id(public_bytes(seed)), "evidence_body": body}
    signature = ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(DOMAIN + canonical(payload))
    pack = {**payload, "signature": signature.hex()}
    if len(canonical(pack)) > MAX_PACKET_BYTES:
        raise AuditError("audit_pack_size")
    return pack


def authenticate_pack(pack: object, trusted_public_key: bytes,
                      expected_manifest_sha256: str) -> dict:
    """Authenticate the original bytes AND the caller's independent run anchor."""
    _, ed25519 = _crypto()
    from cryptography.exceptions import InvalidSignature

    try:
        if (type(pack) is not dict or set(pack) != {
            "schema_version", "algorithm", "key_id", "evidence_body", "signature",
        } or pack["schema_version"] != "1.0" or pack["algorithm"] != "ed25519"
                or pack["key_id"] != key_id(trusted_public_key)
                or type(pack["signature"]) is not str
                or not re.fullmatch(r"[a-f0-9]{128}", pack["signature"])):
            raise AuditError("invalid_audit_signature")
        payload = {k: v for k, v in pack.items() if k != "signature"}
        encoded = canonical(payload)
        if len(encoded) > MAX_PACKET_BYTES:
            raise AuditError("audit_pack_size")
        ed25519.Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            bytes.fromhex(pack["signature"]), DOMAIN + encoded,
        )
        body = pack["evidence_body"]
        manifest = RunManifestV1.from_wire(body["manifest"])
        if (type(expected_manifest_sha256) is not str
                or not _HEX.fullmatch(expected_manifest_sha256)
                or digest(manifest.to_wire()) != expected_manifest_sha256):
            raise AuditError("audit_manifest_mismatch")
        return body
    except (InvalidSignature, ValueError, TypeError, KeyError, RecursionError) as error:
        if isinstance(error, AuditError):
            raise
        raise AuditError("invalid_audit_signature") from None


@dataclass(frozen=True)
class AuditReplay:
    signature_verified: bool
    reason_code: str
    run_id: str | None
    manifest_sha256: str | None
    verification: Verification

    def to_wire(self) -> dict:
        return {"signature_verified": self.signature_verified, "reason_code": self.reason_code,
                "run_id": self.run_id, "manifest_sha256": self.manifest_sha256,
                **asdict(self.verification)}


def _unknown(reason: str, *, authenticated=False, run_id=None, anchor=None) -> AuditReplay:
    return AuditReplay(authenticated, reason, run_id, anchor,
                       Verification(False, False, False, "indeterminate"))


def replay_audit_pack(pack: object, *, trusted_public_key: bytes,
                      expected_manifest_sha256: str) -> AuditReplay:
    """No execution, model, network, DB, claimed verdict or pack-supplied oracle is trusted."""
    try:
        body = authenticate_pack(pack, trusted_public_key, expected_manifest_sha256)
    except AuditError as error:
        return _unknown(str(error))
    try:
        manifest = RunManifestV1.from_wire(body["manifest"])
        context = dict(authenticated=True, run_id=manifest.run_id, anchor=expected_manifest_sha256)
        if manifest.implementation_sha256 != implementation_digest():
            return _unknown("audit_implementation_mismatch", **context)
        cases = [c for c in load_ticket_cases() if digest(c.to_wire()) == manifest.case_sha256]
        if len(cases) != 1:
            return _unknown("audit_unknown_fixture", **context)
        oracle = TicketOracle.for_case(cases[0])
        result = verify_witness_body(body, expected_manifest_sha256=expected_manifest_sha256,
                                     oracle=oracle, run_id=manifest.run_id)
        return AuditReplay(True, "replayed" if result.verdict != "indeterminate"
                           else "audit_insufficient_evidence", manifest.run_id,
                           expected_manifest_sha256, result)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return _unknown("audit_invalid_evidence", authenticated=True)


def replay_in_subprocess(pack: object, *, trusted_public_key: bytes,
                         expected_manifest_sha256: str, timeout: float = 5.0) -> AuditReplay:
    try:
        request_id = secrets.token_hex(16)
        request = canonical(service_message("replay_ticket", request_id, {
            "pack": pack, "trusted_public_key": trusted_public_key.hex(),
            "expected_manifest_sha256": expected_manifest_sha256,
        }))
        if len(request) > MAX_PACKET_BYTES:
            return _unknown("audit_pack_size")
        process = subprocess.run(
            [sys.executable, "-m", "octoberblue.ticket_audit_worker"], input=request,
            capture_output=True, check=False, timeout=timeout,
        )
        if process.returncode != 0 or len(process.stdout) > 2048:
            return _unknown("audit_replay_worker_failed")
        result = service_payload(decode(process.stdout), operation="replay_ticket",
                                 request_id=request_id, response=True)
        if (result["verdict"] != "indeterminate"
                and result["manifest_sha256"] != expected_manifest_sha256):
            return _unknown("audit_replay_worker_failed")
        fields = {"signature_verified", "reason_code", "run_id", "manifest_sha256",
                  "task_success", "attempted", "completed", "verdict"}
        if (type(result) is not dict or set(result) != fields
                or any(type(result[k]) is not bool for k in (
                    "signature_verified", "task_success", "attempted", "completed"))
                or type(result["reason_code"]) is not str
                or result["verdict"] not in ("pass", "fail", "indeterminate")
                or (result["verdict"] != "indeterminate" and not result["signature_verified"])
                or (result["verdict"] == "indeterminate" and any(
                    result[k] for k in ("task_success", "attempted", "completed")))
                or (result["verdict"] == "pass" and (
                    not result["task_success"] or result["completed"]))):
            return _unknown("audit_replay_worker_failed")
        verification = Verification(**{k: result[k] for k in (
            "task_success", "attempted", "completed", "verdict")})
        return AuditReplay(result["signature_verified"], result["reason_code"],
                           result["run_id"], result["manifest_sha256"], verification)
    except (OSError, ValueError, TypeError, AttributeError, RecursionError,
            subprocess.TimeoutExpired):
        return _unknown("audit_replay_worker_failed")


def load_pack(path: str | Path) -> object:
    try:
        return decode(_read_file(path, MAX_PACKET_BYTES))
    except (ValueError, RecursionError) as error:
        if isinstance(error, AuditError):
            raise
        raise AuditError("invalid_audit_json") from None


def export_pack(record: dict, output: str | Path, *, trusted_public_key: bytes) -> str:
    """Export only a witness-signed acquisition; never accept a signing key here."""
    try:
        pack = record["audit_pack"]
        if pack is None:
            raise AuditError("run_has_no_acquisition_signature")
        body = record["evidence"]["body"]
        anchor = digest(body["manifest"])
        authenticated = authenticate_pack(pack, trusted_public_key, anchor)
        if authenticated != body or authenticated["manifest"]["run_id"] != record["run_id"]:
            raise AuditError("audit_record_mismatch")
        raw = canonical(pack) + b"\n"
        if len(raw) > MAX_PACKET_BYTES:
            raise AuditError("audit_pack_size")
        write_new(output, raw)
        return anchor
    except (KeyError, TypeError):
        raise AuditError("run_has_no_acquisition_signature") from None
