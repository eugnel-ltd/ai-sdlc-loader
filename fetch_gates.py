#!/usr/bin/env python3
"""Fetch and verify the signed AI-SDLC gate record and bundle for this run (ai-sdlc #731).

  fetch_gates.py bundle --verifier <dir> --out <dir>   verify, fetch and unpack the served bundle
  fetch_gates.py record --verifier <dir> --out <file>  write the newest verified record as JSON

The broker only checks the caller's OIDC token. This script does every signature, freshness,
digest and path check, with the pinned cosign and trusted root in <dir> (verifier/fetch_cosign.sh).
Exit 0 on success, 1 on a refusal, 2 on bad input or an unreachable service.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request


BROKER = "https://ai-sdlc-gates.fol2hk.workers.dev"
AUDIENCE = "ai-sdlc-gates"
USER_AGENT = "ai-sdlc-loader/1"
PREDICATE_TYPE = "https://eugnel.com/ai-sdlc/record/v1"
CERTIFICATE_IDENTITY = "https://github.com/eugnel-ltd/ai-sdlc/.github/workflows/release-tag.yml@refs/heads/main"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
LOADER_WORKFLOW = re.compile(
    r"eugnel-ltd/ai-sdlc-loader/\.github/workflows/[a-z-]+\.yml@(refs/tags/v3|refs/heads/main|[0-9a-f]{40})"
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_ARCHIVE = 100 * 1024 * 1024
MAX_UNPACKED = 512 * 1024 * 1024


class Refused(Exception):
    """A record, archive or caller failed a check."""


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: object) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("time is not a string")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("time has no zone")
    return parsed


def oidc_token() -> str:
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not request_token:
        raise OSError("Actions OIDC is not available: the caller must grant id-token: write")
    separator = "&" if urllib.parse.urlsplit(url).query else "?"
    request = urllib.request.Request(
        f"{url}{separator}audience={AUDIENCE}",
        headers={"Authorization": f"Bearer {request_token}", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        token = json.load(response).get("value")
    if not isinstance(token, str) or not token:
        raise OSError("Actions OIDC response has no token")
    return token


def token_claims(token: str) -> dict[str, object]:
    # Read only: this token came straight from GitHub, and the broker verifies it.
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def broker_get(broker: str, token: str, path: str, limit: int) -> bytes:
    request = urllib.request.Request(
        f"{broker.rstrip('/')}{path}",
        headers={"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        raise OSError(f"broker {path.split('/')[2]} read failed with HTTP {error.code}") from None
    if len(body) > limit:
        raise Refused(f"broker answer for {path} is over {limit} bytes")
    return body


def statement(bundle: object) -> tuple[dict[str, object], list[object]]:
    """The record and subjects from a bundle's DSSE payload (cosign writes in-toto v0.1)."""
    try:
        decoded = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True))
    except (KeyError, TypeError, ValueError):
        raise Refused("record has no DSSE statement") from None
    if not isinstance(decoded, dict) or decoded.get("predicateType") != PREDICATE_TYPE:
        raise Refused("record has the wrong predicate type")
    record = decoded.get("predicate")
    subjects = decoded.get("subject")
    if not isinstance(record, dict) or not isinstance(subjects, list):
        raise Refused("record statement is incomplete")
    return record, subjects


def bundle_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise Refused("bundle is not an object")
    source, digest, size = value.get("source_sha"), value.get("archive_sha256"), value.get("archive_size")
    if not (isinstance(source, str) and HEX40.fullmatch(source) and isinstance(digest, str)
            and HEX64.fullmatch(digest) and type(size) is int and 0 < size <= MAX_ARCHIVE):
        raise Refused("bundle fields are invalid")
    return value


def check_record(record: dict[str, object], serial: object, now: dt.datetime) -> None:
    if record.get("type") != "ai-sdlc.record.v1" or type(record.get("serial")) is not int:
        raise Refused("record type or serial is invalid")
    if record["serial"] != serial:
        raise Refused("record serial differs from its key")
    try:
        if parse_time(record.get("expires")) <= now:
            raise Refused("record has expired")
    except ValueError:
        raise Refused("record expiry is invalid") from None
    bundle_object(record.get("current"))
    if record.get("pin") is not None:
        bundle_object(record["pin"])
    if not isinstance(record.get("revoked", []), list) or not isinstance(record.get("loader_shas", []), list):
        raise Refused("record lists are invalid")


def cosign_verifies(verifier: Path, bundle: dict[str, object], digest: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="gates-record-") as temporary:
        path = Path(temporary) / "record.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        command = [
            str(verifier / "cosign"), "verify-blob-attestation", "--bundle", str(path),
            "--new-bundle-format", "--type", PREDICATE_TYPE,
            "--certificate-identity", CERTIFICATE_IDENTITY, "--certificate-oidc-issuer", OIDC_ISSUER,
            "--trusted-root", str(verifier / "trusted_root.json"),
            "--digest", digest, "--digestAlg", "sha256",
        ]
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def newest_record(answer: object, verify, now: dt.datetime) -> dict[str, object]:
    """The highest serial that verifies and has not expired (#731 contract B)."""
    entries = answer.get("records") if isinstance(answer, dict) else None
    if not isinstance(entries, list):
        raise Refused("broker answer has no record list")
    ordered = sorted((entry for entry in entries if isinstance(entry, dict) and type(entry.get("serial")) is int),
                     key=lambda entry: entry["serial"], reverse=True)
    for entry in ordered:
        try:
            record, subjects = statement(entry.get("object"))
            check_record(record, entry["serial"], now)
            digest = record["current"]["archive_sha256"]
            if not any(isinstance(subject, dict) and isinstance(subject.get("digest"), dict)
                       and subject["digest"].get("sha256") == digest for subject in subjects):
                raise Refused("record subject is not its current archive")
            if verify(entry["object"], digest):
                return record
        except Refused:
            continue
    raise Refused("no record verifies and is unexpired")


def served(record: dict[str, object], claims: dict[str, object]) -> tuple[str, dict[str, object]]:
    """The bundle this loader call may run (#731 sections 2 and 5)."""
    match = LOADER_WORKFLOW.fullmatch(str(claims.get("job_workflow_ref", "")))
    loader_sha = claims.get("job_workflow_sha")
    if not match or not isinstance(loader_sha, str) or not HEX40.fullmatch(loader_sha):
        raise Refused("this run is not a loader workflow call")
    version = match.group(1)
    if HEX40.fullmatch(version):
        candidate = record.get("candidate")
        if version != loader_sha or not isinstance(candidate, dict) or candidate.get("loader_sha") != loader_sha:
            raise Refused(f"loader {loader_sha} is not the record's candidate")
        route, bundle = "candidate", bundle_object(candidate)
    else:
        if version == "refs/tags/v3" and loader_sha not in record.get("loader_shas", []):
            raise Refused(f"loader {loader_sha} is not in the record's loader_shas")
        route, bundle = ("pin", record["pin"]) if record.get("pin") is not None else ("current", record["current"])
    if bundle["source_sha"] in record.get("revoked", []):
        raise Refused(f"source {bundle['source_sha']} is revoked")
    return route, bundle


def check_archive(body: bytes, bundle: dict[str, object]) -> None:
    if len(body) != bundle["archive_size"] or hashlib.sha256(body).hexdigest() != bundle["archive_sha256"]:
        raise Refused("archive digest or size differs from the record")


def unpack(archive: Path, destination: Path) -> None:
    """Unpack into an empty directory: regular files and directories only, no escape, size capped."""
    with tempfile.TemporaryDirectory(prefix="gates-unpack-") as temporary:
        tar_path = Path(temporary) / "gates.tar"
        result = subprocess.run(["zstd", "-q", "-d", "-o", str(tar_path), str(archive)], capture_output=True)
        if result.returncode != 0:
            raise Refused("archive does not decompress")
        with tarfile.open(tar_path) as bundle:
            members = bundle.getmembers()
            total = 0
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                    raise Refused(f"archive member is not allowed: {member.name}")
                total += member.size
            if total > MAX_UNPACKED:
                raise Refused("archive unpacks over the size limit")
            destination.mkdir(parents=True, exist_ok=False)
            bundle.extractall(destination, members=members, filter="data")


def run(args: argparse.Namespace) -> int:
    verifier = Path(args.verifier)
    token = oidc_token()
    answer = json.loads(broker_get(args.broker, token, "/v1/records", 10 * 1024 * 1024))
    record = newest_record(answer, lambda bundle, digest: cosign_verifies(verifier, bundle, digest), utc_now())
    if args.command == "record":
        Path(args.out).write_text(json.dumps(record, separators=(",", ":")), encoding="utf-8")
        print(f"GATES-LOADER RECORD serial={record['serial']} loader_shas={','.join(record.get('loader_shas', [])) or '-'}")
        return 0
    route, bundle = served(record, token_claims(token))
    body = broker_get(args.broker, token, f"/v1/archive/{bundle['archive_sha256']}", MAX_ARCHIVE)
    check_archive(body, bundle)
    with tempfile.TemporaryDirectory(prefix="gates-archive-") as temporary:
        archive = Path(temporary) / "gates.tar.zst"
        archive.write_bytes(body)
        unpack(archive, Path(args.out))
    print(f"GATES-LOADER OK serial={record['serial']} route={route} source={bundle['source_sha']} "
          f"archive={bundle['archive_sha256']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("bundle", "record"))
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--broker", default=BROKER)
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Refused as error:
        print(f"GATES-LOADER REFUSED: {error}")
        return 1
    except (OSError, ValueError, urllib.error.URLError) as error:
        print(f"GATES-LOADER ERROR: {str(error).splitlines()[0] if str(error) else type(error).__name__}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
