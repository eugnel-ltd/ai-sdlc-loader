"""Checks for fetch_gates.py: record choice, served bundle, archive digest and unpacking."""

import base64
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fetch_gates as loader  # noqa: E402

NOW = dt.datetime(2026, 10, 26, 12, tzinfo=dt.timezone.utc)
LOADER = "a" * 40
SOURCE = "b" * 40
OTHER = "c" * 40


def bundle(source=SOURCE, body=b"archive"):
    return {"source_sha": source, "archive_sha256": hashlib.sha256(body).hexdigest(), "archive_size": len(body)}


def record(serial, **fields):
    value = {"type": "ai-sdlc.record.v1", "serial": serial, "issued_at": "2026-10-26T00:00:00Z",
             "expires": "2026-11-02T00:00:00Z", "current": bundle(), "pin": None, "revoked": [],
             "candidate": None, "loader_shas": [], "transition": None}
    value.update(fields)
    return value


def entry(value, serial=None, predicate_type=loader.PREDICATE_TYPE, subject=None):
    digest = subject or value["current"]["archive_sha256"]
    payload = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": predicate_type,
               "subject": [{"name": "gates.tar.zst", "digest": {"sha256": digest}}], "predicate": value}
    envelope = {"dsseEnvelope": {"payload": base64.b64encode(json.dumps(payload).encode()).decode()}}
    return {"serial": value["serial"] if serial is None else serial, "object": envelope}


def claims(version, sha=LOADER):
    return {"job_workflow_ref": f"eugnel-ltd/ai-sdlc-loader/.github/workflows/checks.yml@{version}",
            "job_workflow_sha": sha}


def always(_bundle, _digest):
    return True


class NewestRecord(unittest.TestCase):
    def test_highest_verified_unexpired_serial_wins(self):
        answer = {"records": [entry(record(2)), entry(record(3)), entry(record(1))]}
        self.assertEqual(loader.newest_record(answer, always, NOW)["serial"], 3)

    def test_unverified_expired_and_mismatched_heads_are_skipped(self):
        planted = entry(record(5))
        planted["object"]["planted"] = True
        answer = {"records": [
            planted,
            entry(record(4, expires="2026-10-26T11:00:00Z")),
            entry(record(3), serial=9),
            entry(record(2), predicate_type="https://example.invalid/v1"),
            entry(record(1)),
        ]}
        verify = lambda bundle, _digest: "planted" not in bundle  # noqa: E731
        self.assertEqual(loader.newest_record(answer, verify, NOW)["serial"], 1)

    def test_a_subject_other_than_the_current_archive_is_skipped(self):
        answer = {"records": [entry(record(2), subject="d" * 64), entry(record(1))]}
        self.assertEqual(loader.newest_record(answer, always, NOW)["serial"], 1)

    def test_nothing_valid_is_refused(self):
        with self.assertRaises(loader.Refused):
            loader.newest_record({"records": [entry(record(1))]}, lambda *_: False, NOW)

    def test_the_verifier_gets_the_current_archive_digest(self):
        seen = []
        loader.newest_record({"records": [entry(record(1))]}, lambda _b, digest: seen.append(digest) or True, NOW)
        self.assertEqual(seen, [bundle()["archive_sha256"]])


class Served(unittest.TestCase):
    def test_candidate_route_serves_the_candidate_bundle(self):
        candidate = {"loader_sha": LOADER, **bundle(OTHER, b"candidate")}
        route, served = loader.served(record(1, candidate=candidate), claims(LOADER))
        self.assertEqual((route, served["source_sha"]), ("candidate", OTHER))

    def test_another_sha_is_refused(self):
        candidate = {"loader_sha": OTHER, **bundle()}
        with self.assertRaises(loader.Refused):
            loader.served(record(1, candidate=candidate), claims(LOADER))
        with self.assertRaises(loader.Refused):
            loader.served(record(1), claims(LOADER))

    def test_v3_needs_the_loader_sha_in_loader_shas(self):
        with self.assertRaises(loader.Refused):
            loader.served(record(1, loader_shas=[OTHER]), claims("refs/tags/v3"))
        route, _ = loader.served(record(1, loader_shas=[LOADER]), claims("refs/tags/v3"))
        self.assertEqual(route, "current")

    def test_every_loader_file_is_a_loader_call(self):
        for name in ("checks", "security", "nightly-gates"):
            call = {"job_workflow_ref": f"eugnel-ltd/ai-sdlc-loader/.github/workflows/{name}.yml@refs/tags/v3",
                    "job_workflow_sha": LOADER}
            self.assertEqual(loader.served(record(1, loader_shas=[LOADER]), call)[0], "current")
        with self.assertRaises(loader.Refused):
            loader.served(record(1, loader_shas=[LOADER]), {
                "job_workflow_ref": "eugnel-ltd/ai-sdlc-loader/.github/workflows/tag-sync.yml@refs/tags/v3",
                "job_workflow_sha": LOADER})

    def test_pin_wins_over_current(self):
        route, served = loader.served(record(1, pin=bundle(OTHER)), claims("refs/heads/main"))
        self.assertEqual((route, served["source_sha"]), ("pin", OTHER))

    def test_a_revoked_source_is_never_served(self):
        with self.assertRaises(loader.Refused):
            loader.served(record(1, revoked=[SOURCE]), claims("refs/heads/main"))
        candidate = {"loader_sha": LOADER, **bundle(OTHER)}
        with self.assertRaises(loader.Refused):
            loader.served(record(1, candidate=candidate, revoked=[OTHER]), claims(LOADER))

    def test_a_non_loader_caller_is_refused(self):
        with self.assertRaises(loader.Refused):
            loader.served(record(1), {"job_workflow_ref": "eugnel-ltd/other/.github/workflows/checks.yml@refs/heads/main",
                                      "job_workflow_sha": LOADER})


def tar_zst(directory, members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    tar_path = Path(directory) / "in.tar"
    tar_path.write_bytes(raw.getvalue())
    out = Path(directory) / "in.tar.zst"
    subprocess.run(["zstd", "-q", "-f", "-o", str(out), str(tar_path)], check=True)
    return out


def file_member(name, data=b"x"):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


class Unpack(unittest.TestCase):
    def test_regular_files_unpack(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = tar_zst(directory, [file_member("./scripts/review_on_head.sh", b"echo ok\n")])
            loader.unpack(archive, Path(directory) / "out")
            self.assertEqual((Path(directory) / "out/scripts/review_on_head.sh").read_bytes(), b"echo ok\n")

    def test_escapes_and_links_are_refused(self):
        link = tarfile.TarInfo("scripts/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        for members in ([file_member("../evil")], [file_member("/abs")], [(link, None)]):
            with tempfile.TemporaryDirectory() as directory:
                archive = tar_zst(directory, members)
                with self.assertRaises(loader.Refused):
                    loader.unpack(archive, Path(directory) / "out")
                self.assertFalse((Path(directory) / "out").exists())

    def test_over_the_size_cap_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = tar_zst(directory, [file_member("a", b"12345"), file_member("b", b"12345")])
            with mock.patch.object(loader, "MAX_UNPACKED", 9), self.assertRaises(loader.Refused):
                loader.unpack(archive, Path(directory) / "out")
            self.assertFalse((Path(directory) / "out").exists())

    def write_tree(self, directory, files, manifest):
        for name, data in files.items():
            (directory / name).parent.mkdir(parents=True, exist_ok=True)
            (directory / name).write_bytes(data)
        (directory / "MANIFEST.sha256").write_text(manifest)

    def test_manifest_lists_every_file_with_its_digest(self):
        files = {"scripts/a.sh": b"a", "bin/linux-amd64/tool": b"b"}
        lines = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items()))
        with tempfile.TemporaryDirectory() as directory:
            self.write_tree(Path(directory), files, lines)
            loader.check_manifest(Path(directory))
        for changed in ({"scripts/a.sh": b"x", "bin/linux-amd64/tool": b"b"},
                        {**files, "scripts/extra.sh": b"c"}):
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(loader.Refused):
                self.write_tree(Path(directory), changed, lines)
                loader.check_manifest(Path(directory))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(loader.Refused):
            loader.check_manifest(Path(directory))

    def test_digest_and_size_must_match(self):
        loader.check_archive(b"archive", bundle())
        with self.assertRaises(loader.Refused):
            loader.check_archive(b"archivf", bundle())


class Main(unittest.TestCase):
    def test_bundle_run_reads_records_then_one_archive(self):
        body = b"archive"
        answer = json.dumps({"records": [entry(record(1, candidate={"loader_sha": LOADER, **bundle(body=body)}))]})
        token = "h." + base64.urlsafe_b64encode(json.dumps(claims(LOADER)).encode()).decode().rstrip("=") + ".s"
        paths = []

        def broker_get(_broker, _token, path, _limit):
            paths.append(path)
            return answer.encode() if path == "/v1/records" else body

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(loader, "oidc_token", return_value=token), \
                mock.patch.object(loader, "broker_get", side_effect=broker_get), \
                mock.patch.object(loader, "cosign_verifies", return_value=True), \
                mock.patch.object(loader, "utc_now", return_value=NOW), \
                mock.patch.object(loader, "check_manifest") as check_manifest, \
                mock.patch.object(loader, "unpack") as unpack:
            code = loader.main(["bundle", "--verifier", directory, "--out", f"{directory}/out"])
        self.assertEqual(code, 0)
        check_manifest.assert_called_once_with(Path(f"{directory}/out"))
        self.assertEqual(paths, ["/v1/records", f"/v1/archive/{bundle(body=body)['archive_sha256']}"])
        unpack.assert_called_once()

    def test_record_run_writes_the_newest_record_and_fetches_no_archive(self):
        answer = json.dumps({"records": [entry(record(1)), entry(record(2, loader_shas=[LOADER]))]}).encode()
        paths = []

        def broker_get(_broker, _token, path, _limit):
            paths.append(path)
            return answer

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(loader, "oidc_token", return_value="token"), \
                mock.patch.object(loader, "broker_get", side_effect=broker_get), \
                mock.patch.object(loader, "cosign_verifies", return_value=True), \
                mock.patch.object(loader, "utc_now", return_value=NOW), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = loader.main(["record", "--verifier", directory, "--out", f"{directory}/record.json"])
            written = json.loads(Path(f"{directory}/record.json").read_text())
        self.assertEqual(code, 0)
        self.assertEqual(paths, ["/v1/records"])
        self.assertEqual((written["serial"], written["loader_shas"]), (2, [LOADER]))
        self.assertIn(f"serial=2 loader_shas={LOADER}", out.getvalue())

    def fetch_then_unpack(self, unpack_claims, tamper=None, verify_on_unpack=True):
        body = b"archive"
        signed = entry(record(1, candidate={"loader_sha": LOADER, **bundle(body=body)}))
        answer = json.dumps({"records": [signed]}).encode()
        paths = []

        def broker_get(_broker, _token, path, _limit):
            paths.append(path)
            return answer if path == "/v1/records" else body

        def token(claim):
            return "h." + base64.urlsafe_b64encode(json.dumps(claim).encode()).decode().rstrip("=") + ".s"

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(loader, "broker_get", side_effect=broker_get), \
                mock.patch.object(loader, "cosign_verifies", return_value=True), \
                mock.patch.object(loader, "utc_now", return_value=NOW), \
                mock.patch.object(loader, "check_manifest") as check_manifest, \
                mock.patch.object(loader, "unpack") as unpack:
            with mock.patch.object(loader, "oidc_token", return_value=token(claims(LOADER))):
                fetched = loader.main(["fetch", "--verifier", directory, "--out", f"{directory}/saved"])
            if tamper:
                tamper(Path(directory) / "saved")
            calls = len(paths)
            with mock.patch.object(loader, "oidc_token", return_value=token(unpack_claims)), \
                    mock.patch.object(loader, "cosign_verifies", return_value=verify_on_unpack):
                code = loader.main(["unpack", "--verifier", directory, "--saved", f"{directory}/saved",
                                    "--loader-sha", LOADER, "--out", f"{directory}/out"])
        # Unpacked means unpacked and checked against MANIFEST.sha256.
        return fetched, code, paths[calls:], unpack.called and check_manifest.called

    def test_fetch_saves_the_pair_and_unpack_needs_no_broker(self):
        fetched, code, later_paths, unpacked = self.fetch_then_unpack(claims(LOADER))
        self.assertEqual((fetched, code, later_paths, unpacked), (0, 0, [], True))

    def test_unpack_refuses_another_loader_commit(self):
        _, code, _, unpacked = self.fetch_then_unpack(claims(OTHER, OTHER))
        self.assertEqual((code, unpacked), (1, False))

    def test_unpack_refuses_a_changed_archive(self):
        _, code, _, unpacked = self.fetch_then_unpack(
            claims(LOADER), lambda saved: (saved / "gates.tar.zst").write_bytes(b"archivf"))
        self.assertEqual((code, unpacked), (1, False))

    def test_unpack_refuses_a_record_that_no_longer_verifies(self):
        _, code, _, unpacked = self.fetch_then_unpack(claims(LOADER), verify_on_unpack=False)
        self.assertEqual((code, unpacked), (1, False))

    def test_a_refusal_exits_one_and_never_prints_the_token(self):
        token = "h." + base64.urlsafe_b64encode(json.dumps(claims(OTHER)).encode()).decode().rstrip("=") + ".secret"
        answer = json.dumps({"records": [entry(record(1))]}).encode()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(loader, "oidc_token", return_value=token), \
                mock.patch.object(loader, "broker_get", return_value=answer), \
                mock.patch.object(loader, "cosign_verifies", return_value=True), \
                mock.patch.object(loader, "utc_now", return_value=NOW), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = loader.main(["bundle", "--verifier", directory, "--out", f"{directory}/out"])
        self.assertEqual(code, 1)
        self.assertIn("GATES-LOADER REFUSED", out.getvalue())
        self.assertNotIn("secret", out.getvalue())


class Pins(unittest.TestCase):
    # ai-sdlc #731 contract C: the loader carries a byte copy of ai-sdlc gates/verifier/.
    CONTRACT = {
        "cosign-linux-arm64": "ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2",
        "cosign-linux-amd64": "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa",
        "cosign-darwin-arm64": "9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4",
        "trusted_root.json": "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
    }

    def test_pins_and_trusted_root_match_the_contract(self):
        verifier = Path(__file__).resolve().parents[1] / "verifier"
        pins = {}
        for line in (verifier / "pins.txt").read_text().splitlines():
            if line and not line.startswith("#"):
                digest, name = line.split()
                pins[name] = digest
        self.assertEqual(pins, self.CONTRACT)
        self.assertEqual(hashlib.sha256((verifier / "trusted_root.json").read_bytes()).hexdigest(),
                         self.CONTRACT["trusted_root.json"])


if __name__ == "__main__":
    unittest.main()
