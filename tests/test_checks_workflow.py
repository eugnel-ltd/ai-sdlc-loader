"""Text and shell checks for .github/workflows/checks.yml (no YAML reader needed)."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/checks.yml").read_text()

# ai-sdlc #731 section 8: job ids and names stay byte for byte.
JOBS = {
    "resolve": "Resolve the PR and its head",
    "review-on-head": "Independent APPROVE names the head",
    "owner-decisions": "owner-decisions.md is append-only",
    "locked-tests": "A fix leaves its failing test alone",
    "secret-scan": "No credentials in the PR range",
    "manifest": "product.yaml is valid and a published product has its baseline",
    "cloudflare-cost": "Cloudflare config stays inside the US$5 plan",
}


class ChecksWorkflow(unittest.TestCase):
    def test_job_ids_and_names_are_unchanged(self):
        for job, name in JOBS.items():
            self.assertIn(f"\n  {job}:\n    name: {name}\n", WORKFLOW)
        self.assertIn("context=ai-sdlc/review-on-head", WORKFLOW)

    def test_every_job_may_mint_an_oidc_token(self):
        # A called workflow's permissions block sets id-token to none when it leaves it out.
        top = WORKFLOW[WORKFLOW.index("\npermissions:\n"):WORKFLOW.index("\njobs:\n")]
        self.assertIn("\n  id-token: write\n", top)
        for block in WORKFLOW.split("\n    permissions:\n")[1:]:
            self.assertIn("      id-token: write", block.split("\n    steps:")[0])

    def test_one_broker_fetch_per_run(self):
        self.assertEqual(WORKFLOW.count('fetch_gates.py" fetch '), 1)
        self.assertNotIn('fetch_gates.py" bundle', WORKFLOW)
        self.assertEqual(WORKFLOW.count("uses: actions/upload-artifact@"), 1)

    def test_shell_gates_run_from_the_signed_bundle(self):
        # Slice 2: these gates no longer read the caller's vendored copies.
        for script in ("review_on_head.sh", "owner_decisions_check.sh", "secret_scan.sh", "locked_tests_check.py"):
            self.assertIn(f'"$gates/scripts/{script}"', WORKFLOW)
            self.assertNotIn(f"$SCRIPTS/{script}", WORKFLOW)
        self.assertEqual(WORKFLOW.count("uses: actions/download-artifact@"), 6)
        self.assertEqual(WORKFLOW.count('sh "$loader/load_gates.sh"'), 6)

    def test_native_gates_run_the_archive_binaries(self):
        # Slice 3: no gate reads the caller's copies or builds anything.
        for call in ('"$bin/written-by" --body-file "$RUNNER_TEMP/pr-body.txt" --files "$RUNNER_TEMP/pr-files.txt"',
                     '"$bin/manifest-check" "$RUNNER_TEMP/product.yaml"',
                     '"$bin/cf-cost-check" --head "$sha" --base "$base_sha" "$@"'):
            self.assertIn(call, WORKFLOW)
        self.assertNotIn("$SCRIPTS", WORKFLOW)
        self.assertNotIn("setup-go", WORKFLOW)
        self.assertNotIn("go build", WORKFLOW)
        self.assertEqual(WORKFLOW.count("bin=$gates/bin/$os-$arch"), 3)

    def test_written_by_unknown_only_warns_and_errors_still_fail(self):
        step = WORKFLOW.split("      - name: Written by is filled in\n", 1)[1]
        block = step.split("        run: |\n", 1)[1]
        lines = []
        for line in block.splitlines():
            if line.strip() and not line.startswith("          "):
                break
            lines.append(line)
        script = textwrap.dedent("\n".join(lines))

        cases = (
            (1, "::error title=Written by::x\nwritten-by: unknown", 0, "written-by: unknown"),
            (0, "written-by: vendor", 0, "written-by: vendor"),
            (2, "::error::input failure", 2, "::error::input failure"),
            (2, "", 2, "written-by: not checked (native setup failure)"),
            (1, "written-by: vendor", 2, "::error::written-by native result violates exit/output contract"),
        )
        for rc, output, expected_rc, last_line in cases:
            with self.subTest(rc=rc, output=output), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                work = Path(directory)
                stubs = work / "stubs"
                stubs.mkdir()
                git = stubs / "git"
                git.write_text(
                    '#!/bin/sh\ncase "$*" in\n'
                    '  *" rev-parse "*) printf "%s\\n" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;\n'
                    '  *" diff "*) printf "%s\\n" app.py ;;\n'
                    '  *) exit 2 ;;\nesac\n'
                )
                git.chmod(0o755)
                os_name = os.uname().sysname.lower()
                arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
                    os.uname().machine, "unknown")
                binary = work / "ai-sdlc-gates" / "bin" / f"{os_name}-{arch}" / "written-by"
                binary.parent.mkdir(parents=True)
                binary.write_text('#!/bin/sh\nprintf \'%s\\n\' "$STUB_OUTPUT"\nexit "$STUB_RC"\n')
                binary.chmod(0o755)
                summary = work / "summary"
                env = {**os.environ, "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
                       "RUNNER_TEMP": str(work), "GITHUB_STEP_SUMMARY": str(summary),
                       "BASE": "main", "BODY": "Written by: cursor", "STUB_RC": str(rc), "STUB_OUTPUT": output}
                result = subprocess.run(["sh", "-e", "-c", script], cwd=work, env=env,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout.splitlines()[-1], last_line)
                self.assertEqual(summary.read_text(), last_line + "\n")
                if last_line == "written-by: unknown":
                    self.assertIn("::warning title=Written by::x\n", result.stdout)
                    self.assertIn("Not blocking: an unrecognised or missing author line only warns", result.stdout)
                    self.assertNotIn("::error", result.stdout)


class GateRunners(unittest.TestCase):
    def test_private_gate_jobs_run_on_small(self):
        # ai-sdlc modules/ci.md R1: the gate jobs run only git, gh, short scripts and small native tools.
        for name in ("checks.yml", "bot-review.yml", "nightly-gates.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            self.assertNotIn('"self-hosted", "linux"', text, name)
        checks = (ROOT / ".github/workflows/checks.yml").read_text()
        self.assertEqual(checks.count("""fromJSON('["self-hosted", "small"]')"""), 7)


class SecurityAndNightly(unittest.TestCase):
    SECURITY = (ROOT / ".github/workflows/security.yml").read_text()
    NIGHTLY = (ROOT / ".github/workflows/nightly-gates.yml").read_text()

    def test_scripts_come_from_the_signed_bundle(self):
        self.assertIn('python3 -I "$RUNNER_TEMP/ai-sdlc-gates/scripts/security_intake.py"', self.SECURITY)
        self.assertIn('fetch_gates.py" bundle', self.SECURITY)
        self.assertIn('"$gates/scripts/nightly_status.py"', self.NIGHTLY)
        self.assertIn('cat "$gates/references/lessons-audit.md"', self.NIGHTLY)
        for text in (self.SECURITY, self.NIGHTLY):
            self.assertNotIn("$SCRIPTS", text)
            self.assertNotIn(".caller/", text)

    def test_a_public_runner_installs_without_homebrew(self):
        # The public path is GitHub-hosted Ubuntu, which has no Homebrew: brew runs only when present,
        # and the Linux path checks each pinned download by SHA-256.
        self.assertIn("visibility == 'public' && fromJSON('[\"ubuntu-24.04\"]')", self.SECURITY)
        install = self.SECURITY[self.SECURITY.index("- name: Install the scanners"):self.SECURITY.index("- name: Load the signed gate bundle")]
        self.assertIn("if command -v brew >/dev/null; then", install)
        self.assertEqual(install.count("brew install"), 1)
        self.assertEqual(install.count("sha256sum -c -"), 2)
        for digest in ("551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
                       "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"):
            self.assertIn(digest, install)

    def test_the_audit_runs_claude_on_the_runner_api_key_only(self):
        # Owner, 26 Oct 2026: "On local you can use api". No bare claude call may use a login.
        self.assertIn('sh "$gates/scripts/claude_api.sh" -p "$prompt"', self.NIGHTLY)
        self.assertNotIn("\n          claude -p", self.NIGHTLY)

    def test_the_caller_cannot_supply_the_audit_command(self):
        # ai-sdlc #731 section 6: the nightly audit_command input is removed.
        self.assertNotIn("audit_command", self.NIGHTLY)
        self.assertEqual(self.NIGHTLY.count('fetch_gates.py" fetch '), 1)

    def test_both_may_mint_an_oidc_token(self):
        for text in (self.SECURITY, self.NIGHTLY):
            top = text[text.index("\npermissions:\n"):text.index("\njobs:\n")]
            self.assertIn("\n  id-token: write\n", top)

    def test_no_pat_and_the_app_token_only_in_the_writing_step(self):
        # ai-sdlc #731 slice 5: no audit_token secret; the audit step alone takes an App token.
        TAG_SYNC = (ROOT / ".github/workflows/tag-sync.yml").read_text()
        BOT = (ROOT / ".github/workflows/bot-review.yml").read_text()
        for text in (self.NIGHTLY, TAG_SYNC, BOT):
            self.assertNotIn("audit_token", text)
            self.assertNotIn("secrets.", text)
            self.assertEqual(text.count("fetch_gates.py repo-token") + text.count('fetch_gates.py" repo-token'), 1)
            self.assertIn('echo "::add-mask::', text)
        for text in (self.NIGHTLY, TAG_SYNC):
            self.assertIn("persist-credentials: false", text)
            self.assertIn("GIT_CONFIG_COUNT=2", text)
            self.assertIn('GIT_CONFIG_VALUE_0=""', text)
        job = TAG_SYNC[TAG_SYNC.index("    permissions:"):TAG_SYNC.index("    steps:")]
        self.assertIn("contents: read", job)
        self.assertNotIn("contents: write", TAG_SYNC.replace("contents: write only", ""))
        self.assertIn("workflow_call:", BOT)
        top = BOT[BOT.index("\npermissions:\n"):BOT.index("\njobs:\n")]
        self.assertNotIn("write", top.replace("id-token: write", ""))
        self.assertIn("GH_TOKEN: ${{ github.token }}", BOT)
        self.assertIn("export REVIEW_TOKEN", BOT)

    def test_cf_cost_failure_points_to_the_one_fix(self):
        self.assertIn("references/cloudflare.md#the-one-way-to-meet-the-limits-and-the-rate-limit", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
