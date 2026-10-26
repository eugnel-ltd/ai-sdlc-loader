"""Text checks for .github/workflows/checks.yml (the stdlib has no YAML reader)."""

from pathlib import Path
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


class SecurityAndNightly(unittest.TestCase):
    SECURITY = (ROOT / ".github/workflows/security.yml").read_text()
    NIGHTLY = (ROOT / ".github/workflows/nightly-gates.yml").read_text()

    def test_scripts_come_from_the_signed_bundle(self):
        self.assertIn('python3 "$RUNNER_TEMP/ai-sdlc-gates/scripts/security_intake.py"', self.SECURITY)
        self.assertIn('fetch_gates.py" bundle', self.SECURITY)
        self.assertIn('"$gates/scripts/nightly_status.py"', self.NIGHTLY)
        self.assertIn('cat "$gates/references/lessons-audit.md"', self.NIGHTLY)
        for text in (self.SECURITY, self.NIGHTLY):
            self.assertNotIn("$SCRIPTS", text)
            self.assertNotIn(".caller/", text)

    def test_the_caller_cannot_supply_the_audit_command(self):
        # ai-sdlc #731 section 6: the nightly audit_command input is removed.
        self.assertNotIn("audit_command", self.NIGHTLY)
        self.assertEqual(self.NIGHTLY.count('fetch_gates.py" fetch '), 1)

    def test_both_may_mint_an_oidc_token(self):
        for text in (self.SECURITY, self.NIGHTLY):
            top = text[text.index("\npermissions:\n"):text.index("\njobs:\n")]
            self.assertIn("\n  id-token: write\n", top)

    def test_cf_cost_failure_points_to_the_one_fix(self):
        self.assertIn("references/cloudflare.md#the-one-way-to-meet-the-limits-and-the-rate-limit", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
