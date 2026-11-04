"""Text and shell checks for .github/workflows/checks.yml (no YAML reader needed)."""

from itertools import product
import os
import re
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

from test_bundle_gate import executable, selector, step

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/checks.yml").read_text()

# Review retains its check run; the other gates retain their names as statuses.
GATES = {
    "review-on-head": "Independent APPROVE names the head",
    "owner-decisions": "owner-decisions.md is append-only",
    "locked-tests": "A fix leaves its failing test alone",
    "secret-scan": "No credentials in the PR range",
    "manifest": "product.yaml is valid and a published product has its baseline",
    "cloudflare-cost": "Cloudflare config stays inside the US$5 plan",
}
STATUS_GATES = {gate: name for gate, name in GATES.items() if gate != "review-on-head"}
JOBS = dict(re.findall(r"^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:\n|\Z)",
                       WORKFLOW.split("\njobs:\n", 1)[1], re.M | re.S))


def gate_block(name):
    return gate_block_from_job(WORKFLOW, name)


def gate_block_from_job(job, name):
    return job.split(f"      - name: {name}\n", 1)[1].split("      - name: ", 1)[0]


def status_publisher():
    return textwrap.dedent(WORKFLOW.split("  GATE_STATUS: |\n", 1)[1].split("  BUNDLE_GATE_SELECTOR:", 1)[0])


class ChecksWorkflow(unittest.TestCase):
    def test_one_job_and_five_exact_status_contexts(self):
        # ai-sdlc #483: one runner job per event; review runs first, then the five gates.
        self.assertEqual(list(JOBS), ["checks"])
        job = JOBS["checks"]
        self.assertIn("    name: AI-SDLC gates\n", job)
        self.assertNotIn("needs:", job)
        self.assertEqual(job.count("uses: actions/checkout@"), 1)
        contexts = re.findall(r"^          STATUS_CONTEXT: (.*)$", job, re.M)
        self.assertEqual(contexts, ["checks / " + name for name in STATUS_GATES.values()])
        names = re.findall(r"^      - name: (.*)$", job, re.M)
        self.assertEqual([n for n in names if n in GATES.values()], list(GATES.values()))
        review = gate_block(GATES["review-on-head"])
        self.assertIn("context=ai-sdlc/review-on-head", review)
        self.assertNotIn("STATUS_CONTEXT", review)
        self.assertNotIn('eval "$GATE_STATUS"', review)

    def test_comment_runs_cannot_replace_pr_event_runs(self):
        header = JOBS["checks"].split("    steps:\n", 1)[0]
        self.assertIn("    if: github.event_name == 'pull_request' || github.event_name == 'pull_request_target' || (github.event_name == 'issue_comment' && github.event.issue.pull_request != null)\n", header)
        self.assertIn("    concurrency:\n", header)
        # Per PR and per event kind: a comment run never replaces a pending PR-event run.
        self.assertIn("      group: ai-sdlc-checks-${{ github.repository }}-${{ github.event.pull_request.number || github.event.issue.number || github.run_id }}-${{ github.event_name == 'issue_comment' && 'review' || 'gates' }}\n", header)
        self.assertIn("      cancel-in-progress: false\n", header)
        caller = (ROOT / ".github/workflows/ai-sdlc-checks.yml").read_text()
        self.assertIn("\nconcurrency:\n", caller)

    def test_a_review_comment_runs_only_the_review_gate(self):
        for gate, name in GATES.items():
            block = gate_block(name)
            if gate == "review-on-head":
                self.assertNotIn("github.event_name != 'issue_comment'", block)
            else:
                self.assertIn("github.event_name != 'issue_comment'", block)

    def test_every_gate_has_a_ten_minute_timeout_with_job_setup_allowance(self):
        for name in GATES.values():
            self.assertIn("        timeout-minutes: 10\n", gate_block(name))
        timeout = int(re.search(r"^    timeout-minutes: (\d+)$", JOBS["checks"], re.M)[1])
        self.assertGreaterEqual(timeout, len(GATES) * 10 + 10)

    def test_gates_continue_after_failure_and_keep_event_guards(self):
        for gate, name in GATES.items():
            block = gate_block(name)
            condition = "if: always() && steps.pr.outputs.is_pr == 'true'"
            if gate != "review-on-head":
                condition += " && github.event_name != 'issue_comment'"
            self.assertIn(condition + "\n", block)
            # All gates run after earlier failures; review alone keeps the old status contract.
            self.assertNotIn("continue-on-error:", block)
            if gate != "review-on-head":
                self.assertIn('eval "$GATE_STATUS"', block)
            self.assertIn("GH_TOKEN: ${{ github.token }}", block)
            self.assertIn("HEAD: ${{ steps.pr.outputs.head }}", block)
            self.assertIn("steps.gates.outcome == 'success' && steps.bundle.outcome == 'success'", block)
            self.assertIn("steps.checkout.outcome == 'success'", block)

    def test_caller_contract_and_identity_checks_remain(self):
        self.assertIn("name: AI-SDLC checks\n\non:\n  workflow_call:", WORKFLOW)
        for item in ("base", "scripts_dir", "test_paths", "runs_on"):
            self.assertIn(f"      {item}:\n", WORKFLOW)
        for permission in ("contents: read", "pull-requests: read", "issues: read",
                           "statuses: write", "id-token: write"):
            self.assertIn("  " + permission + "\n", WORKFLOW)
        for check in ('[ "$number" = "$requested" ] && [ -z "$surplus" ]',
                      'full_sha "$head" && full_sha "$target_base_sha"',
                      'git check-ref-format "refs/heads/$branch"',
                      'git check-ref-format "refs/heads/$target_base_ref"',
                      '[ "$base_repo" = "$GITHUB_REPOSITORY" ]',
                      '[ "$head" = "$PR_HEAD" ] && [ "$branch" = "$PR_BRANCH" ]',
                      '[ "$target_base_ref" = "$PR_BASE_REF" ] && [ "$base_repo" = "$PR_BASE_REPO" ]',
                      'full_sha "$HEAD_SHA" && full_sha "$TARGET_BASE_SHA"',
                      '[ "$target" = "$TARGET_BASE_SHA" ] && [ "$fetched_head" = "$HEAD_SHA" ]'):
            self.assertIn(check, WORKFLOW)
        self.assertIn('"$TARGET_BASE_SHA" "+refs/pull/$PR/head:refs/remotes/pr/head"', WORKFLOW)

    def test_every_job_may_mint_an_oidc_token(self):
        # A called workflow's permissions block sets id-token to none when it leaves it out.
        top = WORKFLOW[WORKFLOW.index("\npermissions:\n"):WORKFLOW.index("\njobs:\n")]
        self.assertIn("\n  id-token: write\n", top)
        for block in WORKFLOW.split("\n    permissions:\n")[1:]:
            self.assertIn("      id-token: write", block.split("\n    steps:")[0])

    def test_one_inline_setup_and_one_broker_fetch(self):
        for job in JOBS.values():
            self.assertEqual(job.count('fetch_gates.py" fetch '), 1)
            self.assertEqual(job.count('fetch_gates.py" unpack '), 1)
            self.assertEqual(job.count('sh "$loader/verifier/fetch_cosign.sh"'), 1)
            fetch = gate_block_from_job(job, "Fetch the signed gate bundle for this run")
            self.assertIn("continue-on-error: true", fetch)
            unpack = gate_block_from_job(job, "Verify and unpack the signed gate bundle")
            self.assertIn("if: steps.pr.outputs.is_pr == 'true' && steps.gates.outcome == 'success'", unpack)
            cleanup = gate_block_from_job(job, "Clean up the gate bundle and temporary inputs")
            self.assertIn("if: always()", cleanup)
            for directory in ("ai-sdlc-fetch", "ai-sdlc-gates", "ai-sdlc-loader", "ai-sdlc-verifier"):
                self.assertIn(f'"$RUNNER_TEMP/{directory}"', cleanup)
        self.assertNotIn('fetch_gates.py" bundle', WORKFLOW)
        self.assertNotIn("actions/upload-artifact@", WORKFLOW)
        self.assertNotIn("actions/download-artifact@", WORKFLOW)
        self.assertIn('--loader-sha "$LOADER_SHA" --out "$RUNNER_TEMP/ai-sdlc-gates"', WORKFLOW)

    def test_each_job_resolves_pr_events_and_review_comments_inline(self):
        for job, event in product(JOBS, ("pull_request", "pull_request_target", "issue_comment")):
            with self.subTest(job=job, event=event), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                executable(work / "stubs/gh", 'printf \'%s\\n\' "$SNAPSHOT"\n')
                head, target = "a" * 40, "b" * 40
                env = {**os.environ, "BASH_ENV": "/dev/null",
                       "PATH": str(work / "stubs") + os.pathsep + os.environ["PATH"],
                       "GITHUB_OUTPUT": str(work / "output"), "GITHUB_REPOSITORY": "example/product",
                       "EVENT": event, "PR_NUMBER": "42", "PR_HEAD": head, "PR_BRANCH": "fix/example",
                       "PR_BASE_REF": "main", "PR_BASE_REPO": "example/product",
                       "ISSUE_NUMBER": "42", "IS_ISSUE_PR": "true",
                       "SNAPSHOT": f"42\t{head}\tfix/example\t{target}\tmain\texample/product"}
                if event == "issue_comment":
                    # Comment payloads have no pull_request metadata; resolve the current head.
                    env.update(PR_NUMBER="", PR_HEAD="", PR_BRANCH="", PR_BASE_REF="", PR_BASE_REPO="")
                result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                         step(JOBS[job], "Resolve the PR")],
                                        env=env, cwd=work, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                outputs = dict(row.split("=", 1) for row in (work / "output").read_text().splitlines())
                self.assertEqual(outputs, {"is_pr": "true", "number": "42", "head": head,
                                           "branch": "fix/example", "target_base_sha": target,
                                           "target_base_ref": "main"})

    def test_shell_gates_run_from_the_signed_bundle(self):
        # Slice 2: these gates no longer read the caller's vendored copies.
        for script in ("review_on_head.sh", "owner_decisions_check.sh", "secret_scan.sh", "locked_tests_check.py"):
            self.assertIn(f'"$gates/scripts/{script}"', WORKFLOW)
            self.assertNotIn(f"$SCRIPTS/{script}", WORKFLOW)
        self.assertNotIn('sh "$loader/load_gates.sh"', WORKFLOW)

    def test_native_gates_run_the_archive_binaries(self):
        # Slice 3: no gate reads the caller's copies or builds anything.
        for name in ("written-by", "manifest-check", "cf-cost-check"):
            self.assertIn(f'select_gate {name} "$bin/{name}"', WORKFLOW)
        for call in ('"${gate[@]}" --body-file "$RUNNER_TEMP/pr-body.txt" --files "$RUNNER_TEMP/pr-files.txt"',
                     '"${gate[@]}" "$RUNNER_TEMP/product.yaml"',
                     '"${gate[@]}" --head "$sha" --base "$base_sha" "$@"'):
            self.assertIn(call, WORKFLOW)
        self.assertNotIn("$SCRIPTS", WORKFLOW)
        self.assertNotIn("setup-go", WORKFLOW)
        self.assertNotIn("go build", WORKFLOW)
        self.assertEqual(WORKFLOW.count("bin=$gates/bin/$os-$arch"), 3)

    def test_written_by_unknown_only_warns_and_errors_still_fail(self):
        # The original written-by shell now follows the scan in its combined gate step.
        script = step(WORKFLOW, GATES["secret-scan"])
        script = script.split("# Written-by ran after a successful scan in the former secret-scan job.\n", 1)[1]

        cases = (
            (1, "::error title=Written by::x\nwritten-by: unknown", 0, "written-by: unknown"),
            (0, "written-by: vendor", 0, "written-by: vendor"),
            (2, "::error::input failure", 2, "::error::input failure"),
            (2, "", 2, "written-by: not checked (native setup failure)"),
            (1, "written-by: vendor", 2, "::error::written-by native result violates exit/output contract"),
        )
        for modern, (rc, output, expected_rc, last_line) in product((False, True), cases):
            with self.subTest(modern=modern, rc=rc, output=output), tempfile.TemporaryDirectory() as directory:
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
                binary = work / "ai-sdlc-gates" / "bin" / f"{os_name}-{arch}" / ("aisdlc" if modern else "written-by")
                binary.parent.mkdir(parents=True)
                binary.write_text('#!/bin/sh\n'
                                  'if [ "$#" -eq 1 ] && [ "$1" = gate ]; then\n'
                                  '  echo "usage: aisdlc gate <name> [args]"; exit 2\nfi\n'
                                  'printf \'%s\\n\' "$STUB_OUTPUT"\nexit "$STUB_RC"\n')
                binary.chmod(0o755)
                summary = work / "summary"
                env = {**os.environ, "BASH_ENV": "/dev/null", "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
                       "RUNNER_TEMP": str(work), "GITHUB_STEP_SUMMARY": str(summary),
                       "BASE": "main", "BODY": "Written by: cursor", "STUB_RC": str(rc), "STUB_OUTPUT": output,
                       "BUNDLE_GATE_SELECTOR": selector(WORKFLOW)}
                result = subprocess.run(["bash", "-e", "-c", script], cwd=work, env=env,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout.splitlines()[-1], last_line)
                self.assertEqual(summary.read_text(), last_line + "\n")
                if last_line == "written-by: unknown":
                    self.assertIn("::warning title=Written by::x\n", result.stdout)
                    self.assertIn("Not blocking: an unrecognised or missing author line only warns", result.stdout)
                    self.assertNotIn("::error", result.stdout)


class GateExecution(unittest.TestCase):
    """Execute the real step bodies; stub only GitHub, git data and the signed tools."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        stubs = self.work / "stubs"
        executable(stubs / "gh", '''if [ "$2" != -X ]; then
  echo "${PR_STATE:-open}"; exit 0
fi
printf '%s\\0' "$@" >> "$STATUS_LOG"
printf '\\n' >> "$STATUS_LOG"
exit "${POST_RC:-0}"
''')
        executable(stubs / "git", '''case "$*" in
  *fetch*) exit "${FETCH_RC:-0}" ;;
  *rev-parse*)
    case "$*" in
      *"$TARGET_BASE_SHA"*) echo "$TARGET_BASE_SHA" ;;
      *) echo "${FETCHED_HEAD:-$HEAD}" ;;
    esac ;;
  *ls-tree*)
    [ "${NO_PRODUCT:-false}" = true ] || echo "100644 blob $HEAD product.yaml" ;;
  *show*) echo 'trusted data' ;;
  *diff*) echo app.py ;;
  *) exit 2 ;;
esac
''')
        executable(stubs / "uname", 'case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n')
        executable(self.work / "ai-sdlc-gates/bin/linux-amd64/aisdlc", '''if [ "$#" -eq 1 ] && [ "$1" = gate ]; then
  echo 'usage: aisdlc gate <name> [args]'; exit 2
fi
printf '%s\\n' "$2" >> "$TOOL_LOG"
if [ "$2" = written-by ]; then
  echo "${WRITTEN_OUTPUT:-written-by: vendor}"; exit "${WRITTEN_RC:-0}"
fi
echo "${TOOL_OUTPUT:-gate result}"
exit "$TOOL_RC"
''')
        self.env = {
            **os.environ, "BASH_ENV": "/dev/null", "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(self.work), "GITHUB_REPOSITORY": "example/product", "GH_TOKEN": "github-token",
            "GITHUB_STEP_SUMMARY": str(self.work / "summary"), "GATE_STATUS": status_publisher(),
            "BUNDLE_GATE_SELECTOR": selector(WORKFLOW), "BUNDLE_READY": "true", "CHECKOUT_READY": "true",
            "STATUS_LOG": str(self.work / "statuses"), "TOOL_LOG": str(self.work / "tools"),
            "HEAD": "a" * 40, "HEAD_SHA": "a" * 40, "TARGET_BASE_SHA": "b" * 40,
            "BASE": "main", "PR": "42", "BRANCH": "fix/example", "TEST_PATHS": "tests/",
            "EVENT": "pull_request_target", "BODY": "Written by: vendor",
            "RUN_URL": "https://github.com/example/product/actions/runs/123", "TOOL_RC": "0",
        }

    def run_gate(self, gate, **env):
        (self.work / "statuses").unlink(missing_ok=True)
        (self.work / "tools").unlink(missing_ok=True)
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step(WORKFLOW, GATES[gate])],
            cwd=self.work, env={**self.env, "STATUS_CONTEXT": "checks / " + GATES[gate], **env},
            capture_output=True, text=True, timeout=10)
        statuses = []
        status_log = self.work / "statuses"
        for row in status_log.read_text().splitlines() if status_log.exists() else ():
            args = row.rstrip("\0").split("\0")
            self.assertEqual(args[:4], ["api", "-X", "POST", "repos/example/product/statuses/" + "a" * 40])
            fields = dict(arg.split("=", 1) for arg in args[4:] if arg != "-f")
            self.assertEqual(fields["target_url"], self.env["RUN_URL"])
            self.assertLessEqual(len(fields["description"]), 140)
            statuses.append(fields)
        return result, statuses

    def test_each_step_publishes_its_exit_result_and_fails_the_summary(self):
        for gate, rc in product(STATUS_GATES, (0, 1, 2, 17)):
            with self.subTest(gate=gate, rc=rc):
                result, statuses = self.run_gate(gate, TOOL_RC=str(rc))
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                self.assertEqual(statuses[-1]["context"], "checks / " + GATES[gate])
                self.assertEqual(statuses[-1]["state"], {0: "success", 1: "failure"}.get(rc, "error"))
                self.assertEqual(len(statuses), 1)

    def test_review_exit_and_status_contract(self):
        for event, rc in product(("pull_request", "pull_request_target", "issue_comment"), (0, 1, 2, 17)):
            with self.subTest(event=event, rc=rc):
                result, statuses = self.run_gate("review-on-head", EVENT=event, TOOL_RC=str(rc))
                self.assertEqual(result.returncode, 0 if rc == 1 else rc, result.stdout + result.stderr)
                self.assertEqual(len(statuses), 1)
                self.assertEqual(statuses[0]["context"], "ai-sdlc/review-on-head")
                self.assertEqual(statuses[0]["state"], {0: "success", 1: "failure"}.get(rc, "error"))

    def test_review_rewrites_its_status_until_a_fresh_read_agrees(self):
        # PR-event and comment runs use separate concurrency groups, so another run can write
        # ai-sdlc/review-on-head between this run's read and write (codex review of e3f61e3).
        tool = self.work / "ai-sdlc-gates/bin/linux-amd64/aisdlc"
        executable(tool, '''if [ "$#" -eq 1 ] && [ "$1" = gate ]; then
  echo 'usage: aisdlc gate <name> [args]'; exit 2
fi
n=$(($(cat "$RUNNER_TEMP/reads" 2>/dev/null || echo 0) + 1)); echo "$n" > "$RUNNER_TEMP/reads"
set -- $READS; shift $((n > $# ? $# - 1 : n - 1)); case "$1" in
  approve) echo "REVIEW-ON-HEAD OK: approved"; exit 0 ;;
  wait) echo "REVIEW-ON-HEAD FAIL: no review names this head"; exit 1 ;;
esac
''')
        for reads, states, rc in (("approve", ["success"], 0),
                                  ("wait approve", ["pending", "success"], 0),
                                  ("approve wait", ["success", "pending"], 0),
                                  ("wait approve wait approve wait approve", ["pending", "success", "pending", "success", "pending"], 2)):
            with self.subTest(reads=reads):
                (self.work / "reads").unlink(missing_ok=True)
                result, statuses = self.run_gate("review-on-head", READS=reads)
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                self.assertEqual([status["state"] for status in statuses], states)

    def test_failed_fetch_unpack_or_checkout_fails_all_steps_closed_even_with_stale_tools(self):
        # False readiness also covers a fetch failure followed by a skipped unpack. Tools
        # deliberately remain on disk, so an old self-hosted bundle must never be selected.
        for gate, failure in product(GATES, ("BUNDLE_READY", "CHECKOUT_READY")):
            with self.subTest(gate=gate, failure=failure):
                result, statuses = self.run_gate(gate, **{failure: "false", "BRANCH": "feature/example", "NO_PRODUCT": "true"})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(statuses[-1]["state"], "error")
                self.assertFalse((self.work / "tools").exists())
                if gate == "review-on-head":
                    self.assertEqual(statuses[0]["context"], "ai-sdlc/review-on-head")
                    self.assertEqual(statuses[0]["state"], "error")
                    self.assertEqual(len(statuses), 1)

    def test_legacy_review_status_pending_failure_and_closed_pr_are_preserved(self):
        for output, legacy_state in (("REVIEW-ON-HEAD FAIL: no review names this head", "pending"),
                                     ("REVIEW-ON-HEAD FAIL: rejected", "failure")):
            result, statuses = self.run_gate("review-on-head", TOOL_RC="1", TOOL_OUTPUT=output)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(statuses[0]["state"], legacy_state)
            self.assertEqual(statuses[0]["context"], "ai-sdlc/review-on-head")
            self.assertEqual(statuses[0]["description"], output)
            self.assertEqual(len(statuses), 1)
        for ready in ("true", "false"):
            result, statuses = self.run_gate("review-on-head", PR_STATE="closed", BUNDLE_READY=ready)
            self.assertEqual(result.returncode, 0 if ready == "true" else 2)
            self.assertEqual(statuses, [])
            self.assertFalse((self.work / "tools").exists())

    def test_failed_status_write_fails_every_gate(self):
        for gate in GATES:
            with self.subTest(gate=gate):
                result, _ = self.run_gate(gate, POST_RC="1")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("could not write the status", result.stdout)
        result, statuses = self.run_gate("review-on-head", POST_RC="1", TOOL_RC="1",
                                         TOOL_OUTPUT="REVIEW-ON-HEAD FAIL: no review names this head")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(statuses[0]["state"], "pending")

    def test_written_by_failures_and_warning_feed_the_secret_scan_status(self):
        for rc, output, expected in ((1, "written-by: unknown", 0), (2, "input error", 2),
                                     (1, "written-by: vendor", 2)):
            result, statuses = self.run_gate("secret-scan", WRITTEN_RC=str(rc), WRITTEN_OUTPUT=output)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertEqual(statuses[-1]["state"], "success" if expected == 0 else "error")
        result, _ = self.run_gate("secret-scan", TOOL_RC="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual((self.work / "tools").read_text(), "secret-scan\n")

    def test_locked_tests_still_refuses_a_changed_pr_identity(self):
        result, statuses = self.run_gate("locked-tests", FETCHED_HEAD="c" * 40)
        self.assertEqual(result.returncode, 2)
        self.assertIn("fetched PR identity mismatch", result.stdout)
        self.assertEqual(statuses[-1]["state"], "error")
        self.assertFalse((self.work / "tools").exists())

    def test_cleanup_removes_the_bundle_after_failures(self):
        for directory in ("ai-sdlc-fetch", "ai-sdlc-loader", "ai-sdlc-verifier"):
            (self.work / directory).mkdir()
        result = subprocess.run(["bash", "-e", "-c", step(WORKFLOW, "Clean up the gate bundle and temporary inputs")],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        for directory in ("ai-sdlc-fetch", "ai-sdlc-gates", "ai-sdlc-loader", "ai-sdlc-verifier"):
            self.assertFalse((self.work / directory).exists())


class GateRunners(unittest.TestCase):
    def test_private_gate_jobs_run_on_small(self):
        # ai-sdlc modules/ci.md R1: the gate jobs run only git, gh, short scripts and small native tools.
        for name in ("checks.yml", "bot-review.yml", "nightly-gates.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            self.assertNotIn('"self-hosted", "linux"', text, name)
        checks = (ROOT / ".github/workflows/checks.yml").read_text()
        self.assertEqual(checks.count("""fromJSON('["self-hosted", "small"]')"""), 1)


class SecurityAndNightly(unittest.TestCase):
    SECURITY = (ROOT / ".github/workflows/security.yml").read_text()
    NIGHTLY = (ROOT / ".github/workflows/nightly-gates.yml").read_text()

    def test_scripts_come_from_the_signed_bundle(self):
        self.assertIn('select_gate security-intake python3 -I "$gates/scripts/security_intake.py"', self.SECURITY)
        self.assertIn('"${gate[@]}" --repo "$GITHUB_REPOSITORY" --root .', self.SECURITY)
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
        self.assertIn('select_gate claude-api sh "$gates/scripts/claude_api.sh"', self.NIGHTLY)
        self.assertIn('"${gate[@]}" -p "$prompt"', self.NIGHTLY)
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
