"""Run the workflows' reader-first selector without GitHub or a bundle download."""

from itertools import product
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("checks", "bot-review", "nightly-gates", "security")
GATES = ("review-on-head", "owner-decisions", "locked-tests", "secret-scan",
         "written-by", "manifest-check", "cf-cost-check", "bot-review",
         "claude-api", "bookmark", "nightly-status", "security-intake")


def workflow(name):
    return (ROOT / ".github/workflows" / f"{name}.yml").read_text()


def selector(text):
    return textwrap.dedent(text.split("  BUNDLE_GATE_SELECTOR: |\n", 1)[1].split("\njobs:\n", 1)[0])


def step(text, name):
    block = text.split(f"      - name: {name}\n", 1)[1].split("        run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


class BundleGate(unittest.TestCase):
    def test_each_workflow_has_one_shared_selector(self):
        expected = selector(workflow("checks"))
        for name in WORKFLOWS:
            text = workflow(name)
            self.assertEqual(text.count("select_gate() {"), 1, name)
            self.assertEqual(selector(text), expected, name)
            self.assertIn("# until step 8c", expected)

    def test_selection_arguments_and_exit_codes(self):
        # Every gate: availability and the exact first line of `aisdlc gate`.
        # Usage exits 2; a real gate failure never retries through the old path.
        states = ("missing", "not-executable", "unknown", "failed", "usage-zero", "usage-two",
                  "usage-stderr", "usage-later", "usage-prefix", "usage-suffix", "empty")
        for name, state, rc in product(GATES, states, (0, 1, 2)):
            with self.subTest(name=name, state=state, rc=rc), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gates = root / "signed bundle"
                stubs = root / "stubs"
                executable(stubs / "uname", 'case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; esac\n')
                binary = gates / "bin/darwin-arm64/aisdlc"
                if state != "missing":
                    executable(binary, '''if [ "$#" -eq 1 ] && [ "$1" = gate ]; then
  echo probe >> "$PROBES"
  case "$PROBE_STATE" in
    unknown) echo 'unknown gate: fixture (usage: aisdlc gate <name>)'; exit 2 ;;
    failed) echo 'cannot start fixture'; exit 126 ;;
    usage-later) echo 'diagnostic first' ;;
    usage-prefix) echo 'prefix usage: aisdlc gate <name> [args]'; exit 2 ;;
    usage-suffix) echo 'usage: aisdlc gate <name> [args] suffix'; exit 2 ;;
    empty) exit 2 ;;
    usage-stderr) exec 1>&2 ;;
  esac
  echo 'usage: aisdlc gate <name> [args]'
  echo 'additional usage details'
  [ "$PROBE_STATE" = usage-zero ] && exit 0
  exit 2
fi
printf '%s\\0' "$@" > "$CALLS"
echo binary
exit "$GATE_RC"
''')
                    if state == "not-executable":
                        binary.chmod(0o644)
                legacy = gates / "scripts/original.sh"
                executable(legacy, 'printf "%s\\0" "$@" > "$CALLS"\necho legacy\nexit "$GATE_RC"\n')
                env = {**os.environ, "BASH_ENV": "/dev/null", "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
                       "gates": str(gates), "LEGACY": str(legacy), "NAME": name,
                       "PROBE_STATE": state, "GATE_RC": str(rc), "CALLS": str(root / "calls"),
                       "PROBES": str(root / "probes")}
                args = ["space and\nnewline", "--flag", "*.py", ""]
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", selector(workflow("checks")) +
                     '\nselect_gate bookmark sh "$LEGACY"\n'
                     'select_gate "$NAME" sh "$LEGACY"\n"${gate[@]}" "$@"', "fixture", *args],
                    env=env, capture_output=True, text=True, timeout=5)
                modern = state in ("usage-zero", "usage-two", "usage-stderr")
                self.assertEqual(result.returncode, rc, result.stderr)
                self.assertEqual(result.stdout, "binary\n" if modern else "legacy\n")
                self.assertEqual(result.stderr, "")
                expected = (["gate", name] if modern else []) + args
                self.assertEqual((root / "calls").read_bytes(), b"".join(x.encode() + b"\0" for x in expected))
                if state in ("missing", "not-executable"):
                    self.assertFalse((root / "probes").exists())
                else:
                    self.assertEqual((root / "probes").read_text(), "probe\n")

    def test_locked_tests_only_runs_the_trusted_bundle_helper(self):
        text = workflow("checks")
        run_locked = text.split("          run_locked() {\n", 1)[1].split('\n          run_locked "$trusted"', 1)[0]
        script = "run_locked() {\n" + textwrap.dedent(run_locked)
        for modern, rc in product((False, True), (0, 1, 2)):
            with self.subTest(modern=modern, rc=rc), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gates = root / "bundle"
                stubs = root / "stubs"
                executable(stubs / "uname", 'case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n')
                executable(stubs / "git", 'printf "%s\\n" "$3"\n')
                if modern:
                    executable(gates / "bin/linux-amd64/aisdlc", '''if [ "$#" -eq 1 ] && [ "$1" = gate ]; then
  echo 'usage: aisdlc gate <name> [args]'; exit 2
fi
printf '%s\\n' "$0" "$@"
exit "$GATE_RC"
''')
                helper = gates / "scripts/locked_tests_check.py"
                helper.parent.mkdir(parents=True, exist_ok=True)
                helper.write_text('import os, sys\n'
                                  'if "--help" in sys.argv:\n'
                                  '    print("usage: locked_tests_check.py --base BASE")\n'
                                  '    sys.exit(0)\n'
                                  'print(__file__)\nprint("\\n".join(sys.argv[1:]))\n'
                                  'sys.exit(int(os.environ["GATE_RC"]))\n')
                # Neither a helper nor a binary in the PR's working tree may run.
                executable(root / "scripts/locked_tests_check.py", "echo PR-code-ran; exit 99\n")
                executable(root / "bin/linux-amd64/aisdlc", "echo PR-code-ran; exit 99\n")
                copied = root / "trusted-locked.py"
                env = {**os.environ, "BASH_ENV": "/dev/null", "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
                       "gates": str(gates), "GATE_RC": str(rc)}
                command = (selector(text) + "\ntest_paths='tests/ :(glob)**/*_test.go'\n" + script +
                           '\nrun_locked trusted pinned-base pinned-head "$1" "$2"')
                result = subprocess.run(["bash", "-eu", "-c", command, "fixture", str(helper), str(copied)],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertNotIn("PR-code-ran", result.stdout)
                source = gates / "bin/linux-amd64/aisdlc" if modern else copied
                expected = [str(source)] + (["gate", "locked-tests"] if modern else [])
                expected += ["--base", "pinned-base^{commit}", "--head", "pinned-head^{commit}",
                             "--test-paths", "tests/ :(glob)**/*_test.go"]
                self.assertEqual(result.stdout.splitlines(), expected)
                self.assertEqual(copied.exists(), not modern)

    def test_bookmark_selection_matches_the_prompt_and_allowed_tools(self):
        text = workflow("nightly-gates")
        audit = step(text, "Run the audit")
        # Run the actual selection/prompt lines and audit command, bypassing only
        # the earlier authentication and git setup, which this change does not alter.
        audit = audit[audit.index("gates=$RUNNER_TEMP/ai-sdlc-gates"):]
        for modern in (False, True):
            with self.subTest(modern=modern), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gates = root / "ai-sdlc-gates"
                stubs = root / "stubs"
                executable(stubs / "uname", 'case "$1" in -s) echo Darwin ;; -m) echo x86_64 ;; esac\n')
                record = 'printf "%s\\0" "$@" > "$CALLS"\nexit 1\n'
                executable(gates / "scripts/claude_api.sh", record)
                if modern:
                    executable(gates / "bin/darwin-amd64/aisdlc", '''if [ "$#" -eq 1 ] && [ "$1" = gate ]; then
  echo 'usage: aisdlc gate <name> [args]'
  exit 2
fi
''' + record)
                reference = gates / "references/lessons-audit.md"
                reference.parent.mkdir(parents=True)
                reference.write_text("Audit fixture.\n")
                env = {**os.environ, "BASH_ENV": "/dev/null", "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
                       "RUNNER_TEMP": str(root), "BUNDLE_GATE_SELECTOR": selector(text),
                       "CALLS": str(root / "calls")}
                result = subprocess.run(["bash", "-eu", "-c", audit], cwd=root, env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                args = (root / "calls").read_bytes().decode().split("\0")[:-1]
                if modern:
                    self.assertEqual(args[:2], ["gate", "claude-api"])
                bookmark = (f"{gates}/bin/darwin-amd64/aisdlc gate bookmark" if modern else
                            f"python3 {gates}/scripts/bookmark.py")
                self.assertIn(f"For bookmark operations use {bookmark} with the same arguments.", args[args.index("-p") + 1])
                self.assertEqual(args[args.index("--permission-mode") + 1], "acceptEdits")
                self.assertEqual(args[args.index("--allowedTools") + 1],
                                 f"Bash(git:*) Bash(gh:*) Bash(date:*) Bash({bookmark}:*) Read Edit Write Grep Glob")
                self.assertIn("exit=1", result.stdout)
