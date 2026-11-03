Implemented step 8b using the gate names in ai-sdlc's `gate_commands.go` and its gate implementations. One shared `select_gate` function per workflow selects a Bash command array; no Go implementation or policy is duplicated in the loader.

Below, `A` means `"$gates/bin/$os-$arch/aisdlc" gate`. Old paths are relative to the verified bundle; argument suffixes shown after the new gate name remain unchanged for the old entry point too.

| Workflow / step | Before | After |
|---|---|---|
| checks / review-on-head | `sh scripts/review_on_head.sh` | `A review-on-head "$PR" "$HEAD" --repo "$GITHUB_REPOSITORY"` |
| checks / owner-decisions | `sh scripts/owner_decisions_check.sh` | `A owner-decisions "origin/$BASE" pr/head` |
| checks / locked-tests | Copy `scripts/locked_tests_check.py` to `$RUNNER_TEMP`, run with Python | `A locked-tests --base "$locked_base_arg" --head "$locked_head_arg" --test-paths "$test_paths"` |
| checks / secret-scan | `sh scripts/secret_scan.sh` | `A secret-scan "origin/$BASE" pr/head` |
| checks / written-by | `bin/<target>/written-by` | `A written-by --body-file "$RUNNER_TEMP/pr-body.txt" --files "$RUNNER_TEMP/pr-files.txt"` |
| checks / manifest | `bin/<target>/manifest-check` | `A manifest-check "$RUNNER_TEMP/product.yaml"` |
| checks / Cloudflare cost | `bin/<target>/cf-cost-check` | `A cf-cost-check --head "$sha" --base "$base_sha" "$@"` (trusted base decisions) |
| bot-review / review | `sh scripts/bot_review.sh` | `A bot-review --repo "$GITHUB_REPOSITORY"` |
| nightly / audit | `sh scripts/claude_api.sh` | `A claude-api -p "$prompt" --permission-mode acceptEdits --allowedTools ...` |
| nightly / bookmark permission | `python3 scripts/bookmark.py` | `A bookmark`, in both the prompt and `--allowedTools`, with the same bookmark arguments |
| nightly / tracking | `python3 -I scripts/nightly_status.py` | `A nightly-status --repo "$GITHUB_REPOSITORY"`, then unchanged `red --runner ... --cause ...` or `green --result ...` |
| security / digest | `python3 -I scripts/security_intake.py` | `A security-intake --repo "$GITHUB_REPOSITORY" --root . --gitleaks "$out/gitleaks.json" --osv "$out/osv.json" --semgrep "$out/semgrep.json" --file` |

The fallback, marked `# until step 8c`, retains every original entry point and interpreter flag. Each workflow has one selector block. When loaded, it sets `aisdlc=$gates/bin/$os-$arch/aisdlc` and checks that the binary is executable and the first line of `"$aisdlc" gate 2>&1` is exactly `usage: aisdlc gate <name> [args]`. The expected usage exit of 2 is accepted, including under Bash's `errexit` and `pipefail`. ai-sdlc #961 introduced the command and all twelve gate names together, so this single bundle probe is reused by every subsequent selection in the step. Missing/non-executable binaries and any other first line select the original path. Detection uses POSIX shell syntax; the existing Bash command-array interface preserves arguments. No per-gate help, HOME override, API-key diagnostic or Claude invocation is needed. A gate failure never retries through the fallback.

Locked-tests still resolves the independently pinned target/head and uses only the signed bundle. Its complete copied-Python and older-interface fallbacks remain. Written-by retains its native exit/last-line contract and the owner's warning-only treatment of an unknown author. No gate decision, secret, permission, runner, trigger, concurrency setting, bundle fetch or verification changed. The only visible changes are command routing and the nightly prompt/allow-list naming the selected bookmark command.

No files or launchers were deleted. This loader has no Go package to redesign; its existing Python test runner remains.

| Old suite | Parity outcome |
|---|---|
| `test_checks_workflow.py` | All assertions retained or updated to assert selected commands and their original arguments; every written-by case now runs through both binary layouts. |
| `test_fetch_gates.py` | Unchanged; all signature, routing, archive and manifest assertions pass. |
| `test_load_gates.py` | Unchanged; repeated verifier setup still passes. |

`test_bundle_gate.py` covers all 12 gates across eleven availability/usage states and exits 0/1/2, exact argument preservation, trusted locked-tests execution, and nightly bookmark prompt/allow-list agreement. It accepts the exact first usage line on stdout or stderr, including exit 2 and subsequent detail lines; it rejects missing, non-executable, unknown, failed and empty binaries, a usage line after a diagnostic, and usage lines with a prefix or suffix. Repeated gate selections assert exactly one bundle probe. `test_checks_workflow.py` uses the same usage-line fixture; its written-by contracts and all unrelated assertions remain. Nothing is skipped or weakened.

Selector follow-up validation (3 November 2026):

- `python3 -m unittest discover -v -s tests`, the command in `test.yml`: all 56 tests passed, including 396 gate/state/exit combinations. `PYTHONDONTWRITEBYTECODE=1`, `BASH_ENV=/dev/null`, and temporary fixtures stayed inside this worktree. To honor the no-commit instruction, a temporary local Git wrapper replaced only the existing loader test's fixture-commit setup with an import of this repository's existing HEAD; no commit command or signing ran, and the test and its assertions were unchanged.
- PyYAML parsed all seven workflows. Comparison with HEAD confirmed that only the four selector blocks changed structurally; all other workflow configuration and steps are identical.
- `bash -n` passed for all four selectors; `sh -n` passed for their POSIX probe blocks. `git diff --check` passed. Actionlint is not installed.

Initial step 8b validation (before the selector follow-up):

- `python3 -m unittest discover -v -s tests`, exactly as `test.yml`: baseline 52 passed; final 56 passed. CPU user+system: 0.399 s before, 3.615 s after. `PYTHONDONTWRITEBYTECODE=1`; fixture signing disabled and `BASH_ENV=/dev/null` isolate host configuration.
- PyYAML loaded all seven workflows. Structural comparison against HEAD confirmed unchanged workflow metadata and fetch/verification steps. `git diff --check` passed. Actionlint is not installed.
- A clean disposable worktree of available ai-sdlc `origin/main` (`efa25faf2e1a5589f613b80bc52ae3820da5e7c8`, #961) passed `sh scripts/aisdlc_build.sh`. Its `.ai-sdlc/bin/aisdlc` selected all 12 gates through the actual selector. Every table command was exercised with harmless inputs or help: fixture checks exited 0; review/bot/Claude/nightly usage paths exited 2; bookmark's missing-file default-window path exited 3; security help exited 0. Claude used an unreadable home; no paid call ran.
- In that checkout's `tools/aisdlc`: `gofmt -l .` printed nothing; `go vet ./...` and `go test -count=1 ./...` passed. Full Go test CPU: 46.877 s. CI's `CGO_ENABLED=1 go test -race -trimpath -count=1` passed for `./internal/quota-report ./internal/ci-runner/... ./internal/merge ./internal/ci/... ./internal/proc ./internal/gh ./internal/platform/... ./internal/lane/... ./internal/review/...`; CPU: 45.221 s. The initial Go runs lacked CI's subscriptions prerequisite; `sh tools/subscriptions-due/check-build.sh` prepared it from a copied offline cache, and both complete runs then passed. Go 1.27.2, `GOTOOLCHAIN=local`, `GOPROXY=off`; all caches outside this worktree.

Proof limitation: `git -C /home/user/ai-sdlc fetch -q origin main` failed because its Git metadata is read-only. A disposable clone's network fetch also failed because the configured proxy was unavailable. The build therefore proves the available #961 snapshot, not a freshly fetched main. The disposable worktree, clone, fixtures, logs and caches were removed.

Follow-up changed files: `.github/workflows/{checks,bot-review,nightly-gates,security}.yml`, `tests/test_checks_workflow.py`, `tests/test_bundle_gate.py`, and this report. `README.md` was changed only in the already committed initial step. No commit or publication was made during this follow-up; autonomy ledgers, Owner settings and spend gates were untouched.
