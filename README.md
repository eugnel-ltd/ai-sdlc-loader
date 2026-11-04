# ai-sdlc-loader

The public loader for the AI-SDLC gates of eugnel-ltd and fol2 repos ([ai-sdlc #731](https://github.com/eugnel-ltd/ai-sdlc/issues/731)).

A repo calls a reusable workflow here. The workflow gets an Actions OIDC token and asks the broker (`ai-sdlc-gates`) for the newest signed release record. It verifies the record offline with the pinned cosign and Sigstore trusted root in `verifier/`. Then it fetches the gate bundle that the record names, checks its digest and size, and unpacks it into the runner's temporary directory. The gates run from that bundle. No repo keeps a copy of the gate scripts.

The broker serves only repos owned by eugnel-ltd or fol2. It does no signature work. This repo does all signature, freshness, digest and path checks.

## Files

| File | What it does |
|---|---|
| `.github/workflows/checks.yml` | One job per event (ai-sdlc #483) resolves the head, fetches the signed record and bundle once, verifies and unpacks the saved pair once, and checks out once. On PR events it runs review-on-head, then owner-decisions, locked-tests, secret-scan (including written-by), manifest and Cloudflare-cost in order. A review comment runs only review-on-head. The job removes its temporary bundle. The gates prefer `bin/<os>-<arch>/aisdlc gate <name>` from that bundle. No gate reads the caller's `.ai-sdlc/`. |
| `.github/workflows/security.yml` | The weekly security scan. Runs the signed bundle's `aisdlc gate security-intake`. |
| `.github/workflows/nightly-gates.yml` | The manual nightly lessons audit on the Mac runner. The prompt and the `claude-api`, `bookmark` and `nightly-status` gates come from the signed bundle; the caller cannot supply the command. |
| `.github/workflows/bot-review.yml` | The App's formal review of each open PR head, from the bundle's `aisdlc gate bot-review`. |
| `.github/workflows/tag-sync.yml` | Moves `v3` only to the newest loader commit in a verified signed record (contract G). It runs every 15 minutes, so the tag can lag the record by one schedule interval (15 minutes). The transition window covers this lag. A delayed or failed run can extend the lag. |
| `.github/workflows/ai-sdlc-checks.yml` | This repo's own PR gate. It calls `checks.yml` at `main`. |
| `fetch_gates.py` | Verifies the record, chooses the served bundle, checks the archive and unpacks it. `fetch` is each job's one broker call; `unpack` checks the saved pair again, then checks every unpacked file against `MANIFEST.sha256`. |
| `load_gates.sh` | Runs `unpack` with this loader commit's pinned verifier. |
| `verifier/` | A byte copy of ai-sdlc `gates/verifier/` (contract C). Change both together in reviewed PRs. |

Each of the four gate workflows has one shared `select_gate` shell function. It uses the bundle's executable `bin/<os>-<arch>/aisdlc` only when that gate's help or harmless usage path identifies it. Until step 8c, a missing binary or gate selects the original bundle script (with its original interpreter and flags) or native tool. A gate failure is returned unchanged; it never triggers a second attempt through the fallback. The nightly bookmark command is selected in both the prompt and `--allowedTools`.

Locked-tests runs the verified bundle binary, when available, against the pinned PR target and head. Its fallback still copies the bundle's Python helper to `$RUNNER_TEMP` before running it; PR code supplies neither helper. The written-by exit/output contract and the owner's warning-only treatment of an unknown author are unchanged.

The `checks` job, named `AI-SDLC gates`, publishes five commit statuses with the caller's former check-run contexts:

- `checks / owner-decisions.md is append-only`
- `checks / A fix leaves its failing test alone`
- `checks / No credentials in the PR range`
- `checks / product.yaml is valid and a published product has its baseline`
- `checks / Cloudflare config stays inside the US$5 plan`

Each status targets the resolved PR head and links to the workflow run. Gates continue after earlier failures, and a failed fetch, unpack or checkout makes every applicable gate fail closed, even on a non-fix branch or without product.yaml. The job fails if any of these gates or status writes fails. All events of one PR share one concurrency group, never cancelled, so review reads and status writes stay serialised. GitHub keeps one pending run per group, so a review-comment run can replace a queued PR-event run; the comment run therefore reads the head's statuses from `github-actions[bot]` and runs any of these five gates the head lacks (all five if the read fails). Otherwise a comment run skips them. The caller's workflow-level group still applies.

The same job's review step keeps the step name `Independent APPROVE names the head` and publishes only `ai-sdlc/review-on-head`. It runs on every event, review comments included. It keeps the existing pending, failure and closed-PR status rules. A missing approval leaves the step green after the pending status is written; that status holds the merge (#622). A rejected review likewise leaves the step green after writing its failure status. Setup errors and failed status writes still fail the job.

Every gate step has a ten-minute timeout. The job has a 70-minute limit: ten minutes for setup and cleanup plus the six gate limits.

No live run exists yet for this one-job workflow. The first live proof will be this PR's own run under the new workflow after merge, a run on the canary repo, and release evidence reading the statuses. Local tests use stubs; live status writes, concurrency and per-step timeouts remain unverified.

## Which bundle a call gets

- `checks.yml@<40-hex sha>`: only the canary may call at the record's `candidate.loader_sha`. It gets the candidate bundle.
- `checks.yml@v3`: the loader commit must be in the record's `loader_shas`. It gets the record's `pin`, or else `current`.
- During a promotion, the record's `loader_shas` holds both the old and the new loader commit until `transition.until` (two hours after promotion). GitHub can resolve a run to the old `v3` commit before `tag-sync.yml` moves the tag. That run can still fetch the bundle and finish with its saved record. After the window, the next record names only the new commit. The loader refuses a new run on the old commit against that record. It checks `loader_shas`, not `transition.until` (contract E).
- `checks.yml@main`: only this repo, for its own PRs. It gets `pin` or `current`.
- A bundle whose source is in `revoked` is never served.

## Rules for this repo

- Every change is a PR from a fork into `main`. No other branch can be created here.
- `main` needs the status `ai-sdlc/review-on-head`: an independent APPROVE from a company other than every writer's, on the PR head.
- Only the `eugnel-ai-sdlc-gates` App can move tags. `tag-sync.yml` gets its token from the broker (`fetch_gates.py repo-token`): one hour, this repo only, `contents: write`.
- The nightly audit gets the same kind of token for its own repo (contents, issues and pull-requests write). No workflow here takes a PAT or a caller secret.

Test: `python3 -m unittest discover -v -s tests` (needs `zstd` for the zstd archive tests).
