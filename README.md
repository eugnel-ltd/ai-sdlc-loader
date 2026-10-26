# ai-sdlc-loader

The public loader for the AI-SDLC gates of eugnel-ltd and fol2 repos ([ai-sdlc #731](https://github.com/eugnel-ltd/ai-sdlc/issues/731)).

A repo calls a reusable workflow here. The workflow gets an Actions OIDC token and asks the broker (`ai-sdlc-gates`) for the newest signed release record. It verifies the record offline with the pinned cosign and Sigstore trusted root in `verifier/`. Then it fetches the gate bundle that the record names, checks its digest and size, and unpacks it into the runner's temporary directory. The gates run from that bundle. No repo keeps a copy of the gate scripts.

The broker serves only repos owned by eugnel-ltd or fol2. It does no signature work. This repo does all signature, freshness, digest and path checks.

## Files

| File | What it does |
|---|---|
| `.github/workflows/checks.yml` | The PR checks. Slice 1 runs `review-on-head` from the signed bundle. The other jobs still read the caller's `.ai-sdlc/` until slice 2. |
| `.github/workflows/tag-sync.yml` | Moves `v3` to the newest loader commit in the signed record (contract G). |
| `.github/workflows/ai-sdlc-checks.yml` | This repo's own PR gate. It calls `checks.yml` at `main`. |
| `fetch_gates.py` | Verifies the record, chooses the served bundle, checks the archive and unpacks it. |
| `verifier/` | A byte copy of ai-sdlc `gates/verifier/` (contract C). Change both together in reviewed PRs. |
| `.ai-sdlc/` | The two shell gates that this repo's own PR checks still read until slice 2. |

## Which bundle a call gets

- `checks.yml@<40-hex sha>`: only the canary may call at the record's `candidate.loader_sha`. It gets the candidate bundle.
- `checks.yml@v3`: the loader commit must be in the record's `loader_shas`. It gets the record's `pin`, or else `current`.
- `checks.yml@main`: only this repo, for its own PRs. It gets `pin` or `current`.
- A bundle whose source is in `revoked` is never served.

## Rules for this repo

- Every change is a PR from a fork into `main`. No other branch can be created here.
- `main` needs the status `ai-sdlc/review-on-head`: an independent APPROVE from a company other than every writer's, on the PR head.
- Only GitHub Actions can move tags. Only `tag-sync.yml` has `contents: write`.

Test: `python3 -m unittest -v tests/test_fetch_gates.py` (needs `zstd`).
