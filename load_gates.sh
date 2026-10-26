#!/bin/sh
# load_gates.sh <saved-dir> <out-dir>: in a later job of a loader run, verify the signed record and
# archive that the resolve job fetched, with this loader commit's pinned verifier, then unpack the
# archive into <out-dir> (ai-sdlc #731 section 3). No broker call. Exit 0, or non-zero on any failure.
set -eu
[ "$#" -eq 2 ] || { echo "usage: load_gates.sh <saved-dir> <out-dir>" >&2; exit 2; }
here=$(CDPATH= cd "$(dirname "$0")" && pwd)
verifier=${RUNNER_TEMP:?}/ai-sdlc-verifier
sh "$here/verifier/fetch_cosign.sh" "$verifier"
python3 -I "$here/fetch_gates.py" unpack --verifier "$verifier" --saved "$1" \
  --loader-sha "$(git -C "$here" rev-parse HEAD)" --out "$2"
