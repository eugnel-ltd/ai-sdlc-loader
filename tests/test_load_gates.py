"""load_gates.sh runs twice in one job: each run takes a fresh verifier directory."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LoadGates(unittest.TestCase):
    def test_a_second_run_in_the_same_job_gets_its_own_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            loader = work / "loader"
            (loader / "verifier").mkdir(parents=True)
            shutil.copy(ROOT / "load_gates.sh", loader / "load_gates.sh")
            # Fakes: fetch_cosign.sh refuses a directory that already has cosign, like the real one.
            (loader / "verifier/fetch_cosign.sh").write_text(
                '[ ! -e "$1/cosign" ] || { echo "destination already has cosign" >&2; exit 1; }\n'
                'mkdir -p "$1" && : > "$1/cosign"\n')
            (loader / "fetch_gates.py").write_text("import sys\nsys.exit(0)\n")
            subprocess.run(["git", "init", "-q", str(loader)], check=True)
            subprocess.run(["git", "-C", str(loader), "-c", "user.email=t@t", "-c", "user.name=t",
                            "commit", "-q", "--allow-empty", "-m", "t"], check=True)
            (work / "tmp").mkdir()
            (work / "tmp/ai-sdlc-verifier").mkdir()
            (work / "tmp/ai-sdlc-verifier/cosign").write_text("")
            env = {**os.environ, "RUNNER_TEMP": str(work / "tmp")}
            for _ in range(2):
                result = subprocess.run(["sh", str(loader / "load_gates.sh"), str(work / "saved"), str(work / "out")],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
