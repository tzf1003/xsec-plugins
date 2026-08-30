"""Static safety checks for the source reconciliation workflow."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "reconcile-source.yml"


class ReconcileSourceWorkflowTests(unittest.TestCase):
    def test_sensitive_reconciliation_scripts_have_valid_bash_syntax(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is unavailable")

        source = WORKFLOW.read_text(encoding="utf-8")
        for name in (
            "Controlled supersede of an obsolete same-plugin Beta candidate",
            "Authenticate, sign, and source-gate the exact generated Beta candidate",
        ):
            with self.subTest(name=name):
                step = f"      - name: {name}\n"
                start = source.index(step)
                run = source.index("        run: |\n", start) + len("        run: |\n")
                boundaries = [
                    source.find("\n      - name:", run),
                    source.find("\n  reconcile-smoke:", run),
                ]
                end = min(boundary for boundary in boundaries if boundary >= 0)
                script = "\n".join(
                    line[10:] if line.startswith("          ") else line
                    for line in source[run:end].splitlines()
                )
                with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
                    script_file = Path(temporary_directory) / "workflow-step.sh"
                    with script_file.open("w", encoding="utf-8", newline="\n") as output:
                        output.write(script)
                    result = subprocess.run(
                        [bash, "-n", f"./{script_file.relative_to(ROOT).as_posix()}"],
                        capture_output=True,
                        check=False,
                        cwd=ROOT,
                    )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
