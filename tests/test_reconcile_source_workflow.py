"""Static safety checks for the source reconciliation workflow."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "reconcile-source.yml"


class ReconcileSourceWorkflowTests(unittest.TestCase):
    def test_controlled_supersede_script_has_valid_bash_syntax(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is unavailable")

        source = WORKFLOW.read_text(encoding="utf-8")
        step = "      - name: Controlled supersede of an obsolete same-plugin Beta candidate\n"
        start = source.index(step)
        run = source.index("        run: |\n", start) + len("        run: |\n")
        end = source.index("      - name:", run)
        script = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in source[run:end].splitlines()
        )

        result = subprocess.run(
            [bash, "-n", "-c", script],
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
