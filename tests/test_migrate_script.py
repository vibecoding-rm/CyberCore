import os
import subprocess
import sys
from pathlib import Path


def test_migrate_script_resolves_app_import_when_run_directly():
    repo_root = Path(__file__).resolve().parents[1]
    script_dir = repo_root / "scripts"
    env = os.environ.copy()
    env["PYTHONPATH"] = ""
    env["DATABASE_URL"] = "******127.0.0.1:1/cybercore"
    env["DATABASE_CONNECT_TIMEOUT_SECONDS"] = "1"

    result = subprocess.run(
        [sys.executable, "migrate_db.py"],
        cwd=script_dir,
        env=env,
        capture_output=True,
        text=True,
    )

    output = f"{result.stdout}\n{result.stderr}"
    assert "ModuleNotFoundError: No module named 'app'" not in output
