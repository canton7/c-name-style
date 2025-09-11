import json
from pathlib import Path
import subprocess
from pytest_snapshot.plugin import Snapshot  # type: ignore

import pytest


SNAPSHOTS_DIR = Path(__file__).parent / "snapshots"


@pytest.fixture
def project_dir(pytestconfig) -> Path:
    return pytestconfig.rootpath


def run_cli(project_dir: Path, path: Path, input_file: str, config_file: str) -> str:
    result = subprocess.run(
        ["python", project_dir / "lib/c-name-style.py", "-c", config_file, input_file],
        cwd=path,
        capture_output=True,
        text=True,
    )

    if result.returncode not in (0, 1):
        raise AssertionError(f"Exit Code: {result.returncode}\n{result.stderr}\n")

    return result.stdout.strip()


@pytest.mark.parametrize("path", [pytest.param(p, id=p.name) for p in sorted(SNAPSHOTS_DIR.iterdir())])
def test_snapshot(project_dir: Path, snapshot: Snapshot, path: Path):
    snapshot.snapshot_dir = path

    with open(path / "test_setup.json") as f:
        config = json.load(f)

    output = run_cli(project_dir, path, config["input"], "config.ini")
    snapshot.assert_match(output, "output.txt")
