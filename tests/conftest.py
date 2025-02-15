import pathlib
import sys


def pytest_configure(config):
    project_root = pathlib.Path(__file__).parent.parent
    sys.path.insert(0, str(project_root / "src"))  # Add "src" to Python path