from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = list((ROOT / "src" / "parrot_safety_center").glob("*.py")) + [ROOT / "parrot_safety_center.py"]


def read_all():
    return "\n".join(path.read_text(encoding="utf-8") for path in SOURCE_FILES)


def test_all_python_files_parse():
    for path in SOURCE_FILES:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_no_shell_true():
    text = read_all()
    assert "shell=True" not in text


def test_no_os_system():
    text = read_all()
    assert "os.system" not in text


def test_identity():
    text = read_all()
    assert "Parrot Safety Center" in text
    assert "CodeWithAmeer" in text
    assert "Apache-2.0" in text


def test_forbidden_guard_present():
    text = read_all()
    assert "FORBIDDEN_COMMAND_PATTERNS" in text
    assert "Blocked by read-only safety guard" in text


if __name__ == "__main__":
    for name, func in sorted(globals().items()):
        if name.startswith("test_") and callable(func):
            func()
    print("static safety checks passed")
