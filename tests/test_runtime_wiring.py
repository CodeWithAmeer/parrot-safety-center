from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]


def test_worker_imports_redaction_helpers():
    text = (ROOT / "src" / "parrot_safety_center" / "workers.py").read_text(encoding="utf-8")
    assert "from .redaction import redact_data, redact_text" in text


def test_command_result_is_dataclass():
    tree = ast.parse((ROOT / "src" / "parrot_safety_center" / "models.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "CommandResult":
            decorators = {getattr(dec, "id", "") for dec in node.decorator_list}
            assert "dataclass" in decorators
            return
    raise AssertionError("CommandResult class not found")
