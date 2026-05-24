import ast
from pathlib import Path

import constants as C

WORKSPACE_ROOT = Path(".")
CONSTANTS_FILE = Path("constants.py")
MIN_NON_TRIVIAL_LITERAL_LEN = 3


def _protected_string_values() -> set[str]:
    protected: set[str] = set()
    for name, value in vars(C).items():
        if not (name.isupper() and isinstance(value, str)):
            continue
        if len(value) < MIN_NON_TRIVIAL_LITERAL_LEN:
            continue
        protected.add(value)
    return protected


def _target_python_files() -> list[Path]:
    files = [path for path in WORKSPACE_ROOT.glob("*.py") if path.name != CONSTANTS_FILE.name]
    return sorted(files)


def _iter_string_literals(tree: ast.AST) -> list[tuple[str, int]]:
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent

    literals: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        if not isinstance(node.value, str):
            continue

        parent = parents.get(id(node))
        if isinstance(parent, ast.Expr):
            # Skip docstrings and any standalone string expression.
            continue

        literals.append((node.value, getattr(node, "lineno", 0)))

    return literals


def test_no_non_trivial_direct_literals_outside_constants() -> None:
    protected = _protected_string_values()
    target_files = _target_python_files()
    violations: list[str] = []

    for fpath in target_files:
        source = fpath.read_text(encoding=C.ENCODING_UTF8)
        tree = ast.parse(source, filename=str(fpath))
        for value, line in _iter_string_literals(tree):
            if len(value) < MIN_NON_TRIVIAL_LITERAL_LEN:
                continue
            if value in protected:
                violations.append(f"{fpath}:{line} contains protected literal: {value}")
                continue
            violations.append(f"{fpath}:{line} contains non-trivial direct literal: {value}")

    assert not violations, "\n".join(violations)
