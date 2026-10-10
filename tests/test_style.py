"""Enforces house rules that linters do not check.

* Every function and class, including private and nested ones, has a
  docstring explaining why it exists.
* Imports follow the Google Python Style Guide: ``import x`` or
  ``from x import module`` only, except for typing names.
"""

import ast
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = (*sorted((ROOT / "torrelay").glob("*.py")),
           *sorted((ROOT / "tests").glob("*.py")),
           ROOT / "bin" / "torrelay")
NAME_IMPORT_ALLOWED = ("__future__", "typing", "collections.abc")
_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def parse(path: pathlib.Path) -> ast.Module:
    """Parses a source file.

    Args:
        path: Python source.

    Returns:
        Its AST.
    """
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def missing_docstrings(path: pathlib.Path) -> list[str]:
    """Lists definitions in a file that have no docstring.

    Args:
        path: Python source.

    Returns:
        ``file:line name`` for each undocumented function or class.
    """
    return [f"{path.relative_to(ROOT)}:{node.lineno} {node.name}"
            for node in ast.walk(parse(path))
            if isinstance(node, _DEFINITIONS) and not ast.get_docstring(node)]


def is_module(name: str) -> bool:
    """Whether a dotted name refers to an importable module.

    Args:
        name: e.g. ``torrelay.tor``.

    Returns:
        True if it is a module or package.
    """
    try:
        return importlib.util.find_spec(name) is not None
    except ModuleNotFoundError:
        return False


def name_imports(path: pathlib.Path) -> list[str]:
    """Lists ``from x import y`` statements where ``y`` is not a module.

    Args:
        path: Python source.

    Returns:
        ``file:line x.y`` for each violation.
    """
    location = path.relative_to(ROOT)
    return [f"{location}:{node.lineno} {node.module}.{alias.name}"
            for node in ast.walk(parse(path))
            if isinstance(node, ast.ImportFrom)
            and node.module not in NAME_IMPORT_ALLOWED
            for alias in node.names
            if not is_module(f"{node.module}.{alias.name}")]


class StyleTest(unittest.TestCase):
    """Repository-wide style rules."""

    def test_every_definition_has_a_docstring(self):
        """No function or class may be undocumented."""
        missing = [entry for path in SOURCES
                   for entry in missing_docstrings(path)]
        self.assertEqual(missing, [], "add docstrings to:\n"
                         + "\n".join(missing))

    def test_imports_are_modules(self):
        """Only modules are imported by name (Google style)."""
        violations = [entry for path in SOURCES
                      for entry in name_imports(path)]
        self.assertEqual(violations, [], "import the module instead:\n"
                         + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
