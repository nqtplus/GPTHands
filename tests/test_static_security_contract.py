from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "src" / "gpthands"
_FORBIDDEN_BUILTINS = {"eval", "exec"}
_FORBIDDEN_OS_CALLS = {"system", "popen"}
_SUBPROCESS_CALLS = {"Popen", "run", "call", "check_call", "check_output"}


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _qualified_call(node: ast.Call) -> tuple[str | None, str | None]:
    func = node.func
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None, None


class StaticRuntimeSecurityContractTests(unittest.TestCase):
    def test_runtime_has_no_dynamic_eval_or_shell_execution(self) -> None:
        violations: list[str] = []
        for path in sorted(RUNTIME.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                owner, name = _qualified_call(node)
                location = f"{path.relative_to(ROOT)}:{getattr(node, 'lineno', '?')}"

                if owner is None and name in _FORBIDDEN_BUILTINS:
                    violations.append(f"{location}: forbidden builtin {name}()")
                    continue

                if owner == "os" and name in _FORBIDDEN_OS_CALLS:
                    violations.append(f"{location}: forbidden os.{name}()")
                    continue

                if owner == "subprocess" and name in _SUBPROCESS_CALLS:
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and _is_true(keyword.value):
                            violations.append(f"{location}: subprocess.{name}(..., shell=True) is forbidden")

        self.assertEqual(violations, [], "\n".join(violations))

    def test_runtime_does_not_import_unsafe_deserialization_modules(self) -> None:
        forbidden = {"pickle", "marshal", "shelve"}
        violations: list[str] = []
        for path in sorted(RUNTIME.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".", 1)[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".", 1)[0]]
                for name in names:
                    if name in forbidden:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{getattr(node, 'lineno', '?')}: forbidden import {name}"
                        )
        self.assertEqual(violations, [], "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
