"""AST allowlist for LLM-generated executable modules.

Generated code is executable, but only a narrow Python surface is allowed so a
prompt-injected README cannot turn the harness into a host reverse shell.
"""

from __future__ import annotations

import ast

ALLOWED_IMPORTS = frozenset(
    {
        "json",
        "re",
        "math",
        "typing",
        "dataclasses",
        "collections",
        "copy",
        "datetime",
        "decimal",
        "functools",
        "itertools",
        "operator",
        "string",
        "textwrap",
        "uuid",
    }
)

FORBIDDEN_NAMES = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "open",
        "__import__",
        "breakpoint",
        "input",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
    }
)


class AstGuardError(ValueError):
    pass


def validate_module_source(
    source: str,
    *,
    required_fns: frozenset[str],
    filename: str = "toolpain_gen.py",
    max_len: int = 40_000,
) -> ast.Module:
    if len(source) > max_len:
        raise AstGuardError(f"{filename} too large")
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise AstGuardError(f"{filename} syntax error: {exc}") from exc

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            else:
                if node.module:
                    names = [node.module.split(".")[0]]
            for name in names:
                if name not in ALLOWED_IMPORTS:
                    raise AstGuardError(f"import not allowlisted: {name}")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            raise AstGuardError(f"forbidden name: {node.id}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise AstGuardError(f"forbidden attribute: {node.attr}")

    defined = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = required_fns - defined
    if missing:
        raise AstGuardError(f"{filename} must define: {', '.join(sorted(missing))}")
    return tree


def validate_probe_source(source: str) -> ast.Module:
    return validate_module_source(
        source,
        required_fns=frozenset({"build_plans"}),
        filename="toolpain_probe_gen.py",
    )


def validate_workdir_source(source: str) -> ast.Module:
    return validate_module_source(
        source,
        required_fns=frozenset({"pick_workdir"}),
        filename="toolpain_workdir_gen.py",
        max_len=20_000,
    )


def validate_oracle_source(source: str) -> ast.Module:
    return validate_module_source(
        source,
        required_fns=frozenset({"review_observations"}),
        filename="toolpain_oracle_gen.py",
    )
