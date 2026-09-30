"""Enforce the acyclic, layered module structure of the rootstock_graph package.

Every module is parsed statically, including imports nested inside functions,
so deferred imports cannot hide a dependency cycle or a layering inversion.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


PACKAGE = "rootstock_graph"
PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / PACKAGE

# Neutral top-level modules that every layer may use. They import only each other.
FOUNDATION = "foundation"
FOUNDATION_MODULES = frozenset(
    {
        PACKAGE,
        f"{PACKAGE}.category_predicates",
        f"{PACKAGE}.constants",
        f"{PACKAGE}.cypher",
        f"{PACKAGE}.models",
        f"{PACKAGE}.neo4j",
        f"{PACKAGE}.paths",
        f"{PACKAGE}.server_validation",
    }
)
SUBPACKAGES = frozenset({"api_support", "inference", "ingestion", "reporting", "vulnerability"})
NON_CODE_DIRECTORIES = frozenset({"__pycache__", "resources"})

# rootstock_graph.api is the ASGI app and console entry point; it sits on top.
API = "api"
API_MODULE = f"{PACKAGE}.api"
# Package modules allowed to import rootstock_graph.api: none, so routes cannot
# register themselves on the app as an import side effect.
API_IMPORTERS: frozenset[str] = frozenset()

# Intended dependency direction, lowest layer first:
#   foundation <- vulnerability <- ingestion <- reporting <- api_support <- api
#   foundation <- inference <- api_support
# Each component may import itself and the components listed for it; nothing else.
ALLOWED_DEPENDENCIES: dict[str, frozenset[str]] = {
    FOUNDATION: frozenset({FOUNDATION}),
    "vulnerability": frozenset({"vulnerability", FOUNDATION}),
    "ingestion": frozenset({"ingestion", "vulnerability", FOUNDATION}),
    "inference": frozenset({"inference", FOUNDATION}),
    "reporting": frozenset({"reporting", "ingestion", "vulnerability", FOUNDATION}),
    "api_support": frozenset({"api_support", "reporting", "inference", FOUNDATION}),
    API: frozenset({"api_support", FOUNDATION}),
}

DYNAMIC_IMPORT_CALLS = {("importlib", "import_module"), (None, "__import__")}


@dataclass
class ModuleImports:
    name: str
    is_package: bool
    dependencies: set[str] = field(default_factory=set)
    private_imports: list[str] = field(default_factory=list)
    dynamic_imports: list[int] = field(default_factory=list)


def _module_name(path: Path) -> tuple[str, bool]:
    parts = list(path.relative_to(PACKAGE_ROOT.parent).with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts.pop()
    return ".".join(parts), is_package


def _discover_modules() -> dict[str, Path]:
    modules = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        name, _is_package = _module_name(path)
        modules[name] = path
    return modules


MODULES = _discover_modules()


def _component(module: str) -> str:
    """Return the declared layer of a module, or the module itself if undeclared."""
    parts = module.split(".")
    if module == API_MODULE:
        return API
    if module in FOUNDATION_MODULES:
        return FOUNDATION
    if len(parts) > 1 and parts[1] in SUBPACKAGES:
        return parts[1]
    return module


def _resolve_base(current: ModuleImports, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    package = current.name.split(".")
    if not current.is_package:
        package = package[:-1]
    package = package[: len(package) - (node.level - 1)]
    return ".".join(package + ([node.module] if node.module else []))


def _is_internal(module: str) -> bool:
    return module == PACKAGE or module.startswith(f"{PACKAGE}.")


def _record_import_from(current: ModuleImports, node: ast.ImportFrom, aliases: dict) -> None:
    base = _resolve_base(current, node)
    if not _is_internal(base):
        return
    for alias in node.names:
        submodule = f"{base}.{alias.name}"
        if submodule in MODULES:
            current.dependencies.add(submodule)
            aliases[alias.asname or alias.name] = submodule
            continue
        current.dependencies.add(base)
        if alias.name.startswith("_") and base != current.name:
            current.private_imports.append(f"from {base} import {alias.name}")


def _record_import(current: ModuleImports, node: ast.Import, aliases: dict) -> None:
    for alias in node.names:
        if _is_internal(alias.name):
            current.dependencies.add(alias.name)
            aliases[alias.asname or alias.name] = alias.name


def _call_target(node: ast.Call) -> tuple[str | None, str] | None:
    function = node.func
    if isinstance(function, ast.Name):
        return None, function.id
    if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
        return function.value.id, function.attr
    return None


def _private_attribute(node: ast.Attribute, aliases: dict[str, str]) -> str | None:
    if not isinstance(node.value, ast.Name) or node.value.id not in aliases:
        return None
    if not node.attr.startswith("_") or node.attr.startswith("__"):
        return None
    return f"{aliases[node.value.id]}.{node.attr}"


def _visit(current: ModuleImports, node: ast.AST, aliases: dict[str, str]) -> None:
    if isinstance(node, ast.ImportFrom):
        _record_import_from(current, node, aliases)
    elif isinstance(node, ast.Import):
        _record_import(current, node, aliases)
    elif isinstance(node, ast.Call) and _call_target(node) in DYNAMIC_IMPORT_CALLS:
        current.dynamic_imports.append(node.lineno)
    elif isinstance(node, ast.Attribute) and (private := _private_attribute(node, aliases)):
        current.private_imports.append(private)


def _analyze(name: str, path: Path) -> ModuleImports:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    current = ModuleImports(name=name, is_package=path.name == "__init__.py")
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        _visit(current, node, aliases)
    current.dependencies = {
        dependency
        for dependency in current.dependencies
        if dependency != current.name and dependency in MODULES
    }
    return current


ANALYSIS = {name: _analyze(name, path) for name, path in MODULES.items()}


# ── Re-export detection ─────────────────────────────────────────────────────
# Ruff F401 does not catch re-exports: it treats `from x import y as y`, names
# listed in `__all__`, and F401 suppression comments as intentional. Each module must
# instead be imported from the module that defines the name.


def _module_imports(tree: ast.Module) -> list[ast.Import | ast.ImportFrom]:
    return [node for node in tree.body if isinstance(node, ast.Import | ast.ImportFrom)]


def _redundant_aliases(imports: list[ast.Import | ast.ImportFrom]) -> list[str]:
    return [
        f"line {node.lineno}: import {alias.name} as {alias.asname}"
        for node in imports
        for alias in node.names
        if alias.asname == alias.name
    ]


def _dunder_all(tree: ast.Module) -> list[str]:
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else []
        if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
            return [ast.literal_eval(element) for element in node.value.elts]
    return []


def _all_reexports(tree: ast.Module, imports: list[ast.Import | ast.ImportFrom]) -> list[str]:
    imported = {
        alias.asname or alias.name.split(".")[0] for node in imports for alias in node.names
    }
    return [f"__all__ lists imported {name}" for name in _dunder_all(tree) if name in imported]


def _module_aliases(name: str, imports: list[ast.Import | ast.ImportFrom]) -> set[str]:
    aliases: dict[str, str] = {}
    current = ModuleImports(name=name, is_package=MODULES[name].name == "__init__.py")
    for node in imports:
        if isinstance(node, ast.ImportFrom):
            _record_import_from(current, node, aliases)
        else:
            _record_import(current, node, aliases)
    return set(aliases)


def _attribute_aliases(tree: ast.Module, module_aliases: set[str]) -> list[str]:
    return [
        f"line {node.lineno}: {ast.unparse(node)}"
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id in module_aliases
    ]


def _reexports(name: str, path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    imports = _module_imports(tree)
    findings = _redundant_aliases(imports) + _all_reexports(tree, imports)
    findings += _attribute_aliases(tree, _module_aliases(name, imports))
    if "noqa: F401" in source:
        findings.append("suppresses F401 to keep an unused import")
    return [f"{name}: {finding}" for finding in findings]


def _reaches(graph: dict[str, set[str]], start: str, goal: str) -> bool:
    seen: set[str] = set()
    pending = list(graph[start])
    while pending:
        node = pending.pop()
        if node == goal:
            return True
        if node not in seen:
            seen.add(node)
            pending.extend(graph[node])
    return False


def _modules_on_cycles(graph: dict[str, set[str]]) -> list[str]:
    """Return every module that can reach itself through its imports."""
    return sorted(module for module in graph if _reaches(graph, module, module))


def test_package_modules_were_discovered() -> None:
    assert f"{PACKAGE}.api" in MODULES
    assert f"{PACKAGE}.api_support.routes" in MODULES
    assert len(MODULES) > 50


def test_every_module_belongs_to_a_declared_layer() -> None:
    directories = {
        path.name
        for path in PACKAGE_ROOT.iterdir()
        if path.is_dir() and path.name not in NON_CODE_DIRECTORIES
    }
    assert directories == SUBPACKAGES
    unknown = sorted(name for name in MODULES if _component(name) not in ALLOWED_DEPENDENCIES)
    assert unknown == []


def test_module_imports_are_acyclic() -> None:
    graph = {name: analysis.dependencies for name, analysis in ANALYSIS.items()}
    assert _modules_on_cycles(graph) == []


def test_layers_only_depend_downward() -> None:
    violations = sorted(
        f"{name} -> {dependency}"
        for name, analysis in ANALYSIS.items()
        for dependency in analysis.dependencies
        if _component(dependency) not in ALLOWED_DEPENDENCIES.get(_component(name), ())
    )
    assert violations == []


def test_ingestion_does_not_import_inference_reporting_or_api() -> None:
    forbidden = {"inference", "reporting", "api_support", API}
    violations = sorted(
        f"{name} -> {dependency}"
        for name, analysis in ANALYSIS.items()
        if _component(name) == "ingestion"
        for dependency in analysis.dependencies
        if _component(dependency) in forbidden
    )
    assert violations == []


def test_vulnerability_imports_no_other_subpackage() -> None:
    violations = sorted(
        f"{name} -> {dependency}"
        for name, analysis in ANALYSIS.items()
        if _component(name) == "vulnerability"
        for dependency in analysis.dependencies
        if _component(dependency) not in {"vulnerability", FOUNDATION}
    )
    assert violations == []


def test_only_api_entry_modules_import_the_api_module() -> None:
    importers = sorted(
        name for name, analysis in ANALYSIS.items() if API_MODULE in analysis.dependencies
    )
    assert importers == sorted(API_IMPORTERS)


def test_no_private_names_are_imported_across_modules() -> None:
    violations = sorted(
        f"{name}: {private}"
        for name, analysis in ANALYSIS.items()
        for private in analysis.private_imports
    )
    assert violations == []


def test_no_module_reexports_names_it_does_not_define() -> None:
    violations = sorted(
        finding for name, path in MODULES.items() for finding in _reexports(name, path)
    )
    assert violations == []


def test_no_dynamic_imports_register_side_effects() -> None:
    violations = sorted(
        f"{name}:{line}" for name, analysis in ANALYSIS.items() for line in analysis.dynamic_imports
    )
    assert violations == []
