## 2026-03-29 - In-place directory pruning with os.walk vs pathlib.rglob

**Learning:** `pathlib.Path.rglob('*')` traverses all files in a tree before filters can be applied, causing massive performance bottlenecks when scanning repos with large ignored directories like `node_modules` or `.git`. In-place directory list mutation in `os.walk(..., followlinks=False)` (`dirs[:] = [d for d in dirs if d not in skip]`) prevents descending into ignored directories entirely, achieving over 100x speedups.
**Action:** Always prefer `os.walk` with top-down in-place directory pruning (`dirs[:] = ...`) when scanning directory trees that contain ignored vendor or build directories.

## 2026-03-30 - Expression pruning in AST function collection

**Learning:** `ast.walk(tree)` visits every expression, identifier, and constant node in an AST module, causing significant overhead when searching for function statement definitions. Pruning `ast.expr` nodes during stack traversal (`if not isinstance(child, ast.expr)`) skips expression subtrees entirely and allows finding all function definitions in a single top-down pass.
**Action:** When searching for statement-level constructs (like `FunctionDef` or `ClassDef`) in Python ASTs, prune `ast.expr` nodes during stack/deque traversal instead of running unconstrained `ast.walk(tree)`.
