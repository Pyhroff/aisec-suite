## 2026-03-29 - String pre-filtering before AST parsing & os.walk pruning for static extractors

**Learning:** AST parsing (`ast.parse`) and full-tree directory walking (`rglob('*')`) incur significant CPU and memory allocation overhead when scanning repositories for specific patterns (like `@mcp.tool` decorators). Pre-filtering file string content before calling `ast.parse` avoids parsing irrelevant ASTs (~2x speedup on Python source files), and using `os.walk` with `dirnames[:]` slice pruning prevents traversing ignored subtrees (`node_modules`, `.git`, `venv`) and creating unneeded `Path` objects (~3.3x speedup on directory scanning).

**Action:** Before parsing files into ASTs or walking deep directory structures in static analysis routines, always use fast substring pre-checks (`if "@" not in text or "tool" not in text: return []`) and prune directory walks at the top level using `dirnames[:]`.
