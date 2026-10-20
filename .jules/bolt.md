## 2026-03-29 - Redundant AST Re-Parsing and Full-Tree Traversals in Multi-Tool Reachability Analysis

**Learning:** When statically evaluating multiple MCP tools per file/module in `reach.assess_python`, re-parsing module source code with `ast.parse(src)` and re-traversing the whole module AST (`ast.walk(tree)`) for every individual tool creates $O(N \cdot M)$ overhead.
**Action:** Cache module AST parsing and function index generation per source string (`functools.lru_cache`). Reuse pre-indexed function dictionaries to achieve $O(1)$ handler lookups and eliminate redundant AST traversals.
