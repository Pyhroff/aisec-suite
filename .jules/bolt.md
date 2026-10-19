## 2025-05-18 - Module AST Caching in Multi-Tool Static Analysis
**Learning:** Calling `ast.parse()` and re-indexing functions per tool in static analysis tools creates massive redundant overhead ($O(N)$ parses for $N$ tools in the same file). Additionally, un-memoized AST subtree walks in taint propagation lead to repeated $O(N^2)$ AST traversals.
**Action:** Always parse and index module ASTs once per file string using `lru_cache`, and reuse flat AST node lists and node-level identifier sets during taint flow checks.
