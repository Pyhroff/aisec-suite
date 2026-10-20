## 2026-03-29 - Consolidate Full-Tree Module AST Traversals in Reachability Analysis

**Learning:** When statically evaluating MCP tools in `reach.assess_python`, calling `ast.walk(tree)` once to find `fn` and then creating `_Ctx` which calls `ast.walk(tree)` again creates duplicate $O(N)$ AST traversals for every tool in the module.
**Action:** Instantiate `_Ctx` first (which already builds `ctx.funcs` in a single pass) and perform $O(1)$ handler lookup directly on `ctx.funcs`.
