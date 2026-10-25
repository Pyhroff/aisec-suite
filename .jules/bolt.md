## 2025-05-18 - Avoid Repeated AST Traversals with Pre-Collected Lists
**Learning:** Calling `ast.walk(fn)` multiple times across static analysis passes (propagation, guard detection, call scanning) creates unnecessary AST generator overhead and tree traversals.
**Action:** Collect AST nodes into a list `nodes = list(ast.walk(fn))` once at function entry and pass `nodes` to helper functions.
