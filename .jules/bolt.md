## 2026-10-18 - Pruning directory walks vs Path.rglob
**Learning:** `Path.rglob("*")` recursively traverses all nested subdirectories (including `node_modules`, `.git`, `venv`, `dist`, `build`) before filtering relative path parts, issuing thousands of unneeded `stat()` syscalls and Path object instantiations.
**Action:** Always prefer `os.walk()` with in-place `dirs[:]` filtering when scanning repository roots to prune skipped directories before descending into them.
