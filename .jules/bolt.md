## 2026-03-29 - In-place directory pruning with os.walk vs pathlib.rglob

**Learning:** `pathlib.Path.rglob('*')` traverses all files in a tree before filters can be applied, causing massive performance bottlenecks when scanning repos with large ignored directories like `node_modules` or `.git`. In-place directory list mutation in `os.walk(..., followlinks=False)` (`dirs[:] = [d for d in dirs if d not in skip]`) prevents descending into ignored directories entirely, achieving over 100x speedups.
**Action:** Always prefer `os.walk` with top-down in-place directory pruning (`dirs[:] = ...`) when scanning directory trees that contain ignored vendor or build directories.
