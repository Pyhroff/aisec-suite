# Bolt's Performance Journal

## 2026-11-10 - Regex Word Boundaries and Substring Guarding in Schema Extractors
**Learning:** In static code analysis extractors scanning arbitrary code or regex match windows (e.g. 4,500 characters after tool registration anchors), unanchored regexes matching patterns like `(\w+)\s*:\s*(?:z|zod)` cause catastrophic slowdowns on non-matching text (like padded descriptions) due to testing the pattern at every character offset. Adding a word boundary anchor (`\b`) along with short-circuit substring checks (`'z' not in block`, `'type' not in block`) drops non-matching window processing from ~350ms to ~0.004ms per call.
**Action:** When writing regex extractors over arbitrary code windows, always anchor token starts with `\b` and guard with cheap substring containment checks before executing complex multi-branch regexes.
