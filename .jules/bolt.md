## 2025-05-18 - Combine Regex Patterns Per Feature Category in Structural Poisoning Detector
**Learning:** In Python's `re` module, iterating over a list of individual regex compiled objects with `any(rx.search(s) for rx in patterns)` incurs significant Python interpreter loop overhead compared to compiling a single combined pattern `(?:p1)|(?:p2)|...` and executing `combined_rx.search(s)`.
**Action:** When matching multiple regex patterns against text per category, pre-compile them into a single disjunctive non-capturing regex `re.compile("|".join(f"(?:{p})" for p in patterns))`.
