"""Adaptive multi-turn red-teaming of LLM targets you own or are authorised to test.

``engine.run`` drives attack strategies (``attacks``) against a ``Target`` (``targets``), scores every reply with a
``Judge`` (``judge``) and returns a result that ``report.to_report`` turns into JSON. See docs/REDTEAM.md.
"""
