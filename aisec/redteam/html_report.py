"""Render a red-team JSON report as one self-contained HTML page for reading the transcripts.

A score says an attack breached; only the transcript says whether that verdict is right. This page puts every payload,
reply and verdict in front of a person. It has no scripts and loads nothing from the network, and a
Content-Security-Policy forbids both: the page displays text written by an attacker model and by the target under
attack, so every value is escaped and nothing in it can run. Like the JSON report, it contains whatever the target
leaked; handle it with the same care.
"""
from __future__ import annotations

import json
from html import escape

_CSS = """
:root{--bg:#fbfbfa;--panel:#fff;--ink:#1c1d1f;--muted:#62666d;--line:#e2e3e6;--bad:#b3261e;--bad-bg:#fbe9e7;
--ok:#1e6b3a;--ok-bg:#e6f3ea;--warn:#8a5a00;--warn-bg:#fbf0d9;--code:#f3f4f5}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--panel:#1c1e21;--ink:#e8e9eb;--muted:#9aa0a8;--line:#2e3136;
--bad:#ff8a80;--bad-bg:#3a1c1a;--ok:#7fd39a;--ok-bg:#16301f;--warn:#f0c060;--warn-bg:#33290f;--code:#24272b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0}
.meta{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.note{background:var(--warn-bg);color:var(--warn);border-radius:8px;padding:10px 12px;margin:16px 0;font-size:14px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0 24px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}
.attack{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 16px}
.head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin-bottom:10px}
.badge,.chip,.flag{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600}
.bad{background:var(--bad-bg);color:var(--bad)}.ok{background:var(--ok-bg);color:var(--ok)}
.mid{background:var(--warn-bg);color:var(--warn)}
.flag{background:var(--code);color:var(--muted);font-weight:500}
.path{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px;padding:0;list-style:none}
details{border-top:1px solid var(--line);padding:8px 0}
summary{cursor:pointer;display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px}
summary .tech{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin:10px 0 4px}
pre{background:var(--code);border-radius:6px;padding:10px 12px;margin:0;white-space:pre-wrap;overflow-wrap:anywhere;
font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;max-height:420px;overflow:auto}
.why{margin:8px 0 0;font-size:14px}
"""


def _tone(score: int, breach_score: int) -> str:
    if score >= breach_score:
        return "bad"
    return "mid" if score >= 4 else "ok"


def _chip(score: int, breach_score: int) -> str:
    return f'<span class="chip {_tone(score, breach_score)}">{int(score)}/10</span>'


def _flags(flags: list[str]) -> str:
    return "".join(f'<span class="flag">{escape(str(f))}</span>' for f in flags)


def _turn(turn: dict, breach_score: int) -> str:
    verdict = turn["verdict"]
    evidence = json.dumps(verdict.get("evidence") or {}, indent=2, ensure_ascii=False, sort_keys=True)
    opened = " open" if verdict["score"] >= breach_score else ""
    return (
        f"<details{opened}><summary><strong>Turn {int(turn['turn'])}</strong>{_chip(verdict['score'], breach_score)}"
        f'<span class="tech">{escape(str(turn["technique"]))}</span>{_flags(verdict.get("flags", []))}</summary>'
        f'<div class="label">Attacker sent</div><pre>{escape(str(turn["payload"]))}</pre>'
        f'<div class="label">Target replied</div><pre>{escape(str(turn["response"]))}</pre>'
        f'<p class="why"><strong>Judge ({escape(str(verdict.get("judge", "")))}):</strong> '
        f'{escape(str(verdict.get("rationale", "")))}</p>'
        f'<div class="label">Evidence</div><pre>{escape(evidence)}</pre></details>'
    )


def _attack(attack: dict, breach_score: int) -> str:
    breached = attack["outcome"] == "breached"
    facts = [f"max {int(attack['max_score'])}/10", f"{int(attack['turns_used'])} turns"]
    if attack.get("first_breach_turn") is not None:
        facts.append(f"first breach at turn {int(attack['first_breach_turn'])}")
    if attack.get("system_prompt_extracted"):
        facts.append("system prompt extracted")
    if attack.get("system_prompt_bypassed"):
        facts.append("rules bypassed")
    path = "".join(f"<li>{_chip(step['score'], breach_score)}</li>" for step in attack.get("attack_path", []))
    turns = "".join(_turn(t, breach_score) for t in attack.get("turns", []))
    return (
        f'<section class="attack"><div class="head"><h2>{escape(str(attack["strategy"]))}</h2>'
        f'<span class="badge {"bad" if breached else "ok"}">{"BREACHED" if breached else "RESISTED"}</span>'
        f'<span class="meta">{escape(" · ".join(facts))}</span></div>'
        f'<ol class="path" aria-label="Score per turn">{path}</ol>{turns}</section>'
    )


def _stat(value: object, label: str) -> str:
    return f'<div class="stat"><b>{escape(str(value))}</b><span>{escape(label)}</span></div>'


def to_html(report: dict) -> str:
    """Render the dict from ``report.to_report`` as a complete HTML document."""
    summary, config = report["summary"], report["config"]
    breach_score = int(config["breach_score"])
    breached = summary["verdict"] == "breached"
    note = ""
    if str(report["target"]).startswith("mock:"):
        note = ('<p class="note">The mock target is scripted. This run checks the engine, not any real model, and the '
                "numbers below are not a result.</p>")
    stats = "".join([
        _stat("Breached" if breached else "Resisted", "overall verdict"),
        _stat(f"{summary['attacks_breached']}/{summary['attacks_run']}", "attacks breached"),
        _stat(f"{summary['max_score']}/10", "highest score"),
        _stat("Yes" if summary["system_prompt_extracted"] else "No", "system prompt extracted"),
        _stat("Yes" if summary["system_prompt_bypassed"] else "No", "rules bypassed"),
    ])
    meta = (f"Target {report['target']} · judge {report['judge']} · breach score {breach_score} · "
            f"max turns {config['max_turns']} · {report['generated_at']} · "
            f"{report['tool']['name']} {report['tool']['version']}")
    attacks = "".join(_attack(a, breach_score) for a in report["attacks"])
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>Red-team report: {escape(str(report['target']))}</title><style>{_CSS}</style></head>"
        f'<body><main><h1>Red-team report</h1><p class="meta">{escape(meta)}</p>{note}'
        f'<div class="stats">{stats}</div>{attacks}</main></body></html>\n'
    )
