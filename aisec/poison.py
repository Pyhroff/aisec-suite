"""Structural tool-poisoning detector (stdlib only, no model call).

Keyword matchers ("ignore previous instructions", "<IMPORTANT>") are what published attacks use; they do not survive
paraphrase, schema-field placement or encoding (see benchmarks/poison). This detector instead asks structural
questions about a tool's *metadata*:

  1. does the text talk TO the model rather than describe the tool to a human (directives, standing rules)?
  2. does it reach beyond this tool (other tools, all calls, overriding what the user said)?
  3. does it route data (secrets, chat history) into a parameter, URL or address?
  4. does it ask for concealment or tell the model how to misdescribe the behaviour?
  5. is part of it hidden (invisible Unicode, bidi tricks, base64/hex/rot13/entity/percent encodings)?

Features are scored on every *view* of the text (raw, plus de-obfuscated decodings) and on parameter descriptions /
defaults / enums as well as the tool description. Weights are fixed a priori from the attack taxonomy (MCPTox,
Invariant Labs, MCP-Poison-Bench); only the two decision thresholds below were fitted, on the calibration half of real
tool descriptions and never on any positive example.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse

from aisec.model import Finding

# Fitted on the calibration half of the benchmark's real-tool negatives (see benchmarks/poison/calibrate.py):
THRESHOLD_MEDIUM = 5.5
THRESHOLD_HIGH = 9.5

_I = re.I
_W = {"conceal": 4.0, "tag": 5.0, "sensitive": 2.0, "data_flow": 2.0, "model_directed": 1.5, "cross_tool": 1.0, "override": 1.5}
_F = {  # feature -> (weight, cap, patterns)   (weight/cap are legacy per-text values; per-sentence weights are in _W)
    "model_directed": (2.0, 6.0, [
        r"\b(?:the )?(?:assistant|model|agent|a\.?i\.?|llm|client)\b[^.\n]{0,40}\b(?:should|must|needs? to|is expected to|has to|ought to|will)\b",
        r"\b(?:notes?|reminders?|directives?|instructions?|guidance|memos?|requests?)\b[^.\n]{0,12}\b(?:for|to|addressed to|aimed at|meant for)\b[^.\n]{0,12}\b(?:the )?(?:assistant|model|agent|a\.?i\.?|client|llm|whoever|operator)\b",
        r"\bto the (?:model|assistant|agent|ai)\b",
        r"\b(?:you|your)\b[^.\n]{0,8}\b(?:must|should|need to|will|are expected to|have to)\b",
        r"\b(?:before|after|prior to|once|whenever|each time|every time|any time|the first time|first|then)\b[^.\n]{0,70}\b(?:call|use|invoke|run|read|open|send|post|attach|forward|include|route|record|submit|push|quote|copy|mirror|relay|repoint|rewrite|set)\b",
        r"\bfrom now on\b|\bstanding (?:guidance|rule|instruction)s?\b|\bgoing forward\b",
    ]),
    "cross_tool": (2.0, 4.0, [
        r"\b(?:other|every|all|any|each|whichever|whatever) (?:other )?(?:tools?|calls?|requests?|helpers?|integrations?|functions?)\b",
        r"\b(?:whenever|any time|each time|every time|when|if)\b[^.\n]{0,60}\b(?:tool|helper|integration|reader|mail|payments?|file|email|api|query)\b[^.\n]{0,25}\b(?:is|are|gets?)\b[^.\n]{0,8}\b(?:used|called|invoked|run|composed)\b",
        r"\b(?:the )?(?:mail|email|payments?|file|deletion|delete|query|git|fetch|http)\b[^.\n]{0,12}\b(?:tool|helper|reader|integration)\b",
        r"\b[a-z]+(?:_[a-z]+)+\b[^.\n]{0,30}\b(?:tool|call|argument|parameter)\b|\b(?:call|use|invoke|run)\b[^.\n]{0,12}\b[a-z]+_[a-z_]+\b",
    ]),
    "sensitive": (2.0, 4.0, [
        r"~/\.|\$HOME|/home/\w+|\.ssh\b|id_(?:rsa|ed25519)|private key|\.env\b|dotenv|/etc/(?:passwd|shadow)|\.aws\b|credentials?\b|mcp\.json",
        r"\b(?:passwords?|api[_ -]?keys?|access tokens?|bearer tokens?|tokens?|secrets?|cookies?|wallet|system prompt|configuration prompt|chat history|"
        r"conversation(?: so far| history)?|dialogue so far|full (?:message|conversation)|user'?s (?:last )?message|ssh config|ssh private key)\b",
    ]),
    "data_flow": (2.0, 4.0, [
        r"\b(?:include|pass|put|append|attach|add|send|forward|copy|upload|post|mirror|relay|route|embed|drop|fill|populate|supply|set|record|push|submit|quote|print|paste|store)\b"
        r"[^.\n]{0,90}\b(?:in|into|to|as|via|through|with|at|before)\b[^.\n]{0,45}\b(?:parameters?|arguments?|fields?|notes?|context|metadata|replies|reply|response|output|url|endpoint|server|email|address|webhook|inbox|account|remote|collector|service|bcc|cc)\b",
        r"https?://[^\s)\]\"']+|\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
        r"\b(?:fill|populate|supply) ['\"`]?\w+['\"`]? (?:with|using)\b",
    ]),
    "conceal": (3.0, 6.0, [
        r"\b(?:do not|don't|never|no need to|without|avoid|skip|leave(?: it| that| this| them)? out|keep(?: it| that| this| those| these)?(?: out| between us| secret| quiet| silent| private)|silent(?:ly)?|quiet(?:ly)?|secretly|hide|conceal|stay silent|say nothing|not worth)\b"
        r"[^.\n]{0,60}\b(?:tell|mention|inform|reveal|disclose|show|notify|alert|surface|describe|comment|explain|summar\w*|recap|aware|know|conversation|user|person|people|bring (?:it )?up|point (?:it )?out|report|flag)\b",
        r"\b(?:nobody|no one|users?|people|persons?|end users?)\b[^.\n]{0,40}\b(?:need(?:s)? to|should|find|would find|doesn't need to|don't need to)\b[^.\n]{0,40}\b(?:hear|know|see|aware|confus\w*|alarm\w*|about (?:it|this))\b",
        r"\b(?:present|describe|summari[sz]e|call|label|explain|characteri[sz]e|frame)\b[^.\n]{0,25}\b(?:it |this |that |the (?:update|tool|step|change)? ?)?(?:only )?\b(?:as|simply as)\b[^.\n]{0,30}\b(?:routine|standard|normal|maintenance|cache|tuning|a small|just|performance)\b",
        r"\b(?:it is|it's|this is|that is)\b[^.\n]{0,20}\b(?:internal|routine|housekeeping|standard)\b[^.\n]{0,30}\b(?:no (?:need|reason)|nothing|nobody)\b",
        r"\bwithout (?:asking|confirmation|confirming|prompting)\b|\bskip (?:the )?confirmation\b|\bhas already consented\b|\balready (?:consented|approved|agreed)\b",
    ]),
    "override": (2.0, 4.0, [
        r"\b(?:ignore|disregard|override|overrides|supersede[sd]?|forget|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|instructions?|rules?|guidance|policy|user|confirmation|safeguards?)\b",
        r"\b(?:instead of|in place of|rather than|regardless of|whatever the (?:user|person)|even if the (?:user|person)|replac\w+ the|rewrit\w+ (?:to|the)|swap\w*|repoint\w*)\b",
        r"\b(?:rather|prefer it over|use (?:this|it) (?:instead|over))\b",
    ]),
    "tag": (4.0, 4.0, [
        r"<\s*/?\s*(?:important|system|instruction|instructions|assistant|admin|secret|override|hidden)\b|\[\s*(?:system|instruction|inst|assistant|important)\b[^\]]*\]|###\s*(?:new )?instructions?|<!--",
    ]),
}
_CAT = {k: [re.compile(p, _I) for p in v[2]] for k, v in _F.items()}

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")
_TAG_BLOCK = re.compile("[\U000e0020-\U000e007e]+")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}\s?){16,}\b")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")
_ENT = re.compile(r"(?:&#\d{2,5};\s?){6,}|(?:&#x[0-9a-fA-F]{2,4};\s?){6,}")
_BIDI = re.compile("‮([^‬]*)‬?")


def _printable_text(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s) >= 12 and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) > 0.95:
        return s
    return None


def views(text: str) -> tuple[list[str], list[str]]:
    """-> (text views to score, names of obfuscation layers found). The first view is the raw text."""
    found: list[str] = []
    out = [text]
    if _INVISIBLE.search(text):
        found.append("invisible-characters")
    stripped = _INVISIBLE.sub("", text)
    tags = _TAG_BLOCK.findall(text)
    if tags:
        found.append("unicode-tag-block")
        stripped += " " + " ".join("".join(chr(ord(c) - 0xE0000) for c in t) for t in tags)
    stripped = _TAG_BLOCK.sub("", stripped)
    for m in _BIDI.finditer(text):
        found.append("bidi-override")
        stripped += " " + m.group(1)[::-1]
    stripped = unicodedata.normalize("NFKC", stripped)
    if stripped != text:
        out.append(stripped)
    decoded: list[str] = []
    for m in _B64.finditer(stripped):
        try:
            s = _printable_text(base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True))
        except (binascii.Error, ValueError):
            s = None
        if s:
            decoded.append(s)
            found.append("base64")
    for m in _HEX.finditer(stripped):
        try:
            s = _printable_text(bytes.fromhex(re.sub(r"\s", "", m.group(0))))
        except ValueError:
            s = None
        if s:
            decoded.append(s)
            found.append("hex")
    for m in _PCT.finditer(stripped):
        s = urllib.parse.unquote(m.group(0))
        decoded.append(s)
        found.append("percent-encoding")
    for m in _ENT.finditer(stripped):
        decoded.append(html.unescape(m.group(0)))
        found.append("html-entities")
    # rot13 only when it turns gibberish into text that actually scores
    words = [w for w in re.findall(r"[A-Za-z]{3,}(?:\s+[A-Za-z]{2,}){4,}", stripped)]
    for w in words:
        r13 = codecs.decode(w, "rot13")
        if _score_view(r13)[0] > _score_view(w)[0] + 1:
            decoded.append(r13)
            found.append("rot13")
    out += decoded
    return out, sorted(set(found))


_SENT = re.compile(r"(?<=[.!?;])\s+|\n+|\s[\u2014\u2013-]{1,2}\s|(?<=:)\s+")


def _sentence_score(sent: str) -> tuple[float, list[str]]:
    hit = [name for name in _W if any(rx.search(sent) for rx in _CAT[name])]
    f = set(hit)
    s = sum(_W[n] for n in hit)
    # Co-occurrence inside ONE sentence is what separates an instruction to the model from long benign documentation:
    if "sensitive" in f and f & {"data_flow", "model_directed"}:
        s += 3.0
    if "conceal" in f and f & {"sensitive", "data_flow", "model_directed", "cross_tool", "override"}:
        s += 2.0
    if "override" in f and f & {"sensitive", "conceal", "data_flow"}:
        s += 1.5
    return s, hit


def _score_view(text: str) -> tuple[float, list[str]]:
    scored = sorted((_sentence_score(x) for x in _SENT.split(text) if x and x.strip()), key=lambda t: -t[0])
    if not scored:
        return 0.0, []
    best, feats = scored[0]
    rest = sum(sc for sc, _ in scored[1:3]) * 0.3   # a second hostile sentence adds a little; a long doc adds nothing
    return best + min(rest, 2.0), feats


def score_text(text: str) -> tuple[float, list[str], list[str]]:
    vs, layers = views(text)
    best, feats = 0.0, []
    for v in vs:
        s, f = _score_view(v)
        if s > best:
            best, feats = s, f
    if layers and len(vs) > 1 and best >= 2.0:
        best += 2.0   # something was deliberately hidden AND the hidden text reads like a directive
        feats = feats + ["hidden:" + "+".join(layers)]
    if "unicode-tag-block" in layers or "bidi-override" in layers:
        best += 6.0   # no legitimate tool description needs the Unicode tag block or a right-to-left override
        feats = feats + ["hidden:" + "+".join(x for x in layers if x in ("unicode-tag-block", "bidi-override"))]
    elif "invisible-characters" in layers and re.search("[\u200b\u200c\u2060-\u2064]{3,}", text):
        best += 3.0   # a run of zero-width characters (single ZWJ/ZWNJ inside emoji or scripts is normal and ignored)
        feats = feats + ["hidden:zero-width-run"]
    return best, feats, layers


def _param_texts(schema: dict) -> list[tuple[str, str]]:
    out = []
    for k, v in (schema or {}).get("properties", {}).items():
        if not isinstance(v, dict):
            continue
        for fld in ("description", "title", "default", "const", "example"):
            if isinstance(v.get(fld), str):
                out.append((f"{k}.{fld}", v[fld]))
        for i, e in enumerate(v.get("enum", []) if isinstance(v.get("enum"), list) else []):
            if isinstance(e, str):
                out.append((f"{k}.enum[{i}]", e))
    return out


def detect(tool: dict) -> tuple[float, str | None]:
    """-> (score, severity or None) over the description and every parameter text; the max wins."""
    parts = [("description", tool.get("description", ""))] + _param_texts(tool.get("input_schema", {}))
    best = 0.0
    for _where, text in parts:
        if text:
            best = max(best, score_text(text)[0])
    sev = "high" if best >= THRESHOLD_HIGH else "medium" if best >= THRESHOLD_MEDIUM else None
    return best, sev


def explain(tool: dict) -> tuple[float, str | None, str]:
    parts = [("description", tool.get("description", ""))] + _param_texts(tool.get("input_schema", {}))
    best, where, feats = 0.0, "", []
    for w, text in parts:
        if text:
            s, f, _ = score_text(text)
            if s > best:
                best, where, feats = s, w, f
    sev = "high" if best >= THRESHOLD_HIGH else "medium" if best >= THRESHOLD_MEDIUM else None
    return best, sev, f"{where}: {', '.join(feats)} (score {best:g})" if sev else ""


def findings_for(tools: list[dict]) -> list[Finding]:
    out = []
    for t in tools:
        _s, sev, why = explain(t)
        if sev:
            out.append(Finding("aisec", f"structural_poisoning: model-directed content in tool metadata ({why.split(':')[0]})", sev,
                               f"Tool '{t['name']}' metadata is structured like an instruction to the calling model: {why}. "
                               "Static heuristic, review by a human.", t.get("file", "."), t.get("line", 1)))
    return out
