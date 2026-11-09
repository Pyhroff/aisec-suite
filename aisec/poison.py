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
THRESHOLD_MEDIUM = 6.0
THRESHOLD_HIGH = 9.5

_I = re.I
_W = {"conceal": 4.0, "tag": 5.0, "sensitive": 2.0, "data_flow": 2.0, "model_directed": 1.5, "cross_tool": 1.0, "override": 1.5}
_F = {  # feature -> patterns (per-sentence weights live in _W)
    "model_directed": [
        r"\b(?:the )?(?:assistant|model|agent|a\.?i\.?|llm|client)\b[^.\n]{0,40}\b(?:should|must|needs? to|is expected to|has to|ought to|will)\b",
        r"\b(?:notes?|reminders?|directives?|instructions?|guidance|memos?|requests?)\b[^.\n]{0,12}\b(?:for|to|addressed to|aimed at|meant for)\b[^.\n]{0,12}\b(?:the )?(?:assistant|model|agent|a\.?i\.?|client|llm|whoever|operator)\b",
        r"\bto the (?:model|assistant|agent|ai)\b",
        r"\b(?:you|your)\b[^.\n]{0,8}\b(?:must|should|need to|will|are expected to|have to)\b",
        r"\b(?:before|after|prior to|once|whenever|each time|every time|any time|the first time|first|then)\b[^.\n]{0,70}\b(?:call|use|invoke|run|read|open|send|post|attach|forward|include|route|record|submit|push|quote|copy|mirror|relay|repoint|rewrite|set)\b",
        r"\bfrom now on\b|\bstanding (?:guidance|rule|instruction)s?\b|\bgoing forward\b",
    ],
    "cross_tool": [
        r"\b(?:other|every|all|any|each|whichever|whatever) (?:other )?(?:tools?|calls?|requests?|helpers?|integrations?|functions?)\b",
        r"\b(?:whenever|any time|each time|every time|when|if)\b[^.\n]{0,60}\b(?:tool|helper|integration|reader|mail|payments?|file|email|api|query)\b[^.\n]{0,25}\b(?:is|are|gets?)\b[^.\n]{0,8}\b(?:used|called|invoked|run|composed)\b",
        r"\b(?:the )?(?:mail|email|payments?|file|deletion|delete|query|git|fetch|http)\b[^.\n]{0,12}\b(?:tool|helper|reader|integration)\b",
        r"\b[a-z]+(?:_[a-z]+)+\b[^.\n]{0,30}\b(?:tool|call|argument|parameter)\b|\b(?:call|use|invoke|run)\b[^.\n]{0,12}\b[a-z]+_[a-z_]+\b",
    ],
    "sensitive": [
        r"~/\.|\$HOME|/home/\w+|\.ssh\b|id_(?:rsa|ed25519)|private key|\.env\b|dotenv|/etc/(?:passwd|shadow)|\.aws\b|credentials?\b|mcp\.json",
        r"\b(?:passwords?|api[_ -]?keys?|access tokens?|bearer tokens?|tokens?|secrets?|cookies?|wallet|system prompt|configuration prompt|chat history|"
        r"conversation(?: so far| history)?|dialogue so far|full (?:message|conversation)|user'?s (?:last )?message|ssh config|ssh private key)\b",
    ],
    "data_flow": [
        r"\b(?:include|pass|put|append|attach|add|send|forward|copy|upload|post|mirror|relay|route|embed|drop|fill|populate|supply|set|record|push|submit|quote|print|paste|store)\b"
        r"[^.\n]{0,90}\b(?:in|into|to|as|via|through|with|at|before)\b[^.\n]{0,45}\b(?:parameters?|arguments?|fields?|notes?|context|metadata|replies|reply|response|output|url|endpoint|server|email|address|webhook|inbox|account|remote|collector|service|bcc|cc)\b",
        r"https?://[^\s)\]\"']+|\b[\w.+-]{1,64}@[\w-]{1,255}\.[\w.-]{1,255}\b",
        r"\b(?:fill|populate|supply) ['\"`]?\w+['\"`]? (?:with|using)\b",
    ],
    "conceal": [
        r"\b(?:do not|don't|never|no need to|without|avoid|skip|leave(?: it| that| this| them)? out|keep(?: it| that| this| those| these)?(?: out| between us| secret| quiet| silent| private)|silent(?:ly)?|quiet(?:ly)?|secretly|hide|conceal|stay silent|say nothing|not worth)\b"
        r"[^.\n]{0,60}\b(?:tell|mention|inform|reveal|disclose|show|notify|alert|surface|describe|comment|explain|summar\w*|recap|aware|know|conversation|user|person|people|bring (?:it )?up|point (?:it )?out|report|flag)\b",
        r"\b(?:nobody|no one|users?|people|persons?|end users?)\b[^.\n]{0,40}\b(?:need(?:s)? to|should|find|would find|doesn't need to|don't need to)\b[^.\n]{0,40}\b(?:hear|know|see|aware|confus\w*|alarm\w*|about (?:it|this))\b",
        r"\b(?:present|describe|summari[sz]e|call|label|explain|characteri[sz]e|frame)\b[^.\n]{0,25}\b(?:it |this |that |the (?:update|tool|step|change)? ?)?(?:only )?\b(?:as|simply as)\b[^.\n]{0,30}\b(?:routine|standard|normal|maintenance|cache|tuning|a small|just|performance)\b",
        r"\b(?:it is|it's|this is|that is)\b[^.\n]{0,20}\b(?:internal|routine|housekeeping|standard)\b[^.\n]{0,30}\b(?:no (?:need|reason)|nothing|nobody)\b",
        r"\bwithout (?:asking|confirmation|confirming|prompting)\b|\bskip (?:the )?confirmation\b|\bhas already consented\b|\balready (?:consented|approved|agreed)\b",
    ],
    "override": [
        r"\b(?:ignore|disregard|override|overrides|supersede[sd]?|forget|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|instructions?|rules?|guidance|policy|user|confirmation|safeguards?)\b",
        r"\b(?:instead of|in place of|rather than|regardless of|whatever the (?:user|person)|even if the (?:user|person)|replac\w+ the|rewrit\w+ (?:to|the)|swap\w*|repoint\w*)\b",
        r"\b(?:rather|prefer it over|use (?:this|it) (?:instead|over))\b",
    ],
    "tag": [
        r"<\s*/?\s*(?:important|system|instruction|instructions|assistant|admin|secret|override|hidden)\b|\[\s*(?:system|instruction|inst|assistant|important)\b[^\]]*\]|###\s*(?:new )?instructions?|<!--",
    ],
}
# Bolt: Pre-compile combined per-category regexes so each category requires only a single regex search
# rather than looping over individual compiled regex patterns per sentence. Order of _W is preserved.
_CAT = {k: re.compile("|".join(f"(?:{p})" for p in _F[k]), _I) for k in _W}

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")
_TAG_BLOCK = re.compile("[\U000e0020-\U000e007e]+")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}\s?){16,}\b")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")
_ENT = re.compile(r"(?:&#\d{2,5};\s?){6,}|(?:&#x[0-9a-fA-F]{2,4};\s?){6,}")
_BIDI = re.compile("‮([^‬]*)‬?")
_B64URL = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*[_-][A-Za-z0-9_-]*(?![A-Za-z0-9_-])")
_B32 = re.compile(r"(?<![A-Z2-7])[A-Z2-7]{24,}=*(?![A-Z2-7])")
# Runs of words that could be rot13 text. The lookbehind restricts matches to word starts: without it, a long unbroken
# run of letters is retried from every position and backtracked in full each time (quadratic).
_ROT13_CANDIDATE = re.compile(r"(?<![A-Za-z])[A-Za-z]{3,}(?:\s+[A-Za-z]{2,}){4,}")
_UESC = re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}|(?:\\x[0-9a-fA-F]{2}){6,}")

# Latin look-alikes from other scripts (subset of Unicode confusables.txt: Cyrillic, Greek, Armenian, Latin
# small-capital/IPA forms). NFKC does not fold these, so "аssistant" would otherwise not match "assistant".
_CONFUSABLES = str.maketrans({
    # Cyrillic lowercase
    "а": "a", "б": "b", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "ɡ": "g",
    "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k", "ӏ": "l", "м": "m", "п": "n",
    "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t", "ц": "u", "ѵ": "v",
    "ԝ": "w", "х": "x", "у": "y", "з": "z",
    # Cyrillic uppercase
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K",
    "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "У": "Y", "Ү": "Y",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
    # Armenian
    "ա": "a", "հ": "h", "ո": "n", "օ": "o", "ր": "n", "ս": "u", "զ": "q",
    # Latin small capitals / IPA
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ʜ": "h", "ɪ": "i", "ᴊ": "j",
    "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s",
    "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
})
_LATIN = re.compile(r"[A-Za-z]")
_MIXED_WORD = re.compile(r"\w+")
_SPACED = re.compile(r"\b(?:[A-Za-z] ){2,}[A-Za-z]\b")
# Bolt: Pre-compile a character class matching any non-Latin confusable code point in _CONFUSABLES.
# Over 99% of scanned text contains only standard ASCII/Latin characters. Checking for confusable
# characters in one C-level regex search avoids word extraction and translation overhead.
_CONFUSABLES_RX = re.compile(f"[{re.escape(''.join(chr(k) for k in _CONFUSABLES))}]")


def _mixed_script(text: str) -> bool:
    """A single word mixing Latin letters with look-alikes from another script (UTS #39 'mixed script confusable')."""
    # Bolt: Short-circuit if text has no confusable look-alike codepoints (~30x faster for clean text).
    if not _CONFUSABLES_RX.search(text):
        return False
    for w in _MIXED_WORD.findall(text):
        if _LATIN.search(w) and w.translate(_CONFUSABLES) != w:
            return True
    return False


def _canonical(text: str) -> str:
    """Formatting-insensitive view: fold look-alikes, re-join spaced-out letters, reflow hard-wrapped lines and bullet
    lists into running text, collapse whitespace. Blank lines still separate paragraphs."""
    # Bolt: Translate confusables only if confusable characters are present; guard _SPACED substitution.
    s = text.translate(_CONFUSABLES) if _CONFUSABLES_RX.search(text) else text
    if " " in s:
        s = _SPACED.sub(lambda m: m.group(0).replace(" ", ""), s)
    if "\n" in s:
        s = re.sub(r"\n[ \t]*[-*\u2022][ \t]+", ", ", s)
        s = re.sub(r"(?<!\n)\n(?!\n)", " ", s)
    return re.sub(r"[ \t]{2,}", " ", s).strip()


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
    if _mixed_script(stripped):
        found.append("mixed-script")
    if stripped != text:
        out.append(stripped)
    canonical = _canonical(stripped)
    if canonical not in out:
        out.append(canonical)
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
    for m in _B64URL.finditer(stripped):
        tok = m.group(0)
        if len(tok) < 24:
            continue
        try:
            s = _printable_text(base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4)))
        except (binascii.Error, ValueError):
            s = None
        if s:
            decoded.append(s)
            found.append("base64url")
    for m in _B32.finditer(stripped):
        try:
            body = m.group(0).rstrip("=")
            s = _printable_text(base64.b32decode(body + "=" * (-len(body) % 8)))
        except (binascii.Error, ValueError):
            s = None
        if s:
            decoded.append(s)
            found.append("base32")
    for m in _UESC.finditer(stripped):
        try:
            s = m.group(0).encode("ascii").decode("unicode_escape")
        except UnicodeDecodeError:
            s = ""
        if _printable_text(s.encode("utf-8")):
            decoded.append(s)
            found.append("escape-sequences")
    for m in _PCT.finditer(stripped):
        s = urllib.parse.unquote(m.group(0))
        decoded.append(s)
        found.append("percent-encoding")
    for m in _ENT.finditer(stripped):
        decoded.append(html.unescape(m.group(0)))
        found.append("html-entities")
    # rot13 only when it turns gibberish into text that actually scores.
    # Bolt: Short-circuit when r13 score <= 1.0; since _score_view(w)[0] >= 0,
    # r13 can only beat _score_view(w)[0] + 1 if r13 score is strictly > 1.0.
    # This avoids expensive sentence scoring of clean English clauses.
    words = _ROT13_CANDIDATE.findall(stripped)
    for w in words:
        r13 = codecs.decode(w, "rot13")
        r13_score = _score_view(r13)[0]
        if r13_score > 1.0 and r13_score > _score_view(w)[0] + 1:
            decoded.append(r13)
            found.append("rot13")
    out += decoded
    return out, sorted(set(found))


_SENT = re.compile(r"(?<=[.!?;])\s+|\n+|\s[\u2014\u2013-]{1,2}\s|(?<=:)\s+")


def _sentence_score(sent: str) -> tuple[float, list[str]]:
    hit = [name for name, rx in _CAT.items() if rx.search(sent)]
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


# Splitting one instruction into fragments ("Read ~/.ssh/id_rsa. Put it in notes.") must not dissolve the co-occurrence
# signal, so adjacent sentence pairs are also scored, at a fixed discount (a priori, not fitted).
WINDOW_PENALTY = 1.5


def _score_view(text: str) -> tuple[float, list[str]]:
    sents = [x for x in _SENT.split(text) if x and x.strip()]
    scored = sorted((_sentence_score(x) for x in sents), key=lambda t: -t[0])
    if not scored:
        return 0.0, []
    best, feats = scored[0]
    rest = sum(sc for sc, _ in scored[1:3]) * 0.3   # a second hostile sentence adds a little; a long doc adds nothing
    best += min(rest, 2.0)
    # A pair can only win outright; it never feeds `rest` (that would double-count its own sentences).
    for a, b in zip(sents, sents[1:], strict=False):
        sc, f = _sentence_score(f"{a} {b}")
        if sc - WINDOW_PENALTY > best:
            best, feats = sc - WINDOW_PENALTY, f
    return best, feats


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


def _parts(tool: dict) -> list[tuple[str, str]]:
    """Every metadata text, plus the description and parameter descriptions read as one document, so an instruction
    split across fields still meets the sentence-pair window at the field boundary."""
    params = _param_texts(tool.get("input_schema", {}))
    parts = [("description", tool.get("description", ""))] + params
    prose = [t.strip().rstrip(".") for w, t in parts if (w == "description" or w.endswith(".description")) and t.strip()]
    if len(prose) > 1:
        parts.append(("description+parameters", ". ".join(prose) + "."))
    return parts


def detect(tool: dict) -> tuple[float, str | None]:
    """-> (score, severity or None) over the description and every parameter text; the max wins."""
    parts = _parts(tool)
    best = 0.0
    for _where, text in parts:
        if text:
            best = max(best, score_text(text)[0])
    sev = "high" if best >= THRESHOLD_HIGH else "medium" if best >= THRESHOLD_MEDIUM else None
    return best, sev


def explain(tool: dict) -> tuple[float, str | None, str]:
    parts = _parts(tool)
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
