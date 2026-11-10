"""Text carriers used by the steganography attacks, and the decoders the judge and the mock target read replies with."""
from __future__ import annotations

import base64
import binascii
import codecs
import re

# Code points are spelled as numbers so this file holds no invisible characters for scanners to flag.
ZERO_WIDTH = chr(0x200B)
MAX_TEXT = 200_000   # replies are untrusted; nothing here looks past this many characters

_ZW = re.compile("[" + "".join(map(chr, (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))) + "]")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_LEET = str.maketrans("431057@$", "aeiostas")
_UNLEET = str.maketrans("aeiost", "431057")
_ACROSTIC_WORDS = {
    "a": "amber", "b": "birch", "c": "cedar", "d": "delta", "e": "ember", "f": "fjord", "g": "grove", "h": "harbor",
    "i": "inlet", "j": "jade", "k": "kelp", "l": "linen", "m": "maple", "n": "north", "o": "olive", "p": "pine",
    "q": "quartz", "r": "river", "s": "slate", "t": "tidal", "u": "umber", "v": "vale", "w": "willow", "x": "xenon",
    "y": "yarrow", "z": "zinc",
}


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def zero_width(text: str) -> str:
    """Put a zero-width space between every character: unchanged to a reader, different to a keyword filter."""
    return ZERO_WIDTH.join(text)


def leet(text: str) -> str:
    return text.lower().translate(_UNLEET)


def spaced(text: str, sep: str = "-") -> str:
    return sep.join(text)


def acrostic(text: str) -> str:
    """One line per character; the first characters of the lines spell ``text`` (``-`` stands for a space)."""
    lines = []
    for ch in text:
        low = ch.lower()
        lines.append("-" if ch == " " else (ch + _ACROSTIC_WORDS[low][1:] if low in _ACROSTIC_WORDS else ch))
    return "\n".join(lines)


def _printable(data: bytes) -> str:
    text = data.decode("utf-8", errors="ignore")
    good = sum(c.isprintable() or c in "\n\t" for c in text)
    return text if text and good / max(len(data), 1) >= 0.85 else ""


def _b64_decoded(text: str) -> str:
    out = []
    for token in _B64.findall(text):
        body = token.rstrip("=").replace("-", "+").replace("_", "/")
        try:
            out.append(_printable(base64.b64decode(body + "=" * (-len(body) % 4))))
        except (binascii.Error, ValueError):
            continue
    return "\n".join(x for x in out if x)


def _hex_decoded(text: str) -> str:
    return "\n".join(x for x in (_printable(bytes.fromhex(t)) for t in _HEX.findall(text)) if x)


def _acrostic_decoded(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return "".join(" " if ln[0] == "-" else ln[0] for ln in lines) if len(lines) >= 8 else ""


def decoded_views(text: str, *, leet_view: bool = False) -> list[tuple[str, str]]:
    """``(name, text)`` for the raw text and every decoding that produced something. ``raw`` is always first."""
    text = text[:MAX_TEXT]
    views = [("raw", text)]
    stripped = _ZW.sub("", text)
    candidates = [
        ("zero-width", stripped if stripped != text else ""),
        ("base64", _b64_decoded(stripped)),
        ("hex", _hex_decoded(stripped)),
        ("rot13", rot13(stripped)),
        ("reversed", stripped[::-1]),
        ("acrostic", _acrostic_decoded(stripped)),
    ]
    if leet_view:
        candidates.append(("leet", stripped.lower().translate(_LEET)))
    views.extend((name, view) for name, view in candidates if view)
    return views
