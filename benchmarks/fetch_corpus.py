"""Check out the repositories the reachability evaluation needs, pinned to the commits the study labelled.

Only the 22 repositories behind the 120 labelled findings are fetched (shallow, by commit SHA). The code is cloned
and parsed by `aisec.extract`; it is never installed, imported or executed.

Usage: python -m benchmarks.fetch_corpus --study ../mcp-scan-study --out corpus
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess  # nosec B404 - runs git with validated arguments only

from benchmarks.eval_reach import SETS


def needed(study: pathlib.Path) -> dict[str, dict]:
    data = study / "data"
    corpus = {**json.loads((data / "corpus.json").read_text(encoding="utf-8")),
              **json.loads((data / "fresh_corpus.json").read_text(encoding="utf-8"))}
    repos = {s["repo"] for _lkey, fname in SETS.values() for s in json.loads((data / fname).read_text(encoding="utf-8"))}
    return {r: corpus[r] for r in sorted(repos)}


_URL = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?")
_SHA = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"[\w-][\w.-]*/[\w-][\w.-]*")   # no leading dot: ".." is never a GitHub owner or repo


def fetch(repo: str, url: str, sha: str, out: pathlib.Path) -> None:
    # The study files are data: refuse anything that is not a plain GitHub repo, URL and full commit SHA.
    if not (_REPO.fullmatch(repo) and _URL.fullmatch(url) and _SHA.fullmatch(sha)):
        raise ValueError(f"refusing unexpected corpus entry: {repo!r} {url!r} {sha!r}")
    git_bin = shutil.which("git")
    if git_bin is None:
        raise RuntimeError("git is required")
    dest = out / repo.replace("/", "__")
    if (dest / ".git").is_dir():
        head = subprocess.run([git_bin, "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, encoding="utf-8")  # noqa: S603
        if head.stdout.strip() == sha:
            return
    dest.mkdir(parents=True, exist_ok=True)
    git = [git_bin, "-C", str(dest), "-c", "advice.detachedHead=false"]
    # Arguments are the absolute git path plus the validated URL/SHA above; no shell.
    subprocess.run([git_bin, "init", "-q", str(dest)], check=True)  # noqa: S603
    subprocess.run([*git, "fetch", "-q", "--depth", "1", url, sha], check=True, timeout=600)  # noqa: S603
    subprocess.run([*git, "checkout", "-q", "FETCH_HEAD"], check=True)  # noqa: S603


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--study", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    for repo, meta in needed(pathlib.Path(a.study)).items():
        fetch(repo, meta["url"], meta["sha"], out)
        print(f"{repo} @ {meta['sha'][:10]}")


if __name__ == "__main__":
    main()
