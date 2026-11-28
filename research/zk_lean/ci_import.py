"""Reassemble ci_export.py bundles from public check-run annotations.

Usage: python ci_import.py OWNER/REPO JOB_ID OUTDIR
Writes OUTDIR/<name>.tar.gz after checking the exported SHA256, then
extracts with path checks. No token is used or read.
"""
import base64
import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath


def annotations(repo, job):
    out, page = [], 1
    while True:
        url = f"https://api.github.com/repos/{repo}/check-runs/{job}/annotations?per_page=100&page={page}"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": "zkl-ci-import"})
        with urllib.request.urlopen(req) as r:
            batch = json.load(r)
        out += batch
        if len(batch) < 100:
            return out
        page += 1


def main():
    repo, job, outdir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    groups = {}
    for a in annotations(repo, job):
        parts = (a.get("title") or "").split()
        if len(parts) != 5 or parts[0] != "zklx":
            continue
        _, name, k, n, digest = parts
        groups.setdefault((name, int(n), digest), {})[int(k)] = a["message"]
    outdir.mkdir(parents=True, exist_ok=True)
    for (name, n, digest), chunks in sorted(groups.items()):
        missing = [k for k in range(n) if k not in chunks]
        if missing:
            print(f"{name}: missing chunks {missing[:10]} of {n}")
            continue
        blob = base64.b64decode("".join(chunks[k] for k in range(n)))
        if hashlib.sha256(blob).hexdigest() != digest:
            print(f"{name}: sha256 mismatch")
            continue
        (outdir / f"{name}.tar.gz").write_bytes(blob)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for m in tar.getmembers():
                p = PurePosixPath(m.name)
                if p.is_absolute() or ".." in p.parts or not m.isfile():
                    raise ValueError(f"unsafe member {m.name}")
            tar.extractall(outdir / name, filter="data")
        print(f"{name}: {len(blob)} bytes ok")


if __name__ == "__main__":
    main()
