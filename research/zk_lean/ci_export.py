"""Export small result files through GitHub check-run annotations.

Annotations of a public repository are readable without a token, unlike
workflow artifacts. Each file is gzip+base64 encoded and split into chunks.
A GitHub step keeps at most 10 notice annotations, so each invocation prints
one slice of at most 10 chunks. ci_import.py reassembles and checks SHA256.
"""
import argparse
import base64
import gzip
import hashlib
import io
import tarfile
from pathlib import Path

CHUNK = 3500
PER_STEP = 10


def bundle(paths):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path in paths:
            for p in sorted(Path(path).rglob("*")) if Path(path).is_dir() else [Path(path)]:
                if p.is_file():
                    info = tar.gettarinfo(str(p), arcname=str(p).replace("\\", "/"))
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with p.open("rb") as f:
                        tar.addfile(info, f)
    return gzip.compress(buf.getvalue(), mtime=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--slice", type=int, required=True)
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    blob = bundle(args.paths)
    text = base64.b64encode(blob).decode()
    digest = hashlib.sha256(blob).hexdigest()
    chunks = [text[i:i+CHUNK] for i in range(0, len(text), CHUNK)] or [""]
    lo = args.slice*PER_STEP
    for k in range(lo, min(lo+PER_STEP, len(chunks))):
        print(f"::notice title=zklx {args.name} {k} {len(chunks)} {digest}::{chunks[k]}")
    if args.slice == 0:
        print(f"export {args.name}: {len(blob)} bytes, {len(chunks)} chunks, sha256 {digest}")


if __name__ == "__main__":
    main()
