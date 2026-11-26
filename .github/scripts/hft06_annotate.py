"""Print an aggregate JSON file as gzip+base64 ::notice parts [start, start+9)."""
import base64, glob, gzip, json, sys

pattern, start = sys.argv[1], int(sys.argv[2])
files = sorted(glob.glob(pattern, recursive=True))
if not files:
    print(f"::error title=missing::{pattern}")
    sys.exit(1)
blob = base64.b64encode(gzip.compress(json.dumps(json.load(open(files[0])), separators=(",", ":")).encode(), 9)).decode()
parts = [blob[i:i + 3800] for i in range(0, len(blob), 3800)]
if start == 0:
    print(f"::notice title=immediacy-report-meta::parts={len(parts)} encoding=gzip+base64 file={files[0]}")
for i in range(start, min(start + 9, len(parts))):
    print(f"::notice title=immediacy-report {i + 1}/{len(parts)}::{parts[i]}")
