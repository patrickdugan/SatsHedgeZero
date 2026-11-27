"""ZKL-22 streaming audit of captured augmented Nova matrices, standard library only."""
import argparse
import hashlib
import json
from pathlib import Path

from audit import BN254_FR, canonical, index, load, number, unique_object

BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583
MAX_ROW_BYTES = 16 * 1024 * 1024
MAX_ROWS = 8_000_000


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def line(stream):
    raw = stream.readline(MAX_ROW_BYTES + 1)
    if len(raw) > MAX_ROW_BYTES or (raw and not raw.endswith(b"\n")):
        raise ValueError("oversized or unterminated JSONL record")
    if not raw:
        return None
    value = json.loads(raw, object_pairs_hook=unique_object)
    if value is None:
        raise ValueError("null is not a valid stream record")
    return value


def stream_audit(path, *, visit=None, omit=None):
    # Reproduce audit.digest exactly, without retaining a complete matrix.
    with path.open("rb") as stream:
        header = line(stream)
        if (not isinstance(header, dict)
                or set(header) != {"format", "modulus", "wires", "public", "constraints"}
                or header["format"] != "zkl-r1cs-stream-v1"):
            raise ValueError("invalid stream header")
        expected = header["constraints"]
        if type(expected) is not int or not 0 <= expected <= MAX_ROWS:
            raise ValueError("row count cap")
        if omit is not None and (type(omit) is not int or not 0 <= omit < expected):
            raise ValueError("invalid omitted global row")
        shape = canonical({"format": "zkl-r1cs-v1", "modulus": header["modulus"],
                           "wires": header["wires"], "public": header["public"], "rows": []})
        p, n = int(shape["modulus"]), shape["wires"]
        if p not in (BN254_FR, BN254_FQ):
            raise ValueError("unexpected field")
        h = hashlib.sha256()
        prefix = compact({"format": shape["format"], "modulus": shape["modulus"],
                          "public": shape["public"]})
        h.update(prefix[:-1] + b',"rows":[')
        deletion = h.copy() if omit is not None else None
        retained = 0
        count = 0
        nonzeros = [0, 0, 0]
        while True:
            raw = line(stream)
            if raw is None:
                break
            if count >= expected or not isinstance(raw, list) or len(raw) != 3:
                raise ValueError("invalid row or excess rows")
            row = []
            for j, terms in enumerate(raw):
                if not isinstance(terms, list):
                    raise ValueError("linear combination is not a list")
                out = []
                previous = -1
                for term in terms:
                    if not isinstance(term, list) or len(term) != 2:
                        raise ValueError("invalid sparse term")
                    i, coeff = term
                    i, c = index(i, n), number(coeff)
                    if not previous < i or not 0 < c < p:
                        raise ValueError("noncanonical sparse column order or coefficient")
                    previous = i
                    out.append([i, str(c)])
                nonzeros[j] += len(out)
                row.append(out)
            if count:
                h.update(b",")
            encoded = compact(row)
            h.update(encoded)
            if deletion is not None and count != omit:
                if retained:
                    deletion.update(b",")
                deletion.update(encoded)
                retained += 1
            if visit is not None:
                visit(count, row, p)
            count += 1
        if count != expected:
            raise ValueError("truncated row stream")
        suffix = b'],"wires":' + compact(n) + b"}"
        h.update(suffix)
        receipt = {"canonical_shape_sha256": h.hexdigest(), "constraints": count,
                   "wires": n, "public": shape["public"], "modulus": str(p),
                   "canonical_nonzeros": nonzeros}
        if deletion is not None:
            deletion.update(suffix)
            receipt.update({"deleted_row": omit, "retained_constraints": retained,
                            "deletion_shape_sha256": deletion.hexdigest()})
        return receipt


def audit_capture(root):
    capture = load(root / "capture.json")
    if (capture["schema"] != "zkl-nova-setup-capture-v1" or capture["nova_version"] != "0.76.0"
            or capture["circuit"] != "Mnr05UnifiedBatchStep" or capture["production_accepted"] is not False
            or capture["production_vk_matched"] is not False or capture["proof_replayed"] is not False):
        raise ValueError("unsupported capture or promotion flag")
    if capture["vk_file"] != "vk.bin" or file_hash(root / "vk.bin") != capture["vk_sha256"]:
        raise ValueError("VK byte hash mismatch")
    receipt = {"schema": "zkl-nova-stream-audit-v1", "capture_sha256": file_hash(root / "capture.json"),
               "vk_sha256": capture["vk_sha256"], "pp_digest": capture["pp_digest"],
               "production_accepted": False, "production_vk_matched": False}
    for side, p in (("primary", BN254_FR), ("secondary", BN254_FQ)):
        meta = capture[side]
        c = meta["capture"]
        raw, stream = f"{side}.shape.bin", f"{side}.rows.jsonl"
        if c["raw_file"] != raw or meta["stream_file"] != stream:
            raise ValueError("unexpected artifact path")
        if file_hash(root / raw) != c["raw_sha256"] or c["raw_sha256"] != meta["mirror_roundtrip_sha256"]:
            raise ValueError("raw shape hash or mirror mismatch")
        if file_hash(root / stream) != meta["stream_sha256"]:
            raise ValueError("row stream hash mismatch")
        a = stream_audit(root / stream)
        if (int(a["modulus"]) != p or a["modulus"] != meta["modulus"]
                or a["constraints"] != c["constraints"] or c["public"] != 2
                or a["public"] != [1, 2] or a["wires"] != c["auxiliary"]+3
                or a["wires"] != meta["wires"]):
            raise ValueError("shape dimension, field or interface mismatch")
        if any(x > y for x, y in zip(a["canonical_nonzeros"], meta["native_nonzeros"], strict=True)):
            raise ValueError("canonical nonzero count exceeds native count")
        receipt[side] = {**a, "raw_sha256": c["raw_sha256"],
                         "native_shape_digest": c["native_shape_digest"],
                         "stream_sha256": meta["stream_sha256"]}
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    result = audit_capture(args.root)
    with (args.root / "stream-audit.json").open("x", encoding="utf-8") as out:
        json.dump(result, out, sort_keys=True, indent=2)
        out.write("\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
