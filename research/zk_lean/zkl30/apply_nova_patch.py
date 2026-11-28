"""Apply the ZKL-30 experimental hook to an unpacked nova-snark 0.76.0 source tree.

Usage: python apply_nova_patch.py <nova-snark-0.76.0 dir>
Refuses to patch unless src/nova/mod.rs and src/lib.rs match the pinned
crates.io 0.76.0 bytes (Cargo.lock checksum c9bb3809...bb31 for the crate).
"""
import hashlib
import shutil
import sys
from pathlib import Path

PINS = {"src/nova/mod.rs": "4186708bb1a01946b624a02b0015940a7786146e4c1426ab777ed2974a22b9d6",
        "src/lib.rs": "205db2f14b9a52db2771b3eda2c659951ce48e03ade3bdeec829a3a5442ebdb9"}
SITES = {"circuit_primary.synthesize(&mut cs)": ("cs", "Primary"),
         "circuit_secondary.synthesize(&mut cs)": ("cs", "Secondary"),
         "circuit_primary.synthesize(&mut cs_primary)": ("cs_primary", "Primary"),
         "circuit_secondary.synthesize(&mut cs_secondary)": ("cs_secondary", "Secondary")}
EXPECTED_SITES = 8


def main():
    root = Path(sys.argv[1])
    for rel, pin in PINS.items():
        data = (root / rel).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(data).hexdigest() != pin:
            raise SystemExit(f"{rel}: not the pinned nova-snark 0.76.0 source")
    mod = (root / "src/nova/mod.rs").read_text(encoding="utf-8").replace("\r\n", "\n")
    total = 0
    for old, (var, side) in SITES.items():
        total += mod.count(old)
        mod = mod.replace(old, f"{old.split('(')[0]}(&mut crate::zkl30::Skip::new(&mut {var}, "
                               f"crate::zkl30::Side::{side}, std::any::type_name::<C>()))")
    if total != EXPECTED_SITES:
        raise SystemExit(f"expected {EXPECTED_SITES} synthesis sites, found {total}")
    (root / "src/nova/mod.rs").write_text(mod, encoding="utf-8")
    lib = (root / "src/lib.rs").read_text(encoding="utf-8").replace("\r\n", "\n")
    lib = lib.replace("pub mod nova;\n", "pub mod nova;\npub mod zkl30;\n", 1)
    (root / "src/lib.rs").write_text(lib, encoding="utf-8")
    shutil.copy(Path(__file__).with_name("zkl30.rs"), root / "src/zkl30.rs")
    print(f"patched {total} synthesis sites in {root}")


if __name__ == "__main__":
    main()
