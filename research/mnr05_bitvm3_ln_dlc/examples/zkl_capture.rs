//! ZKL-22: capture the actual augmented shapes passed to Nova setup.
//! Research only; the original circuit and commitment-key sizing are unchanged.
use bincode::Options;
use ff::PrimeField;
use nova_snark::{
    nova::{CompressedSNARK, PublicParams},
    provider::ipa_pc::EvaluationEngine,
    r1cs::R1CSShape,
    spartan::snark::RelaxedR1CSSNARK,
    traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use shz_mnr05_bitvm3_ln_dlc::unified_batch_circuit::{B1, B2, Mnr05UnifiedBatchStep};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

type S1 = RelaxedR1CSSNARK<B1, EvaluationEngine<B1>>;
type S2 = RelaxedR1CSSNARK<B2, EvaluationEngine<B2>>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

const FR: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const FQ: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
const FR_MINUS_ONE: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
const FQ_MINUS_ONE: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46";

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

fn fresh(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[derive(Default)]
struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn file_sha(path: &Path) -> Result<String> {
    let mut writer = HashWriter::default();
    io::copy(&mut BufReader::new(File::open(path)?), &mut writer)?;
    Ok(hex::encode(writer.0.finalize()))
}

fn field_hex<F: PrimeField>(value: &F) -> String {
    let mut bytes = value.to_repr().as_ref().to_vec();
    bytes.reverse();
    format!("0x{}", hex::encode(bytes))
}

fn check_field<F: PrimeField>(minus_one: &str) {
    assert_eq!(field_hex(&F::ONE), format!("0x{:064x}", 1u64));
    assert_eq!(field_hex(&(-F::ONE)), format!("0x{minus_one}"));
}

#[derive(Serialize)]
struct Captured {
    raw_file: String,
    raw_sha256: String,
    native_shape_digest: String,
    constraints: usize,
    auxiliary: usize,
    public: usize,
    ck_floor: usize,
}

fn capture<E: Engine>(
    dir: &Path,
    name: &str,
    shape: &R1CSShape<E>,
    ck_floor: usize,
) -> Result<Captured> {
    let raw_file = format!("{name}.shape.bin");
    let path = dir.join(&raw_file);
    let mut writer = BufWriter::new(fresh(&path)?);
    codec().serialize_into(&mut writer, shape)?;
    writer.flush()?;
    drop(writer);
    Ok(Captured {
        raw_file,
        raw_sha256: file_sha(&path)?,
        native_shape_digest: field_hex(&shape.digest()),
        constraints: shape.num_cons(),
        auxiliary: shape.num_vars(),
        public: shape.num_io(),
        ck_floor,
    })
}

// The private Nova 0.76.0 R1CSShape and SparseMatrix have this serialized
// field order. Reject any codec/layout drift by reserializing the typed
// mirror and requiring the hash of the original captured bytes to match.
#[derive(Serialize, Deserialize)]
struct Csr<F> {
    data: Vec<F>,
    indices: Vec<usize>,
    indptr: Vec<usize>,
    cols: usize,
}

#[derive(Serialize, Deserialize)]
struct Mirror<F> {
    num_cons: usize,
    num_vars: usize,
    num_io: usize,
    a: Csr<F>,
    b: Csr<F>,
    c: Csr<F>,
}

impl<F: PrimeField> Csr<F> {
    fn validate(&self, rows: usize, cols: usize) {
        assert_eq!(self.cols, cols);
        assert_eq!(self.data.len(), self.indices.len());
        assert_eq!(self.indptr.len(), rows + 1);
        assert_eq!(self.indptr.first(), Some(&0));
        assert_eq!(self.indptr.last(), Some(&self.data.len()));
        assert!(self.indptr.windows(2).all(|x| x[0] <= x[1]));
        assert!(self.indices.iter().all(|&i| i < cols));
        assert!(self.data.iter().all(|x| *x != F::ZERO));
    }

    fn row(&self, index: usize, auxiliary: usize, public: usize) -> Vec<(usize, String)> {
        let mut terms = BTreeMap::<usize, F>::new();
        for j in self.indptr[index]..self.indptr[index+1] {
            let wire = canonical_wire(self.indices[j], auxiliary, public);
            *terms.entry(wire).or_insert(F::ZERO) += self.data[j];
        }
        terms.into_iter().filter(|(_, c)| *c != F::ZERO)
            .map(|(i, c)| (i, field_hex(&c))).collect()
    }
}

// Nova native column order is [auxiliary, one, public]. Ordinary audit
// order is [one, public, auxiliary]. This is a total permutation only.
fn canonical_wire(native: usize, auxiliary: usize, public: usize) -> usize {
    assert!(native < auxiliary + 1 + public);
    if native < auxiliary {
        native + 1 + public
    } else {
        native - auxiliary
    }
}

fn export<E: Engine>(
    dir: &Path,
    name: &str,
    captured: Captured,
    modulus: &str,
    minus_one: &str,
) -> Result<serde_json::Value> {
    check_field::<E::Scalar>(minus_one);
    let raw = dir.join(&captured.raw_file);
    let mirror: Mirror<E::Scalar> = codec().deserialize_from(BufReader::new(File::open(&raw)?))?;
    let mut writer = HashWriter::default();
    codec().serialize_into(&mut writer, &mirror)?;
    let roundtrip = hex::encode(writer.0.finalize());
    assert_eq!(roundtrip, captured.raw_sha256, "private shape codec changed");
    assert_eq!((mirror.num_cons, mirror.num_vars, mirror.num_io),
               (captured.constraints, captured.auxiliary, captured.public));
    assert_eq!(mirror.num_io, 2, "Nova augmented IO expected");
    let wires = mirror.num_vars + 1 + mirror.num_io;
    for m in [&mirror.a, &mirror.b, &mirror.c] {
        m.validate(mirror.num_cons, wires);
    }
    let stream_file = format!("{name}.rows.jsonl");
    let path = dir.join(&stream_file);
    let mut out = BufWriter::new(fresh(&path)?);
    let public: Vec<usize> = (1..=mirror.num_io).collect();
    writeln!(out, "{}", json!({
        "format": "zkl-r1cs-stream-v1", "modulus": modulus, "wires": wires,
        "public": public, "constraints": mirror.num_cons
    }))?;
    for row in 0..mirror.num_cons {
        serde_json::to_writer(&mut out, &[
            mirror.a.row(row, mirror.num_vars, mirror.num_io),
            mirror.b.row(row, mirror.num_vars, mirror.num_io),
            mirror.c.row(row, mirror.num_vars, mirror.num_io),
        ])?;
        writeln!(out)?;
    }
    out.flush()?;
    drop(out);
    Ok(json!({
        "capture": captured, "modulus": modulus, "wires": wires,
        "stream_file": stream_file, "stream_sha256": file_sha(&path)?,
        "mirror_roundtrip_sha256": roundtrip,
        "native_column_order": "[auxiliary, one, public]",
        "audit_column_order": "[one, public, auxiliary]",
        "native_nonzeros": [mirror.a.data.len(), mirror.b.data.len(), mirror.c.data.len()],
    }))
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let dir = PathBuf::from(args.next().ok_or("usage: zkl_capture <new-output-dir>")?);
    if args.next().is_some() {
        return Err("unexpected arguments".into());
    }
    fs::create_dir(&dir)?;
    let primary = Rc::new(RefCell::new(None));
    let secondary = Rc::new(RefCell::new(None));
    let primary_slot = Rc::clone(&primary);
    let secondary_slot = Rc::clone(&secondary);
    let primary_dir = dir.clone();
    let secondary_dir = dir.clone();
    let floor1 = S1::ck_floor();
    let floor2 = S2::ck_floor();
    let hook1 = move |shape: &R1CSShape<B1>| {
        let size = floor1(shape);
        let value = capture(&primary_dir, "primary", shape, size).expect("primary capture");
        assert!(primary_slot.replace(Some(value)).is_none(), "primary callback repeated");
        size
    };
    let hook2 = move |shape: &R1CSShape<B2>| {
        let size = floor2(shape);
        let value = capture(&secondary_dir, "secondary", shape, size).expect("secondary capture");
        assert!(secondary_slot.replace(Some(value)).is_none(), "secondary callback repeated");
        size
    };
    let blank = Mnr05UnifiedBatchStep::blank();
    let pp = PublicParams::<B1, B2, Mnr05UnifiedBatchStep>::setup(&blank, &hook1, &hook2)
        .map_err(|e| format!("PublicParams::setup: {e:?}"))?;
    let p = primary.borrow_mut().take().ok_or("missing primary capture")?;
    let s = secondary.borrow_mut().take().ok_or("missing secondary capture")?;
    assert_eq!(pp.num_constraints(), (p.constraints, s.constraints));
    assert_eq!(pp.num_variables(), (p.auxiliary, s.auxiliary));
    let pp_digest = field_hex(&pp.digest());
    let (pk, vk) = CompressedSNARK::<B1, B2, Mnr05UnifiedBatchStep, S1, S2>::setup(&pp)
        .map_err(|e| format!("CompressedSNARK::setup: {e:?}"))?;
    let mut out = BufWriter::new(fresh(&dir.join("vk.bin"))?);
    codec().serialize_into(&mut out, &vk)?;
    out.flush()?;
    drop(out);
    drop(pk);
    drop(vk);
    drop(pp);

    let p = export::<B1>(&dir, "primary", p, FR, FR_MINUS_ONE)?;
    let s = export::<B2>(&dir, "secondary", s, FQ, FQ_MINUS_ONE)?;
    let manifest = json!({
        "schema": "zkl-nova-setup-capture-v1", "nova_version": "0.76.0",
        "circuit": "Mnr05UnifiedBatchStep", "capture_path": "PublicParams::setup ck_floor callbacks",
        "pp_digest": pp_digest, "vk_file": "vk.bin", "vk_sha256": file_sha(&dir.join("vk.bin"))?,
        "primary": p, "secondary": s,
        "production_accepted": false, "production_vk_matched": false, "proof_replayed": false
    });
    let mut out = BufWriter::new(fresh(&dir.join("capture.json"))?);
    serde_json::to_writer_pretty(&mut out, &manifest)?;
    writeln!(out)?;
    out.flush()?;
    println!("{}", manifest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_to_audit_permutation_and_fields() {
        assert_eq!((0..7).map(|i| canonical_wire(i, 4, 2)).collect::<Vec<_>>(),
                   vec![3, 4, 5, 6, 0, 1, 2]);
        check_field::<<B1 as Engine>::Scalar>(FR_MINUS_ONE);
        check_field::<<B2 as Engine>::Scalar>(FQ_MINUS_ONE);
    }
}
