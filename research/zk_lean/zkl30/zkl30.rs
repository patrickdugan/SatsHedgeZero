//! ZKL-30 experimental hook for nova-snark 0.76.0 (research only, never a
//! production dependency). Wraps the augmented-circuit synthesis in a
//! forwarding constraint system that
//! * drops the constraints whose global enforce index is listed in
//!   ZKL30_SKIP_PRIMARY / ZKL30_SKIP_SECONDARY (comma-separated), and
//! * adds one to the value of one auxiliary variable during witness
//!   generation when ZKL30_TAMPER_PRIMARY_AUX / _SECONDARY_AUX is set.
//! Inactive unless ZKL30_CIRCUIT is a substring of the primary step-circuit
//! type name, so other circuits in the same process are unchanged.
use crate::frontend::{ConstraintSystem, LinearCombination, SynthesisError, Variable};
use ff::PrimeField;
use std::collections::BTreeSet;
use std::marker::PhantomData;

/// Which augmented circuit is being synthesized.
#[derive(Clone, Copy, Debug)]
pub enum Side {
  /// Augmented circuit over the primary step circuit.
  Primary,
  /// Augmented circuit over the trivial secondary circuit.
  Secondary,
}

fn var(name: &str) -> Option<String> {
  std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Forwarding constraint system with the ZKL-30 skip and tamper hooks.
pub struct Skip<'a, F: PrimeField, CS: ConstraintSystem<F>> {
  inner: &'a mut CS,
  skip: BTreeSet<usize>,
  tamper: Option<usize>,
  side: Side,
  active: bool,
  enforced: usize,
  skipped: usize,
  aux: usize,
  tampered: bool,
  _f: PhantomData<F>,
}

impl<'a, F: PrimeField, CS: ConstraintSystem<F>> Skip<'a, F, CS> {
  /// Wrap `inner`; `circuit` is `std::any::type_name` of the primary step circuit.
  pub fn new(inner: &'a mut CS, side: Side, circuit: &str) -> Self {
    let active = var("ZKL30_CIRCUIT").is_some_and(|c| circuit.contains(&c));
    let key = match side {
      Side::Primary => "PRIMARY",
      Side::Secondary => "SECONDARY",
    };
    let skip = if active {
      var(&format!("ZKL30_SKIP_{key}"))
        .map(|s| s.split(',').map(|x| x.trim().parse().expect("ZKL30 skip index")).collect())
        .unwrap_or_default()
    } else {
      BTreeSet::new()
    };
    let tamper = if active {
      var(&format!("ZKL30_TAMPER_{key}_AUX")).map(|s| s.parse().expect("ZKL30 tamper index"))
    } else {
      None
    };
    Skip { inner, skip, tamper, side, active, enforced: 0, skipped: 0, aux: 0, tampered: false, _f: PhantomData }
  }
}

impl<F: PrimeField, CS: ConstraintSystem<F>> Drop for Skip<'_, F, CS> {
  fn drop(&mut self) {
    if self.active {
      eprintln!(
        "ZKL30 side={:?} witness={} enforce_calls={} skipped={} aux={} tamper={:?} tamper_applied={}",
        self.side,
        self.inner.is_witness_generator(),
        self.enforced,
        self.skipped,
        self.aux,
        self.tamper,
        self.tampered
      );
    }
  }
}

impl<F: PrimeField, CS: ConstraintSystem<F>> ConstraintSystem<F> for Skip<'_, F, CS> {
  type Root = Self;

  fn alloc<Fn_, A, AR>(&mut self, annotation: A, f: Fn_) -> Result<Variable, SynthesisError>
  where
    Fn_: FnOnce() -> Result<F, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    let index = self.aux;
    self.aux += 1;
    if self.tamper == Some(index) && self.inner.is_witness_generator() {
      self.tampered = true;
      self.inner.alloc(annotation, || f().map(|v| v + F::ONE))
    } else {
      self.inner.alloc(annotation, f)
    }
  }

  fn alloc_input<Fn_, A, AR>(&mut self, annotation: A, f: Fn_) -> Result<Variable, SynthesisError>
  where
    Fn_: FnOnce() -> Result<F, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    self.inner.alloc_input(annotation, f)
  }

  fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
  where
    A: FnOnce() -> AR,
    AR: Into<String>,
    LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
  {
    let index = self.enforced;
    self.enforced += 1;
    if self.skip.contains(&index) {
      self.skipped += 1;
    } else {
      self.inner.enforce(annotation, a, b, c);
    }
  }

  fn push_namespace<NR, N>(&mut self, name_fn: N)
  where
    NR: Into<String>,
    N: FnOnce() -> NR,
  {
    self.inner.get_root().push_namespace(name_fn);
  }

  fn pop_namespace(&mut self) {
    self.inner.get_root().pop_namespace();
  }

  fn get_root(&mut self) -> &mut Self::Root {
    self
  }

  fn is_witness_generator(&self) -> bool {
    self.inner.is_witness_generator()
  }

  fn extend_inputs(&mut self, new_inputs: &[F]) {
    self.inner.extend_inputs(new_inputs);
  }

  fn extend_aux(&mut self, new_aux: &[F]) {
    self.aux += new_aux.len();
    self.inner.extend_aux(new_aux);
  }

  fn allocate_empty(&mut self, aux_n: usize, inputs_n: usize) -> (&mut [F], &mut [F]) {
    self.aux += aux_n;
    self.inner.allocate_empty(aux_n, inputs_n)
  }

  fn allocate_empty_inputs(&mut self, n: usize) -> &mut [F] {
    self.inner.allocate_empty_inputs(n)
  }

  fn allocate_empty_aux(&mut self, n: usize) -> &mut [F] {
    self.aux += n;
    self.inner.allocate_empty_aux(n)
  }

  fn inputs_slice(&self) -> &[F] {
    self.inner.inputs_slice()
  }

  fn aux_slice(&self) -> &[F] {
    self.inner.aux_slice()
  }
}
