//! Constraint-system audit tooling: a recording [`ConstraintSystem`] that keeps the R1CS,
//! the assignment and every variable's and constraint's name, plus the checks run on it:
//! variable-level mutation, under-constraint search (single variables and constraint-local
//! pairs), the variable-occurrence audit, per-gadget constraint counts, and an export in the
//! iden3 `.r1cs` binary format (readable by circom tooling such as Picus or snarkjs).
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr as F;
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable},
    traits::circuit::StepCircuit,
};
use serde::Serialize;
use std::collections::BTreeMap;

/// Variable 0 is the constant one; aux variable `j` is `j + 1`.
pub type Row = Vec<(u32, F)>;

#[derive(Default)]
pub struct AuditCS {
    pub names: Vec<String>,
    pub values: Vec<F>,
    pub rows: Vec<[Row; 3]>,
    pub row_names: Vec<String>,
    ns: Vec<String>,
}

fn key(v: Variable) -> u32 {
    match v.get_unchecked() {
        Index::Input(0) => 0,
        Index::Input(i) => panic!("input {i}: the audited steps allocate no inputs"),
        Index::Aux(j) => j as u32 + 1,
    }
}

fn row(lc: &LinearCombination<F>) -> Row {
    lc.iter().map(|(v, c)| (key(v), *c)).collect()
}

impl ConstraintSystem<F> for AuditCS {
    type Root = Self;
    fn new() -> Self {
        AuditCS { names: vec!["ONE".into()], values: vec![F::ONE], ..Default::default() }
    }
    fn alloc<Fn_, A, AR>(&mut self, annotation: A, f: Fn_) -> Result<Variable, SynthesisError>
    where
        Fn_: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let j = self.values.len() - 1;
        self.values.push(f()?);
        self.names.push(self.path(annotation().into()));
        Ok(Variable::new_unchecked(Index::Aux(j)))
    }
    fn alloc_input<Fn_, A, AR>(&mut self, _: A, _: Fn_) -> Result<Variable, SynthesisError>
    where
        Fn_: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        unimplemented!("no public inputs inside a Nova step")
    }
    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        let (a, b, c) = (a(LinearCombination::zero()), b(LinearCombination::zero()), c(LinearCombination::zero()));
        self.rows.push([row(&a), row(&b), row(&c)]);
        let n = self.path(annotation().into());
        self.row_names.push(n);
    }
    fn push_namespace<NR: Into<String>, N: FnOnce() -> NR>(&mut self, f: N) {
        self.ns.push(f().into());
    }
    fn pop_namespace(&mut self) {
        self.ns.pop();
    }
    fn get_root(&mut self) -> &mut Self {
        self
    }
}

impl AuditCS {
    fn path(&self, leaf: String) -> String {
        let mut p = self.ns.join("/");
        if !p.is_empty() {
            p.push('/');
        }
        p.push_str(&leaf);
        p
    }
    fn eval(&self, r: &Row, values: &[F]) -> F {
        r.iter().map(|(v, c)| values[*v as usize] * c).sum()
    }
    pub fn satisfied(&self) -> Option<usize> {
        self.rows.iter().position(|r| self.eval(&r[0], &self.values) * self.eval(&r[1], &self.values) != self.eval(&r[2], &self.values))
    }
    fn occurrences(&self) -> Vec<Vec<u32>> {
        let mut occ = vec![Vec::new(); self.values.len()];
        for (i, r) in self.rows.iter().enumerate() {
            let mut seen: Vec<u32> = r.iter().flatten().map(|(v, _)| *v).collect();
            seen.sort_unstable();
            seen.dedup();
            for v in seen {
                occ[v as usize].push(i as u32);
            }
        }
        occ
    }
}

/// A gadget-level name: path components with digits removed, first `depth` components.
pub fn gadget_of(path: &str, depth: usize) -> String {
    path.split('/').take(depth).map(|c| c.trim_end_matches(|ch: char| ch.is_ascii_digit() || ch == '_')).collect::<Vec<_>>().join("/")
}

#[derive(Serialize, Debug, Clone)]
pub struct AuditReport {
    pub constraints: usize,
    pub variables: usize,
    pub public_io: usize,
    pub nonzero_entries: usize,
    pub satisfied: bool,
    /// Every variable perturbed by +1 and by a random field element: rejected counts.
    pub single_mutations: usize,
    pub single_rejected: usize,
    /// Variables whose perturbation leaves every constraint satisfied (a second witness).
    pub single_free: Vec<String>,
    /// Pairs of variables sharing a constraint: perturb one, re-solve the shared
    /// constraint for the other, check every constraint either touches.
    pub pair_mutations: usize,
    pub pair_rejected: usize,
    pub pair_free: Vec<String>,
    /// Variables in fewer than 2 constraints, grouped by gadget name, with a count.
    pub low_occurrence: BTreeMap<String, usize>,
    /// Constraints per gadget (namespace with indices removed, 2 levels).
    pub constraints_per_gadget: BTreeMap<String, usize>,
}

fn delta(seed: &mut u64) -> F {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    F::from(*seed) * F::from(seed.rotate_left(29)) + F::ONE
}

impl AuditCS {
    /// `public` are the step's `z_in` and `z_out` variables (the IO a verifier sees).
    pub fn audit(&self, public: &[u32], pair_budget: usize) -> AuditReport {
        let occ = self.occurrences();
        let nv = self.values.len();
        let ok = self.satisfied().is_none();
        let base: Vec<[F; 3]> = self.rows.iter().map(|r| [self.eval(&r[0], &self.values), self.eval(&r[1], &self.values), self.eval(&r[2], &self.values)]).collect();
        let coeff = |r: &Row, v: u32| r.iter().filter(|(x, _)| *x == v).map(|(_, c)| *c).sum::<F>();
        // rows holds after changing variables `ds` by their deltas
        let holds = |row_ids: &[u32], ds: &[(u32, F)]| -> bool {
            row_ids.iter().all(|&ri| {
                let r = &self.rows[ri as usize];
                let mut abc = base[ri as usize];
                for (k, lc) in r.iter().enumerate() {
                    for &(v, d) in ds {
                        abc[k] += coeff(lc, v) * d;
                    }
                }
                abc[0] * abc[1] == abc[2]
            })
        };
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let (mut sm, mut sr, mut sfree) = (0, 0, Vec::new());
        for v in 1..nv as u32 {
            for d in [F::ONE, delta(&mut seed)] {
                sm += 1;
                if holds(&occ[v as usize], &[(v, d)]) {
                    sfree.push(self.names[v as usize].clone());
                } else {
                    sr += 1;
                }
            }
        }
        sfree.dedup();
        // pairs: perturb u, solve one shared constraint (linear in w) for w's delta
        let (mut pm, mut pr, mut pfree) = (0, 0, Vec::new());
        'outer: for (ri, r) in self.rows.iter().enumerate() {
            let mut vars: Vec<u32> = r.iter().flatten().map(|(v, _)| *v).filter(|&v| v != 0).collect();
            vars.sort_unstable();
            vars.dedup();
            vars.truncate(8);
            for &u in &vars {
                for &w in &vars {
                    if u == w {
                        continue;
                    }
                    if pm >= pair_budget {
                        break 'outer;
                    }
                    let du = delta(&mut seed);
                    // f(dw) = (a + au du + aw dw)(b + bu du + bw dw) - (c + cu du + cw dw); keep it linear
                    let [a, b, c] = base[ri];
                    let (au, bu, cu) = (coeff(&r[0], u), coeff(&r[1], u), coeff(&r[2], u));
                    let (aw, bw, cw) = (coeff(&r[0], w), coeff(&r[1], w), coeff(&r[2], w));
                    let (a1, b1, c1) = (a + au * du, b + bu * du, c + cu * du);
                    if aw * bw != F::ZERO {
                        continue;
                    }
                    let lin = aw * b1 + bw * a1 - cw;
                    let cons = a1 * b1 - c1;
                    let Some(inv) = Option::<F>::from(lin.invert()) else { continue };
                    let dw = -cons * inv;
                    if dw == F::ZERO {
                        continue;
                    }
                    pm += 1;
                    let mut ids = occ[u as usize].clone();
                    ids.extend(&occ[w as usize]);
                    ids.sort_unstable();
                    ids.dedup();
                    if holds(&ids, &[(u, du), (w, dw)]) {
                        pfree.push(format!("{} + {}", self.names[u as usize], self.names[w as usize]));
                    } else {
                        pr += 1;
                    }
                }
            }
        }
        let mut low = BTreeMap::new();
        for v in 1..nv {
            if occ[v].len() < 2 {
                *low.entry(format!("{} [{} constraint(s)]{}", gadget_of(&self.names[v], 4), occ[v].len(), if public.contains(&(v as u32)) { " public" } else { "" })).or_insert(0) += 1;
            }
        }
        let mut per = BTreeMap::new();
        for n in &self.row_names {
            *per.entry(gadget_of(n, 2)).or_insert(0) += 1;
        }
        AuditReport {
            constraints: self.rows.len(),
            variables: nv,
            public_io: public.len(),
            nonzero_entries: self.rows.iter().map(|r| r[0].len() + r[1].len() + r[2].len()).sum(),
            satisfied: ok,
            single_mutations: sm,
            single_rejected: sr,
            single_free: sfree,
            pair_mutations: pm,
            pair_rejected: pr,
            pair_free: pfree,
            low_occurrence: low,
            constraints_per_gadget: per,
        }
    }

    /// iden3 `.r1cs` v1 (https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md).
    /// Wire 0 is the constant one; `public` wires are renumbered to 1.. as public outputs
    /// (z_out then z_in, as listed); all others are private inputs. Section 3 maps wires to
    /// this system's variable indices (labels); `names` (one per line) are written beside it.
    pub fn write_r1cs(&self, path: &std::path::Path, public: &[u32]) -> std::io::Result<()> {
        let nv = self.values.len();
        let mut order: Vec<u32> = vec![0];
        let mut is_pub = vec![false; nv];
        for &p in public {
            if !is_pub[p as usize] {
                is_pub[p as usize] = true;
                order.push(p);
            }
        }
        let npub = order.len() - 1;
        order.extend((1..nv as u32).filter(|&v| !is_pub[v as usize]));
        let mut wire = vec![0u32; nv];
        for (w, &v) in order.iter().enumerate() {
            wire[v as usize] = w as u32;
        }
        let prime = {
            let m = F::ZERO - F::ONE; // p - 1
            let mut b = m.to_repr().as_ref().to_vec();
            b[0] += 1; // p - 1 is even, so +1 does not carry
            b
        };
        let mut header = Vec::new();
        header.extend(32u32.to_le_bytes());
        header.extend(&prime);
        header.extend((nv as u32).to_le_bytes());
        header.extend((npub as u32).to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend(((nv - 1 - npub) as u32).to_le_bytes());
        header.extend((nv as u64).to_le_bytes());
        header.extend((self.rows.len() as u32).to_le_bytes());
        let mut cons = Vec::new();
        for r in &self.rows {
            for lc in r {
                let mut m: BTreeMap<u32, F> = BTreeMap::new();
                for (v, c) in lc {
                    *m.entry(wire[*v as usize]).or_insert(F::ZERO) += c;
                }
                m.retain(|_, c| *c != F::ZERO);
                cons.extend((m.len() as u32).to_le_bytes());
                for (w, c) in m {
                    cons.extend(w.to_le_bytes());
                    cons.extend(c.to_repr().as_ref());
                }
            }
        }
        let mut labels = Vec::new();
        for &v in &order {
            labels.extend((v as u64).to_le_bytes());
        }
        let mut out = b"r1cs".to_vec();
        out.extend(1u32.to_le_bytes());
        out.extend(3u32.to_le_bytes());
        for (t, s) in [(1u32, header), (2, cons), (3, labels)] {
            out.extend(t.to_le_bytes());
            out.extend((s.len() as u64).to_le_bytes());
            out.extend(s);
        }
        std::fs::write(path, out)?;
        let names: String = order.iter().map(|&v| format!("{}\n", self.names[v as usize])).collect();
        std::fs::write(path.with_extension("wires.txt"), names)
    }
}

/// Synthesize `step` on an [`AuditCS`] with input `z`; returns the system and the public
/// IO variables (`z_in` then `z_out`).
pub fn record<C: StepCircuit<F>>(step: &C, z: &[F]) -> (AuditCS, Vec<u32>) {
    let mut cs = AuditCS::new();
    let zin: Vec<AllocatedNum<F>> = z.iter().enumerate().map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z_in{i}")), || Ok(*v)).unwrap()).collect();
    let out = step.synthesize(&mut cs, &zin).expect("synthesize");
    let mut public: Vec<u32> = zin.iter().map(|n| key(n.get_variable())).collect();
    public.extend(out.iter().map(|n| key(n.get_variable())));
    (cs, public)
}
