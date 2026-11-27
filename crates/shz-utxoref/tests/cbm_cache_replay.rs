//! CBM-CACHE-02: native digest/signature workload. Synthetic keys and outpoints only.
//! No signer, reservation book, chain, or payment-channel state is mutated.
use std::{collections::BTreeSet, time::Instant};

use shz_dlc::{Bip340Signature, bip340_sign, bip340_verify, pubkey_x_from_secret};
use shz_utxoref::{
    mnr02::{
        Mnr02TaprootTree, SegwitTx, SegwitTxIn, SIGHASH_ALL, SIGHASH_DEFAULT,
        SIGHASH_SINGLE_ANYONECANPAY,
    },
    signing_target::derive_utxoref_funding_output,
    verification_cache::SchnorrVerificationCache,
};

fn secret(n: u32) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[28..].copy_from_slice(&n.to_be_bytes());
    s
}

fn pk(n: u32) -> [u8; 32] {
    pubkey_x_from_secret(&secret(n)).unwrap()
}

fn payout(n: u32) -> Vec<u8> {
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&pk(n));
    spk
}

fn input(root: u32, id: u32, spk: Vec<u8>) -> SegwitTxIn {
    // Deliberately fictitious txid; no funding or live UTXO claim.
    let fake = u64::from(root) * 100_000 + u64::from(id);
    SegwitTxIn::from_display_txid(
        &format!("{fake:064x}"), id, 0xffff_fffe, 100_000, spk,
    ).unwrap()
}

#[derive(Clone)]
struct Check {
    pk: [u8; 32],
    digest: [u8; 32],
    sig: Bip340Signature,
}

impl Check {
    fn new(n: u32, digest: [u8; 32]) -> Self {
        Self { pk: pk(n), digest, sig: bip340_sign(&secret(n), &digest).unwrap() }
    }

    fn tuple(&self) -> [u8; 128] {
        let mut k = [0; 128];
        k[..32].copy_from_slice(&self.pk);
        k[32..64].copy_from_slice(&self.digest);
        k[64..].copy_from_slice(&self.sig.to_bytes());
        k
    }
}

struct Draft {
    tx: SegwitTx,
    checks: Vec<Check>,
    first_leaf: [u8; 32],
}

fn draft(root: u32, regime: u32, c: u32) -> Draft {
    let mut offline = match regime {
        0 => vec![0, 1, 2, 3],
        1 => vec![0, 1, 2 + c % 10, 2 + (c + 3) % 10],
        _ => (4*c..4*c+4).collect(),
    };
    offline.rotate_left(((root + c) % 4) as usize);
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut trees = Vec::new();
    for &i in &offline {
        let tree = Mnr02TaprootTree::build(
            pk(60_000+i), pk(50_000+i), pk(70_000), 1000, 6, 144,
        ).unwrap();
        inputs.push(input(root,i,tree.script_pubkey.clone()));
        outputs.push((60_000,payout(30_000+i)));
        trees.push(tree);
    }
    let bilateral = [c % 12,(c+5)%12];
    let mut bilateral_trees = Vec::new();
    for &i in &bilateral {
        let tree = derive_utxoref_funding_output(pk(80_000+i),pk(81_000+i),144).unwrap();
        inputs.push(input(root,1_000+i,tree.script_pubkey.clone()));
        bilateral_trees.push(tree);
    }
    let pay = 100_000+17*u64::from(c);
    outputs.extend([
        (pay,payout(40_000+c%5)),
        (600_000-240_000-330-1_500-pay,payout(41_000+c%7)),
        (330,payout(42_000)),
    ]);
    let tx = SegwitTx { version: 2, inputs, outputs, locktime: 1000 };
    assert_eq!(
        tx.inputs.iter().map(|i| i.prevout_value_sats).sum::<u64>(),
        tx.outputs.iter().map(|o| o.0).sum::<u64>()+1_500
    );
    assert_eq!(tx.inputs.iter().map(|i| i.outpoint).collect::<BTreeSet<_>>().len(),6);
    let mut checks = Vec::new();
    for (slot, (&i,tree)) in offline.iter().zip(&trees).enumerate() {
        let template = SegwitTx {
            version: tx.version, inputs: vec![tx.inputs[slot].clone()],
            outputs: vec![tx.outputs[slot].clone()], locktime: tx.locktime,
        };
        let pinned = template.bip341_sighash(
            0,SIGHASH_SINGLE_ANYONECANPAY,Some(&tree.route_leaf_hash)
        ).unwrap();
        assert_eq!(pinned,tx.bip341_sighash(
            slot,SIGHASH_SINGLE_ANYONECANPAY,Some(&tree.route_leaf_hash)
        ).unwrap());
        let all = tx.bip341_sighash(slot,SIGHASH_ALL,Some(&tree.route_leaf_hash)).unwrap();
        checks.extend([Check::new(50_000+i,pinned),Check::new(60_000+i,all),Check::new(70_000,all)]);
    }
    for (j,(&i,tree)) in bilateral.iter().zip(&bilateral_trees).enumerate() {
        let all=tx.bip341_sighash(4+j,SIGHASH_DEFAULT,Some(&tree.cet_leaf_hash)).unwrap();
        checks.extend([Check::new(80_000+i,all),Check::new(81_000+i,all)]);
    }
    assert_eq!(checks.len(),16);
    Draft { tx, checks, first_leaf: trees[0].route_leaf_hash }
}

#[test]
fn native_digest_scope_and_cached_verification() {
    let d=draft(91,0,0);
    let pinned=&d.checks[0];
    let all=&d.checks[1];
    let l=d.first_leaf;
    let mut cache=SchnorrVerificationCache::new(32).unwrap();
    cache.verify(&pinned.pk,&pinned.digest,&pinned.sig).unwrap();
    cache.verify(&all.pk,&all.digest,&all.sig).unwrap();

    // Reordering matched SINGLE input/output and modifying other outputs preserves
    // only the pinned digest. These are signature-scope tests, not spend-validity tests.
    let mut moved=d.tx.clone();
    moved.inputs.swap(0,1);
    moved.outputs.swap(0,1);
    moved.outputs[4].0+=1;
    moved.outputs[5].0-=1;
    let digest=moved.bip341_sighash(1,SIGHASH_SINGLE_ANYONECANPAY,Some(&l)).unwrap();
    assert_eq!(digest,pinned.digest);
    cache.verify(&pinned.pk,&digest,&pinned.sig).unwrap();
    let digest=moved.bip341_sighash(1,SIGHASH_ALL,Some(&l)).unwrap();
    assert_ne!(digest,all.digest);
    assert!(cache.verify(&all.pk,&digest,&all.sig).is_err());

    for case in 0..11 {
        let mut t=d.tx.clone();
        let mut leaf=l;
        let mut ht=SIGHASH_SINGLE_ANYONECANPAY;
        match case {
            0 => t.version+=1,
            1 => t.locktime+=1,
            2 => t.inputs[0].outpoint[0]^=1,
            3 => t.inputs[0].prevout_value_sats+=1,
            4 => t.inputs[0].prevout_script_pubkey[2]^=1,
            5 => t.inputs[0].sequence-=1,
            6 => t.outputs[0].0+=1,
            7 => t.outputs[0].1[2]^=1,
            8 => leaf[0]^=1,
            9 => ht=SIGHASH_ALL,
            _ => ht=SIGHASH_DEFAULT,
        }
        let digest=t.bip341_sighash(0,ht,Some(&leaf)).unwrap();
        assert_ne!(digest,pinned.digest);
        assert!(bip340_verify(&pinned.pk,&digest,&pinned.sig).is_err());
        assert!(cache.verify(&pinned.pk,&digest,&pinned.sig).is_err());
    }
    assert_eq!(cache.len(),2);
    assert_eq!(cache.stats().hits,1);
    assert_eq!(cache.stats().rejected,12);
}

#[test]
fn native_candidate_replay() {
    let mut requests=0;
    let mut misses=0;
    for regime in 0..3 {
        for root in [91u32,92,93] {
            let drafts: Vec<_>=(0..24).map(|c| draft(root,regime,c)).collect();
            assert_eq!(drafts.iter().map(|d|d.tx.txid_hex()).collect::<BTreeSet<_>>().len(),24);
            let mut trace: Vec<&Check> = Vec::new();
            for (i,d) in drafts.iter().enumerate() {
                trace.extend(&d.checks);
                if i%3==2 {
                    trace.extend(&d.checks);
                    trace.extend(&drafts[(root as usize+7*i)%(i+1)].checks);
                }
            }
            assert_eq!(trace.len(),640);
            let start=Instant::now();
            for q in &trace { bip340_verify(&q.pk,&q.digest,&q.sig).unwrap(); }
            let cold_us=start.elapsed().as_micros();
            let mut cache=SchnorrVerificationCache::new(32).unwrap();
            let start=Instant::now();
            for q in &trace { cache.verify(&q.pk,&q.digest,&q.sig).unwrap(); }
            let cache_us=start.elapsed().as_micros();
            let stats=cache.stats();
            let distinct=trace.iter().map(|q|q.tuple()).collect::<BTreeSet<_>>().len();
            assert!(stats.misses>=distinct as u64);
            assert_eq!(stats.hits+stats.misses,trace.len() as u64);
            assert_eq!(stats.rejected,0);
            assert!(stats.hits>0 && cache.len()<=32);
            println!("CBM_CACHE_NATIVE regime={regime} root={root} requests={} distinct={distinct} misses={} hits={} cold_us={cold_us} cache_us={cache_us}",trace.len(),stats.misses,stats.hits);
            requests+=trace.len() as u64;
            misses+=stats.misses;
        }
    }
    assert_eq!(requests,5760);
    assert!(misses<requests);
    println!("CBM_CACHE_NATIVE_TOTAL requests={requests} misses={misses}");
}
