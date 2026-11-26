//! Secret-key operations for the venue page, compiled to `ui/venue/sign.wasm`.
//!
//! The page keeps verification and hashing in JS; everything that touches a
//! secret scalar runs here on `k256` (constant-time field and scalar arithmetic).
//! No allocator and no imports: JS writes inputs into one static 256-byte I/O
//! buffer (`shz_buf`), calls an operation, reads the output, and every
//! operation wipes the buffer region holding secret input before returning.
//!
//! Buffer layout per operation (offsets in bytes; return 0 = ok, 1 = rejected):
//! - `shz_pubkey`:       in sk[0..32]                              out xonly[32..64]
//! - `shz_sign`:         in sk[0..32] msg[32..64] aux[64..96]      out sig[96..160]
//! - `shz_tweak_secret`: in sk[0..32] root[32..64] has_root[64]    out sk'[96..128]
//! - `shz_keygen`:       in entropy[0..64]                         out sk[64..96]
//!
//! Build (from the repo root; output committed as ui/venue/sign.wasm):
//! `CARGO_PROFILE_RELEASE_OPT_LEVEL=s CARGO_PROFILE_RELEASE_LTO=true CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
//!  CARGO_PROFILE_RELEASE_PANIC=abort CARGO_PROFILE_RELEASE_STRIP=true
//!  cargo build --release -p shz-wasm-sign --target wasm32-unknown-unknown`
//! then copy `<target>/wasm32-unknown-unknown/release/shz_wasm_sign.wasm`.

#![cfg_attr(target_arch = "wasm32", no_std)]

use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::PrimeField;
use k256::schnorr::SigningKey;
use k256::{FieldBytes, Scalar, WideBytes};
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

pub const BUF_LEN: usize = 256;
static mut BUF: [u8; BUF_LEN] = [0; BUF_LEN];

fn buf() -> &'static mut [u8; BUF_LEN] {
    // SAFETY: wasm32 is single-threaded and each export takes the buffer once;
    // native callers (tests) use the pure functions below, not the exports.
    unsafe { &mut *core::ptr::addr_of_mut!(BUF) }
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[..32]);
    out
}

fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // Volatile so the wipe is not elided as a dead store.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
}

/// x-only public key of `sk` (BIP340).
pub fn pubkey(sk: &[u8; 32]) -> Option<[u8; 32]> {
    let key = SigningKey::from_bytes(sk).ok()?;
    Some(key.verifying_key().to_bytes().into())
}

/// BIP340 signature of a 32-byte message with auxiliary randomness `aux`.
pub fn sign(sk: &[u8; 32], msg: &[u8; 32], aux: &[u8; 32]) -> Option<[u8; 64]> {
    let key = SigningKey::from_bytes(sk).ok()?;
    let sig = key.sign_raw(msg, aux).ok()?;
    Some(sig.to_bytes())
}

fn tap_tweak(px: &[u8; 32], root: Option<&[u8; 32]>) -> [u8; 32] {
    let tag = Sha256::digest(b"TapTweak");
    let mut h = Sha256::new();
    h.update(tag);
    h.update(tag);
    h.update(px);
    if let Some(r) = root {
        h.update(r);
    }
    h.finalize().into()
}

/// BIP341 tweak of a secret key: d' = d_even + H_TapTweak(P || root) mod n.
/// The matching output key is the x coordinate of d'·G.
pub fn tweak_secret(sk: &[u8; 32], root: Option<&[u8; 32]>) -> Option<[u8; 32]> {
    let key = SigningKey::from_bytes(sk).ok()?;
    // SigningKey already holds the even-y form of d.
    let d = *key.as_nonzero_scalar().as_ref();
    let px: [u8; 32] = key.verifying_key().to_bytes().into();
    let t = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(tap_tweak(&px, root))))?;
    let out = d + t;
    if bool::from(out.is_zero()) {
        return None;
    }
    Some(out.to_bytes().into())
}

/// Secret key from 64 bytes of caller entropy, reduced mod n (bias below 2^-128).
pub fn keygen(entropy: &[u8; 64]) -> Option<[u8; 32]> {
    let mut w = WideBytes::default();
    w.copy_from_slice(entropy);
    let s = <Scalar as Reduce<U512>>::reduce_bytes(&w);
    wipe(&mut w);
    if bool::from(s.is_zero()) {
        return None;
    }
    Some(s.to_bytes().into())
}

#[unsafe(no_mangle)]
pub extern "C" fn shz_buf() -> *mut u8 {
    core::ptr::addr_of_mut!(BUF) as *mut u8
}

#[unsafe(no_mangle)]
pub extern "C" fn shz_pubkey() -> u32 {
    let b = buf();
    let r = pubkey(&arr32(&b[0..32]));
    wipe(&mut b[0..32]);
    match r {
        Some(x) => {
            b[32..64].copy_from_slice(&x);
            0
        }
        None => 1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn shz_sign() -> u32 {
    let b = buf();
    let r = sign(&arr32(&b[0..32]), &arr32(&b[32..64]), &arr32(&b[64..96]));
    wipe(&mut b[0..32]);
    match r {
        Some(sig) => {
            b[96..160].copy_from_slice(&sig);
            0
        }
        None => 1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn shz_tweak_secret() -> u32 {
    let b = buf();
    let root = arr32(&b[32..64]);
    let r = tweak_secret(&arr32(&b[0..32]), if b[64] != 0 { Some(&root) } else { None });
    wipe(&mut b[0..32]);
    match r {
        Some(sk) => {
            b[96..128].copy_from_slice(&sk);
            0
        }
        None => 1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn shz_keygen() -> u32 {
    let b = buf();
    let mut e = [0u8; 64];
    e.copy_from_slice(&b[0..64]);
    let r = keygen(&e);
    wipe(&mut e);
    wipe(&mut b[0..64]);
    match r {
        Some(sk) => {
            b[64..96].copy_from_slice(&sk);
            0
        }
        None => 1,
    }
}

/// Wipes the whole I/O buffer (JS calls this after reading a secret output).
#[unsafe(no_mangle)]
pub extern "C" fn shz_wipe() {
    wipe(buf());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dlc_sig(s: &[u8; 64]) -> shz_dlc::Bip340Signature {
        shz_dlc::Bip340Signature { r_x: s[..32].try_into().unwrap(), s: s[32..].try_into().unwrap() }
    }

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // BIP340 test-vectors.csv, signing rows 0-3 (index, seckey, pubkey, aux, msg, sig).
    const VECTORS: [(&str, &str, &str, &str, &str); 4] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        ),
        (
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        ),
        (
            "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        ),
        (
            "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
            "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
        ),
    ];

    #[test]
    fn bip340_official_vectors() {
        for (sk, pk, aux, msg, sig) in VECTORS {
            let (sk, aux, msg) = (h32(sk), h32(aux), h32(msg));
            assert_eq!(hex::encode_upper(pubkey(&sk).unwrap()), pk);
            let s = sign(&sk, &msg, &aux).unwrap();
            assert_eq!(hex::encode_upper(s), sig);
            let parsed = dlc_sig(&s);
            shz_dlc::bip340_verify(&h32(pk), &msg, &parsed).unwrap();
        }
    }

    #[test]
    fn signatures_verify_under_shz_dlc_and_tamper_fails() {
        for i in 1u8..20 {
            let mut e = [0u8; 64];
            e.iter_mut().enumerate().for_each(|(j, b)| *b = i.wrapping_mul(31).wrapping_add(j as u8));
            let sk = keygen(&e).unwrap();
            let pk = pubkey(&sk).unwrap();
            let msg = [i; 32];
            let s = sign(&sk, &msg, &[i ^ 0x5a; 32]).unwrap();
            let parsed = dlc_sig(&s);
            shz_dlc::bip340_verify(&pk, &msg, &parsed).unwrap();
            let mut bad = s;
            bad[63] ^= 1;
            let parsed = dlc_sig(&bad);
            assert!(shz_dlc::bip340_verify(&pk, &msg, &parsed).is_err());
        }
    }

    #[test]
    fn rejects_out_of_range_secrets() {
        assert!(pubkey(&[0u8; 32]).is_none());
        let n = h32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        assert!(pubkey(&n).is_none());
        assert!(sign(&n, &[0; 32], &[0; 32]).is_none());
        assert!(keygen(&[0u8; 64]).is_none());
    }

    #[test]
    fn bip86_tweaked_secret_matches_output_key() {
        // BIP86 first receiving key m/86'/0'/0'/0/0.
        let sk = h32("41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361");
        assert_eq!(
            hex::encode(pubkey(&sk).unwrap()),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
        let tweaked = tweak_secret(&sk, None).unwrap();
        assert_eq!(
            hex::encode(pubkey(&tweaked).unwrap()),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
        let s = sign(&tweaked, &[7; 32], &[0; 32]).unwrap();
        let q = h32("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c");
        shz_dlc::bip340_verify(&q, &[7; 32], &dlc_sig(&s)).unwrap();
    }

    #[test]
    fn exports_wipe_secret_input() {
        let b = buf();
        b[0..32].copy_from_slice(&h32("0000000000000000000000000000000000000000000000000000000000000003"));
        b[32..96].fill(0);
        assert_eq!(shz_sign(), 0);
        assert_eq!(b[0..32], [0u8; 32]);
        assert_eq!(
            hex::encode_upper(&b[96..160]),
            VECTORS[0].4
        );
        shz_wipe();
        assert!(b.iter().all(|&x| x == 0));
    }
}
