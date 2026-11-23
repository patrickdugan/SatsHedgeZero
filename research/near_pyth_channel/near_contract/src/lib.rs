//! Experimental NEAR contract. Reviews and NEAR testnet execution remain pending.
//! Checks Pyth Pro Solana Ed25519 envelope authenticity and objective relay
//! double-signing. Decoding the authenticated Pyth inner price payload is TODO.
//! It must never assert that signed JSON is a native Pyth price proof.
use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize},
    env, near_bindgen, AccountId, NearToken, PanicOnDefault, Promise,
    serde::{Deserialize, Serialize}, serde_json,
};

const PYTH_SOLANA_FORMAT_MAGIC: u32 = 2_182_742_457;
const RELAY_DOMAIN: &str = "SHZ/NEAR-PRICE-IMPORT/V1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(crate="near_sdk::serde",rename_all="camelCase")]
pub struct SignedRelayClaim {
    pub near_chain_id: String,
    pub near_contract: String,
    pub relayer_id: String,
    pub request_id: String,
    pub event_id: String,
    pub round: u64,
    pub receipt_hash: String,
    pub claimed_price_e8: String,
    pub publish_time_us: String,
    pub precommit_root: String,
    pub signature_hex: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate="near_sdk::borsh")]
pub struct ShzNearFraudGuard {
    pub owner: AccountId,
    pub relayer_account: AccountId,
    pub near_chain_id: String,
    pub relayer_id: String,
    pub pyth_signer: [u8; 32],
    pub relayer_signer: [u8; 32],
    pub relayer_bond_yocto: u128,
    pub slashed: bool,
}

fn signer32(value: &str) -> [u8;32] {
    let b=hex::decode(value).expect("public key must be hex");
    b.try_into().expect("Ed25519 public key must be 32 bytes")
}

impl ShzNearFraudGuard {
    fn relay_message(&self,r:&SignedRelayClaim)->Vec<u8> {
        assert!(r.round<=9_007_199_254_740_991,"round must fit JS canonical integer");
        let array=serde_json::json!([
            RELAY_DOMAIN,&r.near_chain_id,&r.near_contract,&r.relayer_id,
            &r.request_id,&r.event_id,r.round,&r.receipt_hash,&r.claimed_price_e8,
            &r.publish_time_us,&r.precommit_root
        ]);
        serde_json::to_vec(&array).expect("canonical JSON array")
    }
    fn verify_relay_sig(&self,r:&SignedRelayClaim)->bool {
        if r.near_chain_id!=self.near_chain_id || r.near_contract!=env::current_account_id().to_string()
          || r.relayer_id!=self.relayer_id || r.request_id.len()>128 || r.event_id.len()>128
          || r.receipt_hash.len()!=64 || r.precommit_root.len()!=64 {return false}
        let Ok(s)=hex::decode(&r.signature_hex) else {return false};
        let Ok(sig) = <[u8;64]>::try_from(s.as_slice()) else {return false};
        env::ed25519_verify(&sig,self.relay_message(r),&self.relayer_signer)
    }
}

#[near_bindgen]
impl ShzNearFraudGuard {
    #[init]
    pub fn new(owner:AccountId,relayer_account:AccountId,near_chain_id:String,
               relayer_id:String,pyth_signer_hex:String,relayer_signer_hex:String)->Self {
        assert!(!env::state_exists(),"initialized");
        assert!(near_chain_id=="near:mainnet" || near_chain_id=="near:testnet","unsupported chain");
        assert!(!relayer_id.is_empty() && relayer_id.len()<=128,"invalid relayer id");
        Self {owner,relayer_account,near_chain_id,relayer_id,
              pyth_signer:signer32(&pyth_signer_hex),relayer_signer:signer32(&relayer_signer_hex),
              relayer_bond_yocto:0,slashed:false}
    }
    /// Verification authenticates the bytes. It does not parse the BTC/USD price
    /// or prove freshness. The signer must be pinned from an independently audited
    /// Pyth signer registry, not supplied by a relayer.
    pub fn verify_pyth_pro_solana_envelope(&self,raw:Vec<u8>)->bool {
        if raw.len()<103 || raw.len()>16384 {return false}
        if u32::from_le_bytes(raw[0..4].try_into().unwrap())!=PYTH_SOLANA_FORMAT_MAGIC{return false}
        let n=u16::from_le_bytes(raw[100..102].try_into().unwrap()) as usize;
        if n==0 || raw.len()!=102+n {return false}
        if &raw[68..100]!=self.pyth_signer.as_slice(){return false}
        let sig: [u8;64]=raw[4..68].try_into().unwrap();
        env::ed25519_verify(&sig,&raw[102..],&self.pyth_signer)
    }
    #[payable]
    pub fn post_relayer_bond(&mut self) {
        assert_eq!(env::predecessor_account_id(),self.relayer_account,"relayer only");
        assert!(!self.slashed,"relayer already slashed");
        let amount=env::attached_deposit().as_yoctonear();
        assert!(amount>0,"empty bond");
        self.relayer_bond_yocto=self.relayer_bond_yocto.checked_add(amount).expect("bond overflow");
    }
    /// Objective fraud regime: same signer, round and event, differing commitments.
    /// Full NEAR escrow policy (minimum bond, account rotation, grace period,
    /// challenger distribution and restitution) needs production design review.
    pub fn submit_relayer_equivocation(&mut self,a:SignedRelayClaim,b:SignedRelayClaim)->Promise {
        assert!(!self.slashed && self.relayer_bond_yocto>0,"inactive or unbonded relayer");
        assert_eq!(a.near_chain_id,b.near_chain_id,"different chains");
        assert_eq!(a.near_contract,b.near_contract,"different contracts");
        assert_eq!(a.relayer_id,b.relayer_id,"different relayers");
        assert_eq!(a.event_id,b.event_id,"different events");
        assert_eq!(a.round,b.round,"different rounds");
        assert_eq!(a.request_id,b.request_id,"different requests");
        assert!(self.verify_relay_sig(&a) && self.verify_relay_sig(&b),"invalid relay signatures");
        assert!(a.receipt_hash!=b.receipt_hash || a.claimed_price_e8!=b.claimed_price_e8 ||
                a.precommit_root!=b.precommit_root || a.publish_time_us!=b.publish_time_us,
                "identical signed claims");
        let challenger=env::predecessor_account_id();
        let stake=self.relayer_bond_yocto;
        self.relayer_bond_yocto=0;
        self.slashed=true;
        Promise::new(challenger).transfer(NearToken::from_yoctonear(stake))
    }
    pub fn is_slashed(&self)->bool {self.slashed}
    pub fn bond_balance_yocto(&self)->String {self.relayer_bond_yocto.to_string()}
}
