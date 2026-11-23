//! Experimental NEAR contract. Reviews and NEAR testnet execution remain pending.
//! Checks Pyth Pro Solana Ed25519 envelope authenticity and objective relay
//! double-signing. The signed BTC/USD inner-price decoder is implemented;
//! the owner-pinned signer registry, external NEAR finality and Bitcoin enforcement remain separate.
use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize},
    env, near_bindgen, AccountId, NearToken, PanicOnDefault, Promise,
    serde::{Deserialize, Serialize}, serde_json,
};

mod pyth_payload;

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

#[derive(Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[borsh(crate="near_sdk::borsh")]
#[serde(crate="near_sdk::serde",rename_all="camelCase")]
pub struct StoredPythEpoch {
    pub epoch: u64,
    pub event_id: String,
    pub price_e8: String,
    pub signed_payload_sha256_hex: String,
    pub signer_hex: String,
    pub publish_time_us: String,
    pub feed_update_time_us: String,
    pub challenge_end_block: u64,
    pub challenge_window_closed: bool,
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
    pub latest_pyth_epoch: Option<StoredPythEpoch>,
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
        env::ed25519_verify(&sig,&self.relay_message(r),&self.relayer_signer)
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
              relayer_bond_yocto:0,slashed:false,latest_pyth_epoch:None}
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
    /// Parse fields *inside* the already authenticated Ed25519 Solana payload.
    /// Signed feed ID 1 is Crypto.BTC/USD in Pyth Pro, distinct from Hermes.
    /// This view uses NEAR block timestamp for replay/freshness protection and
    /// returns None until a pinned signer and exact signed fields pass.
    /// No Bitcoin spend authority or cross-chain NEAR finality proof is implied.
    pub fn verify_pyth_btc_usd_price(
        &self, raw: Vec<u8>, max_age_us: u64,
        max_carry_forward_us: u64, max_conf_bps: u64,
    ) -> Option<pyth_payload::BtcUsdSignedPoint> {
        if max_age_us==0 || max_age_us>60_000_000 ||
           max_carry_forward_us>60_000_000 || max_conf_bps>10_000 {return None;}
        if !self.verify_pyth_pro_solana_envelope(raw.clone()) {return None;}
        let point=pyth_payload::parse_btc_usd_signed_price(&raw[102..])?;
        let now=env::block_timestamp()/1_000;
        let stamp=point.publish_time_us.parse::<u64>().ok()?;
        let feed_time=point.feed_update_time_us.parse::<u64>().ok()?;
        let conf=point.confidence_bps.parse::<u64>().ok()?;
        if stamp>now.saturating_add(100_000) || now.saturating_sub(stamp)>max_age_us ||
           stamp.saturating_sub(feed_time)>max_carry_forward_us ||conf>max_conf_bps {
            return None;
        }
        Some(point)
    }
    /// State-changing Pyth import requires an independently pinned Ed25519
    /// signing key, the signed inner BTC/USD fields and the bonded NEAR relayer.
    /// Epochs are monotone and carry a fixed challenge delay. `challenge_window_closed`
    /// is an on-NEAR policy flag, not evidence of NEAR finality on Bitcoin.
    pub fn post_pyth_btc_usd_epoch(
        &mut self, raw: Vec<u8>, epoch: u64, event_id: String,
    ) -> StoredPythEpoch {
        assert_eq!(env::predecessor_account_id(),self.relayer_account,"relayer only");
        assert!(!self.slashed && self.relayer_bond_yocto>0,"relayer requires active bond");
        assert!(!event_id.is_empty() && event_id.len()<=128,"invalid event id");
        if let Some(previous)=&self.latest_pyth_epoch {
            assert!(previous.challenge_window_closed,"prior oracle challenge window remains open");
            assert!(epoch>previous.epoch,"duplicate or reversed oracle epoch");
        }
        let point=self.verify_pyth_btc_usd_price(raw,5_000_000,2_000_000,100)
            .expect("signed Pyth price, timestamp or confidence policy rejected");
        assert_eq!(point.channel_id,3,"require Pyth fixed_rate@200ms");
        if let Some(previous)=&self.latest_pyth_epoch {
            let prev=previous.publish_time_us.parse::<u64>().expect("stored publish timestamp");
            let current=point.publish_time_us.parse::<u64>().expect("signed publish timestamp");
            assert!(current>prev,"replayed or non-monotone signed Pyth update");
        }
        let price=StoredPythEpoch{
            epoch,event_id,price_e8:point.price_e8,
            signed_payload_sha256_hex:point.signed_payload_sha256_hex,
            signer_hex:hex::encode(self.pyth_signer),
            publish_time_us:point.publish_time_us,
            feed_update_time_us:point.feed_update_time_us,
            challenge_end_block:env::block_height().saturating_add(20),
            challenge_window_closed:false,
        };
        self.latest_pyth_epoch=Some(price.clone());
        env::log_str(&format!("SHZ_PYTH_EPOCH:{epoch}:{}",price.signed_payload_sha256_hex));
        price
    }
    /// A challenge window closure on NEAR remains subject to light-client
    /// finality evidence when consumed outside NEAR. It never signs a DLC.
    pub fn close_pyth_epoch_challenge_window(&mut self,epoch:u64)->StoredPythEpoch {
        assert!(!self.slashed,"slashed oracle guard");
        let stored=self.latest_pyth_epoch.as_mut().expect("missing Pyth epoch");
        assert_eq!(stored.epoch,epoch,"wrong oracle epoch");
        assert!(env::block_height()>=stored.challenge_end_block,"challenge window open");
        stored.challenge_window_closed=true;
        stored.clone()
    }
    pub fn latest_pyth_epoch(&self)->Option<StoredPythEpoch>{
        self.latest_pyth_epoch.clone()
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
