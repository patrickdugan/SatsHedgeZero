//! SHZ-INDEX-01: deterministic eight-hour checkpoint membership in NEAR native SHA256.
//! This is a PUBLIC SHA256 verifier, not a ZK verifier or oracle-authenticated settlement.
//! Owner-staged roots are not Bitcoin-finalized. No DLC or dollar-minting capability is exposed.
use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize},
    collections::LookupMap,
    env, near_bindgen,
    serde::{Deserialize, Serialize},
    AccountId, PanicOnDefault,
};
const LEAF_DOMAIN: &[u8] = b"SHZ/HOUR/LEAF/V1";
const NODE_DOMAIN: &[u8] = b"SHZ/HOUR/NODE/V1";
const ROOT_DOMAIN: &[u8] = b"SHZ/8H/ROOT/V1";
const MAGIC: &[u8; 8] = b"SHZIDX01";
const HOURLY_US: u64 = 3_600_000_000;
const MAX_AGE_US: u64 = 300_000_000;
const MAX_SKEW_US: u64 = 60_000_000;
const MAX_PRICE_E8: u64 = 10_000_000_000_000_000;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Checkpoint {
    pub schema: String,
    pub start_hour: String,
    pub genesis: String,
    pub policy_hash: String,
    pub merkle_root: String,
    pub checkpoint_root: String,
    pub packet_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct HourRecord {
    pub genesis: String,
    pub policy_hash: String,
    pub hour_id: String,
    pub status: u8,
    pub hold_reason: u8,
    pub pyth_price_e8: String,
    pub chainlink_price_e8: String,
    pub index_price_e8: String,
    pub pyth_publish_us: String,
    pub chainlink_publish_us: String,
    pub pyth_report_hash: String,
    pub chainlink_report_hash: String,
}

fn parsed_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || (s.len() > 1 && s.starts_with('0'))
       || !s.bytes().all(|b| b.is_ascii_digit()) {return None}
    s.parse::<u64>().ok()
}
fn parsed_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase()) {return None}
    hex::decode(s).ok()?.try_into().ok()
}
fn sha(data: &[u8]) -> [u8; 32] {env::sha256(data).try_into().expect("NEAR SHA256 must return 32 bytes")}
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(NODE_DOMAIN.len()+64);
    bytes.extend_from_slice(NODE_DOMAIN);bytes.extend_from_slice(left);bytes.extend_from_slice(right);
    sha(&bytes)
}
fn distance(a:u64,b:u64)->u64{a.abs_diff(b)}
fn leaf(record: &HourRecord) -> Option<([u8;32],u64)> {
    let genesis=parsed_hex32(&record.genesis)?;
    let policy=parsed_hex32(&record.policy_hash)?;
    let hour=parsed_u64(&record.hour_id)?;
    if hour>=1_000_000_000{return None}
    let vals=[
        parsed_u64(&record.pyth_price_e8)?,
        parsed_u64(&record.chainlink_price_e8)?,
        parsed_u64(&record.index_price_e8)?,
        parsed_u64(&record.pyth_publish_us)?,
        parsed_u64(&record.chainlink_publish_us)?,
    ];
    let [p,c,i,pt,ct]=vals;
    let ph=parsed_hex32(&record.pyth_report_hash)?;
    let ch=parsed_hex32(&record.chainlink_report_hash)?;
    match record.status {
      1 => {
        if record.hold_reason!=0 || p==0 || c==0 || p>MAX_PRICE_E8 || c>MAX_PRICE_E8
            || i==0 || i>MAX_PRICE_E8 || (p as u128+c as u128)/2 != i as u128
            || (distance(p,c) as u128)*20_000 > 50*(p as u128+c as u128)
            || ph==[0u8;32] || ch==[0u8;32] {return None}
        let cutoff=hour.checked_add(1)?.checked_mul(HOURLY_US)?;
        if pt>cutoff || ct>cutoff || cutoff-pt>MAX_AGE_US || cutoff-ct>MAX_AGE_US
            || distance(pt,ct)>MAX_SKEW_US {return None}
      },
      2 => {
        if !(1..=3).contains(&record.hold_reason) || vals.iter().any(|v|*v!=0)
          || ph!=[0u8;32] || ch!=[0u8;32] {return None}
      },
      _=>return None
    }
    let mut bytes=Vec::with_capacity(LEAF_DOMAIN.len()+32+32+8+2+40+64);
    bytes.extend_from_slice(LEAF_DOMAIN);
    bytes.extend_from_slice(&genesis);
    bytes.extend_from_slice(&policy);
    bytes.extend_from_slice(&hour.to_le_bytes());
    bytes.push(record.status);bytes.push(record.hold_reason);
    for v in vals {bytes.extend_from_slice(&v.to_le_bytes());}
    bytes.extend_from_slice(&ph);bytes.extend_from_slice(&ch);
    Some((sha(&bytes),hour))
}
fn checkpoint_hash(cp: &Checkpoint)->Option<([u8;32],u64)> {
    if cp.schema != "shz/hourly-checkpoint/v1" {return None}
    let start=parsed_u64(&cp.start_hour)?;
    if start%8!=0 || start>=1_000_000_000 {return None}
    let genesis=parsed_hex32(&cp.genesis)?;
    let policy=parsed_hex32(&cp.policy_hash)?;
    let merkle=parsed_hex32(&cp.merkle_root)?;
    let announced=parsed_hex32(&cp.checkpoint_root)?;
    let packet=hex::decode(&cp.packet_hex).ok()?;
    if packet.len()!=40 || &packet[..8]!=MAGIC || packet[8..]!=announced[..] {return None}
    let mut input=Vec::with_capacity(ROOT_DOMAIN.len()+32+32+8+32);
    input.extend_from_slice(ROOT_DOMAIN);
    input.extend_from_slice(&genesis);
    input.extend_from_slice(&policy);
    input.extend_from_slice(&start.to_le_bytes());
    input.extend_from_slice(&merkle);
    let committed=sha(&input);
    if announced != committed {return None}
    Some((committed,start))
}
fn verify_hour(cp: &Checkpoint,record: &HourRecord,siblings: &[String]) -> bool {
    let Some((_,start))=checkpoint_hash(cp) else {return false};
    let Some((mut h,hour))=leaf(record) else{return false};
    if record.genesis!=cp.genesis || record.policy_hash!=cp.policy_hash
      || hour<start || hour>=start+8 || siblings.len()!=3 {return false}
    let mut idx=hour-start;
    for s in siblings {
        let Some(other)=parsed_hex32(s) else{return false};
        h=if (idx&1)==1 {node(&other,&h)} else {node(&h,&other)};
        idx >>= 1;
    }
    let Some(root)=parsed_hex32(&cp.merkle_root) else{return false};
    h==root
}

#[near_bindgen]
#[derive(BorshSerialize,BorshDeserialize,PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ShzHourlyIndex {
    pub owner: AccountId,
    checkpoints: LookupMap<String,Checkpoint>,
    pub latest_start_hour:Option<u64>,
}

#[near_bindgen]
impl ShzHourlyIndex {
    #[init]
    pub fn new()->Self {
        Self {owner:env::predecessor_account_id(),checkpoints:LookupMap::new(b"hour-v1"),latest_start_hour:None}
    }
    /// Research-only authorization: this owner-staged root is *not* proven Bitcoin-anchored.
    pub fn stage_checkpoint(&mut self, cp:Checkpoint) -> bool {
        assert_eq!(env::predecessor_account_id(),self.owner,"owner-only research checkpoint");
        let Some((_,start))=checkpoint_hash(&cp) else{return false};
        if self.checkpoints.get(&cp.start_hour).is_some(){return false}
        if let Some(previous)=self.latest_start_hour {
            if previous.checked_add(8)!=Some(start){return false}
        }
        self.checkpoints.insert(&cp.start_hour,&cp);
        self.latest_start_hour=Some(start);
        true
    }
    pub fn checkpoint(&self,start_hour:String)->Option<Checkpoint>{self.checkpoints.get(&start_hour)}
    pub fn verify_hour_inclusion(&self,record:HourRecord,start_hour:String,siblings:Vec<String>)->bool {
        let Some(cp)=self.checkpoints.get(&start_hour) else{return false};
        verify_hour(&cp,&record,&siblings)
    }
    pub fn verify_qualified_hour(&self,record:HourRecord,start_hour:String,siblings:Vec<String>)->bool {
        record.status==1 && self.verify_hour_inclusion(record,start_hour,siblings)
    }
    pub fn proof_relation(&self)->String{"shz/8h-public-sha256-checkpoint/v1".into()}
    pub fn bitcoin_anchor_finality_verified(&self)->bool{false}
    pub fn pyth_chainlink_sources_authenticated(&self)->bool{false}
    pub fn zk_private_hourly_witness_verified(&self)->bool{false}
    pub fn nova_verified(&self)->bool{false}
    pub fn can_authorize_dlc_settlement(&self)->bool{false}
}

#[cfg(all(test,not(target_arch="wasm32")))]
mod tests {
    use super::*;
    use near_sdk::{test_utils::VMContextBuilder,testing_env,serde_json};
    fn fixture()->(ShzHourlyIndex, Vec<HourRecord>,Checkpoint,Vec<Vec<String>>) {
        let mut ctx=VMContextBuilder::new();ctx.current_account_id("shz-hour-index.testnet".parse().unwrap());
        ctx.predecessor_account_id("owner.testnet".parse().unwrap());testing_env!(ctx.build());
        let v:serde_json::Value=serde_json::from_str(include_str!("../../fixtures/checkpoint.json")).unwrap();
        let records:Vec<HourRecord>=serde_json::from_value(v["records"].clone()).unwrap();
        let cp:Checkpoint=serde_json::from_value(v["checkpoint"].clone()).unwrap();
        let siblings=(0..8).map(|i|serde_json::from_value(v["checkpoint"]["inclusion"][i]["siblings"].clone()).unwrap()).collect();
        (ShzHourlyIndex::new(),records,cp,siblings)
    }
    #[test]
    fn accepts_eight_sharable_hourly_membership_proofs() {
        let(mut contract,records,cp,siblings)=fixture();
        assert!(contract.stage_checkpoint(cp));
        for i in 0..8 {
            assert!(contract.verify_hour_inclusion(records[i].clone(),"498000".into(),siblings[i].clone()));
            assert_eq!(contract.verify_qualified_hour(records[i].clone(),"498000".into(),siblings[i].clone()),i!=4);
        }
        assert!(!contract.bitcoin_anchor_finality_verified());
        assert!(!contract.pyth_chainlink_sources_authenticated());
        assert!(!contract.zk_private_hourly_witness_verified());
        assert!(!contract.can_authorize_dlc_settlement());
    }
    #[test]
    fn changed_report_and_wrong_index_fail() {
        let(mut contract,mut records,cp,siblings)=fixture();assert!(contract.stage_checkpoint(cp));
        records[0].pyth_report_hash="ff".repeat(32);
        assert!(!contract.verify_hour_inclusion(records[0].clone(),"498000".into(),siblings[0].clone()));
        records[1].index_price_e8="10010000000001".into();
        assert!(!contract.verify_hour_inclusion(records[1].clone(),"498000".into(),siblings[1].clone()));
    }
    #[test]
    fn owner_cannot_stage_tampered_root(){
        let(mut contract,_,mut cp,_)=fixture();cp.checkpoint_root="00".repeat(32);
        assert!(!contract.stage_checkpoint(cp));
    }
}
