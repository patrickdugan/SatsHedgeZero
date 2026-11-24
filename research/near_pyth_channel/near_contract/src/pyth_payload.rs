//! Pyth Pro/Lazer standard LE signed PayloadData decoder for the NEAR fraud guard.
//! Official spec: pyth-network/pyth-lazer-public/sdk/rust/protocol/src/payload/standard.rs
//! The caller MUST verify the outer Solana Ed25519 signature under the pinned
//! Pyth signer key before using any decoded field for a price policy.
use near_sdk::serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const PAYLOAD_MAGIC: u32 = 2_479_346_549;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(crate="near_sdk::serde",rename_all="camelCase")]
pub struct BtcUsdSignedPoint {
    pub feed_id: u32,
    pub channel_id: u8,
    pub publish_time_us: String,
    pub feed_update_time_us: String,
    pub raw_price: String,
    pub exponent: i16,
    pub confidence_mantissa: String,
    pub price_e8: String,
    pub confidence_bps: String,
    pub signed_payload_sha256_hex: String,
}

struct Reader<'a> { bytes:&'a [u8], pos:usize }
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8])->Self{Self{bytes,pos:0}}
    fn take(&mut self,n:usize)->Option<&'a [u8]>{
        let end=self.pos.checked_add(n)?;
        let part=self.bytes.get(self.pos..end)?;
        self.pos=end;
        Some(part)
    }
    fn u8(&mut self)->Option<u8>{Some(*self.take(1)?.first()?)}
    fn u16(&mut self)->Option<u16>{Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))}
    fn i16(&mut self)->Option<i16>{Some(i16::from_le_bytes(self.take(2)?.try_into().ok()?))}
    fn u32(&mut self)->Option<u32>{Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))}
    fn u64(&mut self)->Option<u64>{Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))}
    fn i64(&mut self)->Option<i64>{Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))}
    fn optional_i64(&mut self)->Option<Option<i64>>{
        let value=self.i64()?;
        Some(if value==0{None}else{Some(value)})
    }
    fn optional_u64(&mut self)->Option<Option<u64>>{
        match self.u8()?{0=>Some(None),1=>Some(Some(self.u64()?)),_=>None}
    }
    fn optional_rate(&mut self)->Option<()> {
        match self.u8()?{0=>Some(()),1=>{self.i64()?;Some(())},_=>None}
    }
}

pub fn parse_btc_usd_signed_price(payload:&[u8])->Option<BtcUsdSignedPoint>{
    if payload.len()<14 || payload.len()>8192{return None;}
    let mut r=Reader::new(payload);
    if r.u32()?!=PAYLOAD_MAGIC{return None;}
    let timestamp_us=r.u64()?;
    let channel_id=r.u8()?;
    if !(1..=4).contains(&channel_id){return None;}
    let num_feeds=r.u8()?;
    if num_feeds==0||num_feeds>32{return None;}
    let mut seen_feeds=BTreeSet::new();
    let mut chosen=None;
    for _ in 0..num_feeds {
        let feed_id=r.u32()?;
        let prop_count=r.u8()?;
        if prop_count==0||prop_count>13||!seen_feeds.insert(feed_id){return None;}
        let mut price=None;
        let mut expo=None;
        let mut confidence=None;
        let mut feed_update=None;
        let mut seen_properties=0u16;
        for _ in 0..prop_count {
            let tag=r.u8()?;
            if tag>12 || seen_properties & (1u16<<tag)!=0{return None;}
            seen_properties|=1u16<<tag;
            match tag {
                0=>price=r.optional_i64()?,
                1|2|10|11=>{r.optional_i64()?;},
                3=>{r.u16()?;},
                4=>expo=Some(r.i16()?),
                5=>confidence=r.optional_i64()?,
                6=>{r.optional_rate()?;},
                7|8=>{r.optional_u64()?;},
                9=>{if !(0..=4).contains(&r.i16()?) {return None;}},
                12=>feed_update=r.optional_u64()?,
                _=>return None,
            }
        }
        if feed_id==1 {
            let p=price?;
            let e=expo?;
            let conf=confidence?;
            let last_update=feed_update?;
            if p<=0||conf<0||!(-18..=12).contains(&e)||last_update>timestamp_us{return None;}
            let raw=p as u128;
            let power=e as i32+8;
            let price_e8=if power>=0 {
                raw.checked_mul(10u128.checked_pow(power as u32)?)?
            }else{
                let den=10u128.checked_pow((-power) as u32)?;
                raw.checked_add(den/2)?.checked_div(den)?
            };
            if price_e8==0||price_e8>u64::MAX as u128{return None;}
            let cbps=(conf as u128).checked_mul(10_000)?.checked_add(raw-1)?.checked_div(raw)?;
            if cbps>u64::MAX as u128{return None;}
            chosen=Some(BtcUsdSignedPoint{
                feed_id,channel_id,publish_time_us:timestamp_us.to_string(),
                feed_update_time_us:last_update.to_string(),raw_price:p.to_string(),
                exponent:e,confidence_mantissa:conf.to_string(),price_e8:price_e8.to_string(),
                confidence_bps:cbps.to_string(),signed_payload_sha256_hex:hex::encode(near_sdk::env::sha256(payload)),
            });
        }
    }
    if r.pos!=payload.len(){return None;}
    chosen
}
