//! SHZ adaptation of the exact pinned TL orderbook throughput input.
//! Run with a generated TL TSV, mode and shard count. Pre-sign outside timing.
//! Virtual arrivals and eligibility delays are NOT real network latency.
use shz_dex::{OrderSide,routing::*};
use shz_dlc::{Bip340Signature,BtcOutPoint};
use std::{fs,time::Instant,collections::BTreeMap};
const NOW:u64=1_000_000;
const ACCOUNT_CAP_SATS:u64=1_000_000_000_000;
// Route consecutive maker/taker ID pairs together in crossing mode.
// Plain id % shards segregates even makers and odd takers at four shards.
fn shard_for(id:u64,shards:u32)->u32{(((id-1)/2)%u64::from(shards)+1)as u32}
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
fn sk(n:u8)->[u8;32]{[n;32]}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn decimal(s:&str,scale:u32)->u64{
 let (a,b)=s.split_once('.').expect("decimal");
 assert_eq!(b.len(),scale as usize);a.parse::<u64>().unwrap()*10u64.pow(scale)+b.parse::<u64>().unwrap()
}
fn peak_rss()->Option<u64>{let s=fs::read_to_string("/proc/self/status").ok()?;s.lines().find(|l|l.starts_with("VmHWM:"))?.split_whitespace().nth(1)?.parse().ok()}
fn pct(v:&[f64],p:f64)->f64{v[((p*v.len()as f64)as usize).min(v.len()-1)]}
fn main(){
 let a:Vec<_>=std::env::args().collect();
 assert_eq!(a.len(),4,"usage: hft_route_bench WORKLOAD.tsv cross|deep ROUTERS");
 let mode=&a[2];assert!(mode=="cross"||mode=="deep");
 let shards:u32=a[3].parse().unwrap();assert!(matches!(shards,1|4));
 let text=fs::read_to_string(&a[1]).unwrap();
 let lines:Vec<_>=text.lines().filter(|l|!l.is_empty()).collect();let n=lines.len();
 assert!((1..=100_000).contains(&n));
 let policy=Policy{network:[99;32],epoch:1,relay_keys:[public(&sk(241)),public(&sk(242))]};
 let scope=policy.scope();let authority=sk(240);
 let plans=(1..=200u8).map(|i|Allocation::signed(scope,&sk(i),&authority,channel(i),ACCOUNT_CAP_SATS,
 (1..=shards).map(|router|Share{router,sats:ACCOUNT_CAP_SATS/u64::from(shards)}).collect()).unwrap()).collect();
 let registry=Registry::new(scope,public(&authority),plans).unwrap();
 let mut routers:Vec<_>=(1..=shards).map(|i|Router::new(policy.clone(),&registry,i).unwrap()).collect();
 let ticks=std::array::from_fn(|i|RelayTick{scope,source:i as u8+1,sequence:1,publish_us:NOW,price_e8:10_000_000_000_000,report_hash:[i as u8+1;32],signature:ZERO}.signed(&sk(241+i as u8)).unwrap());
 for r in &mut routers{r.update_mark(ticks.clone(),NOW).unwrap();}
 let mut intents=Vec::with_capacity(n);
 let mut roles=vec![[0usize;2];shards as usize];
 for (j,line) in lines.iter().enumerate(){
  let f:Vec<_>=line.split('\t').collect();assert_eq!(f.len(),8);
  let id:u64=f[0].parse().unwrap();assert_eq!(id,j as u64+1);
  let session:u8=f[1].parse().unwrap();assert!((1..=200).contains(&session));
  let side=match f[3]{"BUY"=>OrderSide::Long,"SELL"=>OrderSide::Short,_=>panic!("action")};
  let cents=decimal(f[6],2);let price=(100_000i64+(cents as i64-250)*5)as u64;
  let q=decimal(f[7],3);
  let action=if (mode=="deep"&&j<n*8/10)||(mode=="cross"&&id.is_multiple_of(2)){Action::Post}else{Action::Take};
  let tier=if id.is_multiple_of(5){Tier::Priority}else{Tier::Free};
  let router=shard_for(id,shards);
  roles[(router-1)as usize][if action==Action::Post{0}else{1}]+=1;
  let intent=Intent{scope,router,channel:channel(session),owner:[0;32],sequence:id,expires_us:NOW+2_000_000,action,side,tier,quantity:q,limit_usd:price,leverage_bps:100_000,max_fee_ppm:rate_ppm(tier,action),max_fee_sats:1_000_000,cancel_target:[0;32],signature:ZERO}.signed(&sk(session)).unwrap();
  intents.push(intent);
 }
 assert!(roles.iter().all(|r|r[0]>0&&r[1]>0),"each shard needs both maker and taker intents");
 eprintln!("maker/taker inputs by router: {roles:?}");
 let mut admit=Vec::with_capacity(n);let t0=Instant::now();
 for (j,i) in intents.into_iter().enumerate(){
  let a=Instant::now();routers[i.router as usize-1].submit(i,NOW+j as u64).unwrap();admit.push(a.elapsed().as_secs_f64()*1e6);
 }
 let admit_wall=t0.elapsed().as_secs_f64();
 let mut execute=Vec::with_capacity(n);let mut fills=0usize;let mut posts=0usize;let mut rejected=0usize;
 let mut maker_fee=0u128;let mut taker_fee=0u128;let mut oracle=0u128;let mut router_fee=0u128;let mut volume=0u128;
 let mut errors:BTreeMap<String,usize>=BTreeMap::new();
 let t0=Instant::now();
 // All simulated arrivals fall inside 100 ms; 450 ms makes all orders
 // eligible while the mark is fresh. Per-router scheduler preserves due order.
 for r in &mut routers{
  loop{
   let a=Instant::now();let event=r.process_one(NOW+450_000).unwrap();
   let Some(event)=event else{break};
   match event{
    Outcome::Posted(_)=>posts+=1,
    Outcome::Filled(f)=>{fills+=1;assert_eq!(f.spec.fee_policy,shz_margin::ZeroFeePolicy::ZERO);volume+=f.spec.usd_notional as u128;maker_fee+=f.maker_fee_sats as u128;taker_fee+=f.taker_fee_sats as u128;oracle+=f.oracle_due_sats as u128;router_fee+=f.router_due_sats as u128;},
    Outcome::Rejected(e)=>{rejected+=1;*errors.entry(format!("{e:?}")).or_default()+=1;},
    Outcome::Cancelled(_)=>panic!("unexpected cancellation"),
   }
   execute.push(a.elapsed().as_secs_f64()*1e6);
  }
 }
 let execute_wall=t0.elapsed().as_secs_f64();
 assert_eq!(execute.len(),n);assert_eq!(posts+fills+rejected,n);assert_eq!(maker_fee+taker_fee,oracle+router_fee);
 for r in &routers{for i in 1..=200u8{assert!(r.balance(&channel(i)).unwrap().conserved());}}
 assert_eq!(routers.iter().map(Router::pending_fills).sum::<usize>(),fills);
 admit.sort_by(|a,b|a.total_cmp(b));execute.sort_by(|a,b|a.total_cmp(b));
 let rss=peak_rss().map_or("null".into(),|x|x.to_string());
 println!("{{\"engine\":\"shz-routing-v1\",\"mode\":\"{}\",\"orders\":{},\"router_shards\":{},\"posted\":{},\"fills\":{},\"rejected\":{},\"resting\":{},\"matched_usd\":{},\"maker_fee_sats\":{},\"taker_fee_sats\":{},\"oracle_due_sats\":{},\"router_due_sats\":{},\"admit_orders_per_sec\":{:.0},\"execute_orders_per_sec\":{:.0},\"combined_orders_per_sec\":{:.0},\"admit_p50_us\":{:.2},\"admit_p99_us\":{:.2},\"execution_p50_us\":{:.2},\"execution_p99_us\":{:.2},\"peak_rss_kb\":{},\"signing_timed\":false,\"signature_verification_timed\":true,\"network_latency_measured\":false,\"live_settlement\":false}}",
 mode,n,shards,posts,fills,rejected,routers.iter().map(Router::resting).sum::<usize>(),volume,maker_fee,taker_fee,oracle,router_fee,n as f64/admit_wall,n as f64/execute_wall,n as f64/(admit_wall+execute_wall),pct(&admit,0.5),pct(&admit,0.99),pct(&execute,0.5),pct(&execute,0.99),rss);
 eprintln!("rejections: {errors:?}");
}
