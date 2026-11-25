//! SHZ adaptation of the exact pinned TL orderbook throughput input.
//! Run with a generated TL TSV, mode and shard count. Pre-sign outside timing.
//! Virtual arrivals and eligibility delays are NOT real network latency.
use shz_dex::{OrderSide,routing::*};
use shz_dlc::{Bip340Signature,BtcOutPoint};
use std::{fs,time::Instant,thread};
use sha2::{Sha256,Digest};
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
 assert_eq!(a.len(),6,"usage: hft02_bench WORKLOAD.tsv cross|deep ROUTERS scan|indexed|joint|both serial|parallel");
 let engine=match a[4].as_str(){"scan"=>Engine::Scan,"indexed"=>Engine::Indexed,"joint"=>Engine::Joint,"both"=>Engine::Both,_=>panic!("engine")};
 let parallel=match a[5].as_str(){"serial"=>false,"parallel"=>true,_=>panic!("execution mode")};
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
 let mut routers:Vec<_>=(1..=shards).map(|i|Router::new_with_engine(policy.clone(),&registry,i,engine).unwrap()).collect();
 let ticks=std::array::from_fn(|i|RelayTick{scope,source:i as u8+1,sequence:1,publish_us:NOW,price_e8:10_000_000_000_000,report_hash:[i as u8+1;32],signature:ZERO}.signed(&sk(241+i as u8)).unwrap());
 for r in &mut routers{r.update_mark(ticks.clone(),NOW).unwrap();}
 let mut intents:Vec<Vec<(u64,Intent)>>=(0..shards).map(|_|Vec::new()).collect();
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
  intents[(router-1)as usize].push((NOW+j as u64,intent));
 }
 assert!(roles.iter().all(|r|r[0]>0&&r[1]>0),"each shard needs both maker and taker intents");
 eprintln!("maker/taker inputs by router: {roles:?}");

 let mut work:Vec<_>=routers.into_iter().zip(intents).collect();
 // Preserve a barrier between admission and execution in both arms.
 let t0=Instant::now();
 let mut admissions=if parallel{
  thread::scope(|s|{
   let hs:Vec<_>=work.iter_mut().map(|(r,is)|s.spawn(move||admit(r,std::mem::take(is)))).collect();
   hs.into_iter().map(|h|h.join().unwrap()).collect::<Vec<_>>()
  })
 }else{work.iter_mut().map(|(r,is)|admit(r,std::mem::take(is))).collect()};
 let admit_wall=t0.elapsed().as_secs_f64();
 let t0=Instant::now();
 let mut executed=if parallel{
  thread::scope(|s|{
   let hs:Vec<_>=work.iter_mut().map(|(r,_)|s.spawn(move||execute(r))).collect();
   hs.into_iter().map(|h|h.join().unwrap()).collect::<Vec<_>>()
  })
 }else{work.iter_mut().map(|(r,_)|execute(r)).collect()};
 let execute_wall=t0.elapsed().as_secs_f64();
 let mut admit_times=Vec::with_capacity(n);for v in &mut admissions{admit_times.append(v)}
 let mut execution_times=Vec::with_capacity(n);
 let(mut posts,mut fills,mut rejects,mut resting)=(0usize,0usize,0usize,0usize);
 let(mut mf,mut tf,mut oracle,mut router_fee,mut volume)=(0u128,0u128,0u128,0u128,0u128);
 let mut digest=Sha256::new();
 // Full ordered per-shard receipt digest and conservation outside the timer.
 for (idx,((r,_),(lat,outcomes))) in work.iter().zip(executed.iter_mut()).enumerate(){
  digest.update((idx as u64).to_le_bytes());execution_times.append(lat);
  let mut shard_fills=0;
  for o in outcomes{
   match o{
    Outcome::Posted(_)=>posts+=1,
    Outcome::Rejected(_)=>rejects+=1,
    Outcome::Filled(f)=>{
     fills+=1;shard_fills+=1;assert_eq!(f.spec.fee_policy,shz_margin::ZeroFeePolicy::ZERO);
     mf+=f.maker_fee_sats as u128;tf+=f.taker_fee_sats as u128;
     oracle+=f.oracle_due_sats as u128;router_fee+=f.router_due_sats as u128;volume+=f.spec.usd_notional as u128;
    },
    Outcome::Cancelled(_)=>panic!("unexpected cancel"),
   }
   digest.update(format!("{o:?}\n").as_bytes());
  }
  for i in 1..=200u8{let b=r.balance(&channel(i)).unwrap();assert!(b.conserved());digest.update(format!("{b:?}\n").as_bytes());}
  assert_eq!(r.pending_fills(),shard_fills);
  resting+=r.resting();
 }
 assert_eq!(admit_times.len(),n);assert_eq!(execution_times.len(),n);
 assert_eq!(posts+fills+rejects,n);assert_eq!(mf+tf,oracle+router_fee);
 admit_times.sort_by(|a,b|a.total_cmp(b));execution_times.sort_by(|a,b|a.total_cmp(b));
 let rss=peak_rss().map_or("null".into(),|x|x.to_string());
 let trace=hex::encode(digest.finalize());
 println!(concat!("{{\"engine\":\"{}\",\"schedule\":\"{}\",\"mode\":\"{}\",\"orders\":{},\"router_shards\":{},",
  "\"posted\":{},\"fills\":{},\"rejected\":{},\"resting\":{},\"matched_usd\":{},",
  "\"maker_fee_sats\":{},\"taker_fee_sats\":{},\"oracle_due_sats\":{},\"router_due_sats\":{},\"receipt_digest\":\"{}\",",
  "\"admit_orders_per_sec\":{:.0},\"execute_orders_per_sec\":{:.0},\"combined_orders_per_sec\":{:.0},",
  "\"admit_p50_us\":{:.2},\"admit_p99_us\":{:.2},\"execution_p50_us\":{:.2},\"execution_p99_us\":{:.2},",
  "\"peak_rss_kb\":{},\"signature_verification_timed\":true,\"network_latency_measured\":false,\"live_settlement\":false}}"),
  a[4],a[5],mode,n,shards,posts,fills,rejects,resting,volume,mf,tf,oracle,router_fee,trace,
  n as f64/admit_wall,n as f64/execute_wall,n as f64/(admit_wall+execute_wall),
  pct(&admit_times,0.5),pct(&admit_times,0.99),pct(&execution_times,0.5),pct(&execution_times,0.99),rss);
}
fn admit(r:&mut Router,intents:Vec<(u64,Intent)>)->Vec<f64>{
 let mut lat=Vec::with_capacity(intents.len());
 for (at,i) in intents{let t=Instant::now();r.submit(i,at).unwrap();lat.push(t.elapsed().as_secs_f64()*1e6);}
 lat
}
fn execute(r:&mut Router)->(Vec<f64>,Vec<Outcome>){
 let cap=r.pending_orders();let mut lat=Vec::with_capacity(cap);let mut outcomes=Vec::with_capacity(cap);
 loop{
  let t=Instant::now();let Some(event)=r.process_one(NOW+450_000).unwrap()else{break};
  lat.push(t.elapsed().as_secs_f64()*1e6);outcomes.push(event);
 }
 (lat,outcomes)
}
