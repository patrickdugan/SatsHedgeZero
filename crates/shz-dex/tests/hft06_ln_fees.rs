use shz_dex::{OrderSide,routing::*};
use shz_dex::routing::durable::*;
use shz_dex::routing::ln_fees::*;
use shz_dlc::{Bip340Signature,BtcOutPoint,bip340_sign};
use std::{fs,path::PathBuf,sync::atomic::{AtomicU64,Ordering}};

const NOW:u64=1_000_000;
const AUTH:[u8;32]=[77;32];
const ZERO:Bip340Signature=Bip340Signature{r_x:[0;32],s:[0;32]};
type Key=[u8;32];
fn sk(n:u8)->[u8;32]{[n;32]}
fn pk(n:u8)->Key{public(&sk(n))}
fn channel(n:u8)->BtcOutPoint{BtcOutPoint{txid:[n;32],vout:0}}
fn policy()->Policy{Policy{network:[99;32],epoch:7,relay_keys:[pk(50),pk(51)]}}
fn setup(cap:u64)->(Policy,Registry){
 let p=policy();
 let plans=(1..=4).map(|n|Allocation::signed(p.scope(),&sk(n),&AUTH,channel(n),cap*2,vec![Share{router:1,sats:cap},Share{router:2,sats:cap}]).unwrap()).collect();
 let r=Registry::new(p.scope(),public(&AUTH),plans).unwrap();(p,r)
}
fn marks(p:&Policy,seq:u64,t:u64,prices:[u64;2])->[RelayTick;2]{
 std::array::from_fn(|i|RelayTick{scope:p.scope(),source:i as u8+1,sequence:seq,publish_us:t,price_e8:prices[i],report_hash:[i as u8+1;32],signature:ZERO}.signed(&sk(50+i as u8)).unwrap())
}
fn order(p:&Policy,n:u8,seq:u64,action:Action,side:OrderSide,tier:Tier,q:u64)->Intent{
 Intent{scope:p.scope(),router:1,channel:channel(n),owner:[0;32],sequence:seq,expires_us:NOW+10_000_000,action,side,tier,quantity:q,limit_usd:100_000,leverage_bps:10_000,max_fee_ppm:rate_ppm(tier,action),max_fee_sats:100_000,cancel_target:[0;32],signature:ZERO}.signed(&sk(n)).unwrap()
}
static COUNTER:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp{
 fn new()->Self{
  let p=std::env::temp_dir().join(format!("shz-hft06-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::Relaxed)));
  fs::create_dir(&p).unwrap();Self(p)
 }
 fn path(&self,n:&str)->PathBuf{self.0.join(n)}
}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn lanes()->Vec<Lane>{
 (1..=4u8).map(|n|Lane{channel:channel(n),peer:pk(70+n),monitor:pk(90+n),initial:Head{revision:0,commitment:10,state:[110+n;32]}}).collect()
}
fn recipients()->FeeRecipients{FeeRecipients{oracle:pk(110),router:pk(111)}}
fn approvals(b:&Batch)->Vec<BatchApproval>{
 b.accounts().iter().map(|a|{
  let n=a.channel.txid[0];let h=b.approval_message(&a.channel).unwrap();
  BatchApproval{channel:a.channel.clone(),signature:bip340_sign(&sk(n),&h).unwrap()}
 }).collect()
}
fn resign(d:&DurableRouter,seq:u64,disp:Disposition,a:&mut ChannelAck){
 let n=a.channel.txid[0];let h=d.ack_message(seq,disp,a).unwrap();
 a.signatures=[bip340_sign(&sk(n),&h).unwrap(),bip340_sign(&sk(70+n),&h).unwrap(),bip340_sign(&sk(90+n),&h).unwrap()];
}
fn ack(d:&DurableRouter,b:&Batch,disp:Disposition)->AckBundle{
 let mut channels=Vec::new();
 for a in b.accounts(){
  let n=a.channel.txid[0];
  let previous=d.head(&a.channel).unwrap().unwrap();let mut next=previous;next.revision+=1;
  if disp==Disposition::Commit{next.commitment+=1;next.state=[130+n+b.sequence()as u8;32];}
  let mut c=ChannelAck{channel:a.channel.clone(),previous,next,evidence:[150+n+b.sequence()as u8;32],
   fee_evidence:if disp==Disposition::Commit&&a.fee_sats>0{let mut v=[0;32];v[0]=n;v[1..9].copy_from_slice(&b.sequence().to_le_bytes());v[31]=180;v}else{[0;32]},signatures:[ZERO;3]};
  resign(d,b.sequence(),disp,&mut c);channels.push(c);
 }
 AckBundle{sequence:b.sequence(),batch:b.digest(),disposition:disp,channels}
}
fn post_take(d:&mut DurableRouter,p:&Policy,at:u64,seq:u64,post:u64,take:u64){
 d.submit(order(p,1,seq,Action::Post,OrderSide::Short,Tier::Priority,post),at).unwrap();
 assert!(matches!(d.process_one(at).unwrap().unwrap(),Outcome::Posted(_)));
 d.submit(order(p,2,seq,Action::Take,OrderSide::Long,Tier::Priority,take),at).unwrap();
 assert!(matches!(d.process_one(at+100_000).unwrap().unwrap(),Outcome::Filled(_)));
}

/// Three HFT-05 batches: 1 committed, 2 fenced-aborted, 3 committed. Synthetic funds only.
struct Fx{_t:Temp,d:DurableRouter,b:[Batch;3],a:[AckBundle;3]}
fn fixture()->Fx{
 let t=Temp::new();let (p,g)=setup(100_000_000);
 let mut d=DurableRouter::create(&t.path("router.wal"),p.clone(),&g,1,Engine::Both,lanes(),recipients()).unwrap();
 d.update_mark(marks(&p,1,NOW,[10_000_000_000_000;2]),NOW).unwrap();
 post_take(&mut d,&p,NOW,1,1000,1000);
 d.process_one(NOW+200_000).unwrap();let b1=d.seal_fill_batch().unwrap().unwrap();
 d.prepare(1,approvals(&b1)).unwrap();let a1=ack(&d,&b1,Disposition::Commit);assert!(d.resolve(a1.clone()).unwrap());
 post_take(&mut d,&p,NOW+200_000,2,1000,100);
 d.process_one(NOW+400_000).unwrap();let b2=d.seal_fill_batch().unwrap().unwrap();
 d.prepare(2,approvals(&b2)).unwrap();let a2=ack(&d,&b2,Disposition::FencedAbort);assert!(d.resolve(a2.clone()).unwrap());
 post_take(&mut d,&p,NOW+600_000,3,1000,1000);
 d.process_one(NOW+800_000).unwrap();let b3=d.seal_fill_batch().unwrap().unwrap();
 d.prepare(3,approvals(&b3)).unwrap();let a3=ack(&d,&b3,Disposition::Commit);assert!(d.resolve(a3.clone()).unwrap());
 assert_eq!(d.fee_totals().unwrap(),(308,132));
 Fx{_t:t,d,b:[b1,b2,b3],a:[a1,a2,a3]}
}
const OPS:[(u8,u32);3]=[(120,3),(121,1),(122,1)];
fn rpolicy()->RecipientPolicy{
 RecipientPolicy{version:1,oracle_operators:OPS.iter().map(|(n,w)|(pk(*n),*w)).collect(),upkeep:(pk(123),1000),router:pk(124)}
}
fn group()->GroupCommit{GroupCommit{max_obligations:1000,max_delay_us:1_000_000}}
fn receipt(recipient:u8,msat:u64,preimage:u8,refs:Vec<BatchRef>)->FeeReceipt{
 let pre=[preimage;32];
 FeeReceipt{recipient:pk(recipient),amount_msat:msat,payment_hash:MockAdapter::payment_hash(&pre),preimage:pre,batch_refs:refs,signature:ZERO}.signed(&sk(recipient)).unwrap()
}
fn sum(l:&FeeLedger,keys:&[Key])->RecipientTotals{
 let mut t=RecipientTotals::default();
 for k in keys{let x=l.totals(k);t.accrued+=x.accrued;t.reversed+=x.reversed;t.committed+=x.committed;t.collected+=x.collected;t.outstanding+=x.outstanding}
 t
}
fn all_keys()->Vec<Key>{vec![pk(120),pk(121),pk(122),pk(123),pk(124)]}

#[test]fn split_conserves_with_largest_remainder_and_key_order_ties(){
 let p=rpolicy();p.validate().unwrap();
 let s=p.split(154,66);
 assert_eq!(s.upkeep,(pk(123),15));
 // 139 over weights 3:1:1 -> 83.4, 27.8, 27.8: floors 83,27,27 + two leftovers to the largest remainders.
 assert_eq!(s.operators,vec![(pk(120),83),(pk(121),28),(pk(122),28)]);
 assert_eq!(s.router,(pk(124),66));
 for oracle in 0..400u64{for router in [0u64,1,66]{
  let s=p.split(oracle,router);
  let total=s.upkeep.1+s.operators.iter().map(|o|o.1).sum::<u64>()+s.router.1;
  assert_eq!(total,oracle+router);assert_eq!(s.shares().values().sum::<u64>(),oracle+router);
 }}
 // equal remainders: lower key wins the odd sat
 let tie=RecipientPolicy{version:1,oracle_operators:vec![(pk(9),1),(pk(8),1)],upkeep:(pk(123),0),router:pk(124)};
 let lo=pk(8).min(pk(9));let hi=pk(8).max(pk(9));
 let s=tie.split(5,0);let get=|k:Key|s.operators.iter().find(|o|o.0==k).unwrap().1;
 assert_eq!((get(lo),get(hi)),(3,2));
 let mut bad=rpolicy();bad.oracle_operators.push((pk(120),1));assert!(bad.validate().is_err());
 let mut bad=rpolicy();bad.upkeep.1=10_001;assert!(bad.validate().is_err());
 assert_eq!(DLC_SETTLEMENT_FEE_SATS,0);
}

#[test]fn accrued_only_is_not_revenue_and_never_instructed(){
 let f=fixture();
 let mut l=FeeLedger::in_memory(1,rpolicy(),group()).unwrap();
 for b in &f.b{assert!(l.observe_batch(b).unwrap());assert!(!l.observe_batch(b).unwrap());}
 for b in &f.b{for leg in b.legs(){assert_eq!(leg.spec.fee_policy,shz_margin::ZeroFeePolicy::ZERO)}}
 assert_eq!(l.batch_state(1),Some(BatchState::Accrued));
 let t=sum(&l,&all_keys());
 assert_eq!(t.accrued,154+66+15+7+154+66);assert_eq!((t.committed,t.collected,t.outstanding),(0,0,0));
 assert_eq!(t.unresolved(),t.accrued);
 assert!(l.poll(u64::MAX/2).unwrap().is_empty());assert_eq!(l.emissions(),0);
 // a batch that is not the router's is refused
 let mut other=FeeLedger::in_memory(2,rpolicy(),group()).unwrap();
 assert!(matches!(other.observe_batch(&f.b[0]),Err(LedgerError::BatchMismatch)));
}

#[test]fn full_economic_loop_commit_abort_receipts_instructions_and_reconcile(){
 let f=fixture();let t=Temp::new();
 let mut l=FeeLedger::create(&t.path("fees.wal"),1,rpolicy(),group()).unwrap();
 let keys=all_keys();
 for i in 0..3{l.observe_batch(&f.b[i]).unwrap();}
 // Resolutions: out of order delivery is fine, wrong bundle is not.
 let mut forged=f.a[0].clone();forged.channels[0].fee_evidence=[9;32];
 assert!(matches!(l.observe_resolution(&f.d,&forged,NOW+300_000),Err(LedgerError::BadResolution)));
 assert!(matches!(l.observe_resolution(&f.d,&f.a[0],NOW+300_000),Ok(true)));
 assert!(matches!(l.observe_resolution(&f.d,&f.a[0],NOW+300_000),Ok(false)));
 assert!(matches!(l.observe_resolution(&f.d,&f.a[1],NOW+500_000),Ok(true)));
 assert!(matches!(l.observe_resolution(&f.d,&f.a[2],NOW+900_000),Ok(true)));
 assert_eq!((l.batch_state(1),l.batch_state(2),l.batch_state(3)),(Some(BatchState::Committed),Some(BatchState::Reversed),Some(BatchState::Committed)));
 // A commit cannot be retroactively reversed in the ledger.
 let mut flipped=f.a[0].clone();flipped.disposition=Disposition::FencedAbort;
 assert!(l.observe_resolution(&f.d,&flipped,NOW).is_err());
 let t0=sum(&l,&keys);
 assert_eq!(t0.accrued,154+66+15+7+154+66);assert_eq!(t0.reversed,22);assert_eq!(t0.committed,440);
 assert_eq!((t0.collected,t0.outstanding,t0.unresolved()),(0,440,0));
 assert_eq!(l.committed_by_role(),(308,132));
 let r=l.reconcile(&f.d).unwrap();assert!(r.clean(),"{:?}",r.mismatches);
 assert_eq!((r.ledger_oracle,r.ledger_router,r.router_oracle,r.router_router),(308,132,308,132));
 // Receipts. Router recipient: 132 committed over batches 1 and 3.
 let mut ad=MockAdapter::new();
 let first=receipt(124,66_000,1,vec![(1,1)]);
 assert!(l.receive_receipt(&ad,&first).unwrap());
 assert_eq!(l.totals(&pk(124)),RecipientTotals{accrued:66+7+66,reversed:7,committed:132,collected:66,outstanding:66});
 // the reversed batch's router share (7) is in `reversed`, never in committed
 // duplicate identical receipt: idempotent, even with the adapter down
 ad.set_connected(false);
 assert!(!l.receive_receipt(&ad,&first).unwrap());
 // conflicting duplicate
 let mut conflicting=first.clone();conflicting.amount_msat=1_000;
 assert!(matches!(l.receive_receipt(&ad,&conflicting),Err(LedgerError::ConflictingReceipt)));
 // disconnected adapter: obligations stay outstanding
 let second=receipt(124,66_000,2,vec![(1,3)]);
 assert!(matches!(l.receive_receipt(&ad,&second),Err(LedgerError::Adapter(AdapterError::Disconnected))));
 assert_eq!(l.totals(&pk(124)).outstanding,66);
 ad.set_connected(true);
 // overpayment beyond batch 3's outstanding, beyond the recipient's total, and for a reversed batch
 let over=receipt(124,67_000,3,vec![(1,3)]);
 assert!(matches!(l.receive_receipt(&ad,&over),Err(LedgerError::Overpayment)));
 let over_all=receipt(124,67_000,4,vec![(1,1),(1,3)]);
 assert!(matches!(l.receive_receipt(&ad,&over_all),Err(LedgerError::Overpayment)));
 let on_reversed=receipt(124,1_000,5,vec![(1,2)]);
 assert!(matches!(l.receive_receipt(&ad,&on_reversed),Err(LedgerError::BadReceipt)));
 let wrong_router=receipt(124,1_000,6,vec![(2,1)]);
 assert!(matches!(l.receive_receipt(&ad,&wrong_router),Err(LedgerError::BadReceipt)));
 let fractional=receipt(124,1_500,7,vec![(1,3)]);
 assert!(matches!(l.receive_receipt(&ad,&fractional),Err(LedgerError::BadReceipt)));
 // invalid proofs: wrong preimage, wrong signer
 let mut bad_pre=receipt(124,1_000,8,vec![(1,3)]);bad_pre.preimage=[0xee;32];
 assert!(matches!(l.receive_receipt(&ad,&bad_pre),Err(LedgerError::Adapter(AdapterError::Invalid))));
 let mut bad_sig=receipt(124,1_000,9,vec![(1,3)]);bad_sig.signature=receipt(120,1_000,9,vec![(1,3)]).signature;
 assert!(matches!(l.receive_receipt(&ad,&bad_sig),Err(LedgerError::Adapter(AdapterError::Invalid))));
 assert_eq!(l.totals(&pk(124)).collected,66);
 // a receipt for an operator spanning batches 1 and 3, exact outstanding
 let op0=l.totals(&pk(120));assert_eq!(op0.committed,2*83);
 let both=receipt(120,op0.committed*1000,10,vec![(1,1),(1,3)]);assert!(l.receive_receipt(&ad,&both).unwrap());
 assert_eq!(l.totals(&pk(120)),RecipientTotals{accrued:83*2+op0_batch2_share(),reversed:op0_batch2_share(),committed:166,collected:166,outstanding:0});
 // Instructions: nothing before the bound, then only committed outstanding amounts.
 assert!(l.poll(NOW+900_001).unwrap().is_empty());
 let ins=l.poll(NOW+900_000+1_000_000).unwrap();
 let total_ins:u64=ins.iter().map(|i|i.amount_sats).sum();
 let now_sum=sum(&l,&keys);
 assert_eq!(total_ins,now_sum.outstanding);assert_eq!(now_sum.outstanding,440-66-166);
 assert!(ins.iter().all(|i|i.batch_refs.iter().all(|r|r.1!=2)));
 assert!(ins.iter().all(|i|i.recipient!=pk(120)),"fully collected recipient is not re-instructed");
 assert!(l.poll(NOW+9_000_000).unwrap().is_empty());assert_eq!(l.emissions(),1);
 // Conservation across recipients per role.
 let ops:u64=[120,121,122].iter().map(|n|l.totals(&pk(*n)).committed).sum();
 assert_eq!(ops+l.totals(&pk(123)).committed,308);assert_eq!(l.totals(&pk(124)).committed,132);
 // Reopen replays to the identical state.
 let snapshot=l.all_totals();let emitted=l.emission(0).unwrap().to_vec();drop(l);
 let l=FeeLedger::open(&t.path("fees.wal"),1,rpolicy(),group()).unwrap();
 assert_eq!(l.all_totals(),snapshot);assert_eq!(l.emission(0).unwrap(),emitted.as_slice());
 assert!(l.reconcile(&f.d).unwrap().clean());
}
fn op0_batch2_share()->u64{
 // batch 2 oracle due is 15: upkeep 1, remainder 14 over weights 3:1:1 -> 8.4,2.8,2.8 -> 8,3,3
 rpolicy().split(15,7).operators[0].1
}

#[test]fn group_commit_count_bound_triggers_without_delay(){
 let f=fixture();
 let mut l=FeeLedger::in_memory(1,rpolicy(),GroupCommit{max_obligations:6,max_delay_us:u64::MAX}).unwrap();
 l.observe_batch(&f.b[0]).unwrap();l.observe_resolution(&f.d,&f.a[0],NOW).unwrap();
 // one committed batch with 5 obligations (3 operators, upkeep, router): below the bound
 assert!(l.poll(NOW+1).unwrap().is_empty());
 l.observe_batch(&f.b[1]).unwrap();l.observe_resolution(&f.d,&f.a[1],NOW).unwrap();
 assert!(l.poll(NOW+2).unwrap().is_empty());
 l.observe_batch(&f.b[2]).unwrap();l.observe_resolution(&f.d,&f.a[2],NOW).unwrap();
 let ins=l.poll(NOW+3).unwrap();
 assert_eq!(ins.len(),5);assert!(ins.iter().all(|i|i.batch_refs==vec![(1,1),(1,3)]));
 assert_eq!(ins.iter().map(|i|i.amount_sats).sum::<u64>(),440);
}

#[test]fn timeouts_never_change_state_or_release_collateral(){
 let f=fixture();
 let mut l=FeeLedger::in_memory(1,rpolicy(),GroupCommit{max_obligations:1000,max_delay_us:10}).unwrap();
 let balances:Vec<_>=(1..=4).map(|n|f.d.balance(&channel(n)).unwrap().unwrap()).collect();
 l.observe_batch(&f.b[0]).unwrap();
 let before=l.all_totals();
 // accrued-only obligations: no amount of waiting changes anything
 for t in [NOW+1_000,NOW+10_000_000,u64::MAX/4]{assert!(l.poll(t).unwrap().is_empty())}
 assert_eq!(l.all_totals(),before);assert_eq!(l.batch_state(1),Some(BatchState::Accrued));assert_eq!(l.emissions(),0);
 l.observe_resolution(&f.d,&f.a[0],NOW).unwrap();
 let committed=l.all_totals();
 // adapter is down for the whole interval; time passes; only an instruction emission may occur
 let mut ad=MockAdapter::new();ad.set_connected(false);
 assert!(matches!(l.receive_receipt(&ad,&receipt(124,1_000,1,vec![(1,1)])),Err(LedgerError::Adapter(AdapterError::Disconnected))));
 assert!(matches!(ad.commitment_status(&channel(1)),Err(AdapterError::Disconnected)));
 assert!(l.check_channels(&ad,&f.b[0]).iter().all(|c|c.1==Err(AdapterError::Disconnected)));
 let ins=l.poll(NOW+5_000_000_000).unwrap();assert!(!ins.is_empty());
 assert_eq!(l.all_totals(),committed,"instruction emission does not change any quantity");
 assert_eq!(sum(&l,&all_keys()).outstanding,220);
 // the router's collateral state is untouched by anything the ledger does
 let after:Vec<_>=(1..=4).map(|n|f.d.balance(&channel(n)).unwrap().unwrap()).collect();
 assert_eq!(balances,after);
 ad.set_connected(true);ad.set_channel(&channel(1),ChannelStatus::Open{commitment:11});
 assert_eq!(l.check_channels(&ad,&f.b[0])[0].1,Ok(ChannelStatus::Open{commitment:11}));
 assert!(l.check_channels(&ad,&f.b[0]).iter().any(|c|c.1==Err(AdapterError::Unknown)));
}

#[test]fn journal_replay_torn_tail_crash_cut_and_hash_chain(){
 let f=fixture();let t=Temp::new();let path=t.path("fees.wal");
 let mut l=FeeLedger::create(&path,1,rpolicy(),group()).unwrap();
 assert!(matches!(FeeLedger::open(&path,1,rpolicy(),group()),Err(LedgerError::Locked)));
 l.observe_batch(&f.b[0]).unwrap();l.observe_batch(&f.b[1]).unwrap();
 // Crash after the commit event is fsynced but before it is applied.
 let evidence=f.a[0].channels.iter().filter(|c|c.fee_evidence!=[0;32]).map(|c|(c.channel.clone(),c.fee_evidence)).collect();
 l.append_without_apply(&LedgerEvent::Commit{sequence:1,digest:f.b[0].digest(),fee_evidence:evidence,at_us:NOW}).unwrap();
 assert_eq!(l.batch_state(1),Some(BatchState::Accrued));
 drop(l);
 let mut l=FeeLedger::open(&path,1,rpolicy(),group()).unwrap();
 assert_eq!(l.batch_state(1),Some(BatchState::Committed));
 // identical re-application of the same resolution is a no-op and writes nothing
 let size=fs::metadata(&path).unwrap().len();
 assert!(!l.observe_resolution(&f.d,&f.a[0],NOW).unwrap());assert_eq!(fs::metadata(&path).unwrap().len(),size);
 l.observe_resolution(&f.d,&f.a[1],NOW).unwrap();
 let snapshot=l.all_totals();drop(l);
 let bytes=fs::read(&path).unwrap();
 // exact replay
 assert_eq!(FeeLedger::open(&path,1,rpolicy(),group()).unwrap().all_totals(),snapshot);
 // torn tails at several cut points fail closed
 for cut in [3usize,12,40,bytes.len()-1,bytes.len()-33]{
  let q=t.path(&format!("torn-{cut}"));fs::write(&q,&bytes[..cut]).unwrap();
  assert!(matches!(FeeLedger::open(&q,1,rpolicy(),group()),Err(LedgerError::Corrupt)),"cut {cut}");
 }
 // altered byte in the middle breaks the hash chain
 let mut bad=bytes.clone();let mid=bad.len()/2;bad[mid]^=1;let q=t.path("flip");fs::write(&q,&bad).unwrap();
 assert!(matches!(FeeLedger::open(&q,1,rpolicy(),group()),Err(LedgerError::Corrupt)));
 // configuration substitution is refused
 let mut other=rpolicy();other.version=2;
 assert!(matches!(FeeLedger::open(&path,1,other,group()),Err(LedgerError::Config)));
 assert!(matches!(FeeLedger::open(&path,1,rpolicy(),GroupCommit{max_obligations:1,max_delay_us:1}),Err(LedgerError::Config)));
}

#[test]fn reconcile_reports_missing_and_mismatched_state(){
 let f=fixture();
 let mut l=FeeLedger::in_memory(1,rpolicy(),group()).unwrap();
 // only batch 1 is committed in the ledger; the router has committed batch 3 as well
 l.observe_batch(&f.b[0]).unwrap();l.observe_resolution(&f.d,&f.a[0],NOW).unwrap();
 let r=l.reconcile(&f.d).unwrap();assert!(!r.clean());
 assert!(r.mismatches.contains(&Mismatch::OracleTotal{ledger:154,router:308}));
 assert!(r.mismatches.contains(&Mismatch::RouterTotal{ledger:66,router:132}));
 assert!(r.mismatches.contains(&Mismatch::MissingInLedger{sequence:2}));
 assert!(r.mismatches.contains(&Mismatch::MissingInLedger{sequence:3}));
 // an accrued batch whose router phase is already resolved is flagged as a phase mismatch
 l.observe_batch(&f.b[2]).unwrap();
 let r=l.reconcile(&f.d).unwrap();
 assert!(r.mismatches.iter().any(|m|matches!(m,Mismatch::Phase{sequence:3,ledger:BatchState::Accrued,router:Some(Phase::Committed)})));
 // a reversal observed for a committed batch cannot be recorded
 let mut wrong=f.a[2].clone();wrong.disposition=Disposition::FencedAbort;
 assert!(l.observe_resolution(&f.d,&wrong,NOW).is_err());
}
