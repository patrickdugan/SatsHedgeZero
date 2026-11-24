/**
 * SHZ-CHANNEL-01: multi-counterparty CLOSEOUT routing, not transfer of DLC ownership.
 * This computes a deterministic proposal. A separate Bitcoin/Lightning adapter MUST
 * prove every bilateral exit or preauthorization before any collateral is released.
 */
import { createHash } from 'node:crypto';

const sha = v => createHash('sha256').update(v).digest('hex');
const positive = (value,label) => {
  if (!/^(0|[1-9][0-9]*)$/.test(String(value))) throw new Error(`${label}: unsigned integer required`);
  const n=BigInt(value); if(n<=0n || n>21000000n*100000000n) throw new Error(`${label}: positive Bitcoin amount required`);
  return n;
};
const nonnegative=(v,label)=>v===0 || v==='0' ? 0n : positive(v,label);
function roundSignedHalfAway(num,den) {
  if (den<=0n) throw new Error('invalid denominator');
  return (num<0n?-1n:1n)*(( (num<0n?-num:num) +den/2n)/den);
}
function add(map,k,value) {map.set(k,(map.get(k)??0n)+value);}
/** Exact inverse PnL in sats, rounded once per bilateral contract. */
export function inversePnlSats(notionalUsd,entryUsd,markUsd) {
  const N=positive(notionalUsd,'USD notional');
  const P0=positive(entryUsd,'entry USD');
  const P=positive(markUsd,'mark USD');
  return roundSignedHalfAway(N*100000000n*(P-P0),P*P0);
}
function validHex(h,n=64){return typeof h==='string' && new RegExp(`^[a-f0-9]{${n}}$`).test(h)}
/** Calculate liability and matched exposure, retaining the original bilateral edges. */
export function netBilateralTrades(trades,markUsd) {
  const mark=positive(markUsd,'clearing mark');
  const exposures=new Map(), pnl=new Map(), margin=new Map(), ids=new Set(), obligations=[];
  if (!Array.isArray(trades)||trades.length===0||trades.length>64) throw new Error('invalid trade count');
  for(const t of trades) {
    if(!t.id||ids.has(t.id)||!t.long||!t.short||t.long===t.short) throw new Error('duplicate or invalid bilateral trade');
    ids.add(t.id);
    if (!validHex(t.fundingTxid)||!Number.isInteger(t.fundingVout)||t.fundingVout<0) throw new Error('unbound funding outpoint');
    const N=positive(t.notionalUsd,'notional USD');
    const L=positive(t.longMarginSats,'long margin');
    const S=positive(t.shortMarginSats,'short margin');
    const gain=inversePnlSats(N,t.entryUsd,mark);
    if (gain>S || -gain>L) throw new Error('insufficient bilateral loss collateral');
    add(exposures,t.long,N);add(exposures,t.short,-N);
    add(pnl,t.long,gain);add(pnl,t.short,-gain);
    add(margin,t.long,L);add(margin,t.short,S);
    obligations.push({tradeId:t.id, from:gain<0n?t.long:t.short,
      to:gain<0n?t.short:t.long, sats:(gain<0n?-gain:gain).toString()});
  }
  if ([...pnl.values()].reduce((a,b)=>a+b,0n)!==0n) throw new Error('PnL conservation failed');
  const parties=[...margin.keys()].sort().map(p=>{
    const m=margin.get(p),profit=pnl.get(p)||0n,receivable=m+profit;
    if(receivable<0n) throw new Error(`insufficient account backing for ${p}`);
    return {party:p,deltaUsd:(exposures.get(p)||0n).toString(),postedMarginSats:m.toString(),
      realizedPnlSats:profit.toString(),grossPayoutSats:receivable.toString()};
  });
  return {markUsd:mark.toString(), allPartiesFlat:parties.every(p=>p.deltaUsd==='0'),
    parties, obligations, bitcoinSettlementEnforced:false};
}
/** Integer max-flow over explicitly permissioned vault-to-vault / vault-to-beneficiary edges. */
export function solvePermittedFunding({parties,vaults,routes}) {
  if(!Array.isArray(vaults)||!Array.isArray(routes)||vaults.length>64||routes.length>512) throw new Error('invalid funding graph');
  const balances=new Map(parties.map(p=>[p.party,BigInt(p.realizedPnlSats)]));
  const loss=new Map([...balances].filter(([,v])=>v<0n).map(([k,v])=>[k,-v]));
  const demand=new Map([...balances].filter(([,v])=>v>0n));
  const vaultIndex=new Map();let totalSupply=new Map();
  for(const v of vaults){
    if(!v.id||vaultIndex.has(v.id)||!balances.has(v.owner)||!v.nettingSetId) throw new Error('invalid vault identity or domain');
    const funded=nonnegative(v.fundedSats,'vault funds'),reserve=nonnegative(v.protectedSats,'protected reserve');
    if(reserve>funded) throw new Error('vault under reserve');
    vaultIndex.set(v.id,v);add(totalSupply,v.owner,funded-reserve);
  }
  for(const [owner,owed] of loss) if((totalSupply.get(owner)||0n)<owed) throw new Error(`unfunded loss owner ${owner}`);
  const vertices=new Set(['@src','@sink']);
  for(const v of vaults) vertices.add('v:'+v.id);
  for(const party of demand.keys()) vertices.add('p:'+party);
  const cap=new Map(); const flow=new Map(); const authorized=new Set();
  const edge=(a,b,c)=>{
    if(c<0n)throw new Error('negative capacity');
    const k=a+'\u0000'+b, rev=b+'\u0000'+a;
    if(authorized.has(k))throw new Error('duplicate funding edge');
    authorized.add(k);
    if(!cap.has(k)){cap.set(k,0n);flow.set(k,0n)}
    cap.set(k,cap.get(k)+c);
    if(!cap.has(rev)){cap.set(rev,0n);flow.set(rev,0n)}
  };
  // Source capacity is bounded by each owner's realized loss and apportioned
  // deterministically across their vaults, avoiding double-counted collateral.
  for(const [owner,owed] of loss) {
    let remaining=owed;
    for(const v of [...vaults].filter(v=>v.owner===owner).sort((a,b)=>a.id.localeCompare(b.id))){
      const usable=nonnegative(v.fundedSats,'funded')-nonnegative(v.protectedSats,'reserve');
      const portion=remaining<usable?remaining:usable;
      edge('@src','v:'+v.id,portion);remaining-=portion;
    }
    if(remaining!==0n)throw new Error('unfunded realized loss');
  }
  for(const [party,value] of demand) edge('p:'+party,'@sink',value);
  for(const r of routes){
    const from=vaultIndex.get(r.fromVaultId);
    if(!from)throw new Error('unknown source vault');
    const dest=r.toVaultId?'v:'+r.toVaultId:'p:'+r.toParty;
    if(!vertices.has(dest))throw new Error('unknown beneficiary');
    if(r.toVaultId && vaultIndex.get(r.toVaultId).nettingSetId!==from.nettingSetId) throw new Error('cross-domain route');
    if(!r.policyDigest||!validHex(r.policyDigest)) throw new Error('unbound route authorization policy');
    edge('v:'+r.fromVaultId,dest,nonnegative(r.capacitySats,'route capacity'));
  }
  const adjacency=new Map([...vertices].map(x=>[x,[]]));
  for (const k of cap.keys()){const [a,b]=k.split('\u0000'); if(cap.get(k)>0n){adjacency.get(a).push(b);adjacency.get(b).push(a)}}
  for(const l of adjacency.values())l.sort();
  let sent=0n; const paths=[];
  while(true){
    const parent=new Map([['@src',null]]),queue=['@src'];
    for(let qi=0;qi<queue.length&&!parent.has('@sink');qi++){
      const a=queue[qi];for(const b of adjacency.get(a)||[]){
        if(!parent.has(b)&&cap.get(a+'\u0000'+b)-flow.get(a+'\u0000'+b)>0n){parent.set(b,a);queue.push(b)}
      }
    }
    if(!parent.has('@sink'))break;
    const nodes=['@sink'];let delta=null;
    while(nodes[0]!=='@src'){
      const b=nodes[0],a=parent.get(b),rem=cap.get(a+'\u0000'+b)-flow.get(a+'\u0000'+b);
      delta=delta===null||rem<delta?rem:delta;nodes.unshift(a);
    }
    for(let i=1;i<nodes.length;i++){
      const a=nodes[i-1],b=nodes[i];const ab=a+'\u0000'+b,ba=b+'\u0000'+a;
      flow.set(ab,flow.get(ab)+delta);flow.set(ba,flow.get(ba)-delta);
    }
    sent+=delta;paths.push({nodes,sats:delta.toString()});
  }
  const required=[...demand.values()].reduce((a,b)=>a+b,0n);
  return {feasible:sent===required,requiredSats:required.toString(),routedSats:sent.toString(),
    shortfallSats:(required-sent).toString(),paths,authorizationVerified:false,spendEnforced:false};
}
export function buildCloseoutProposal({routeId,markUsd,oracleImport,trades,vaults,routes,channelHops=[],currentHeight}) {
  if(!routeId||!Number.isSafeInteger(currentHeight)||currentHeight<0)throw new Error('invalid clearing route or height');
  if(!oracleImport||oracleImport.priceE8!== (BigInt(markUsd)*100000000n).toString() || !oracleImport.receiptHash) throw new Error('unbound oracle mark');
  const accounting=netBilateralTrades(trades,markUsd);
  const funding=solvePermittedFunding({parties:accounting.parties,vaults,routes});
  const hopIds=new Set();
  let previousExpiry=null;
  for(const hop of channelHops){
    if(!hop.channelId||hopIds.has(hop.channelId)||!hop.commitmentTxid||!validHex(hop.commitmentTxid)) throw new Error('invalid channel commitment');
    hopIds.add(hop.channelId);
    if(!Number.isSafeInteger(hop.timeoutHeight)||hop.timeoutHeight<=currentHeight)throw new Error('expired channel lock');
    if(previousExpiry!==null&&previousExpiry-hop.timeoutHeight<6)throw new Error('unsafe HTLC timeout ladder');
    previousExpiry=hop.timeoutHeight;
    if(!['interactive-bilateral','mnr02-0x83-at-maturity'].includes(hop.authorizationMode))throw new Error('unrecognized channel authorization');
    if(hop.originalPeerOffline && hop.authorizationMode!=='mnr02-0x83-at-maturity')throw new Error('offline counterparty needs origination preauthorization');
    if(hop.originalPeerOffline&& (!hop.preauthorizationPackageDigest||!validHex(hop.preauthorizationPackageDigest))) throw new Error('missing MNR02 preauthorization commitment');
  }
  const core={routeId,markUsd:String(markUsd),oracleReceiptHash:oracleImport.receiptHash,
    trades:trades.map(t=>({id:t.id,fundingTxid:t.fundingTxid,fundingVout:t.fundingVout})),
    payout:accounting.parties,routes,channelHops};
  return {routeId,proposalHash:sha(Buffer.from(JSON.stringify(core))),accounting,funding,
    channelHops:channelHops.map(h=>({...h})),
    status:'PROPOSED_ONLY', requiredProofs:[
      'independently-verified-Pyth-source', 'NEAR-state-finality-or-fallback',
      'complete-bilateral-CET-and-recovery-signatures',
      'per-channel-signed-commitments-and-revocations',
      'HTLC/PTLC-success-and-penalty-exit-scripts',
      'Bitcoin-UTXO-and-sighash-enforcement','independent-routing-journal-head'
    ],
    readyToReleaseCollateral:false,
    note:'Offsets close against new counterparties. Bilateral DLC ownership stays unchanged until authorized settlement.'};
}
