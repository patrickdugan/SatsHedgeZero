import { createHash } from 'node:crypto';
import { verifyWithdrawalReceipt, rejectExplorerOrSimulated } from './withdrawal-receipt.mjs';
const check=(v,m)=>{if(!v)throw Error(m)};
const hex=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s)&&!/^0+$/.test(s);
const n=v=>{check(Number.isSafeInteger(v),'unsafe explorer integer');return BigInt(v)};
const u=v=>{const x=n(v);check(x>=0n,'negative unsigned explorer field');return x};
const hash=s=>createHash('sha256').update(s).digest('hex');
function outpoint(o,raw=false){
  const tx=raw?(Array.isArray(o?.txid)&&o.txid.length===32&&o.txid.every(x=>Number.isInteger(x)&&x>=0&&x<=255)?Buffer.from(o.txid).toString('hex'):null):o?.txid;
  check(hex(tx)&&Number.isInteger(o.vout)&&o.vout>=0&&o.vout<=0xffffffff,'invalid lane outpoint');return tx+':'+o.vout;
}
function one(xs,p){check(Array.isArray(xs),'missing explorer list');const m=xs.filter(p);check(m.length===1,'missing or duplicate explorer row');return m[0]}
function journal(x){const j=x?.journal;check(hex(j?.tip?.digest)&&hex(j.config_hash)&&u(j.tip.records)>0n&&u(j.next_resolution)>0n,'invalid explorer journal');return [j.config_hash,j.tip.records,j.tip.digest,j.next_resolution]}
// Actual venue explorer JSON contract. `get` is trusted read-only transport.
// This is deliberately a non-authorizing screen; no withdrawal exists in the router API.
async function inspectCandidate({get,sequence,owner,channel}){
  check(typeof get==='function'&&Number.isSafeInteger(sequence)&&sequence>0&&hex(owner),'invalid explorer request');
  const lane=outpoint(channel),before=journal(await get('/api/explorer/journal'));
  const b=(await get('/api/explorer/batch/'+sequence))?.batch;
  const accounts=await get('/api/explorer/accounts');
  const after=journal(await get('/api/explorer/journal'));
  check(JSON.stringify(before)===JSON.stringify(after),'router changed during read');
  check(b?.seq===sequence&&hex(b.digest)&&b.phase==='committed'&&b.ledger_state==='Committed'&&u(b.committed_us)>0n&&before[3]>sequence,'batch not durably committed');
  const a=one(b.accounts,x=>outpoint(x.channel)===lane);
  check(a.owner===owner&&a.approved===true,'owner/approval mismatch');
  const ack=one(b.acks,x=>outpoint(x.channel)===lane);
  check(ack.owner_signed===true&&hex(ack.evidence),'missing acknowledgement');
  const s=one(b.settlements,x=>outpoint(x.channel)===lane);
  check(s.owner===owner,'settlement owner mismatch');
  const c=b.clearing;check(c&&Array.isArray(c.rows)&&c.rows.length===b.accounts.length,'V3 clearing required');
  const seen=new Set();let total=0n;
  for(const r of c.rows){const k=outpoint(r.channel,true);check(!seen.has(k)&&b.accounts.some(a=>outpoint(a.channel)===k),'duplicate/unknown clearing lane');seen.add(k);const net=n(r.net);check(net===u(r.paid)-u(r.collected),'clearing row mismatch');total+=net}
  check(total+n(c.cash_after)-n(c.cash_before)===0n,'clearing conservation mismatch');
  const r=one(c.rows,x=>outpoint(x.channel,true)===lane);
  check(n(s.realized_pnl_sats)===n(r.net)&&u(s.payout_sats)===u(s.released_margin_sats)+n(r.net),'settlement cash mismatch');
  const acct=one(accounts,x=>outpoint(x.outpoint)===lane);
  check(acct.owner===owner,'current account owner mismatch');
  const free=u(acct.balance.free),realized=n(acct.balance.realized_pnl),net=n(r.net);
  const limit=[free,realized,net].reduce((x,y)=>x<y?x:y);
  const candidateSats=(limit>0n?limit:0n).toString();
  const observation={scope:'explorer-candidate-only',sequence,owner,lane,batchDigest:b.digest,routerConfig:before[0],routerTip:{records:before[1],digest:before[2]},candidateSats,kind:acct.kind,simulatedChannel:true,withdrawalAuthorized:false,proofOfFunding:false,receiptEligible:false};
  return {...observation,observationDigest:hash(JSON.stringify(observation))};
}
function verifyDurableWithdrawalReceipt(candidateOrReceipt, policy){
  rejectExplorerOrSimulated(candidateOrReceipt);
  return verifyWithdrawalReceipt(candidateOrReceipt, policy);
}
export {inspectCandidate, verifyDurableWithdrawalReceipt};
