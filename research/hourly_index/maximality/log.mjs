/** INDEX-MAX-01: sorted prefix log with authenticated subtree minima.
 * Trust boundary: roots must be independently pinned after valid admission and
 * seal transitions. A seal proves closure of the admitted log, not provider availability.
 */
import {sha,shahex,hex32,u64le,uint64,HOURLY_US} from '../index.mjs';
import {POLICY_HASH,empty,evidenceLeaf,evidenceRoot,deriveRecord} from '../policy_nova/policy.mjs';
export const MAX=0xffffffffffffffffn;
export const DOM=Object.freeze({leaf:'SHZ/LOG/LEAF/V2',empty:'SHZ/LOG/EMPTY/V2',node:'SHZ/LOG/NODE/V2',snapshot:'SHZ/LOG/SNAPSHOT/V2'});
const B=s=>Buffer.from(s,'ascii');const ok=(b,m)=>{if(!b)throw Error(m)};
const sourceId=s=>{ok(s==='pyth'||s==='chainlink','source');return s==='pyth'?1:2};
const depthCheck=d=>{ok(Number.isInteger(d)&&d>=1&&d<=24,'depth');return 2**d};
const same=(a,b)=>a.min===b.min&&a.digest===b.digest;
const uint=s=>uint64(s,'uint64');
const validRecord=(r)=>{ok(r&&Object.keys(r).sort().join(',')==='price_e8,publish_us,report_hash','record shape');const p=uint(r.price_e8),t=uint(r.publish_us);hex32(r.report_hash,'report');ok(p>0n&&p<=10_000_000_000_000_000n&&t>0n&&t<MAX&&r.report_hash!=='00'.repeat(32),'invalid admitted report');return t;};
function validateSorted(entries,capacity){ok(Array.isArray(entries)&&entries.length<capacity&&entries.length<=1_000_000,'log capacity');let prev=0n;let seen=new Set();for(const r of entries){const t=validRecord(r);ok(t>prev&&!seen.has(r.report_hash),'nonmonotone time or duplicate digest');prev=t;seen.add(r.report_hash);}}
const asSummary=(s)=>{ok(s&&Object.keys(s).sort().join(',')==='digest,min','summary shape');hex32(s.digest,'summary digest');return {min:uint(s.min),digest:s.digest}};
function encSummary(s){return Buffer.concat([u64le(uint(s.min)),hex32(s.digest,'node hash')]);}
export function leaf(candidate){
 const c=candidate;ok(c&&typeof c.present==='boolean'&&Object.keys(c).sort().join(',')==='present,price_e8,publish_us,report_hash','candidate shape');
 const p=uint(c.price_e8),t=uint(c.publish_us);hex32(c.report_hash,'report');
 if(c.present){validRecord({price_e8:c.price_e8,publish_us:c.publish_us,report_hash:c.report_hash});}
 else ok(p===0n&&t===0n&&c.report_hash==='00'.repeat(32),'sentinel encoding');
 return {min:t.toString(),digest:shahex(B(DOM.leaf),Buffer.from([Number(c.present)]),u64le(p),u64le(t),hex32(c.report_hash,'report'))};
}
export function node(left,right){
 const l=asSummary(left),r=asSummary(right);
 return {min:(l.min<=r.min?l.min:r.min).toString(),digest:shahex(B(DOM.node),encSummary(left),encSummary(right))};
}
export function defaults(depth){depthCheck(depth);let d=[{min:MAX.toString(),digest:shahex(B(DOM.empty))}];for(let i=0;i<depth;i++)d.push(node(d[i],d[i]));return d;}
export function snapshotDigest(h){
 ok(h&&Object.keys(h).sort().join(',')==='count,depth,genesis,last_time,policy_hash,root,sealed_through,source','header shape');
 const cap=depthCheck(h.depth);sourceId(h.source);ok(h.policy_hash===POLICY_HASH,'policy');
 const count=uint(h.count),last=uint(h.last_time),seal=uint(h.sealed_through),root=asSummary(h.root);
 ok(count<BigInt(cap)&&((count===0n)===(last===0n))&&last<MAX&&seal<MAX&&root.min===0n,'header bounds');
 return shahex(B(DOM.snapshot),hex32(h.genesis,'genesis'),hex32(h.policy_hash,'policy'),Buffer.from([sourceId(h.source),h.depth]),u64le(count),u64le(last),u64le(seal),encSummary(h.root));
}
export function buildLog({genesis,source,entries,depth=4,sealed_through='0'}){
 const cap=depthCheck(depth);validateSorted(entries,cap);
 const d=defaults(depth);const candidates=[empty(),...entries.map(e=>({present:true,...e}))];const levels=[candidates.map(leaf)];
 for(let i=0;i<depth;i++){let a=levels[i],b=[];for(let j=0;j<a.length;j+=2)b.push(node(a[j],a[j+1]??d[i]));levels.push(b);}
 const header={genesis,policy_hash:POLICY_HASH,source,depth,count:String(entries.length),last_time:entries.at(-1)?.publish_us??'0',sealed_through,root:levels[depth][0]};
 const pin=snapshotDigest(header);
 const path=(index)=>{ok(Number.isSafeInteger(index)&&index>=0&&index<cap,'index');let k=index;return Array.from({length:depth},(_,i)=>{let s=levels[i][k^1]??d[i];k=Math.floor(k/2);return {...s}})};
 return {header,pin,candidates,path};
}
function pathRoot(start,index,siblings,depth,{cutoff}={}){
 const cap=depthCheck(depth),d=defaults(depth);ok(Number.isSafeInteger(index)&&index>=0&&index<cap,'path index');ok(Array.isArray(siblings)&&siblings.length===depth,'path length');
 let curr=start,k=index;
 for(let i=0;i<depth;i++){
   const sib=siblings[i],m=asSummary(sib).min;ok(m!==MAX||same(sib,d[i]),'noncanonical empty summary');
   const left=(k&1)===0?curr:sib,right=(k&1)===0?sib:curr;
   if(cutoff!==undefined&&(k&1)===0)ok(m>cutoff,'later admitted observation at or before cutoff');
   if(cutoff!==undefined)ok(uint(left.min)<=uint(right.min),'inconsistent ordered subtree minima');
   curr=node(left,right);k=Math.floor(k/2);
 }
 return curr;
}
export function select(tree,cutoff){
 cutoff=BigInt(cutoff);ok(cutoff>=0n&&cutoff<MAX,'cutoff');let lo=0,hi=tree.candidates.length;
 while(lo+1<hi){let mid=Math.floor((lo+hi)/2);if(uint(tree.candidates[mid].publish_us)<=cutoff)lo=mid;else hi=mid;}
 return {header:tree.header,index:String(lo),candidate:tree.candidates[lo],siblings:tree.path(lo)};
}
export function verifySelection(w,{pin,cutoff,genesis,source}){
 try{
 const h=w.header;cutoff=BigInt(cutoff);ok(cutoff>=0n&&cutoff<MAX,'cutoff');ok(snapshotDigest(h)===pin,'independent snapshot pin');ok(h.genesis===genesis&&h.source===source,'snapshot context');ok(uint(h.sealed_through)>=cutoff,'unsealed cutoff');
 const i=uint(w.index);ok(i<=uint(h.count),'outside admitted prefix');const c=w.candidate;ok(c.present===(i!==0n),'sentinel index');ok(uint(c.publish_us)<=cutoff&&uint(c.publish_us)<=uint(h.last_time),'candidate time');
 const root=pathRoot(leaf(c),Number(i),w.siblings,h.depth,{cutoff});ok(same(root,h.root),'root mismatch');return true;
 }catch{return false;}
}
// Receiver checks a known genesis (sentinel only), each append, and seal transitions.
// New observation must be strictly newer than both the old tail and old watermark.
// Sibling path is identical on old and new roots, so no other entry can be changed.
export function verifyAppend({oldHeader,newHeader,record,siblings},{oldPin,newPin}){
 try{
 const a=oldHeader,b=newHeader;ok(snapshotDigest(a)===oldPin&&snapshotDigest(b)===newPin,'root pin');
 for(const k of ['genesis','source','policy_hash','depth','sealed_through'])ok(a[k]===b[k],'append changed header context');
 const i=uint(a.count)+1n;ok(uint(b.count)===i,'nonconsecutive append');const t=uint(record.publish_us);ok(t>uint(a.last_time)&&t>uint(a.sealed_through)&&b.last_time===record.publish_us,'late or nonmonotone append');
 const d=defaults(a.depth);const oldRoot=pathRoot(d[0],Number(i),siblings,a.depth),newRoot=pathRoot(leaf({present:true,...record}),Number(i),siblings,a.depth);
 ok(same(oldRoot,a.root)&&same(newRoot,b.root),'append path root mismatch');return true;
 }catch{return false;}
}
export function verifySeal(oldHeader,newHeader,{oldPin,newPin}){
 try{ok(snapshotDigest(oldHeader)===oldPin&&snapshotDigest(newHeader)===newPin,'root pin');for(const k of ['genesis','source','policy_hash','depth','count','last_time'])ok(oldHeader[k]===newHeader[k],'seal changed history');ok(same(oldHeader.root,newHeader.root),'seal changed root');ok(uint(newHeader.sealed_through)>=uint(oldHeader.sealed_through),'seal regression');return true}catch{return false;}
}
export function verifyGenesis(h,pin){try{ok(h.count==='0'&&h.last_time==='0'&&h.sealed_through==='0','genesis');let t=buildLog({genesis:h.genesis,source:h.source,depth:h.depth,entries:[]});return snapshotDigest(h)===pin&&t.pin===pin}catch{return false;}}
// Evidence bridge: same candidate bytes and digest as INDEX-POLICY-01. Receiver
// MUST supply the two independently authenticated snapshot pins, not copy proof metadata.
export function verifyEight({genesis,start_hour,openings},{pins,expectedEvidenceRoot}){
 try{const start=uint(start_hour);ok(start%8n===0n&&start<=999999992n,'start');ok(openings.length===8,'eight hours');let leaves=[];let records=[];
 for(let i=0;i<8;i++){let hour_id=String(start+BigInt(i)),cutoff=(BigInt(hour_id)+1n)*HOURLY_US;const w=openings[i];ok(w.hour_id===hour_id,'hour order');for(const source of ['pyth','chainlink'])ok(verifySelection(w[source],{pin:pins[source],cutoff,genesis,source}),'source selection');let e={genesis,hour_id,pyth:w.pyth.candidate,chainlink:w.chainlink.candidate};leaves.push(evidenceLeaf(e));records.push(deriveRecord(e));}
 ok(evidenceRoot({genesis,start_hour,leaves})===expectedEvidenceRoot,'policy evidence root mismatch');return {evidence_leaves:leaves,records};
 }catch{return null;}
}
