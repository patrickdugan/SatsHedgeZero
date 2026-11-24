// SHZ-IPA02: transparent BN254 inner-product argument bound to a frozen MNR-03 public state.
// This does NOT verify Nova's Pallas/Vesta folding or Spartan/IPA compressed proof.
import {createHash} from 'node:crypto';
export const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const DOM = 'SHZ/NEAR-IPA02-MNR03-STATE/FS/V2';
export const GEN = 'SHZ/NEAR-IPA-BN254/GENERATOR/V1';
export const SNAPSHOT_DOMAIN = 'SHZ/NEAR-IPA02-MNR03-FROZEN-STATE/V1';
export const FROZEN = Object.freeze({
  epoch_id:177,
  count:3,
  collateral_sats:3900,
  payout_sats:3450,
  fee_sats:450,
  oracle_receipt_hash_hex:'7a0a6d8d97a231fd0adcef7892d29232d131adfe8c92391deb228b9dd598e51e',
  bitcoin_assertion_txid_hex:'ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1',
  nova_batch_txid_hex:'5e439e3cdf3f4f61c61edaf3bba197d32b6ab54c88fef8092ac9c7ae0bf7d5e8',
  nova_journal_sha256_hex:'d87e089251413e3f47f90c9e3aadb21c98d164798f77b953d19b361402a28a40',
  nova_proof_sha256_hex:'14e9985b67569c2db18b10eb43e0036cfe76fac21ab2674b35ae6324fe08a043',
  nova_vk_sha256_hex:'4eafbd223936cc3c1e9b16e750f1946a57cd5413f86578f6f1d37d9abb53e38b',
  init_poseidon_hex:'988541fdecd9cc499ad8d97b8525c45f13e25e8d484d9977cb4b113f77517861',
  final_poseidon_hex:'35c6cd69174a0379456d11b5944e1aa6b7086b5b473e83c6804973ec910a84ac',
});
const mod=(v,n)=>((v%n)+n)%n;
const h=(...parts)=>createHash('sha256').update(Buffer.concat(parts)).digest();
const utf=(s)=>Buffer.from(s,'utf8');
const le=(n,size)=>{let v=BigInt(n);if(v<0n)throw Error('negative unsigned');const p=Buffer.alloc(size);for(let i=0;i<size;i++){p[i]=Number(v&255n);v>>=8n}if(v)throw Error('integer overflow');return p};
const unle=(p)=>{let k=0n;for(let i=p.length-1;i>=0;i--)k=(k<<8n)|BigInt(p[i]);return k};
const hash32=(v)=>{if(typeof v!=='string'||!/^[0-9a-f]{64}$/.test(v))throw Error('invalid digest');return Buffer.from(v,'hex')};
const modpow=(a,e,q)=>{let z=1n;a=mod(a,q);for(;e>0n;e>>=1n,a=mod(a*a,q))if(e&1n)z=mod(z*a,q);return z};
const inv=(a,q)=>{if(mod(a,q)===0n)throw Error('zero inversion');return modpow(a,q-2n,q)};
export const pb=(p)=>p?Buffer.concat([le(p.x,32),le(p.y,32)]):Buffer.alloc(64);
export const phex=(p)=>pb(p).toString('hex');
export const fromHex=(s)=>{if(typeof s!=='string'||!/^[0-9a-f]{128}$/.test(s))throw Error('invalid point hex');let p=Buffer.from(s,'hex');const x=unle(p.subarray(0,32)),y=unle(p.subarray(32));if(x===0n&&y===0n)return null;if(x>=Q||y>=Q||mod(y*y-x*x*x-3n,Q))throw Error('not on BN254 curve');return {x,y}};
// Jacobian group law keeps 256-bit scalar multiplications from performing an inversion per bit.
const inf=()=>({X:0n,Y:1n,Z:0n});
const jac=p=>p?{X:p.x,Y:p.y,Z:1n}:inf();
const affine=p=>{if(p.Z===0n)return null;const zi=inv(p.Z,Q),z2=mod(zi*zi,Q);return{x:mod(p.X*z2,Q),y:mod(p.Y*z2*zi,Q)}};
const dbl=p=>{if(p.Z===0n||p.Y===0n)return inf();const A=mod(p.X*p.X,Q),B=mod(p.Y*p.Y,Q),C=mod(B*B,Q),D=mod(2n*(mod((p.X+B)*(p.X+B),Q)-A-C),Q),E=mod(3n*A,Q),F=mod(E*E,Q);return{X:mod(F-2n*D,Q),Y:mod(E*(D-mod(F-2n*D,Q))-8n*C,Q),Z:mod(2n*p.Y*p.Z,Q)}};
const jacadd=(p,q)=>{if(p.Z===0n)return q;if(q.Z===0n)return p;const z1=mod(p.Z*p.Z,Q),z2=mod(q.Z*q.Z,Q),U1=mod(p.X*z2,Q),U2=mod(q.X*z1,Q),S1=mod(p.Y*q.Z*z2,Q),S2=mod(q.Y*p.Z*z1,Q),H=mod(U2-U1,Q),Rr=mod(S2-S1,Q);if(H===0n)return Rr===0n?dbl(p):inf();const HH=mod(H*H,Q),HHH=mod(H*HH,Q),U1HH=mod(U1*HH,Q),X=mod(Rr*Rr-HHH-2n*U1HH,Q);return{X,Y:mod(Rr*(U1HH-X)-S1*HHH,Q),Z:mod(H*p.Z*q.Z,Q)}};
export const add=(p,q)=>affine(jacadd(jac(p),jac(q)));
export const mul=(p,s)=>{let a=jac(p),r=inf();for(let k=mod(s,R);k>0n;k>>=1n,a=dbl(a))if(k&1n)r=jacadd(r,a);return affine(r)};
export const msm=(ps,ss)=>{if(ps.length!==ss.length)throw Error('MSM arity mismatch');let acc=inf();for(let i=0;i<ps.length;i++){let a=jac(ps[i]),n=mod(ss[i],R),r=inf();for(;n>0n;n>>=1n,a=dbl(a))if(n&1n)r=jacadd(r,a);acc=jacadd(acc,r)}return affine(acc)};
export function generators(n){if(!Number.isInteger(n)||n<4||n>32||(n&(n-1)))throw Error('unsupported generator dimension');const g=(tag)=>{let x=BigInt('0x'+h(utf(GEN),utf(tag)).toString('hex'))%Q;for(let i=0;i<100;i++,x=mod(x+1n,Q)){let ysq=mod(x*x*x+3n,Q);let y=modpow(ysq,(Q+1n)/4n,Q);if(mod(y*y,Q)===ysq){if(y&1n)y=Q-y;return{x,y}}}throw Error('hash to curve failed')};let a={g:Array.from({length:n},(_,i)=>g(`G${i}`)),h:Array.from({length:n},(_,i)=>g(`H${i}`)),u:g('U')};let points=[...a.g,...a.h,a.u].map(phex);if(new Set(points).size!==2*n+1)throw Error('generator collision');return a}
export function snapshotHash(s=FROZEN){const parts=[utf(SNAPSHOT_DOMAIN)];for(let k of ['epoch_id','count','collateral_sats','payout_sats','fee_sats'])parts.push(le(s[k],8));for(let k of ['oracle_receipt_hash_hex','bitcoin_assertion_txid_hex','nova_batch_txid_hex','nova_journal_sha256_hex','nova_proof_sha256_hex','nova_vk_sha256_hex','init_poseidon_hex','final_poseidon_hex'])parts.push(hash32(s[k]));return h(...parts).toString('hex')}
export const FROZEN_ROOT = snapshotHash();
function checkStatement(st){if(!st||![8,16,32].includes(st.dimension))throw Error('bad dimension');if(st.snapshot_root_hex!==FROZEN_ROOT||st.oracle_receipt_hash_hex!==FROZEN.oracle_receipt_hash_hex||st.bitcoin_assertion_txid_hex!==FROZEN.bitcoin_assertion_txid_hex||st.nova_journal_sha256_hex!==FROZEN.nova_journal_sha256_hex||st.nova_proof_sha256_hex!==FROZEN.nova_proof_sha256_hex)throw Error('unaccepted frozen receipt');if(st.epoch_id!==177||st.row_count!==3||st.collateral_sats!==3900||st.payout_sats!==3450||st.fee_sats!==450||st.conservation_claim!==3)throw Error('unaccepted frozen public state');if(st.collateral_sats!==st.payout_sats+st.fee_sats)throw Error('accounting mismatch')}
function vectors(n){let a=[3n,3900n,3450n,450n,...Array(n-4).fill(0n)];let b=[1n,5n,R-5n,R-5n,...Array(n-4).fill(0n)];return {a,b}}
const dot=(a,b)=>mod(a.reduce((v,x,i)=>v+x*b[i],0n),R);
function challenge(state,l,r){const msg=h(state,pb(l),pb(r));const x=BigInt('0x'+msg.toString('hex'))%R;if(x===0n)throw Error('zero Fiat-Shamir challenge');return {x,next:h(state,pb(l),pb(r),le(x,32))}}
function statement(n,commitment){return {dimension:n,epoch_id:177,row_count:3,collateral_sats:3900,payout_sats:3450,fee_sats:450,conservation_claim:3,snapshot_root_hex:FROZEN_ROOT,oracle_receipt_hash_hex:FROZEN.oracle_receipt_hash_hex,bitcoin_assertion_txid_hex:FROZEN.bitcoin_assertion_txid_hex,nova_journal_sha256_hex:FROZEN.nova_journal_sha256_hex,nova_proof_sha256_hex:FROZEN.nova_proof_sha256_hex,commitment_hex:phex(commitment)}}
function seed(st,c){return h(utf(DOM),le(st.dimension,4),hash32(st.snapshot_root_hex),hash32(st.oracle_receipt_hash_hex),hash32(st.bitcoin_assertion_txid_hex),hash32(st.nova_journal_sha256_hex),hash32(st.nova_proof_sha256_hex),Buffer.from(st.commitment_hex,'hex'),le(c,32))}
export function prove(n){const gs=generators(n),{a,b}=vectors(n),c=dot(a,b);if(c!==3n)throw Error('frozen accounting inconsistent');const commitment=msm([...gs.g,...gs.h],[...a,...b]);const st=statement(n,commitment);checkStatement(st);let G=[...gs.g],H=[...gs.h],A=[...a],B=[...b];let P=add(commitment,mul(gs.u,c));let fs=seed(st,c);const l=[],r=[];while(A.length>1){const half=A.length/2;const aL=A.slice(0,half),aR=A.slice(half),bL=B.slice(0,half),bR=B.slice(half),gL=G.slice(0,half),gR=G.slice(half),hL=H.slice(0,half),hR=H.slice(half);
 const L=add(msm([...gR,...hL],[...aL,...bR]),mul(gs.u,dot(aL,bR)));
 const RR=add(msm([...gL,...hR],[...aR,...bL]),mul(gs.u,dot(aR,bL)));
 l.push(phex(L));r.push(phex(RR));const {x,next}=challenge(fs,L,RR),xi=inv(x,R);fs=next;
 A=aL.map((v,i)=>mod(x*v+xi*aR[i],R));B=bL.map((v,i)=>mod(xi*v+x*bR[i],R));
 G=gL.map((v,i)=>add(mul(v,xi),mul(gR[i],x)));H=hL.map((v,i)=>add(mul(v,x),mul(hR[i],xi)));
 P=add(add(mul(L,mod(x*x,R)),P),mul(RR,mod(xi*xi,R)));
 }
 const expected=msm([G[0],H[0],gs.u],[A[0],B[0],mod(A[0]*B[0],R)]);
 if(phex(P)!==phex(expected))throw Error('invalid construction');return {statement:st,proof:{l_hex:l,r_hex:r,a_final_hex:le(A[0],32).toString('hex'),b_final_hex:le(B[0],32).toString('hex')},honesty:{frozen_mnr03_public_state_bound:true,transparent:true,full_nova_verifier_constrained:false,source_authenticated:false,bitcoin_witness_proved:false,settlement_authorized:false,production_ready:false}};
}
export function verify(f){try {const st=f.statement,pf=f.proof;checkStatement(st);const gs=generators(st.dimension),{a,b}=vectors(st.dimension),c=dot(a,b);const commitment=msm([...gs.g,...gs.h],[...a,...b]);if(st.commitment_hex!==phex(commitment))return false;let P=add(commitment,mul(gs.u,c)),G=[...gs.g],H=[...gs.h],fs=seed(st,c);const rounds=Math.log2(st.dimension);if(!Array.isArray(pf.l_hex)||!Array.isArray(pf.r_hex)||pf.l_hex.length!==rounds||pf.r_hex.length!==rounds)return false;
 for(let i=0;i<rounds;i++){const L=fromHex(pf.l_hex[i]),RR=fromHex(pf.r_hex[i]);const {x,next}=challenge(fs,L,RR),xi=inv(x,R);fs=next;const half=G.length/2;G=G.slice(0,half).map((v,j)=>add(mul(v,xi),mul(G[half+j],x)));H=H.slice(0,half).map((v,j)=>add(mul(v,x),mul(H[half+j],xi)));P=add(add(mul(L,mod(x*x,R)),P),mul(RR,mod(xi*xi,R)))}
 const scalar=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('scalar encoding');const x=unle(Buffer.from(s,'hex'));if(x>=R)throw Error('scalar out of range');return x};const aa=scalar(pf.a_final_hex),bb=scalar(pf.b_final_hex);return phex(P)===phex(msm([G[0],H[0],gs.u],[aa,bb,mod(aa*bb,R)]))}catch{return false}}
