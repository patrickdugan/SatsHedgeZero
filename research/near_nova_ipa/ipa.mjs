// Independent, transparent BN254 G1 IPA prover/verifier reference for NEAR gas feasibility.
// It proves a committed inner product, not Nova folding and not source oracle authorization.
import {createHash} from 'node:crypto';
export const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const DOM='SHZ/NEAR-IPA-BN254/FS/V1';
export const GEN='SHZ/NEAR-IPA-BN254/GENERATOR/V1';
const mod=(v,q)=>((v%q)+q)%q;
const h=(...bs)=>createHash('sha256').update(Buffer.concat(bs)).digest();
const b=(s)=>Buffer.from(s,'utf8');
const modpow=(a,n,m)=>{let z=1n;a=mod(a,m);for(;n>0n;n>>=1n,a=mod(a*a,m))if(n&1n)z=mod(z*a,m);return z;};
const inv=(a,m)=>{if(mod(a,m)===0n)throw Error('zero inversion');return modpow(a,m-2n,m);};
const le32=(n)=>{const p=Buffer.alloc(32);let v=n;for(let i=0;i<32;i++){p[i]=Number(v&255n);v>>=8n;}if(v!==0n)throw Error('not uint256');return p;};
const uintle=(p)=>{let n=0n;for(let i=p.length-1;i>=0;i--)n=(n<<8n)|BigInt(p[i]);return n;};
export const pointBytes=(p)=>p?Buffer.concat([le32(p.x),le32(p.y)]):Buffer.alloc(64);
const pointHex=(p)=>pointBytes(p).toString('hex');
export const pointFromHex=(s)=>{if(typeof s!=='string'||!/^[0-9a-f]{128}$/.test(s))throw Error('point hex');let raw=Buffer.from(s,'hex');const x=uintle(raw.subarray(0,32)),y=uintle(raw.subarray(32));if(x===0n&&y===0n)return null;if(x>=Q||y>=Q||mod(y*y-x*x*x-3n,Q)!==0n)throw Error('point not on BN254');return{x,y};};
export const add=(p,q)=>{if(!p)return q;if(!q)return p;if(p.x===q.x&&mod(p.y+q.y,Q)===0n)return null;let m;if(p.x===q.x){m=mod(3n*p.x*p.x*inv(2n*p.y,Q),Q)}else{m=mod((q.y-p.y)*inv(q.x-p.x,Q),Q)}let x=mod(m*m-p.x-q.x,Q);return{x,y:mod(m*(p.x-x)-p.y,Q)};};
export const mul=(p,s)=>{let a=p,r=null;for(let k=mod(s,R);k>0n;k>>=1n,a=add(a,a))if(k&1n)r=add(r,a);return r;};
export const msm=(ps,scalars)=>ps.reduce((a,p,i)=>add(a,mul(p,scalars[i])),null);
export const generators=()=>{const gen=(tag)=>{let x=BigInt('0x'+h(b(GEN),b(tag)).toString('hex'))%Q;for(let i=0;i<100;i++,x=mod(x+1n,Q)){const ysq=mod(x*x*x+3n,Q);let y=modpow(ysq,(Q+1n)/4n,Q);if(mod(y*y,Q)===ysq){if(y&1n)y=Q-y;return{x,y};}}throw Error('hash to curve failed')};return {g:Array.from({length:4},(_,i)=>gen(`G${i}`)),h:Array.from({length:4},(_,i)=>gen(`H${i}`)),u:gen('U')};};
export const validateGenerators=(gs)=>{const xs=[...gs.g,...gs.h,gs.u].map(pointHex);if(new Set(xs).size!==9)throw Error('generator collision');return xs;};
function foldChallenge(state,l,r){let x=BigInt('0x'+h(state,pointBytes(l),pointBytes(r)).toString('hex'))%R;if(x===0n)throw Error('zero Fiat-Shamir challenge');return {x,next:h(state,pointBytes(l),pointBytes(r),le32(x))};}
export function prove({epochHash,pythPrice,chainlinkPrice}){
 const gs=generators();validateGenerators(gs);
 const a=[BigInt(pythPrice),BigInt(chainlinkPrice),0n,0n];const bb=[1n,1n,0n,0n];const c=mod(a[0]+a[1],R);
 const commitment=msm([...gs.g,...gs.h],[...a,...bb]);
 let P=add(commitment,mul(gs.u,c));let G=[...gs.g],H=[...gs.h],A=[...a],B=[...bb];let state=h(b(DOM),Buffer.from(epochHash,'hex'),pointBytes(commitment),le32(c));
 let left=[],right=[];
 while(A.length>1){let n=A.length/2;let aL=A.slice(0,n),aR=A.slice(n),bL=B.slice(0,n),bR=B.slice(n),gL=G.slice(0,n),gR=G.slice(n),hL=H.slice(0,n),hR=H.slice(n);
  const dot=(x,y)=>mod(x.reduce((t,v,i)=>t+v*y[i],0n),R);
  const L=add(msm([...gR,...hL],[...aL,...bR]),mul(gs.u,dot(aL,bR)));
  const RR=add(msm([...gL,...hR],[...aR,...bL]),mul(gs.u,dot(aR,bL)));
  left.push(pointHex(L));right.push(pointHex(RR));
  const {x,next}=foldChallenge(state,L,RR),xi=inv(x,R);state=next;
  A=aL.map((v,i)=>mod(x*v+xi*aR[i],R));B=bL.map((v,i)=>mod(xi*v+x*bR[i],R));
  G=gL.map((v,i)=>add(mul(v,xi),mul(gR[i],x)));H=hL.map((v,i)=>add(mul(v,x),mul(hR[i],xi)));
  P=add(add(mul(L,mod(x*x,R)),P),mul(RR,mod(xi*xi,R)));
 }
 const expected=msm([G[0],H[0],gs.u],[A[0],B[0],mod(A[0]*B[0],R)]);
 if(pointHex(P)!==pointHex(expected))throw Error('prover consistency');
 const sum=a[0]+a[1];const half=sum/2n;
 return {statement:{epoch_hash_hex:epochHash,pyth_price_e8:a[0].toString(),chainlink_price_e8:a[1].toString(),mean_e8:half.toString(),commitment_hex:pointHex(commitment)},proof:{l_hex:left,r_hex:right,a_final_hex:le32(A[0]).toString('hex'),b_final_hex:le32(B[0]).toString('hex')},parameters:{generator_sha256:h(...validateGenerators(gs).map(s=>Buffer.from(s,'hex'))).toString('hex'),setup:'transparent deterministic hash-to-curve',statement:'IPA proof of two-source public vector inner product only',nova_verified:false}};
}
export function verify({statement,proof}){
 try {
  const gs=generators(),epoch=Buffer.from(statement.epoch_hash_hex,'hex');if(epoch.length!==32||!/^[0-9a-f]{64}$/.test(statement.epoch_hash_hex))return false;
  const a=BigInt(statement.pyth_price_e8),bb=BigInt(statement.chainlink_price_e8),mean=BigInt(statement.mean_e8);
  if(a<=0||bb<=0||a>10n**16n||bb>10n**16n)return false;
  const sum=a+bb;if(mean!==sum/2n||20000n*(a>bb?a-bb:bb-a)>50n*sum)return false;
  let C=msm([gs.g[0],gs.g[1],gs.h[0],gs.h[1]],[a,bb,1n,1n]);if(pointHex(C)!==statement.commitment_hex)return false;
  let P=add(C,mul(gs.u,sum));let G=[...gs.g],H=[...gs.h],state=h(b(DOM),epoch,pointBytes(C),le32(sum));
  if(!Array.isArray(proof.l_hex)||proof.l_hex.length!==2||!Array.isArray(proof.r_hex)||proof.r_hex.length!==2)return false;
  for(let j=0;j<2;j++){const L=pointFromHex(proof.l_hex[j]),RR=pointFromHex(proof.r_hex[j]);const {x,next}=foldChallenge(state,L,RR),xi=inv(x,R);state=next;
    const n=G.length/2;G=G.slice(0,n).map((v,i)=>add(mul(v,xi),mul(G[n+i],x)));H=H.slice(0,n).map((v,i)=>add(mul(v,x),mul(H[n+i],xi)));
    P=add(add(mul(L,mod(x*x,R)),P),mul(RR,mod(xi*xi,R)));
  }
  const f=(v)=>{if(!/^[0-9a-f]{64}$/.test(v))throw Error('scalar hex');let n=uintle(Buffer.from(v,'hex'));if(n>=R)throw Error('noncanonical scalar');return n;};
  const aa=f(proof.a_final_hex),bbb=f(proof.b_final_hex);
  return pointHex(P)===pointHex(msm([G[0],H[0],gs.u],[aa,bbb,mod(aa*bbb,R)]));
 }catch{return false;}
}
