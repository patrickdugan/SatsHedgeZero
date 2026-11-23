// Independent integer encoding, used to test injectivity and wire layout.
// Canonical parent state only; a packed equality alone is NOT a range proof.
const need=(b,m)=>{if(!b)throw Error(m)};
const limit=n=>1n<<BigInt(n);
const check=(x,w)=>{need(typeof x==='bigint'&&x>=0n&&x<limit(w),'noncanonical component');return x};
const num=(s,w)=>{need(typeof s==='string'&&/^(0|[1-9][0-9]*)$/.test(s),'decimal');return check(BigInt(s),w)};
const bytes=(s)=>{need(typeof s==='string'&&/^[a-f0-9]{64}$/.test(s),'digest');return Buffer.from(s,'hex')};
const le=b=>BigInt('0x'+Buffer.from(b).reverse().toString('hex'));
const limbs=h=>{const b=bytes(h);return [le(b.subarray(0,16)),le(b.subarray(16))]};
const bool=b=>{need(typeof b==='boolean','boolean');return BigInt(b)};
export function legacy(state,genesis,source,depth){
 need(Number.isInteger(state.level)&&state.level>=0&&state.level<=depth&&state.frontier.length===depth+1,'level or frontier');
 need(source==='pyth'||source==='chainlink','source');
 let v=[num(state.operations,32),num(state.leaf_count,32),num(state.last_time,64),num(state.sealed_through,64),bool(state.pending),BigInt(state.level),num(state.carry.min,64),...limbs(state.carry.digest)];
 for(const s of state.frontier)v.push(bool(s.occupied),num(s.min,64),...limbs(s.digest));
 return [...v,...limbs(genesis),source==='pyth'?1n:2n];
}
export function layout(d){
 need(Number.isInteger(d)&&d>=1&&d<=24,'depth');const n=12+4*(d+1);
 const h=[[0,0,32],[1,32,32],[2,64,64],[3,128,64],[4,192,1],[5,193,8]];
 for(let i=0;i<=d;i++)h.push([9+4*i,201+i,1]);
 const out=[h,[[6,0,64],[7,64,128]],[[8,0,128]]];
 for(let i=0;i<=d;i++){const o=9+4*i;out.push([[o+1,0,64],[o+2,64,128]],[[o+3,0,128]])}
 out.push([[n-3,0,128]],[[n-2,0,128]],[[n-1,0,8]]);return out;
}
export function pack(v,d){const l=layout(d);need(v.length===12+4*(d+1),'arity');return l.map(g=>g.reduce((n,[i,o,w])=>n+(check(v[i],w)<<BigInt(o)),0n))}
export function unpack(v,d){const l=layout(d);need(v.length===l.length,'packed arity');const out=Array(12+4*(d+1));for(let j=0;j<l.length;j++){const g=l[j],w=Math.max(...g.map(x=>x[1]+x[2]));let n=check(v[j],w);for(const [i,o,b] of g){out[i]=(n>>BigInt(o))&(limit(b)-1n);n-=out[i]<<BigInt(o)}need(n===0n,'unused packed bits')}return out}
