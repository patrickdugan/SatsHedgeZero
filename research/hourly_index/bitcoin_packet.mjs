/** Bitcoin witness-aware transaction OP_RETURN packet and Merkle inclusion reference.
 * Does NOT establish block-header consensus, PoW, confirmations or canonical-chain membership.
 */
import {createHash} from 'node:crypto';
import {opReturnScript,hex32} from './index.mjs';
const SHA=(data)=>createHash('sha256').update(data).digest();
const SHA2=(data)=>SHA(SHA(data));
const check=(ok,msg)=>{if(!ok)throw Error(msg)};
const asHex=(hex,name)=>{check(typeof hex==='string'&&/^(?:[0-9a-f]{2})+$/.test(hex),`${name}: canonical even-length hex`);return Buffer.from(hex,'hex')};
const reverse=(b)=>Buffer.from(b).reverse();
export function parseTx(hex){
 const raw=asHex(hex,'raw transaction');check(raw.length<=250_000&&raw.length>=10,'transaction byte size');
 let off=0;const take=(n)=>{check(Number.isSafeInteger(n)&&n>=0&&off+n<=raw.length,'truncated transaction');let b=raw.subarray(off,off+n);off+=n;return b};
 const num=()=>take(1)[0];
 const compact=()=>{const a=num();if(a<253)return a;if(a===253){let v=take(2).readUInt16LE();check(v>=253,'noncanonical varint');return v;}if(a===254){let v=take(4).readUInt32LE();check(v>65535,'noncanonical varint');return v;}let v=take(8).readBigUInt64LE();check(v>0xffff_ffffn&&v<100_000n,'out of range varint');return Number(v)};
 const varScript=()=>{const before=off;const n=compact();check(n<=10_000,'oversized script');return {raw:raw.subarray(before,off+n),body:take(n)}};
 const version=take(4);
 let segwit=false;
 if(raw[off]===0){check(raw[off+1]===1,'unsupported witness marker/flag');segwit=true;take(2)}
 const firstStart=off;let nVin=compact();check(nVin>=1&&nVin<=256,'invalid number of inputs');
 const inputs=[];
 for(let i=0;i<nVin;i++){const outpoint=take(36);const script=varScript();const sequence=take(4);inputs.push({outpoint,script:script.body,sequence})}
 const outStart=off;const nOut=compact();check(nOut>=1&&nOut<=256,'invalid number of outputs');
 const outputs=[];
 for(let i=0;i<nOut;i++){const sat=take(8).readBigUInt64LE();const script=varScript().body;outputs.push({value_sats:sat.toString(),script_hex:script.toString('hex')})}
 const outEnd=off;
 if(segwit){for(let i=0;i<nVin;i++){const count=compact();check(count<=256,'witness stack');for(let j=0;j<count;j++){const n=compact();check(n<=150_000,'witness item');take(n)}}}
 const locktime=take(4);check(off===raw.length,'trailing bytes');
 const stripped=Buffer.concat([version,raw.subarray(firstStart,outEnd),locktime]);
 return {txid:reverse(SHA2(stripped)).toString('hex'),wtxid:reverse(SHA2(raw)).toString('hex'),segwit,outputs};
}
export function verifyPacketInTransaction(txHex,checkpoint){
 try{let r=parseTx(txHex),expected=opReturnScript(checkpoint).toString('hex');
  const matches=r.outputs.filter(o=>o.script_hex.startsWith('6a28'+Buffer.from('SHZIDX01').toString('hex')));
  check(matches.length===1,'exactly one SHZIDX01 output');
  check(matches[0].script_hex===expected && matches[0].value_sats==='0','packet or value mismatch');
  return {valid:true,txid:r.txid,wtxid:r.wtxid,bitcoin_finality_verified:false,bitcoin_consensus_verified:false};
 }catch{return {valid:false,bitcoin_finality_verified:false,bitcoin_consensus_verified:false};}
}
export function verifyTxMerkleInHeader({txid,header_hex,branch=[],tx_index}){
 try{
  let header=asHex(header_hex,'block header');check(header.length===80,'80-byte Bitcoin header');
  let idx=Number(tx_index);check(Number.isSafeInteger(idx)&&idx>=0,'tx_index');
  check(Array.isArray(branch)&&branch.length<=32,'Merkle branch length');
  let node=reverse(hex32(txid,'TXID'));
  for(const s of branch){const sib=reverse(hex32(s,'Merkle sibling'));node=SHA2((idx&1)?Buffer.concat([sib,node]):Buffer.concat([node,sib]));idx=Math.floor(idx/2)}
  check(idx===0,'tx_index exceeds Merkle branch');
  check(node.equals(header.subarray(36,68)),'Bitcoin merkle root mismatch');
  return {valid:true,header_hash:reverse(SHA2(header)).toString('hex'),bitcoin_finality_verified:false,proof_type:'Merkle inclusion relative to an UNTRUSTED header'};
 }catch{return{valid:false,bitcoin_finality_verified:false}}
}
