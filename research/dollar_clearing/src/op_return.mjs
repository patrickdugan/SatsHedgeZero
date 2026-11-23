/**
 * Proposed, UNACTIVATED Bitcoin OP_RETURN TL-USDC proof-reference wire, v1.
 * The anchor binds a proof statement and single-use event nullifier. It is not
 * itself a proof, mint command, authority check, or a consensus opcode.
 */
import { demand, hex32 } from './common.mjs';
const MAGIC=Buffer.from('TLUSDC','ascii');
const VERSION=1;
export const HYBRID_V1_DATA_BYTES=76;
export const MINT=1, BURN=2;
function validOp(op) { demand(op===MINT || op===BURN,'unknown hybrid asset operation'); }
export function encodeHybridAnchor({propertyId, operation, statementDigest, originNullifier}) {
  demand(Number.isSafeInteger(propertyId)&&propertyId>=1&&propertyId<=0xffffffff,'invalid TL property ID');
  validOp(operation);
  const p=Buffer.alloc(HYBRID_V1_DATA_BYTES);
  MAGIC.copy(p,0);p[6]=VERSION;p[7]=operation;p.writeUInt32BE(propertyId,8);
  Buffer.from(hex32(statementDigest,'joint statement digest'),'hex').copy(p,12);
  Buffer.from(hex32(originNullifier,'origin event nullifier'),'hex').copy(p,44);
  // 76 payload bytes. Bitcoin script must use OP_PUSHDATA1, not a 76-byte direct push.
  return Buffer.concat([Buffer.from([0x6a,0x4c,HYBRID_V1_DATA_BYTES]),p]).toString('hex');
}
export function decodeHybridAnchor(scriptHex) {
  demand(typeof scriptHex==='string'&&/^(?:[a-f0-9]{2})+$/.test(scriptHex),'invalid script bytes');
  const s=Buffer.from(scriptHex,'hex');
  demand(s.length===HYBRID_V1_DATA_BYTES+3 && s[0]===0x6a && s[1]===0x4c && s[2]===HYBRID_V1_DATA_BYTES,'noncanonical hybrid OP_RETURN envelope');
  demand(s.subarray(3,9).equals(MAGIC)&&s[9]===VERSION,'wrong TL-USDC anchor magic/version');
  const operation=s[10];validOp(operation);
  const propertyId=s.readUInt32BE(11);
  demand(propertyId>0,'zero asset property ID');
  return {propertyId,operation,statementDigest:s.subarray(15,47).toString('hex'),originNullifier:s.subarray(47,79).toString('hex')};
}
export class HybridAnchorReplayGate {
  constructor({propertyId,expectedStatementDigest}) {
    demand(Number.isSafeInteger(propertyId)&&propertyId>0,'invalid admitted property');
    this.propertyId=propertyId;
    this.expectedStatementDigest=hex32(expectedStatementDigest,'pinned joint statement digest');
    this.seen=new Set();
  }
  /** Returns staged metadata only. The TradeLayer consensus mint/burn path remains disabled. */
  observe(scriptHex) {
    const row=decodeHybridAnchor(scriptHex);
    demand(row.propertyId===this.propertyId,'hybrid property substitution');
    demand(row.statementDigest===this.expectedStatementDigest,'hybrid statement substitution');
    const key=`${row.propertyId}:${row.operation}:${row.originNullifier}`;
    demand(!this.seen.has(key),'hybrid mint/burn event replay');
    this.seen.add(key);
    return {...row,referenceObserved:true,tradeLayerSupplyChanged:false,btcAssetProvenanceVerified:false};
  }
}
