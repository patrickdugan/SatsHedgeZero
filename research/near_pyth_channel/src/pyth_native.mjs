/**
 * Pyth Pro/Lazer `solana` signed envelope, byte-for-byte according to
 * pyth-lazer-protocol/message.rs SolanaMessage::serialize.
 * The Ed25519 payload is authenticated, but its feed/price fields remain opaque
 * until the official inner PayloadData parser is ported and independently checked.
 */
import {createPublicKey,verify,createHash} from 'node:crypto';
const PREFIX=Buffer.from('302a300506032b6570032100','hex');
const sha=x=>createHash('sha256').update(x).digest('hex');
const MAGIC=2182742457;
const fail=m=>{throw new Error(m)};
export function verifyPythProSolanaEnvelope(envelopeHex, trustedSignerXHex){
  if(typeof envelopeHex!=='string'||!/^([a-f0-9]{2})+$/.test(envelopeHex)||envelopeHex.length>131072)fail('invalid Pyth envelope hex');
  const raw=Buffer.from(envelopeHex,'hex');
  if(raw.length<103||raw.readUInt32LE(0)!==MAGIC)fail('wrong Pyth Pro Solana envelope magic');
  const len=raw.readUInt16LE(100);
  if(len===0||raw.length!==102+len)fail('invalid signed payload length or trailing bytes');
  const signature=raw.subarray(4,68),pubkey=raw.subarray(68,100),payload=raw.subarray(102);
  const keyHex=pubkey.toString('hex');
  if(!Array.isArray(trustedSignerXHex)||!trustedSignerXHex.includes(keyHex))fail('untrusted Pyth signer');
  const key=createPublicKey({key:Buffer.concat([PREFIX,pubkey]),format:'der',type:'spki'});
  if(!verify(null,payload,key,signature))fail('invalid Pyth Ed25519 signed payload');
  return Object.freeze({format:'pyth-pro-lazer-solana-ed25519',signerKeyHex:keyHex,
    signedPayloadSha256:sha(payload),envelopeSha256:sha(raw),payloadLength:len,
    authenticSignedBytes:true,priceFieldsParsedAndBound:false,nearContractVerified:false,
    bitcoinSettlementAuthorized:false});
}
