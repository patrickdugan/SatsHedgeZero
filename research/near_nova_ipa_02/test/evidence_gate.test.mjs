import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {txidFromSegwitHex,checkReceipt} from '../evidence_gate.mjs';
const d=b=>createHash('sha256').update(b).digest();
test('Bitcoin TXID uses nonwitness double SHA256 and network byte display order',()=>{
 const raw=Buffer.from('02000000'+'01'+'00'.repeat(32)+'00000000'+'00'+'ffffffff'+'01'+'0100000000000000'+'00'+'00000000','hex');
 const want=Buffer.from(d(d(raw))).reverse().toString('hex');
 assert.equal(txidFromSegwitHex(raw.toString('hex')),want);
});
test('SegWit witness content excluded from TXID',()=>{
 const v='02000000'+'0001'+'01'+'00'.repeat(32)+'00000000'+'00'+'ffffffff'+'01'+'0100000000000000'+'00';
 const p0=v+'01'+'01'+'00'+'00000000';
 const p1=v+'01'+'01'+'01'+'00000000';
 assert.equal(txidFromSegwitHex(p0),txidFromSegwitHex(p1));
});
test('truncated and malformed SegWit decoding is rejected',()=>{
 assert.throws(()=>txidFromSegwitHex('02000000000101'));
 assert.throws(()=>txidFromSegwitHex('x'));
});
test('incomplete reported Nova evidence fails closed',()=>assert.throws(()=>checkReceipt({}, {},Buffer.alloc(0))));
