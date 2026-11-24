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
test('three-input five-output SegWit TXID parser retains output and witness stack counts',()=>{
 const mk=(witnessByte)=>{
   const vin=Buffer.concat(Array.from({length:3},(_,i)=>Buffer.concat([
     Buffer.alloc(32,i+1),Buffer.from([i,0,0,0]),Buffer.from([0]),Buffer.from('feffffff','hex')] )));
   const outs=Buffer.concat(Array.from({length:5},(_,i)=>Buffer.concat([
     Buffer.from([10+i,0,0,0,0,0,0,0]),Buffer.from([34]),Buffer.alloc(34,i+5)])));
   const witnesses=Buffer.concat(Array.from({length:3},()=>Buffer.concat([
     Buffer.from([2,65]),Buffer.alloc(65,witnessByte),Buffer.from([3,5,6,7])] )));
   const version=Buffer.from('02000000','hex'),lock=Buffer.from('00000000','hex');
   return {raw:Buffer.concat([version,Buffer.from([0,1,3]),vin,Buffer.from([5]),outs,witnesses,lock]),
    base:Buffer.concat([version,Buffer.from([3]),vin,Buffer.from([5]),outs,lock])};
 };
 const one=mk(33),two=mk(34);
 const id=Buffer.from(d(d(one.base))).reverse().toString('hex');
 assert.equal(txidFromSegwitHex(one.raw.toString('hex')),id);
 assert.equal(txidFromSegwitHex(two.raw.toString('hex')),id);
});
