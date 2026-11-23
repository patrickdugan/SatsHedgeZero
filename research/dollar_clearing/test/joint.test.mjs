import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixture.mjs';
import {verifyJointDollarStatement} from '../src/joint.mjs';
import {digest} from '../src/common.mjs';

const check=f=>verifyJointDollarStatement(f,f.policy);
const tagCoin='SHZ/USD/COIN-ATTESTATION/V1';
function changeCoin(f,mutate){
  const old=f.shzBook.positions[0].attestation.payload;
  f.shzBook.positions[0].attestation=f.attest('shzCoin',mutate({...old}));
  f.repin();
}
function changeHedgeLiability(f,mutate){
  const old=f.shzBook.liability.payload;
  f.shzBook.liability=f.attest('shzLiability',mutate({...old}));
  f.repin();
}
function changeTlLiability(f,mutate){
  const old=f.tlUsdcBook.liability.payload;
  f.tlUsdcBook.liability=f.attest('tlLiability',mutate({...old}));
  f.repin();
}
function changeDeposit(f,mutate){
  const old=f.tlUsdcBook.deposits[0].payload;
  f.tlUsdcBook.deposits[0]=f.attest('tlSourceDeposit',mutate({...old}));
  f.repin();
}

test('joint statement binds disjoint BTC DLC and USDC reserves with source-attested liabilities',()=>{
  const f=fixture(),r=check(f);
  assert.equal(r.shz.assetId,'SHZ-USD');assert.equal(r.tlUsdc.assetId,'TL-USDC');
  assert.equal(r.shz.outstandingMicros,'60000000000');
  assert.equal(r.tlUsdc.outstandingMicros,'65000000000');
  assert.equal(r.tlUsdc.pendingRedemptionMicros,'2000000000');
  assert.equal(r.tlUsdc.reserveMicros,'67000000000');
  assert.equal(r.spot.priceUsdE8,'5987500000000');
  assert.equal(r.spot.tradeCount,3);
  assert.equal(r.shz.stress.length,4);
  assert.equal(r.shz.stress.every(v=>v.passes),true);
  assert.equal(r.disjointBackingResourcesChecked,true);
  assert.match(r.publicStatementDigest,/^[a-f0-9]{64}$/);
  assert.equal(r.novaProofVerified,false);
  assert.equal(r.nearUsdcLightClientVerified,false);
  assert.equal(r.mintAuthorized,false);
});
test('joint digest is deterministic independent of original object property insertion order',()=>{
  const f=fixture(),s=check(f);
  assert.equal(s.publicStatementDigest,digest('SHZ/TL/JOINT-DOLLAR-LIABILITIES/V1',s.statement));
});
test('reject root mismatch when book altered without independent pin',()=>{
  const f=fixture();f.shzBook.positions[0].entryPriceUsd='70000';
  assert.throws(()=>check(f),/pinned commitment/);
});
test('reject changed coin value even with unchanged signed witness',()=>{
  const f=fixture();f.shzBook.positions[0].attestation.payload.valueSats='350000330';f.repin();
  assert.throws(()=>check(f),/invalid evidence signature/);
});
test('reject signed coin amount inconsistent with DLC collateral conservation',()=>{
  const f=fixture();changeCoin(f,p=>({...p,valueSats:'350000330'}));
  assert.throws(()=>check(f),/funding value not conserved/);
});
test('reject duplicate Bitcoin backing resources inside SHZ book',()=>{
  const f=fixture();const c=f.shzBook.positions[0];
  f.shzBook.positions.push({...c,id:'short-hedge-2'});f.repin();
  assert.throws(()=>check(f),/duplicated BTC collateral/);
});
test('reject insolvency at low BTC prices despite apparent 1x USD hedge',()=>{
  const f=fixture();f.policy.shz.stressPricesUsd=['10000','30000','60000','100000'];
  assert.throws(()=>check(f),/stress insolvency/);
});
test('reject improperly scoped oracle and hedge issuer epoch',()=>{
  const f=fixture();f.policy.expectedOracleEpochDigest='9'.repeat(64);
  assert.throws(()=>check(f),/different price epochs/);
});
test('reject silent oracle epoch substitution inside supply certificate',()=>{
  const f=fixture();changeHedgeLiability(f,p=>({...p,oracleEpochDigest:'9'.repeat(64)}));
  assert.throws(()=>check(f),/price epoch substitution/);
});
test('reject issuer signing as source observer when independent key roles overlap',()=>{
  const f=fixture();f.policy.tlUsdc.liabilityAuditors.tlLiability=f.policy.tlUsdc.sourceObservers.tlSourceDeposit;
  assert.throws(()=>check(f),/same evidence key reused/);
});
test('reject duplicated USDC lock event even with different signed serialization',()=>{
  const f=fixture();f.tlUsdcBook.deposits.push(f.tlUsdcBook.deposits[0]);f.repin();
  assert.throws(()=>check(f),/replayed USDC deposit/);
});
test('reject minting bridge supply exceeding finalized reserves',()=>{
  const f=fixture();changeTlLiability(f,p=>({...p,mintedMicros:'85000000000',outstandingMicros:'80000000000'}));
  assert.throws(()=>check(f),/unbacked TL-USDC/);
});
test('reject a release exceeding burned liabilities',()=>{
  const f=fixture();changeTlLiability(f,p=>({...p,burnedMicros:'2000000000',outstandingMicros:'68000000000',pendingRedemptionMicros:'0'}));
  assert.throws(()=>check(f),/invalid USDC supply/);
});
test('reject a burn that loses pending redemption entitlement',()=>{
  const f=fixture();changeTlLiability(f,p=>({...p,pendingRedemptionMicros:'0'}));
  assert.throws(()=>check(f),/USDC burn or supply conservation/);
});
test('reject source token substitution even when attested by trusted verifier',()=>{
  const f=fixture();changeDeposit(f,p=>({...p,tokenContract:'0x'+'c'.repeat(40)}));
  assert.throws(()=>check(f),/source token\/escrow substitution/);
});
test('reject USDC deposit without independently attested finality',()=>{
  const f=fixture();changeDeposit(f,p=>({...p,confirmations:0,finalized:false}));
  assert.throws(()=>check(f),/lacks independently attested finality/);
});
test('reject cross-asset collateral double pledge using signed backing resource',()=>{
  const f=fixture();changeDeposit(f,p=>({...p,additionalBitcoinBackingResourceId:f.sourceCoinId}));
  assert.throws(()=>check(f),/collateral double-counting/);
});
test('reject duplicate asset identities across SHZ and TradeLayer',()=>{
  const f=fixture();f.policy.tlUsdc.assetId='SHZ-USD';
  assert.throws(()=>check(f),/duplicate liability asset/);
});
test('reject dishonest spot window including a self-cross trade',()=>{
  const f=fixture();f.spotWindow.executions[0].taker='market-A';f.repin();
  assert.throws(()=>check(f),/wash\/self-cross/);
});
test('reject altered execution amount under unchanged indexer signature',()=>{
  const f=fixture();f.spotWindow.executions[0].usdcMicros='100000000000';
  assert.throws(()=>check(f),/execution window root mismatch/);
});
test('reject VWAP manipulation diverging from independently pinned Pyth mark',()=>{
  const f=fixture();f.spotWindow.executions=f.spotWindow.executions.map(x=>({...x,usdcMicros:(BigInt(x.usdcMicros)*2n).toString()}));f.repin();
  assert.throws(()=>check(f),/deviates from independent reference/);
});
test('reject stale and expired trade windows',()=>{
  const f=fixture();f.spotWindow.executions[0].height=2440;f.repin();
  assert.throws(()=>check(f),/outside VWAP time window/);
});
test('reject concentration even with multiple unique trade identifiers',()=>{
  const f=fixture();f.spotWindow.executions[0].maker='market-B';f.repin();
  assert.throws(()=>check(f),/insufficient independent spot executions|maker concentration/);
});
test('reject a maliciously repeated trade ID',()=>{
  const f=fixture();f.spotWindow.executions[1].tradeId=f.spotWindow.executions[0].tradeId;f.repin();
  assert.throws(()=>check(f),/replayed trade ID/);
});
test('reject invalid decimal forms, including scientific notation',()=>{
  const f=fixture();changeHedgeLiability(f,p=>({...p,outstandingMicros:'6e10'}));
  assert.throws(()=>check(f),/noncanonical unsigned decimal/);
});
test('reject a different TL execution root reported by the signed indexer',()=>{
  const f=fixture();f.spotWindow.indexerCheckpoint=f.attest('spot',{
    ...f.spotWindow.indexerCheckpoint.payload,executionRoot:'2'.repeat(64)});
  assert.throws(()=>check(f),/spot window checkpoint binding mismatch/);
});
test('reject malformed BTC funding script policy digest',()=>{
  const f=fixture();changeCoin(f,p=>({...p,spendingPolicyDigest:'0'}));
  assert.throws(()=>check(f),/spend authorization policy/);
});
test('reject an unattested unspent assertion',()=>{
  const f=fixture();changeCoin(f,p=>({...p,unspent:false}));
  assert.throws(()=>check(f),/unspentness or confirmations/);
});
test('reject a mismatched TL source escrow',()=>{
  const f=fixture();changeDeposit(f,p=>({...p,escrowAddress:'0x'+'d'.repeat(40)}));
  assert.throws(()=>check(f),/source token\/escrow substitution/);
});

test('signed liability release counter must open exact independently attested USDC exits',()=>{
  const f=fixture();changeTlLiability(f,p=>({...p,releasedMicros:'4000000000'}));
  assert.throws(()=>check(f),/signed supply ledger release total differs/);
});
