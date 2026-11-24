import test from 'node:test';
import assert from 'node:assert/strict';
import {inversePnlSats,netBilateralTrades,solvePermittedFunding,buildCloseoutProposal} from '../src/channels.mjs';
const d='a1'.repeat(32),p='aa'.repeat(32);
function fixture(){
 const trades=[
  {id:'AB',long:'Alice',short:'Bob',notionalUsd:'1',entryUsd:'80000',longMarginSats:'625',shortMarginSats:'1000',fundingTxid:'01'.repeat(32),fundingVout:0},
  {id:'BC',long:'Bob',short:'Carol',notionalUsd:'1',entryUsd:'100000',longMarginSats:'500',shortMarginSats:'625',fundingTxid:'02'.repeat(32),fundingVout:1},
  {id:'CA',long:'Carol',short:'Alice',notionalUsd:'1',entryUsd:'125000',longMarginSats:'400',shortMarginSats:'400',fundingTxid:'03'.repeat(32),fundingVout:2},
 ];
 const vaults=[{id:'b',owner:'Bob',nettingSetId:'btc',fundedSats:'1500',protectedSats:'0'},
 {id:'c',owner:'Carol',nettingSetId:'btc',fundedSats:'1025',protectedSats:'0'}];
 const routes=[{fromVaultId:'b',toParty:'Alice',capacitySats:'250',policyDigest:p},
 {fromVaultId:'c',toParty:'Alice',capacitySats:'200',policyDigest:p}];
 const oracleImport={priceE8:(125000n*100000000n).toString(),receiptHash:d};
 return {routeId:'mnr-shz-01',markUsd:'125000',oracleImport,trades,vaults,routes,currentHeight:120};
}
test('inverse PnL in integer sats telescopes across the three trades',()=>{
 assert.equal(inversePnlSats('1','80000','125000'),450n);
 assert.equal(inversePnlSats('1','100000','125000'),200n);
 assert.equal(inversePnlSats('1','125000','125000'),0n);
 assert.equal(inversePnlSats('33000','50000','60000'),11000000n);
});
test('Alice closes against Carol and all three USD deltas are zero',()=>{
 const f=fixture();const r=netBilateralTrades(f.trades,f.markUsd);
 assert.equal(r.allPartiesFlat,true);
 assert.deepEqual(r.parties.map(p=>[p.party,p.realizedPnlSats,p.grossPayoutSats]),
 [['Alice','450','1475'],['Bob','-250','1250'],['Carol','-200','825']]);
 assert.equal(r.bitcoinSettlementEnforced,false);
});
test('permissioned max flow funds 450 sats from Bob and Carol and no other vault',()=>{
 const f=fixture();const r=buildCloseoutProposal(f);
 assert.equal(r.funding.feasible,true);assert.equal(r.funding.routedSats,'450');
 assert.equal(r.readyToReleaseCollateral,false);assert.equal(r.status,'PROPOSED_ONLY');
});
test('missing route exposes exact shortfall',()=>{
 const f=fixture();f.routes[1].capacitySats='100';const r=buildCloseoutProposal(f);
 assert.equal(r.funding.feasible,false);assert.equal(r.funding.shortfallSats,'100');
});
test('rejects cross-collateral route and insufficient source vault',()=>{
 const f=fixture();f.routes[1]={fromVaultId:'c',toVaultId:'b',capacitySats:'200',policyDigest:p};
 f.vaults[1].nettingSetId='other';
 assert.throws(()=>buildCloseoutProposal(f),/cross-domain route/);
 const g=fixture();g.vaults[0].protectedSats='1400';
 assert.throws(()=>buildCloseoutProposal(g),/unfunded loss owner/);
});
test('rejects invalid trade or missing bilateral margin',()=>{
 const f=fixture();f.trades.push({...f.trades[0]});
 assert.throws(()=>buildCloseoutProposal(f),/duplicate or invalid bilateral trade/);
 const g=fixture();g.trades[0].shortMarginSats='50';
 assert.throws(()=>buildCloseoutProposal(g),/insufficient bilateral loss collateral/);
});
test('incomplete exposure reports the remaining delta',()=>{
 const f=fixture();f.trades.pop();const r=buildCloseoutProposal(f);
 assert.equal(r.accounting.allPartiesFlat,false);
 assert.equal(r.readyToReleaseCollateral,false);
});
test('Bob offline is blocked without a pinned MNR02 origination package',()=>{
 const f=fixture();f.channelHops=[{channelId:'AB',commitmentTxid:d,timeoutHeight:160,
 originalPeerOffline:true,authorizationMode:'interactive-bilateral'}];
 assert.throws(()=>buildCloseoutProposal(f),/offline counterparty/);
 f.channelHops[0].authorizationMode='mnr02-0x83-at-maturity';
 assert.throws(()=>buildCloseoutProposal(f),/missing MNR02 preauthorization/);
 f.channelHops[0].preauthorizationPackageDigest=d;
 assert.equal(buildCloseoutProposal(f).readyToReleaseCollateral,false);
});
test('safe channel timeout ladder enforces at least 6-block hop gap',()=>{
 const f=fixture();f.channelHops=[
 {channelId:'AB',commitmentTxid:d,timeoutHeight:170,authorizationMode:'interactive-bilateral'},
 {channelId:'AC',commitmentTxid:d,timeoutHeight:167,authorizationMode:'interactive-bilateral'}];
 assert.throws(()=>buildCloseoutProposal(f),/unsafe HTLC timeout ladder/);
 f.channelHops[1].timeoutHeight=164;
 assert.equal(buildCloseoutProposal(f).readyToReleaseCollateral,false);
});
test('invalid oracle mark and unbound policy are rejected',()=>{
 const f=fixture();f.oracleImport.priceE8='100';assert.throws(()=>buildCloseoutProposal(f),/unbound oracle mark/);
 const g=fixture();g.routes[0].policyDigest='bad';assert.throws(()=>buildCloseoutProposal(g),/unbound route authorization policy/);
});
test('81 capacity graphs match an independent exhaustive 2-source 2-target allocation oracle',()=>{
 const parties=[{party:'S0',realizedPnlSats:'-2'},{party:'S1',realizedPnlSats:'-2'},
                {party:'W0',realizedPnlSats:'2'},{party:'W1',realizedPnlSats:'2'}];
 const vaults=['S0','S1'].map((x,i)=>({id:x,owner:x,nettingSetId:'BTC',fundedSats:'2',protectedSats:'0'}));
 for(let code=0;code<81;code++){
  let x=code;const caps=[];for(let i=0;i<4;i++){caps.push(x%3);x=Math.floor(x/3)}
  const routes=caps.map((n,i)=>({fromVaultId:'S'+Math.floor(i/2),toParty:'W'+(i%2),capacitySats:String(n),policyDigest:p}));
  const solved=solvePermittedFunding({parties,vaults,routes});
  let best=0;
  for(let a=0;a<=caps[0];a++)for(let b=0;b<=caps[1];b++)
  for(let c=0;c<=caps[2];c++)for(let d=0;d<=caps[3];d++){
    if(a+b<=2&&c+d<=2&&a+c<=2&&b+d<=2)best=Math.max(best,a+b+c+d);
  }
  assert.equal(Number(solved.routedSats),best,`capacity assignment ${code}`);
 }
});
