// Disposable regtest fixture, using the pinned upstream harness. Never point at shared stands.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { checkDecoded } from './adapter.mjs';

const pin='608937d849412a4c25e9b9a66a7571b561396ae0';
const rootArg=process.env.UTEXO_WDK_CHECKOUT;
const rail=process.argv[2];
const attempts=Number(process.argv[3]??100);
const amount=Number(process.argv[4]??25);
assert.equal(process.env.SHZ_DISPOSABLE_REGTEST,'YES','Explicit disposable stand opt-in required');
assert.ok(rootArg&&['btc-ln','rgb-ln','rgb-chain'].includes(rail),'Usage: node benchmark.mjs btc-ln|rgb-ln|rgb-chain [attempts] [fixture asset units]');
assert.ok(Number.isSafeInteger(attempts)&&attempts>=1&&attempts<=100);
assert.ok(Number.isSafeInteger(amount)&&amount>=1&&amount*attempts<=10000);
const checkout=fs.realpathSync(rootArg);
const git=(...args)=>execFileSync('git',['-C',checkout,...args],{encoding:'utf8'}).trim();
assert.equal(git('rev-parse','HEAD'),pin);
assert.equal(git('status','--porcelain','--untracked-files=no'),'','Upstream tracked source must be clean');
const {WalletProcess,daemon,endpoints,mine,prepareChain,prepareIssuer,rpc,until}=await import(pathToFileURL(path.join(checkout,'tests/regtest/harness.mjs')).href);
const evidence=fs.mkdtempSync(path.join(os.tmpdir(),'shz-rgb01a-'));fs.chmodSync(evidence,0o700);
const rows=[],wallets=[];
const report={schema:'SHZ-RGB-01A/v1',upstream:pin,rail,attempts,assetUnits:rail==='btc-ln'?null:amount,carrierMsat:rail==='rgb-chain'?null:3000000,policy:'strict',setup:'unexecuted',rows,scope:'fixture only; no SHZ settlement authorization'};
const save=()=>{const p=path.join(evidence,'summary.json');fs.writeFileSync(p+'.tmp',JSON.stringify(report,null,2),{mode:0o600});fs.renameSync(p+'.tmp',p)};
const start=performance.now();
let errorStage='setup';
try{
  await prepareChain();
  assert.equal((await rpc('getblockchaininfo')).chain,'regtest');
  const a=new WalletProcess(evidence,'alice','node');wallets.push(a);
  const b=new WalletProcess(evidence,'bob','node');wallets.push(b);
  await a.start(29501,'TransactionSync',{permissiveSignerPolicy:false});
  await b.start(29502,'BlockSync',{permissiveSignerPolicy:false});
  for(const w of wallets){
    const addr=await w.call('getAddress');assert.match(addr,/^bcrt1/);
    await rpc('sendtoaddress',[addr,1],'miner');await mine();await w.call('sync');
    await w.call('createUtxos',[{up_to:false,num:10,size:500000,fee_rate:2,skip_sync:false}]);
    await mine();await w.call('sync');
  }
  let asset=null;
  if(rail!=='btc-ln'){
    await prepareIssuer();
    asset=(await daemon('issueassetnia',{ticker:'SHZTEST',name:'SHZ disposable benchmark asset',precision:0,amounts:[1000000]})).asset.asset_id;
    assert.ok(asset);
    const inv=await a.call('createRgbInvoice',[{min_confirmations:1,witness:false}]);
    const sent=await daemon('sendrgb',{donation:true,fee_rate:2,min_confirmations:1,skip_sync:false,recipient_map:{[asset]:[{recipient_id:inv.recipient_id,assignment:{type:'Fungible',value:1000000},transport_endpoints:[endpoints.proxy]}]}});
    await mine();
    await until('fixture RGB funding',async()=>{
      await a.call('refreshTransfers',[{skip_sync:false}]);await daemon('refreshtransfers',{filter:[],skip_sync:false});
      return (await a.call('listTransfersByTxid',[sent.txid])).some(x=>x.status==='Settled');
    });
    assert.equal(String((await a.call('getAssetBalance',[asset])).settled),'1000000');
  }
  if(rail!=='rgb-chain'){
    await a.call('openChannel',[{peer_pubkey_and_opt_addr:b.pubkey+'@127.0.0.1:29502',capacity_sat:1000000,push_msat:0,public:false,with_anchors:true,...(asset?{asset_id:asset,asset_amount:10000,push_asset_amount:0}:{})}]);
    await until('funding broadcast',async()=>{
      const cs=await a.call('listChannels'),pool=await rpc('getrawmempool');
      return cs.some(x=>x.asset_id===asset&&pool.includes(x.funding_txid));
    });
    await mine(12);
    await until('usable channel at both peers',async()=>{
      await a.call('sync');await b.call('sync');
      const ac=await a.call('listChannels'),bc=await b.call('listChannels');
      return ac.some(x=>x.asset_id===asset&&x.is_usable&&bc.some(y=>y.channel_id===x.channel_id&&y.is_usable));
    });
  }
  report.setup='passed';report.setupMs=performance.now()-start;save();
  errorStage='payment';
  for(let i=0;i<attempts;i++){
    const t=performance.now();const row={attempt:i+1,status:'started'};rows.push(row);save();
    try{
      if(rail==='rgb-chain'){
        const before=await b.call('getAssetBalance',[asset]).catch(()=>null);
        // A fresh receiver may not know this asset before its first receipt.
        if(i>0)assert.ok(before,'Missing previously imported asset balance');
        const inv=await b.call('createRgbInvoice',[{min_confirmations:6,witness:false,assignment_kind:'Fungible',assignment_amount:amount,duration_seconds:600}]);
        const d=await a.call('decodeRgbInvoice',[inv.invoice]);
        assert.equal(d.assignment.type,'Fungible');assert.equal(String(d.assignment.value),String(amount));
        const tx=await a.call('sendRgbAsset',[{donation:false,fee_rate:2,min_confirmations:6,recipient_groups:[{asset_id:asset,recipients:[{recipient_id:inv.recipient_id,assignment_kind:'Fungible',assignment_amount:amount,transport_endpoints:d.transport_endpoints}]}]}]);
        const refresh=async()=>{for(const w of [b,a]){const x=await w.call('refreshTransfers',[{skip_sync:false}]);for(const c of Object.values(x.transfers))assert.equal(c.failure,null)}};
        await until('broadcast',async()=>{await refresh();return (await rpc('getrawmempool')).includes(tx.txid)});
        row.broadcastMs=performance.now()-t;
        const m=performance.now();await mine(6);row.syntheticMiningMs=performance.now()-m;
        await until('both RGB histories settled',async()=>{
          await refresh();
          return (await a.call('listTransfers',[asset,tx.txid])).some(x=>x.status==='Settled')&&(await b.call('listTransfers',[asset,tx.txid])).some(x=>x.status==='Settled');
        });
        const core=await rpc('getrawtransaction',[tx.txid,true]);assert.ok(core.confirmations>=6);
        assert.equal(await rpc('getblockhash',[(await rpc('getblockheader',[core.blockhash])).height]),core.blockhash);
        const after=await b.call('getAssetBalance',[asset]);assert.equal(BigInt(after.settled)-BigInt(before?.settled??0),BigInt(amount));
        row.txid=tx.txid;row.anchor=core.blockhash;row.confirmations=core.confirmations;row.minerFeeSats=null;
      }else{
        const inv=await b.call('createLightningInvoice',[{amountMsat:3000000,expirySec:600,...(asset?{assetId:asset,assetAmount:amount}:{})}]);
        const d=await a.call('decodeInvoice',[inv.invoice]);
        assert.equal(String(d.network).toLowerCase(),'regtest');
        assert.equal(String(d.amt_msat),'3000000');
        assert.equal(d.payee_pubkey,b.pubkey);
        assert.match(d.payment_hash,/^[0-9a-f]{64}$/);
        if(asset){
          const now=Math.floor(Date.now()/1000);
          checkDecoded({network:'regtest',assetId:asset,assetUnits:String(amount),carrierMsat:'3000000',payee:b.pubkey,obligationId:'fixture:'+i,expiresAt:now+600},d,now);
        }else{assert.equal(d.asset_id,null);assert.equal(d.asset_amount,null)}
        await a.call('sendPayment',[{invoice:inv.invoice}]);
        await until('two-sided terminal history',async()=>{
          const o=await a.call('getPayment',[d.payment_hash,'Outbound']);
          const p=await b.call('getPayment',[d.payment_hash,'InboundAutoClaim']);
          return o.status==='Succeeded'&&p.status==='Succeeded';
        });
        assert.equal((await b.call('getInvoiceStatus',[inv.invoice])).status,'Succeeded');
        row.paymentHash=d.payment_hash;row.routingFeeMsat=null;
      }
      row.status='observed-success';row.elapsedMs=performance.now()-t;save();
    }catch(e){
      row.status='ambiguous-or-failed';row.elapsedMs=performance.now()-t;save();throw e;
    }
  }
}catch(e){report.failureStage=errorStage;report.failureClass=e.name;report.setup=report.setup==='unexecuted'?'failed':report.setup;process.exitCode=1}
finally{
  for(const w of wallets.reverse()){try{await w.stop()}catch{report.cleanupFailed=true;process.exitCode=1}}
  const ms=rows.filter(r=>r.status==='observed-success').map(r=>r.elapsedMs).sort((x,y)=>x-y);
  const q=p=>ms.length?ms[Math.ceil(p*ms.length)-1]:null;
  report.summary={observedSuccess:ms.length,ambiguousOrFailed:rows.filter(r=>r.status==='ambiguous-or-failed').length,unexecuted:attempts-rows.length,p50Ms:q(.5),p95Ms:q(.95),p99Ms:q(.99)};
  save();console.log(JSON.stringify({evidence,summary:report.summary,setup:report.setup,exitCode:process.exitCode??0}));
}
