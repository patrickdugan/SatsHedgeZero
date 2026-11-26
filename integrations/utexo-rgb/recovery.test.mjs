import { replay } from './recovery-model.mjs';

function runRecoveryTests(){
  let n=0;
  const ok=v=>{if(!v)throw new Error("failed recovery assertion "+n);n++};
  const reject=events=>{let failed=false;try{replay(events)}catch{failed=true}ok(failed)};
  const h=c=>c.repeat(64);
  const r={type:"reserve",id:"a",withdrawalId:"w1",network:"regtest",assetId:"rgb:fixture",units:"25",sats:"1000",carrierMsat:"3000000",payee:"02"+h("a"),batchDigest:h("b"),paymentHash:h("c"),at:1,expiresAt:10};
  const sub={type:"submit",id:"a",at:2};
  const amb={type:"ambiguous",id:"a",at:3};
  const obs={type:"observe",id:"a",at:4,paymentHash:r.paymentHash};
  const done={type:"reconcile",id:"a",at:11,network:r.network,assetId:r.assetId,units:r.units,sats:r.sats,carrierMsat:r.carrierMsat,payee:r.payee,paymentHash:r.paymentHash,btcEvidence:h("d"),rgbEvidence:h("e")};
  const freeze={type:"chain_conflict",id:"a",at:12,conflictEvidence:h("f")};
  const full=[r,sub,amb,obs,done,freeze];
  for(let k=1;k<=full.length;k++){
    const a=replay(full.slice(0,k));ok(JSON.stringify(a)===JSON.stringify(replay(full.slice(0,k))));ok(a[0].credited===(k>=5));
  }
  ok(replay(full)[0].frozen);
  reject([r,r]);reject([r,{...r,id:"b",paymentHash:h("9")}]);reject([r,{...r,id:"b",withdrawalId:"w2"}]);
  reject([r,{...sub,at:10}]);reject([r,obs]);reject([r,done]);reject([r,sub,sub]);reject([r,sub,amb,sub]);reject([r,sub,{...obs,paymentHash:h("1")}]);
  for(const patch of [{units:"26"},{sats:"999"},{carrierMsat:"3000001"},{assetId:"rgb:other"},{network:"signet"},{payee:"03"+h("a")},{paymentHash:h("1")},{btcEvidence:""},{rgbEvidence:h("d")}]) reject([r,sub,{...done,...patch}]);
  reject([r,sub,done,done]);reject([...full,{...done,at:13}]);reject([r,sub,{...obs,at:1}]);
  const r2={...r,id:"b",withdrawalId:"w2",paymentHash:h("1")};
  reject([r,sub,done,r2,{...sub,id:"b"},{...done,id:"b",paymentHash:r2.paymentHash,rgbEvidence:h("2")}]);
  reject([r,sub,done,r2,{...sub,id:"b"},{...done,id:"b",paymentHash:r2.paymentHash,btcEvidence:h("2")}]);
  const candidates=[sub,amb,obs,done,freeze];
  let valid=0,invalid=0;
  // Enumerate every ordered sequence of length 0..5, including duplicate/retry sequences.
  function walk(prefix,depth){
    let a;
    try{a=replay([r,...prefix])}catch{invalid++}
    if(a){valid++;ok(a.length===1);ok(!a[0].credited||prefix.some(x=>x.type==="reconcile"));ok(!a[0].frozen||prefix.some(x=>x.type==="chain_conflict"))}
    if(depth<5) for(const c of candidates)walk([...prefix,c],depth+1);
  }
  walk([],0);ok(valid+invalid===3906);
  return {assertions:n,validSequences:valid,rejectedSequences:invalid};
}

console.log(JSON.stringify(runRecoveryTests()));
