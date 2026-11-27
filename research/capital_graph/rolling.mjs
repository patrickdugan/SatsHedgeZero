// CBM-SHZ-05: bounded rolling forecast scorer and synthetic event replay; no live signing or release authority.
function boundedAmount(x){if(!Number.isSafeInteger(x)||x<0||x>1e9)throw Error("bounded exact integer amount required");return x;}

function remaining(stock,locks){
  const free=stock.map(boundedAmount);
  for(const l of locks){
    if(l.x.length!==stock.length)throw Error("invalid lock");
    for(let v=0;v<free.length;v++){free[v]-=boundedAmount(l.x[v]);if(free[v]<0)throw Error("overcommitted stock");}
  }
  return free;
}

function candidateSplits(free,job){
  const n=free.length;
  const avail=free.map((f,v)=>Math.min(f,boundedAmount(job.u[v])));
  if(job.u.length!==n||!boundedAmount(job.d)||avail.reduce((a,b)=>a+b,0)<job.d)return [];
  const order=Array.from({length:n},(_,i)=>i).sort((a,b)=>avail[b]-avail[a]||a-b);
  const candidates=[],seen=new Set();
  for(const first of [-1,...order]){
    const ids=first===-1?order:[first,...order.filter(v=>v!==first)];
    const x=Array(n).fill(0);let left=job.d;
    for(const v of ids){x[v]=Math.min(avail[v],left);left-=x[v];}
    const key=x.join(",");
    if(!left&&!seen.has(key)){seen.add(key);candidates.push(x);}
  }
  return candidates;
}

function projectedLoss(stock,locks,job,split,forecast,now,horizon){
  let working=[...locks.map(l=>({x:l.x,estimate:l.estimate})),{x:split,estimate:job.estimate}];
  let miss=0;
  for(const f of forecast.jobs.slice().sort((a,b)=>a.a-b.a||a.id.localeCompare(b.id))){
    if(f.a<=now||f.a>now+horizon)continue;
    // Estimates only affect this hypothetical projection, never hard availability.
    working=working.filter(l=>l.estimate>f.a);
    const free=remaining(stock,working),candidate=candidateSplits(free,f)[0];
    if(!candidate){miss+=f.d;continue;}
    working.push({x:candidate,estimate:f.estimate});
  }
  return miss;
}

function chooseSplit(stock,locks,job,forecasts=[],horizon=0){
  if(stock.length<1||stock.length>64||!Number.isSafeInteger(horizon)||horizon<0||forecasts.length>16)throw Error("planner bounds");
  if(!Number.isSafeInteger(job.a)||!Number.isSafeInteger(job.estimate)||job.estimate<=job.a)throw Error("invalid arrival estimate");
  const candidates=candidateSplits(remaining(stock,locks),job);
  let best=null;
  for(const x of candidates){
    let score=0;
    for(const f of forecasts){
      if(!Number.isSafeInteger(f.weight)||f.weight<1||f.weight>1000||f.jobs.length>256)throw Error("forecast bounds");
      for(const j of f.jobs)if(!Number.isSafeInteger(j.a)||!Number.isSafeInteger(j.estimate)||j.estimate<=j.a||j.a<=job.a||j.u.length!==stock.length)throw Error("invalid forecast job");
      score+=f.weight*projectedLoss(stock,locks,job,x,f,job.a,horizon);
    }
    if(!Number.isSafeInteger(score))throw Error("score overflow");
    if(!best||score<best.score)best={x,score};
  }
  return best;
}

function replay(stock,events,forecastFor,horizon){
  // Simulator only: actual release time is kept in the environment, never passed to chooseSplit.
  const locks=new Map(),admissions=[];
  let demand=0,served=0,busySatTicks=0,peak=0,last=0;
  const ordered=events.slice().sort((a,b)=>a.t-b.t||Number(a.kind==="reserve")-Number(b.kind==="reserve")||a.id.localeCompare(b.id));
  const ids=new Set(),released=new Set(),rejected=new Set();
  const busy=()=>[...locks.values()].reduce((sum,l)=>sum+l.x.reduce((a,b)=>a+b,0),0);
  for(const e of ordered){
    if(!Number.isSafeInteger(e.t)||e.t<last)throw Error("bad clock");
    busySatTicks+=busy()*(e.t-last);last=e.t;
    if(e.kind==="release"){
      if(!ids.has(e.id)||released.has(e.id))throw Error("unmatched or duplicate release");
      released.add(e.id);
      if(!rejected.has(e.id)&&!locks.delete(e.id))throw Error("missing lock");
    }else if(e.kind==="reserve"){
      if(ids.has(e.id)||e.job.id!==e.id||e.job.a!==e.t)throw Error("duplicate or mismatched job");
      ids.add(e.id);
      const job=e.job;demand+=boundedAmount(job.d);
      const view=[...locks.values()].map(l=>({x:l.x.slice(),estimate:l.estimate}));
      const forecasts=forecastFor(job,view);
      const q=chooseSplit(stock,view,job,forecasts,horizon);
      if(q){served+=job.d;locks.set(job.id,{x:q.x,estimate:job.estimate});}
      else rejected.add(e.id);
      admissions.push({id:job.id,allocation:q?.x??null});
      remaining(stock,[...locks.values()]);
      peak=Math.max(peak,busy());
    }else throw Error("unknown event");
  }
  if(locks.size||released.size!==ids.size)throw Error("incomplete recovery trace");
  if(!Number.isSafeInteger(busySatTicks)||!Number.isSafeInteger(demand)||!Number.isSafeInteger(served))throw Error("trace overflow");
  return {demand,served,peak,busySatTicks,admissions};
}

function runRollingChecks(){
  const assert=(x,m)=>{if(!x)throw Error(m);};
  const eventsFor=(jobs)=>jobs.flatMap(({r,...job})=>[{kind:"reserve",t:job.a,id:job.id,job},{kind:"release",t:r,id:job.id}]);
  const job=(id,a,r,estimate,u,d)=>({id,a,r,estimate,u,d});
  const s=[1000,1000];
  const flex=job("A",0,3,3,[1000,1000],1000);
  const b1=job("B",1,3,3,[1000,0],1000),b2=job("B",1,3,3,[0,1000],1000);
  const fc=j=>[{weight:1,jobs:[{id:j.id,a:j.a,estimate:j.estimate,u:j.u,d:j.d}]}];
  const base1=replay(s,eventsFor([flex,b1]),()=>[],3),base2=replay(s,eventsFor([flex,b2]),()=>[],3);
  const info1=replay(s,eventsFor([flex,b1]),j=>j.id==="A"?fc(b1):[],3),info2=replay(s,eventsFor([flex,b2]),j=>j.id==="A"?fc(b2):[],3);
  assert(base1.served===1000&&base2.served===2000&&info1.served===2000&&info2.served===2000,"known two-future gap");
  assert(JSON.stringify(base1.admissions[0])===JSON.stringify(base2.admissions[0]),"nonanticipativity");
  // An underestimated release is not spend authority.
  const bad=replay([1000],eventsFor([job("X",0,4,1,[1000],1000),job("Y",2,3,3,[1000],1000)]),()=>[],3);
  assert(bad.served===1000&&bad.busySatTicks===4000,"premature reuse");
  const boundary=replay([1000],eventsFor([job("X",0,2,2,[1000],1000),job("Y",2,3,3,[1000],1000)]),()=>[],3);
  assert(boundary.served===2000&&boundary.busySatTicks===3000,"half-open release");
  let rejected=0;for(const e of [[{kind:"release",t:0,id:"X"}],[{kind:"reserve",t:0,id:"X",job:{id:"X",a:0,estimate:2,u:[1000],d:1000}}]]){try{replay([1000],e,()=>[],3);}catch{rejected++;}}assert(rejected===2,"invalid events accepted");
  let seed=20261127;
  const rand=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return Math.floor(seed/4294967296*n);};
  const traces=[];
  for(let i=0;i<128;i++){
    const jobs=[],predictions=new Map(),truth=new Map(),signals=new Map();
    for(let k=0;k<16;k++){
      const t=5*k,a=rand(4),b=(a+1+rand(3))%4,d=(1+rand(2))*1000;
      const chosen=rand(2)?a:b,other=chosen===a?b:a;
      const flexible=job("F"+k,t,t+4,t+4,[0,1,2,3].map(v=>v===a||v===b?d:0),d);
      const rigid=v=>job("R"+k,t+1,t+4,t+4,[0,1,2,3].map(w=>w===v?d:0),d);
      jobs.push(flexible,rigid(chosen));truth.set(flexible.id,fc(rigid(chosen)));
      const signal=rand(4)<3?chosen:other;signals.set(flexible.id,signal===chosen);
      predictions.set(flexible.id,fc(rigid(signal)));
    }
    traces.push({events:eventsFor(jobs),predictions,truth,signals});
  }
  const rows=[];
  for(const cap of [1000,2000,3000,4000])for(const mode of ["blind","signal75","oracle"]){
    let demand=0,served=0,full=0,busySatTicks=0;
    for(const t of traces){
      const q=replay(Array(4).fill(cap),t.events,j=>mode==="blind"?[]:(mode==="signal75"?t.predictions:t.truth).get(j.id)||[],4);
      demand+=q.demand;served+=q.served;busySatTicks+=q.busySatTicks;if(q.served===q.demand)full++;
    }
    rows.push({mode,cap_per_vault:cap,total_stock_sats:4*cap,trace_count:traces.length,full_traces:full,demand_sats:demand,served_sats:served,busy_sat_ticks:busySatTicks});
  }
  const matched=Object.fromEntries(["blind","signal75","oracle"].map(mode=>[mode,rows.find(x=>x.mode===mode&&x.full_traces===traces.length)?.total_stock_sats??null]));
  const correctSignals=traces.reduce((sum,t)=>sum+[...t.signals.values()].filter(Boolean).length,0);
  assert(matched.blind===16000&&matched.oracle===8000&&matched.signal75===16000,"matched delivery provisioning");
  // Multi-route split, no per-sat loops and exact accounting.
  const split=chooseSplit([600,600],[],{id:"Z",a:0,estimate:3,u:[600,600],d:1000},[],0);
  assert(split.x.reduce((a,b)=>a+b,0)===1000&&split.x.every(x=>x<=600),"split");
  return {traces:traces.length,episodes:traces.length*16,correct_signals:correctSignals,rows,matched_full_service_stock_sats:matched,checks:{two_future:4,nonanticipativity:1,early_release:1,boundary:1,invalid_events:2,split:1},scope:"synthetic separated overlapping pairs; oracle has forbidden future information and is upper control; 75% signal generated by experiment; same-stock hard release gate"};
}

export {chooseSplit, replay, runRollingChecks};
