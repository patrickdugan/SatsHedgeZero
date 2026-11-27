// Tiny exact temporal placement oracle and independent feasibility reference.
function solveTemporal(s, n, upper) {
  // Integral reusable-stock jobs with same-vault reimbursement at release.
  // Only tiny bounded fixtures, all amounts and time ticks safe integers.
  if(!Number.isInteger(n)||n<1||n>5||upper.length!==n||upper.some(x=>!Number.isInteger(x)||x<0||x>8)||!Number.isInteger(s.horizon)||s.horizon<1||s.horizon>400||s.jobs.length>8)throw Error("fixture bounds");
  const jobs=s.jobs;
  for(const j of jobs){
    if(!Number.isInteger(j.d)||j.d<1||j.d>3||!Number.isInteger(j.a)||!Number.isInteger(j.r)||j.a<0||j.r<=j.a||j.r>s.horizon||j.u.length!==n||j.u.some(x=>!Number.isInteger(x)||x<0||x>8))throw Error("invalid job");
  }
  const occ=Array.from({length:n},()=>Array(s.horizon).fill(0));
  const cap=Array(n).fill(0), assignments=[], frontier=[];
  let leaves=0;
  const le=(x,y)=>x.every((v,i)=>v<=y[i]);
  const visit=(i)=>{
    if(frontier.some(p=>le(p.stock,cap)))return;
    if(i===jobs.length){
      leaves++;
      for(let k=frontier.length-1;k>=0;k--)if(le(cap,frontier[k].stock))frontier.splice(k,1);
      frontier.push({stock:[...cap],assignments:assignments.map(x=>[...x])});
      return;
    }
    const j=jobs[i],x=Array(n).fill(0);
    const assign=(v,left)=>{
      if(v===n){
        if(left)return;
        const old=cap.slice();
        for(let k=0;k<n;k++)for(let t=j.a;t<j.r;t++){
          occ[k][t]+=x[k];cap[k]=Math.max(cap[k],occ[k][t]);
        }
        if(le(cap,upper)){assignments.push(x.slice());visit(i+1);assignments.pop();}
        for(let k=0;k<n;k++)for(let t=j.a;t<j.r;t++)occ[k][t]-=x[k];
        for(let k=0;k<n;k++)cap[k]=old[k];
        return;
      }
      for(let a=0;a<=Math.min(left,j.u[v],upper[v]);a++){x[v]=a;assign(v+1,left-a);}
    };
    assign(0,j.d);
  };
  visit(0);
  return {frontier,leaves,busySatTicks:jobs.reduce((a,j)=>a+j.d*(j.r-j.a),0)};
}

function robustTemporal(scenarios,n,upper,weights) {
  if(!scenarios.length||weights.length!==n||weights.some(w=>!Number.isSafeInteger(w)||w<1||w>1e6)||scenarios.some(s=>s.horizon!==scenarios[0].horizon))throw Error("invalid common horizon or weights");
  const all=scenarios.map(s=>solveTemporal(s,n,upper));
  const le=(x,y)=>x.every((v,i)=>v<=y[i]);
  let frontier=[{stock:Array(n).fill(0),witnesses:[]}];
  for(const a of all){
    const next=[];
    for(const p of frontier)for(const q of a.frontier){
      const stock=p.stock.map((x,i)=>Math.max(x,q.stock[i]));
      if(next.some(z=>le(z.stock,stock)))continue;
      for(let i=next.length-1;i>=0;i--)if(le(stock,next[i].stock))next.splice(i,1);
      next.push({stock,witnesses:[...p.witnesses,q.assignments]});
    }
    frontier=next;
  }
  const cost=p=>p.stock.reduce((a,x,i)=>a+x*weights[i],0);
  frontier.sort((a,b)=>cost(a)-cost(b));
  const best=frontier[0]??null,horizon=scenarios[0].horizon;
  return {best,bestWeightedStock:best?cost(best):null,frontierSize:frontier.length,
    reservedSatTicks:best?best.stock.reduce((a,b)=>a+b,0)*horizon:null,
    busySatTicks:all.map(a=>a.busySatTicks)};
}

function independentTemporal(scenarios,n,upper,weights) {
  // Independent fixed-placement search: allocate jobs one unit at a time.
  let optimum=null;
  const fits=(s,stock)=>{
    const used=Array.from({length:n},()=>Array(s.horizon).fill(0));
    const counts=s.jobs.map(()=>Array(n).fill(0));
    const units=s.jobs.flatMap((j,i)=>Array(j.d).fill(i));
    const go=(k)=>{
      if(k===units.length)return true;
      const i=units[k],j=s.jobs[i];
      for(let v=0;v<n;v++){
        if(counts[i][v]>=j.u[v])continue;
        let ok=true;for(let t=j.a;t<j.r;t++)if(used[v][t]===stock[v])ok=false;
        if(!ok)continue;
        counts[i][v]++;for(let t=j.a;t<j.r;t++)used[v][t]++;
        if(go(k+1))return true;
        counts[i][v]--;for(let t=j.a;t<j.r;t++)used[v][t]--;
      }
      return false;
    };
    return go(0);
  };
  const visit=(stock,cost)=>{
    if(optimum!==null&&cost>=optimum)return;
    if(stock.length===n){
      if(scenarios.every(s=>fits(s,stock)))optimum=cost;
      return;
    }
    const i=stock.length;
    for(let k=0;k<=upper[i];k++)visit([...stock,k],cost+k*weights[i]);
  };
  visit([],0);
  return optimum;
}

function verifyTemporal(s,stock,assignments) {
  if(assignments.length!==s.jobs.length)return false;
  const occ=stock.map(()=>Array(s.horizon).fill(0));
  for(let i=0;i<s.jobs.length;i++){
    const j=s.jobs[i],x=assignments[i];
    if(x.length!==stock.length||x.reduce((a,b)=>a+b,0)!==j.d)return false;
    for(let v=0;v<stock.length;v++){
      if(!Number.isInteger(x[v])||x[v]<0||x[v]>j.u[v])return false;
      for(let t=j.a;t<j.r;t++){occ[v][t]+=x[v];if(occ[v][t]>stock[v])return false;}
    }
  }
  return true;
}

function runTemporalChecks(){
  const assert=(x,m)=>{if(!x)throw Error(m);};
  const job=(a,r,u,d=1)=>({a,r,u,d});
  const persistent={horizon:4,jobs:[job(0,2,[1,0]),job(1,3,[1,1]),job(2,4,[0,1])]};
  // each time slice admits a unit-stock matching, but no fixed full-life assignment does.
  const sliced=Array.from({length:4},(_,t)=>({horizon:1,jobs:persistent.jobs.filter(j=>j.a<=t&&t<j.r).map(j=>({...j,a:0,r:1}))}));
  assert(sliced.every(s=>independentTemporal([s],2,[1,1],[1,1])!==null),"instantaneous feasibility");
  assert(robustTemporal([persistent],2,[1,1],[1,1]).best===null,"persistent counterexample");
  const p=robustTemporal([persistent],2,[2,2],[1,1]);assert(p.bestWeightedStock===3,"persistent optimum");
  const reuse={horizon:12,jobs:[job(0,3,[2,0],2),job(3,6,[2,0],2),job(6,9,[2,0],2),job(9,12,[2,0],2)]};
  const extend={...reuse,jobs:reuse.jobs.map(j=>({...j,r:Math.min(12,j.r+3)}))};
  const a=robustTemporal([reuse],2,[8,0],[1,1]),b=robustTemporal([extend],2,[8,0],[1,1]);
  assert(a.bestWeightedStock===2&&b.bestWeightedStock===4,"recovery boundary");
  let seed=2466053;
  const rand=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;};
  let families=0,feasible=0,strict=0,monotonic=0,witnesses=0;
  for(let k=0;k<180;k++){
    const weights=[1+rand(3),1+rand(3),1+rand(3)], upper=[3,3,3];
    const scenarios=Array.from({length:2},()=>({horizon:6,jobs:Array.from({length:4},()=>{
      const a=rand(5),r=a+1+rand(6-a);return job(a,r,[rand(3),rand(3),rand(3)],1+rand(2));
    })}));
    const q=robustTemporal(scenarios,3,upper,weights);
    assert(q.bestWeightedStock===independentTemporal(scenarios,3,upper,weights),"independent optimum mismatch");families++;
    if(q.best){
      feasible++;
      for(let i=0;i<2;i++){assert(verifyTemporal(scenarios[i],q.best.stock,q.best.witnesses[i]),"bad witness");witnesses++;}
      const instant=scenarios.flatMap(s=>Array.from({length:s.horizon},(_,t)=>({horizon:1,jobs:s.jobs.filter(j=>j.a<=t&&t<j.r).map(j=>({...j,a:0,r:1}))})));
      const relaxed=independentTemporal(instant,3,upper,weights);
      assert(relaxed!==null&&relaxed<=q.bestWeightedStock,"instant relaxation bound");if(relaxed<q.bestWeightedStock)strict++;
    }
    const slow=scenarios.map(s=>({...s,jobs:s.jobs.map(j=>({...j,r:Math.min(s.horizon,j.r+1)}))}));
    const slower=robustTemporal(slow,3,upper,weights);
    assert(slower.bestWeightedStock===null||(q.bestWeightedStock!==null&&slower.bestWeightedStock>=q.bestWeightedStock),"longer release cannot improve");monotonic++;
  }
  // Illustrative 24-hour arrival spacing, 6 batches of 1000 sats, all from one vault.
  // One tick = one hour; horizon includes the entire slowest recovery.
  const schedule=hours=>({horizon:288,jobs:Array.from({length:6},(_,i)=>job(i*24,i*24+hours,[1]))});
  const clockSweep=[1,24,25,48,72,144].map(hours=>{
    const q=robustTemporal([schedule(hours)],1,[6],[1]);
    return {recovery_hours:hours,peak_stock_sats:q.bestWeightedStock*1000,reserved_sat_hours:q.reservedSatTicks*1000,busy_sat_hours:q.busySatTicks[0]*1000};
  });
  assert(clockSweep.map(x=>x.peak_stock_sats).join(",")==="1000,1000,2000,2000,3000,6000","clock sweep");
  return {families,feasible,infeasible:families-feasible,strict_instant_relaxation_gap:strict,monotonic,witnesses,persistent:{slice_stock:[1,1],whole_interval_feasible:false,optimal_stock:p.best.stock,integer_stock:p.bestWeightedStock},reuse:{fast_stock:a.bestWeightedStock,slow_stock:b.bestWeightedStock,fast_busy_ticks:a.busySatTicks[0],slow_busy_ticks:b.busySatTicks[0],fast_reserved_ticks:a.reservedSatTicks,slow_reserved_ticks:b.reservedSatTicks},clockSweep,scope:"synthetic integer reusable liquidity; fixed full-interval assignment; same-vault replenishment; scenario-wise recourse with hindsight, not online policy"};
}

console.log(JSON.stringify(runTemporalChecks(),null,2));
