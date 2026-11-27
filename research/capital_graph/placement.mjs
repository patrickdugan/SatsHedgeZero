// Small exact robust placement reference; bounded enumeration, no external dependencies.
function exactPlacement(base, upper, scenarios) {
  const n=base.length;
  if(n!==upper.length||n>8||[...base,...upper].some(x=>!Number.isSafeInteger(x)||x<0)||upper.reduce((a,b)=>a+b,0)>32)throw Error("tiny exact reference bounds");
  // Only tiny integer fixtures; no unchecked JS integer arithmetic.
  if(base.reduce((a,b)=>a+b,0)>1e9)throw Error("fixture budget bound");
  for(const {d,routes} of scenarios){
    if(d.length>12||d.some(x=>!Number.isSafeInteger(x)||x<0||x>1e9)||routes.length>1024)throw Error("fixture target bound");
    for(const [v,j,u] of routes)if(!Number.isSafeInteger(v)||v<0||v>=n||!Number.isSafeInteger(j)||j<0||j>=d.length||!Number.isSafeInteger(u)||u<0||u>1e9)throw Error("invalid route");
  }
  let best=null,visited=0;
  const deficit=(x,{d,routes})=>{
    let max=0;
    for(let m=0;m<(1<<d.length);m++){
      const into=Array(n).fill(0);
      for(const [v,j,u] of routes)if(m&(1<<j))into[v]+=u;
      const need=d.reduce((s,k,j)=>s+((m&(1<<j))?k:0),0);
      const cover=into.reduce((s,k,v)=>s+Math.min(k,base[v]+x[v]),0);
      max=Math.max(max,need-cover);
    }
    return max;
  };
  const visit=(x,total)=>{
    if(best&&total>=best.total)return;
    if(x.length===n){
      visited++;
      if(scenarios.every(s=>deficit(x,s)===0))best={x:[...x],total};
      return;
    }
    for(let k=0;k<=upper[x.length];k++)visit([...x,k],total+k);
  };
  visit([],0);
  return {best,visited,deficit};
}

function bruteOneTarget(base, upper, scenarios){
  const n=base.length;
  let best=Infinity;
  const visit=(x)=>{
    if(x.length===n){
      const ok=scenarios.every(s=>s.routes.reduce((sum,[v,_,u])=>sum+Math.min(base[v]+x[v],u),0)>=s.d[0]);
      if(ok)best=Math.min(best,x.reduce((a,b)=>a+b,0));
      return;
    }
    for(let i=0;i<=upper[x.length];i++)visit([...x,i]);
  };
  visit([]);
  return Number.isFinite(best)?best:null;
}

function runPlacementChecks() {
  const assert=(x,m)=>{if(!x)throw Error(m)};
  const pairMasks=[3,5,6];
  const make=(mask,d)=>({d:[d],routes:[0,1,2].filter(v=>mask&(1<<v)).map(v=>[v,0,2])});
  const triangle=pairMasks.map(m=>make(m,1));
  const result=exactPlacement([0,0,0],[2,2,2],triangle);
  assert(result.best.total===2,"triangle optimum");
  const before=Math.max(...triangle.map(s=>result.deficit([0,0,0],s)));
  const single=[0,1,2].map(v=>Math.max(...triangle.map(s=>result.deficit([0,1,2].map(j=>j===v?1:0),s))));
  assert(single.every(d=>d===before),"worst-cut marginal stall");
  const cases=[];for(let m=1;m<8;m++)for(let d=1;d<=2;d++)cases.push(make(m,d));
  let families=0,improved=0,maxSaved=0;
  for(let a=0;a<cases.length;a++)for(let b=a+1;b<cases.length;b++)for(let c=b+1;c<cases.length;c++){
    const ss=[cases[a],cases[b],cases[c]];
    const q=exactPlacement([0,0,0],[2,2,2],ss);
    assert(q.best.total===bruteOneTarget([0,0,0],[2,2,2],ss),"exact placement mismatch");
    const uniform=[0,1,2].find(t=>ss.every(s=>q.deficit([t,t,t],s)===0))*3;
    const saved=uniform-q.best.total;
    if(saved>0)improved++;
    maxSaved=Math.max(saved,maxSaved);
    families++;
  }
  const fixture={d:[90000,106000,4000],routes:[[0,0,114000],[1,1,100000],[0,2,10000]]};
  const f=exactPlacement([114000,100000],[0,0],[fixture]);
  assert(f.deficit([0,0],fixture)===6000,"Rust fixture deficit");
  // Allow self-retention for the candidate added stock at the winner vault.
  const candidate={...fixture,routes:[[0,0,120000],[1,1,106000],[0,2,10000]]};
  const g=exactPlacement([114000,100000],[0,0],[candidate]);
  assert(g.deficit([6000,0],candidate)===6000&&g.deficit([0,6000],candidate)===0,"placement vs connectivity");
  return {families,uniform_strictly_worse:improved,maximum_units_saved_vs_uniform:maxSaved,triangle:{minimum_integer_stock:result.best.total,one_optimal_placement:result.best.x,uniform_integer_stock:3,lp_relaxation_optimum:"3/2",worst_deficit_before:before,worst_deficit_after_each_single_sat:single},rust_fixture_replay:{deficit_sats:6000,loser_injection_6000_deficit:6000,winner_injection_6000_deficit:0},scope:"synthetic static placement, recourse after scenario; not temporal or execution evidence"};
}

console.log(JSON.stringify(runPlacementChecks(),null,2));
