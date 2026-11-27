import {amount, analyze, cutDeficit, routeIntervals} from "./graph.mjs";

function runChecks() {
  const assert=(x,msg)=>{if(!x)throw new Error(msg);};
  const eq=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  const tuples=(n,base)=>Array.from({length:base**n},(_,q)=>Array.from({length:n},(_,i)=>Math.floor(q/base**i)%base));
  const xy=tuples(4,3),two=tuples(2,3),pairs=[[0,0],[0,1],[1,0],[1,1]],cuts=[[],[0],[1],[0,1]];
  let graphs=0,unit=0,intervals=0,parallel=0;
  for(const U of xy){
    const r=pairs.map(([v,j],i)=>[v,j,U[i]]);
    for(const C of two)for(const D of two){
      const a=analyze(C,D,r);
      let best=0n, worst=0n;
      for(const f of xy){
        if(f.some((x,i)=>x>U[i])||f[0]+f[1]>C[0]||f[2]+f[3]>C[1]||f[0]+f[2]>D[0]||f[1]+f[3]>D[1])continue;
        const val=BigInt(f.reduce((a,b)=>a+b,0));if(val>best)best=val;
      }
      for(const J of cuts){const d=cutDeficit(C,D,r,J);if(d>worst)worst=d;}
      assert(a.delivered===best&&a.deficit===worst,"brute primal/cut mismatch");graphs++;
      // Unit injection to either vault: improvement iff every maximizing cut has
      // strictly more incoming route capacity than that vault's current budget.
      for(let v=0;v<2;v++){
        const relevant=cuts.filter(J=>cutDeficit(C,D,r,J)===worst);
        const expected=relevant.every(J=>r.filter(([a,j])=>a===v&&J.includes(j)).reduce((a,e)=>a+e[2],0)>C[v])?1n:0n;
        const c2=C.slice();c2[v]++;
        assert(analyze(c2,D,r).delivered-a.delivered===expected,"unit marginal mismatch");unit++;
      }
    }
  }
  const r=pairs.map(([v,j])=>[v,j,2]);
  const margins=x=>[x[0]+x[1],x[2]+x[3],x[0]+x[2],x[1]+x[3]];
  for(const x of xy)for(const audited of [[],[0],[1],[0,3]]){
    const fibre=xy.filter(y=>eq(margins(x),margins(y))&&audited.every(i=>x[i]===y[i]));
    const actual=routeIntervals(2,2,r,x,audited);
    for(let i=0;i<4;i++){
      assert(actual[i][0]===BigInt(Math.min(...fibre.map(y=>y[i])))&&actual[i][1]===BigInt(Math.max(...fibre.map(y=>y[i]))),"fibre range mismatch");intervals++;
    }
  }
  const pr=[[0,0,2],[0,0,2]],p=routeIntervals(1,1,pr,[1,1]);
  assert(p.every(([l,h])=>l===0n&&h===2n),"parallel edge range");parallel++;
  assert(analyze([100,100],[100,100],[[0,0,100],[1,0,100]]).deficit===100n,"isolated target");
  assert(analyze(["9007199254740993"],["9007199254740993"],[[0,0,"9007199254740993"]]).deficit===0n,"exact arithmetic");
  let invalid=0;for(const x of [-1,1.5,Number.MAX_SAFE_INTEGER+1,"01"]){try{amount(x);}catch{invalid++;}}assert(invalid===4,"invalid amount acceptance");
  return {graphs,unit_budget_perturbations:unit,coordinate_interval_checks:intervals,parallel_edge_checks:parallel,extra_checks:6,method:"exhaustive independent integer allocations and destination cuts; fixed-margin fibre enumeration"};
}

console.log(JSON.stringify(runChecks(),null,2));
