// Independent read-only research oracle. All satoshi arithmetic is exact BigInt.
function amount(x) {
  if (typeof x === "bigint" && x >= 0n) return x;
  if (typeof x === "number" && Number.isSafeInteger(x) && x >= 0) return BigInt(x);
  if (typeof x === "string" && /^(0|[1-9][0-9]*)$/.test(x)) return BigInt(x);
  throw new Error("expected nonnegative exact satoshi amount");
}

function min(a,b) { return a < b ? a : b; }

function maxFlow(n, edges, s, t) {
  const g = Array.from({length:n},()=>[]);
  const forward = [];
  for (const [a,b,c0] of edges) {
    const c=amount(c0);
    if (!Number.isInteger(a)||!Number.isInteger(b)||a<0||b<0||a>=n||b>=n||a===b) throw new Error("invalid edge");
    const f={to:b,rev:g[b].length,cap:c}, r={to:a,rev:g[a].length,cap:0n};
    g[a].push(f);g[b].push(r);forward.push([f,c]);
  }
  if(s===t) throw new Error("source equals sink");
  let value=0n, reachable;
  while(true){
    const prev=Array(n).fill(null), q=[s];prev[s]=[-1,-1];
    for(let h=0;h<q.length;h++){
      const a=q[h];
      for(let k=0;k<g[a].length;k++){
        const e=g[a][k];if(e.cap>0n&&prev[e.to]===null){prev[e.to]=[a,k];q.push(e.to);}
      }
    }
    if(prev[t]===null){reachable=prev.map(x=>x!==null);break;}
    let d=null;
    for(let b=t;b!==s;){const [a,k]=prev[b];d=d===null?g[a][k].cap:min(d,g[a][k].cap);b=a;}
    for(let b=t;b!==s;){const [a,k]=prev[b],e=g[a][k];e.cap-=d;g[b][e.rev].cap+=d;b=a;}
    value+=d;
  }
  return {value,reachable,flow:forward.map(([e,c])=>c-e.cap)};
}

function normalize(C,D,R) {
  const c=C.map(amount),d=D.map(amount);
  const routes=R.map(([v,j,u])=>{
    if(!Number.isInteger(v)||!Number.isInteger(j)||v<0||j<0||v>=c.length||j>=d.length)throw new Error("invalid route index");
    return [v,j,amount(u)];
  });
  return {c,d,routes};
}

function cutDeficit(C,D,R,J) {
  const {c,d,routes}=normalize(C,D,R),set=new Set(J),u=c.map(()=>0n);
  if(set.size!==J.length||J.some(j=>!Number.isInteger(j)||j<0||j>=d.length))throw new Error("invalid cut");
  for(const [v,j,k] of routes)if(set.has(j))u[v]+=k;
  return J.reduce((a,j)=>a+d[j],0n)-c.reduce((a,k,v)=>a+min(k,u[v]),0n);
}

function analyze(C,D,R) {
  const {c,d,routes}=normalize(C,D,R),s=c.length+d.length,t=s+1;
  const edges=[...c.map((k,v)=>[s,v,k]),...routes.map(([v,j,k])=>[v,c.length+j,k]),...d.map((k,j)=>[c.length+j,t,k])];
  const a=maxFlow(t+1,edges,s,t),J=d.flatMap((_,j)=>a.reachable[c.length+j]?[]:[j]);
  const total=d.reduce((a,b)=>a+b,0n),deficit=total-a.value;
  const flow=a.flow.slice(c.length,c.length+routes.length);
  const out=c.map(()=>0n),inc=d.map(()=>0n);
  for(let i=0;i<routes.length;i++){const [v,j,k]=routes[i];if(flow[i]<0n||flow[i]>k)throw new Error("invalid flow certificate");out[v]+=flow[i];inc[j]+=flow[i];}
  if(out.some((x,v)=>x>c[v])||inc.some((x,j)=>x>d[j])||inc.reduce((a,b)=>a+b,0n)!==a.value||cutDeficit(c,d,routes,J)!==deficit)throw new Error("primal/cut mismatch");
  return {delivered:a.value,deficit,cut:J,flow,used:out,received:inc};
}

function routeIntervals(nVaults,nTargets,R,X,audited=[]) {
  if(!Number.isSafeInteger(nVaults)||!Number.isSafeInteger(nTargets)||nVaults<0||nTargets<0)throw new Error("invalid vertex count");
  const {routes}=normalize(Array(nVaults).fill(0n),Array(nTargets).fill(0n),R);
  const x=X.map(amount),fixed=new Set(audited);
  if(x.length!==routes.length||x.some((k,i)=>k>routes[i][2])||fixed.size!==audited.length||audited.some(i=>!Number.isInteger(i)||i<0||i>=x.length))throw new Error("invalid fibre");
  return routes.map(([v,j,u],i)=>{
    if(fixed.has(i))return [x[i],x[i]];
    const residual=[];
    for(let k=0;k<routes.length;k++){
      if(k===i||fixed.has(k))continue;
      const [a,b,c]=routes[k],w=nVaults+b;
      if(c>x[k])residual.push([a,w,c-x[k]]);
      if(x[k]>0n)residual.push([w,a,x[k]]);
    }
    const w=nVaults+j,n=nVaults+nTargets;
    const increase=min(u-x[i],maxFlow(n,residual,w,v).value);
    const decrease=min(x[i],maxFlow(n,residual,v,w).value);
    return [x[i]-decrease,x[i]+increase];
  });
}

export {amount, analyze, cutDeficit, routeIntervals};
