// Bounded exact nonanticipative temporal placement. Information groups must be independently justified.
function policyTemporal(scenarios,n,upper,weights){
  // Group ids are externally supplied information sets at reservation time.
  // Jobs in a group must share arrival, demand and permitted route capacities.
  // Releases may differ because future recovery events need not be known.
  const groups=new Map();
  if(!Number.isInteger(n)||n<1||n>5||upper.length!==n||weights.length!==n||
     upper.some(x=>!Number.isInteger(x)||x<0||x>8)||
     weights.some(x=>!Number.isInteger(x)||x<1||x>1e6)||
     !scenarios.length||scenarios.length>8)throw Error("policy fixture bounds");
  for(let s=0;s<scenarios.length;s++){
    const sc=scenarios[s],seen=new Set();
    if(!Number.isInteger(sc.horizon)||sc.horizon<1||sc.horizon>400||sc.jobs.length>8||sc.horizon!==scenarios[0].horizon)throw Error("invalid horizon");
    for(const j of sc.jobs){
      if(typeof j.group!=="string"||seen.has(j.group)||!Number.isInteger(j.a)||!Number.isInteger(j.r)||j.a<0||j.r<=j.a||j.r>sc.horizon||
         !Number.isInteger(j.d)||j.d<1||j.d>3||j.u.length!==n||j.u.some(x=>!Number.isInteger(x)||x<0||x>8))throw Error("invalid grouped job");
      seen.add(j.group);
      if(!groups.has(j.group))groups.set(j.group,{a:j.a,d:j.d,u:j.u,instances:[]});
      const g=groups.get(j.group);
      if(g.a!==j.a||g.d!==j.d||g.u.some((x,v)=>x!==j.u[v]))throw Error("inconsistent information set");
      g.instances.push({s,a:j.a,r:j.r});
    }
  }
  const gs=[...groups.entries()].sort((a,b)=>a[1].a-b[1].a||a[0].localeCompare(b[0]));
  if(gs.length>16)throw Error("too many groups");
  const occ=scenarios.map(s=>Array.from({length:n},()=>Array(s.horizon).fill(0)));
  const peak=Array(n).fill(0),assignments=new Map();
  let best=null;
  const cost=()=>peak.reduce((a,b,v)=>a+b*weights[v],0);
  function visit(i){
    if(best&&cost()>=best.cost)return;
    if(i===gs.length){best={stock:peak.slice(),cost:cost(),policy:Object.fromEntries([...assignments].map(([k,x])=>[k,x.slice()]))};return;}
    const [id,g]=gs[i],x=Array(n).fill(0);
    function assign(v,left){
      if(v===n){
        if(left)return;
        const old=peak.slice();
        for(const {s,a,r} of g.instances)for(let k=0;k<n;k++)for(let t=a;t<r;t++){
          occ[s][k][t]+=x[k];peak[k]=Math.max(peak[k],occ[s][k][t]);
        }
        if(peak.every((p,k)=>p<=upper[k])){assignments.set(id,x.slice());visit(i+1);assignments.delete(id);}
        for(const {s,a,r} of g.instances)for(let k=0;k<n;k++)for(let t=a;t<r;t++)occ[s][k][t]-=x[k];
        for(let k=0;k<n;k++)peak[k]=old[k];
        return;
      }
      for(let k=0;k<=Math.min(left,g.u[v],upper[v]);k++){x[v]=k;assign(v+1,left-k);}
    }
    assign(0,g.d);
  }
  visit(0);
  return best;
}

function runPolicyChecks(){
  const assert=(x,m)=>{if(!x)throw Error(m);};
  const mask=m=>[0,1,2].map(i=>(m>>i)&1);
  const cases=(a,b,c)=>[
    {horizon:3,jobs:[{group:"common",a:0,r:3,d:1,u:mask(a)},{group:"futureA",a:1,r:3,d:1,u:mask(b)}]},
    {horizon:3,jobs:[{group:"common",a:0,r:3,d:1,u:mask(a)},{group:"futureB",a:1,r:3,d:1,u:mask(c)}]}
  ];
  function brute(a,b,c,shared){
    let min=Infinity;
    for(let i=0;i<3;i++)for(let j=0;j<3;j++)for(let k=0;k<3;k++)for(let l=0;l<3;l++){
      if(!(a&(1<<i))||!(b&(1<<j))||!(a&(1<<k))||!(c&(1<<l))||(shared&&i!==k))continue;
      let cost=0;
      for(let v=0;v<3;v++)cost+=Math.max(Number(i===v)+Number(j===v),Number(k===v)+Number(l===v));
      min=Math.min(min,cost);
    }
    return min;
  }
  let families=0,gaps=0,maxGap=0;
  for(let a=1;a<8;a++)for(let b=1;b<8;b++)for(let c=1;c<8;c++){
    const ss=cases(a,b,c),shared=policyTemporal(ss,3,[2,2,2],[1,1,1]);
    const separate=ss.map((s,i)=>({...s,jobs:s.jobs.map(j=>({...j,group:j.group==="common"?"common"+i:j.group}))}));
    const perfect=policyTemporal(separate,3,[2,2,2],[1,1,1]);
    assert(shared.cost===brute(a,b,c,true)&&perfect.cost===brute(a,b,c,false),"group optimum mismatch");
    assert(shared.cost>=perfect.cost,"nonanticipativity lower bound");
    const gap=shared.cost-perfect.cost;if(gap>0)gaps++;maxGap=Math.max(maxGap,gap);families++;
  }
  const witness=cases(3,1,2),single=policyTemporal(witness,3,[1,1,0],[1,1,1]);
  assert(single===null,"unit placement cannot promise both futures");
  const extra=policyTemporal(witness,3,[2,2,0],[1,1,1]);
  assert(extra.cost===3,"online-safe capital gap");
  const perfect=policyTemporal(witness.map((s,i)=>({...s,jobs:s.jobs.map(j=>({...j,group:j.group==="common"?"common"+i:j.group}))})),3,[1,1,0],[1,1,1]);
  assert(perfect.cost===2,"hindsight optimum");
  return {families,strict_nonanticipativity_gaps:gaps,max_gap_units:maxGap,witness:{hindsight_stock:perfect.stock,hindsight_cost:perfect.cost,nonanticipative_stock:extra.stock,nonanticipative_cost:extra.cost},scope:"two-scenario synthetic information sets; validity of the information partition is an external assumption"};
}

console.log(JSON.stringify(runPolicyChecks(),null,2));
