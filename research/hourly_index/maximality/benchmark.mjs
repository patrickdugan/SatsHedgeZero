import {performance} from 'node:perf_hooks';
import {GENESIS_TESTNET4,shahex} from '../index.mjs';
import {buildLog,select,verifySelection} from './log.mjs';
const n=144000,depth=18,step=200000n,t0=1792800000000000n;
const start=performance.now();const entries=Array.from({length:n},(_,i)=>({price_e8:String(10_000_000_000_000n+BigInt(i)),publish_us:String(t0+BigInt(i)*step),report_hash:shahex(Buffer.from('synthetic/scale/'+i))}));
const builtAt=performance.now();const seal=t0+BigInt(n)*step;
const tree=buildLog({genesis:GENESIS_TESTNET4,source:'pyth',entries,depth,sealed_through:String(seal)});const endBuild=performance.now();let valid=0,earlierRejected=0;
const cutoffs=Array.from({length:8},(_,i)=>t0+BigInt((i+1)*18000-1)*step);
for(const cutoff of cutoffs){let w=select(tree,cutoff),args={pin:tree.pin,cutoff,source:'pyth',genesis:GENESIS_TESTNET4};if(!verifySelection(w,args))throw Error('selection');valid++;let i=Number(w.index)-1;let a={header:tree.header,index:String(i),candidate:tree.candidates[i],siblings:tree.path(i)};if(verifySelection(a,args))throw Error('earlier accepted');earlierRejected++;}
const done=performance.now();console.log(JSON.stringify({schema:'shz/index-max/scale-reference/v1',synthetic:true,node:process.version,observations:n,depth,period_us:Number(step),valid_hourly_paths:valid,authentic_earlier_paths_rejected:earlierRejected,per_path_sibling_bytes:40*depth,naive_two_path_sibling_bytes:64*depth,generation_ms:Math.round(builtAt-start),tree_build_ms:Math.round(endBuild-builtAt),eight_selections_and_negative_controls_ms:Math.round(done-endBuild),rss_bytes:process.memoryUsage().rss,root:tree.pin,source_authentication:false,nova_verified:false,provider_completeness:false},null,2));
