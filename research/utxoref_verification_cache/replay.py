"""Synthetic clearing trace using independent BIP341 encoding and BIP340 verification.
Public test-only keys and fictitious outpoints. No transactions submitted or authorized.
"""
from collections import OrderedDict, Counter
from dataclasses import dataclass, replace
from functools import lru_cache
import hashlib, json, time, ctypes as C, ctypes.util, heapq, random, sys
from cryptography.hazmat.primitives.asymmetric import ec

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
sha = lambda x: hashlib.sha256(x).digest()
le = lambda x,n: x.to_bytes(n,'little')
be = lambda x: x.to_bytes(32,'big')
def tag(t,m):
    h=sha(t); return sha(h+h+m)
def compact(n):
    if n<253: return bytes([n])
    if n<=65535: return b'\xfd'+le(n,2)
    return b'\xfe'+le(n,4)
@lru_cache(None)
def point(s):
    a=ec.derive_private_key(s,ec.SECP256K1()).public_key().public_numbers()
    return a.x,a.y
@lru_cache(None)
def pub(s): return be(point(s)[0])
def sign(s,m):
    px,py=point(s); d=s if py%2==0 else N-s
    t=bytes(x^y for x,y in zip(be(d),tag(b'BIP0340/aux',bytes(32))))
    k=int.from_bytes(tag(b'BIP0340/nonce',t+be(px)+m),'big')%N
    assert k
    rx,ry=point(k); k=k if ry%2==0 else N-k
    e=int.from_bytes(tag(b'BIP0340/challenge',be(rx)+be(px)+m),'big')%N
    return be(rx)+be((k+e*d)%N)

class Verify:
    """Independent native OpenSSL EC_POINT_mul verification; no verifier-side memoization."""
    def __init__(self):
        lib=C.CDLL(ctypes.util.find_library('crypto')); self.lib=lib; ptr=C.c_void_p
        def bind(name,args,res):
            f=getattr(lib,name); f.argtypes=args; f.restype=res; return f
        self.bn=bind('BN_bin2bn',[C.c_char_p,C.c_int,ptr],ptr); self.bnfree=bind('BN_free',[ptr],None)
        self.ctxnew=bind('BN_CTX_new',[],ptr); self.ctxfree=bind('BN_CTX_free',[ptr],None)
        nid=bind('OBJ_txt2nid',[C.c_char_p],C.c_int)(b'secp256k1')
        self.grp=bind('EC_GROUP_new_by_curve_name',[C.c_int],ptr)(nid); self.grp_free=bind('EC_GROUP_free',[ptr],None)
        self.ptnew=bind('EC_POINT_new',[ptr],ptr); self.ptfree=bind('EC_POINT_free',[ptr],None)
        self.oct=bind('EC_POINT_oct2point',[ptr,ptr,C.c_char_p,C.c_size_t,ptr],C.c_int)
        self.mul=bind('EC_POINT_mul',[ptr,ptr,ptr,ptr,ptr,ptr],C.c_int)
        self.inf=bind('EC_POINT_is_at_infinity',[ptr,ptr],C.c_int)
        self.out=bind('EC_POINT_point2oct',[ptr,ptr,C.c_int,ptr,C.c_size_t,ptr],C.c_size_t)
        self.ctx=self.ctxnew(); self.pk=self.ptnew(self.grp); self.r=self.ptnew(self.grp)
        assert self.grp and self.ctx and self.pk and self.r
    def __call__(self,key):
        pk,m,sig=key[:32],key[32:64],key[64:]; assert len(key)==128
        rx,s=int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')
        if int.from_bytes(pk,'big')>=P or rx>=P or s>=N: return False
        if self.oct(self.grp,self.pk,b'\x02'+pk,33,self.ctx)!=1: return False
        e=int.from_bytes(tag(b'BIP0340/challenge',sig[:32]+pk+m),'big')%N
        bn_s=self.bn(be(s),32,None); bn_e=self.bn(be((-e)%N),32,None); assert bn_s and bn_e
        try:
            assert self.mul(self.grp,self.r,bn_s,self.pk,bn_e,self.ctx)==1
            if self.inf(self.grp,self.r): return False
            buf=C.create_string_buffer(33); assert self.out(self.grp,self.r,2,buf,33,self.ctx)==33
            return buf.raw==b'\x02'+sig[:32]
        finally: self.bnfree(bn_s); self.bnfree(bn_e)
    def close(self):
        self.ptfree(self.pk); self.ptfree(self.r); self.ctxfree(self.ctx); self.grp_free(self.grp)

@dataclass(frozen=True)
class Input:
    outpoint: bytes; amount: int; script: bytes; seq: int=0xfffffffe
@dataclass(frozen=True)
class Tx:
    ins: tuple; outs: tuple; version: int=2; locktime: int=1000
    def sighash(self,i,ht,leaf):
        assert ht in (0,1,0x83) and 0<=i<len(self.ins)
        p=b'\0'+bytes([ht])+le(self.version,4)+le(self.locktime,4)
        def encout(o): return le(o[0],8)+compact(len(o[1]))+o[1]
        if ht!=0x83:
            p+=sha(b''.join(x.outpoint for x in self.ins))+sha(b''.join(le(x.amount,8) for x in self.ins))
            p+=sha(b''.join(compact(len(x.script))+x.script for x in self.ins))+sha(b''.join(le(x.seq,4) for x in self.ins))
            p+=sha(b''.join(encout(o) for o in self.outs))
        p+=bytes([2 if leaf is not None else 0])
        if ht==0x83:
            x=self.ins[i]; p+=x.outpoint+le(x.amount,8)+compact(len(x.script))+x.script+le(x.seq,4)
            p+=sha(encout(self.outs[i]))
        else: p+=le(i,4)
        if leaf is not None: p+=leaf+b'\0'+b'\xff'*4
        return tag(b'TapSighash',p)

def script(s): return b'\x51\x20'+pub(s)
def outpoint(root,kind,i): return sha(f'fixture/{root}/{kind}/{i}'.encode())+le(i,4)
def leaf(root,kind,i): return tag(b'TapLeaf',f'fixture-leaf/{root}/{kind}/{i}'.encode())
def key(s,m): return pub(s)+m+sign(s,m)

def candidate(root,regime,c):
    rng=random.Random(root*100003+c)
    if regime=='pinned': off=[0,1,2,3]
    elif regime=='rotating': off=[0,1,2+c%10,2+(c+3)%10]
    else: off=[c*4+i for i in range(4)]
    rng.shuffle(off); on=[c%12,(c+5)%12]
    inputs=tuple(Input(outpoint(root,'off',i),100000,script(10000+i)) for i in off)+tuple(Input(outpoint(root,'on',i),100000,script(20000+i)) for i in on)
    pay=100000+17*c
    outputs=tuple((60000,script(30000+i)) for i in off)+((pay,script(40000+c%5)),(600000-240000-330-1500-pay,script(41000+c%7)),(330,script(42000)))
    tx=Tx(inputs,outputs); assert sum(x.amount for x in inputs)==sum(v for v,s in outputs)+1500
    req=[]
    for j,i in enumerate(off):
        l=leaf(root,'off',i); d=tx.sighash(j,0x83,l); a=tx.sighash(j,1,l)
        assert d==Tx((inputs[j],),(outputs[j],)).sighash(0,0x83,l)
        req.extend([(key(50000+i,d),'pinned'),(key(60000+i,a),'all'),(key(70000,a),'all')])
    for j,i in enumerate(on,len(off)):
        d=tx.sighash(j,0,leaf(root,'on',i)); req.extend([(key(80000+i,d),'default'),(key(81000+i,d),'default')])
    return tx,off,req

def mutation_audit(verify):
    tx,off,req=candidate(1,'pinned',0); l=leaf(1,'off',off[0]); original=tx.sighash(0,0x83,l); signed=req[0][0]; full=req[1][0]
    assert verify(signed) and verify(full)
    def ci(**kw): return replace(tx,ins=(replace(tx.ins[0],**kw),)+tx.ins[1:])
    def co(j,o): return replace(tx,outs=tx.outs[:j]+(o,)+tx.outs[j+1:])
    def vat(k,d): return verify(k[:32]+d+k[64:])
    changed=[(replace(tx,version=3),l),(replace(tx,locktime=1001),l),(ci(outpoint=bytes(36)),l),(ci(amount=100001),l),(ci(script=script(13)),l),(ci(seq=0xfffffffd),l),(co(0,(60001,tx.outs[0][1])),l),(co(0,(60000,script(14))),l),(tx,bytes(32))]
    for t,ll in changed:
        d=t.sighash(0,0x83,ll); assert d!=original and not vat(signed,d)
    assert not vat(signed,tx.sighash(0,1,l)) and not vat(signed,tx.sighash(0,0,l))
    uncommitted=[replace(tx,ins=(tx.ins[0],replace(tx.ins[1],amount=100001))+tx.ins[2:]),co(4,(tx.outs[4][0]+1,tx.outs[4][1])),replace(tx,outs=tx.outs[:4]+tuple(reversed(tx.outs[4:])))]
    for t in uncommitted:
        assert t.sighash(0,0x83,l)==original and vat(signed,t.sighash(0,0x83,l))
        assert t.sighash(0,1,l)!=tx.sighash(0,1,l) and not vat(full,t.sighash(0,1,l))
    moved=replace(tx,ins=(tx.ins[1],tx.ins[0])+tx.ins[2:],outs=(tx.outs[1],tx.outs[0])+tx.outs[2:])
    assert moved.sighash(1,0x83,l)==original and vat(signed,moved.sighash(1,0x83,l)) and not vat(full,moved.sighash(1,1,l))
    for pos in [0,32,64,127]:
        k=bytearray(signed); k[pos]^=1; assert not verify(bytes(k))
    return dict(bound_mutations=len(changed)+2,uncommitted_changes=len(uncommitted),paired_reorder=1,tuple_mutations=4)

def make_trace(root,regime):
    rng=random.Random(root); drafts=[]; ids=[]; trace=[]; typ=[]; seen={}
    for c in range(24):
        _,_,r=candidate(root,regime,c); drafts.append(r)
        order=[c]
        if c%3==2: order+=[c,rng.randrange(c+1)]
        for n in order:
            ids.append(n)
            for k,t in drafts[n]:
                if k not in seen: seen[k]=len(seen); typ.append(t)
                trace.append(seen[k])
    return list(seen),typ,trace,ids

def run_policy(keys,types,trace,cap,mode,verify=None):
    cache=OrderedDict(); hits=miss=0; by=Counter(); start=time.perf_counter()
    for idx in trace:
        key=keys[idx]; kind=types[idx]
        if key in cache:
            hits+=1; count,old=cache[key]; cache[key]=(count+1,old); cache.move_to_end(key); continue
        miss+=1; by[kind]+=1
        if verify is not None: assert verify(key)
        if cap==0: continue
        if mode=='pinned_only' and kind!='pinned': continue
        if len(cache)==cap:
            if mode=='pinned_priority':
                victim=next((k for k,(_,t) in cache.items() if t!='pinned'),None)
                if victim is None:
                    if kind!='pinned': continue
                    victim=next(iter(cache))
                del cache[victim]
            elif mode=='lfu': del cache[min(cache,key=lambda k:cache[k][0])]
            else: cache.popitem(last=False)
        cache[key]=(1,kind)
    return dict(hits=hits,misses=miss,miss_type=dict(by),elapsed_ms=(time.perf_counter()-start)*1000)

def oracle(trace,cap):
    nxt={}; ends=[len(trace)]*len(trace)
    for i in range(len(trace)-1,-1,-1): ends[i]=nxt.get(trace[i],len(trace)); nxt[trace[i]]=i
    active={}; heap=[]; miss=0
    for i,(k,end) in enumerate(zip(trace,ends)):
        miss+=int(k not in active); active.pop(k,None)
        if end<len(trace): active[k]=end; heapq.heappush(heap,(-end,k))
        while len(active)>cap:
            neg,j=heapq.heappop(heap)
            if active.get(j)==-neg: del active[j]
    return miss

def main():
    v=Verify(); audit=mutation_audit(v); rows=[]
    for regime in ('pinned','rotating','churn'):
        for root in (91,92,93):
            keys,types,trace,ids=make_trace(root,regime); policies={}
            for cap in (16,32,64,128):
                policies[str(cap)]={m:run_policy(keys,types,trace,cap,m,v if cap==32 else None) for m in ('lru','pinned_priority','pinned_only','lfu')}
                policies[str(cap)]['oracle']={'misses':oracle(trace,cap)}
                assert all(x['misses']>=policies[str(cap)]['oracle']['misses'] for x in policies[str(cap)].values())
            cold=run_policy(keys,types,trace,0,'lru',v)
            rows.append(dict(regime=regime,root=root,candidates=len(ids),distinct=len(keys),requests=len(trace),distinct_types=dict(Counter(types)),cold=cold,policies=policies))
            print(regime,root,len(trace),round(cold['elapsed_ms']),{m:p['misses'] for m,p in policies['32'].items()},file=sys.stderr,flush=True)
    v.close(); return dict(scope='independent synthetic digest fixture; not Rust/Bitcoin Core/real LN',audit=audit,rows=rows)
if __name__=='__main__': print(json.dumps(main(),indent=2))
