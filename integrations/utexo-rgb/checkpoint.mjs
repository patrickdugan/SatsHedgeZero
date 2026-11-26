import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { createJournal, openJournal } from './journal.mjs';

const check=(ok,msg)=>{if(!ok)throw new Error(msg)};
const hex=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s)&&!/^0+$/.test(s);
const valid=p=>p&&Object.keys(p).sort().join(',')==='digest,seq'&&Number.isSafeInteger(p.seq)&&p.seq>=0&&hex(p.digest);
const same=(a,b)=>valid(a)&&valid(b)&&a.seq===b.seq&&a.digest===b.digest;
const syncDir=d=>{const fd=fs.openSync(d,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}};
const privateDir=d=>{const s=fs.lstatSync(d);check(s.isDirectory()&&!(s.mode&0o077),'private directory required')};

// Separate trusted local filesystem reference. No automatic stale lock recovery.
function checkpointStore(dir,id,initial){
  check(process.platform==='linux'&&hex(id),'Linux and valid journal identity required');dir=path.resolve(dir);
  const file=path.join(dir,'head.json'),lock=path.join(dir,'.cas');
  function write(pin){
    const tmp=path.join(dir,'.head-'+randomBytes(16).toString('hex'));
    const fd=fs.openSync(tmp,'wx',0o600);
    try{fs.writeFileSync(fd,JSON.stringify({id,seq:pin.seq,digest:pin.digest})+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
    fs.renameSync(tmp,file);syncDir(dir);
  }
  function read(){
    const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    try{const s=fs.fstatSync(fd);check(s.isFile()&&!(s.mode&0o077)&&s.size<=1024,'invalid checkpoint file');
      const x=JSON.parse(fs.readFileSync(fd,'utf8'));const {id:stored,...pin}=x;
      check(stored===id&&valid(pin),'invalid checkpoint identity');return pin;
    }finally{fs.closeSync(fd)}
  }
  function locked(fn){
    fs.mkdirSync(lock,{mode:0o700});
    try{syncDir(dir);return fn()}finally{fs.rmdirSync(lock);syncDir(dir)}
  }
  if(initial!==undefined){check(valid(initial)&&initial.seq===0,'genesis required');fs.mkdirSync(dir,{mode:0o700});syncDir(path.dirname(dir));privateDir(dir);locked(()=>write(initial))}
  privateDir(dir);read();
  return Object.freeze({read,compareAndSwap(expected,next){
    check(valid(expected)&&valid(next)&&next.seq===expected.seq+1&&next.digest!==expected.digest,'invalid checkpoint advance');
    return locked(()=>{check(same(read(),expected),'checkpoint CAS mismatch');write(next);return read()});
  }});
}
function coordinator(j,store){
  let fenced=false,closed=false;
  const usable=()=>check(!closed&&!fenced,'coordinator fenced or closed');
  check(same(j.tip(),store.read()),'initial pin mismatch');
  return Object.freeze({
    tip(){usable();return j.tip()}, snapshot(){usable();return j.snapshot()},
    append(record){
      usable();const before=j.tip();
      // Any uncertainty about either persistence service fences the coordinator.
      try{check(same(before,store.read()),'external pin drift');const next=j.append(record);check(same(store.compareAndSwap(before,next),next),'checkpoint acknowledgement mismatch');return next}
      catch(e){fenced=true;throw e}
    },
    close(){if(!closed){closed=true;j.close()}}
  });
}
function createCoordinator(journalDir,pinDir,policy,id){
  check(path.resolve(journalDir)!==path.resolve(pinDir),'separate checkpoint path required');
  const j=createJournal(journalDir,policy,id);
  try{return coordinator(j,checkpointStore(pinDir,id,j.tip()))}catch(e){j.close();throw e}
}
function openCoordinator(journalDir,pinDir,policy,id){
  const store=checkpointStore(pinDir,id),j=openJournal(journalDir,policy,id,store.read());
  try{return coordinator(j,store)}catch(e){j.close();throw e}
}
export { checkpointStore, coordinator, createCoordinator, openCoordinator };
