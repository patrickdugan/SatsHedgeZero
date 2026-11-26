import { openJournal } from './journal.mjs';
import { checkpointStore } from './checkpoint.mjs';
process.once('message',({dir,pins,policy,id,record,mode})=>{
  const store=checkpointStore(pins,id),before=store.read(),j=openJournal(dir,policy,id,before),after=j.append(record);
  if(mode==='after-cas')store.compareAndSwap(before,after);
  process.send(after);setInterval(()=>{},1000);
});
