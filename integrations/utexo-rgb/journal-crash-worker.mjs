import { openJournal } from './journal.mjs';
process.once('message', ({dir,policy,id,pin,record})=>{
  const j=openJournal(dir,policy,id,pin);
  process.send(j.append(record));
  // Deliberately hold the writer lock until the test parent kills this process.
  setInterval(()=>{},1000);
});
