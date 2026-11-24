//! One approved image for leaf execution and recursive join. The external
//! verifier MUST pin the image ID both in receipt verification and the journal.
use risc0_zkvm::guest::env;
use shz_admission_recursive_core::{execute_leaf,join,Input,Journal};
fn main(){
 let result=match env::read::<Input>(){
  Input::Leaf(w)=>execute_leaf(&w).expect("invalid admission segment").1,
  Input::Join{left,right}=>{
   let a=Journal::decode(&left).expect("left journal");let b=Journal::decode(&right).expect("right journal");
   let parent=join(&a,&b).expect("invalid interval composition");
   // Assumptions are part of the execution claim. The host supplies actual
   // child receipts; succinct proving resolves them in the STARK recursion
   // circuit. An unresolved assumption cannot pass ordinary Receipt::verify.
   env::verify(parent.ctx.image_id,left.as_slice()).expect("left receipt assumption");
   env::verify(parent.ctx.image_id,right.as_slice()).expect("right receipt assumption");
   parent
  }
 };
 env::commit_slice(&result.encode().expect("canonical journal"));
}
