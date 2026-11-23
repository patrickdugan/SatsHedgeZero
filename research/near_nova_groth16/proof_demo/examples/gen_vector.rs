use std::{fs,env};
use shz_groth16_price_proof::{prove_prices, SCALE};
fn main(){
 let argv:Vec<String>=env::args().collect();
 let result=prove_prices(100_000*SCALE,100_200*SCALE,100_100*SCALE);
 assert!(result.native_verified);
 let json=serde_json::to_string_pretty(&result).expect("json");
 if let Some(path)=argv.get(1){fs::write(path,&json).expect("write file");println!("Wrote Groth16 vector to {path}");}
 else {println!("{json}");}
}
