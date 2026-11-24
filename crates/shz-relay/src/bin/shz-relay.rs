//! Operator CLI for the HFT-06 relay.
//!
//!   shz-relay serve --config relay.json [--seconds N]
//!   shz-relay keygen --out key.hex          (prints only the public key)
//!   shz-relay dev-config --dir deploy/hft06 [--ws ADDR] [--http ADDR] [--state DIR]
//!   shz-relay subscribe --url ws://HOST:PORT --client-id ID --key-file F [--count N] [--from-seq S]
//!   shz-relay member --config member.json [--seconds N]
//!   shz-relay checkpoint --http HOST:PORT [--seq N]
//!   shz-relay bench [--clients N] [--seconds S] [--mode trusted_relay|federated|federated-remote] [--intermediate-us D] [--slow-client 1] [--out receipt.json]
//!
//! The relay signing key is read from SHZ_RELAY_SIGNING_KEY or
//! SHZ_RELAY_SIGNING_KEY_FILE; a federation member's key from
//! SHZ_MEMBER_SIGNING_KEY or SHZ_MEMBER_SIGNING_KEY_FILE. Nothing prints
//! secret material.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use shz_relay::{
    bench::{BenchOptions, run},
    client::sign_auth,
    config::{RelayConfig, h32, member_signing_key},
    member::{MemberConfig, MemberOptions, start_member},
    envelope::SecurityMode,
    schedule::ReleasePolicy,
    server::{ClientMsg, ServerMsg},
    service::{StartOptions, start},
};
use tokio_tungstenite::tungstenite::Message;

fn args() -> BTreeMap<String, String> {
    let v: Vec<String> = std::env::args().skip(2).collect();
    v.chunks(2).filter_map(|c| Some((c.first()?.trim_start_matches("--").to_string(), c.get(1).cloned().unwrap_or_default()))).collect()
}
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}
fn now_unix_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let a = args();
    match cmd.as_str() {
        "serve" => {
            let path = a.get("config").unwrap_or_else(|| die("--config required"));
            let cfg = RelayConfig::load(std::path::Path::new(path)).unwrap_or_else(|e| die(e));
            let secs = a.get("seconds").and_then(|s| s.parse().ok());
            let relay = start(cfg, StartOptions { run_seconds: secs, relay_key: None, collator: None, dev_federation: None }).await.unwrap_or_else(|e| die(e));
            eprintln!("shz-relay ws={} http={} mode={:?} production_ready=false", relay.ws_addr, relay.http_addr, relay.verifier.mode());
            let shared = relay.shared.clone();
            tokio::select! {
                r = relay.producer => if let Ok(Err(e)) = r { die(e) },
                _ = tokio::signal::ctrl_c() => {}
            }
            let _ = shared.shutdown.send(true);
        }
        "member" => {
            let path = a.get("config").unwrap_or_else(|| die("--config required"));
            let cfg = MemberConfig::load(std::path::Path::new(path)).unwrap_or_else(|e| die(e));
            let secret = member_signing_key().unwrap_or_else(|e| die(e));
            let secs = a.get("seconds").and_then(|s| s.parse().ok());
            let (idx, url) = (cfg.member, cfg.relay_url.clone());
            let m = start_member(cfg, secret, MemberOptions { collator: None, run_seconds: secs }).await.unwrap_or_else(|e| die(e));
            eprintln!("shz-relay member={idx} relay={url} production_ready=false");
            tokio::signal::ctrl_c().await.ok();
            m.shutdown().await;
        }
        "dev-config" => {
            // Local development config: fixture federation members (dev-only
            // keys), three client keys written to <dir>/clients/<id>.key.
            let dir = std::path::PathBuf::from(a.get("dir").unwrap_or_else(|| die("--dir required")));
            std::fs::create_dir_all(dir.join("clients")).unwrap_or_else(|e| die(e));
            let p = shz_oracle::collator::fixture::policy(1);
            let mut clients = Vec::new();
            for (id, tier) in [("premium-dev", "premium"), ("intermediate-dev", "intermediate"), ("standard-dev", "standard")] {
                let mut sk = [0u8; 32];
                loop {
                    OsRng.fill_bytes(&mut sk);
                    if shz_dlc::pubkey_x_from_secret(&sk).is_ok() {
                        break;
                    }
                }
                let kp = dir.join("clients").join(format!("{id}.key"));
                if !kp.exists() {
                    std::fs::write(&kp, hex::encode(sk)).unwrap_or_else(|e| die(e));
                }
                let sk = h32(std::fs::read_to_string(&kp).unwrap().trim()).unwrap();
                clients.push(serde_json::json!({"id": id, "tier": tier, "pubkey": hex::encode(shz_dlc::pubkey_x_from_secret(&sk).unwrap()), "max_connections": 2}));
            }
            let cfg = serde_json::json!({
                "mode": "trusted_relay",
                "policy": {"network": hex::encode(p.network), "market": hex::encode(p.market), "epoch": p.epoch, "origin_us": 0,
                           "members": p.members.map(hex::encode)},
                "release": ReleasePolicy::default(),
                "ws_listen": a.get("ws").cloned().unwrap_or("127.0.0.1:9440".into()),
                "http_listen": a.get("http").cloned().unwrap_or("127.0.0.1:9441".into()),
                "state_dir": a.get("state").cloned().unwrap_or("./state".into()),
                "history": 3000,
                "subscriber_queue": 256,
                "clients": clients,
                "source": {"kind": "synthetic", "seed": 20261124}
            });
            let out = dir.join("relay.local.json");
            std::fs::write(&out, serde_json::to_string_pretty(&cfg).unwrap()).unwrap_or_else(|e| die(e));
            println!("{}", out.display());
        }
        "keygen" => {
            let out = a.get("out").unwrap_or_else(|| die("--out required"));
            let mut sk = [0u8; 32];
            loop {
                OsRng.fill_bytes(&mut sk);
                if shz_dlc::pubkey_x_from_secret(&sk).is_ok() {
                    break;
                }
            }
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(out).unwrap_or_else(|e| die(format!("{out}: {e}")));
            f.write_all(hex::encode(sk).as_bytes()).unwrap();
            println!("{}", hex::encode(shz_dlc::pubkey_x_from_secret(&sk).unwrap()));
        }
        "subscribe" => {
            let url = a.get("url").unwrap_or_else(|| die("--url required"));
            let id = a.get("client-id").unwrap_or_else(|| die("--client-id required")).clone();
            let mut key = String::new();
            let key_file = a.get("key-file").unwrap_or_else(|| die("--key-file required"));
            std::fs::File::open(key_file).and_then(|mut f| f.read_to_string(&mut key)).unwrap_or_else(|e| die(e));
            let sk = h32(key.trim()).unwrap_or_else(|e| die(e));
            let count: u64 = a.get("count").and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
            let (mut ws, _) = tokio_tungstenite::connect_async(url.as_str()).await.unwrap_or_else(|e| die(e));
            let Some(Ok(m)) = ws.next().await else { die("no challenge") };
            let Ok(ServerMsg::Challenge { nonce, relay_id, server_us }) = serde_json::from_str(m.to_text().unwrap_or("")) else { die("bad challenge") };
            let offset = server_us as i64 - now_unix_us() as i64;
            let sig = sign_auth(&sk, &h32(&relay_id).unwrap(), &h32(&nonce).unwrap(), &id);
            let auth = ClientMsg::Auth { client_id: id, signature: hex::encode(sig.to_bytes()) };
            ws.send(Message::text(serde_json::to_string(&auth).unwrap())).await.unwrap_or_else(|e| die(e));
            let from_seq = a.get("from-seq").and_then(|s| s.parse().ok());
            ws.send(Message::text(serde_json::to_string(&ClientMsg::Subscribe { from_seq }).unwrap())).await.unwrap_or_else(|e| die(e));
            let mut n = 0;
            while let Some(Ok(m)) = ws.next().await {
                let local = now_unix_us() as i64 + offset;
                match serde_json::from_str::<ServerMsg>(m.to_text().unwrap_or("")) {
                    Ok(ServerMsg::Packet(d)) => {
                        let line = serde_json::json!({
                            "seq": d.seq, "tier": d.tier, "digest": d.digest, "late": d.late,
                            "recv_after_boundary_us": local - d.boundary_us as i64,
                            "recv_after_release_us": local - d.release_at_us as i64,
                            "clock_note": "server offset estimated from challenge; includes one-way delay"
                        });
                        println!("{line}");
                        n += 1;
                        if n >= count {
                            break;
                        }
                    }
                    Ok(other) => eprintln!("{}", serde_json::to_string(&other).unwrap()),
                    Err(_) => {}
                }
            }
        }
        "checkpoint" => {
            let host = a.get("http").unwrap_or_else(|| die("--http required"));
            let path = match a.get("seq") {
                Some(s) => format!("/v1/checkpoint/{s}"),
                None => "/v1/checkpoint/latest".into(),
            };
            let mut s = std::net::TcpStream::connect(host).unwrap_or_else(|e| die(e));
            write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").unwrap();
            let mut body = String::new();
            s.read_to_string(&mut body).unwrap();
            println!("{}", body.split("\r\n\r\n").nth(1).unwrap_or(""));
        }
        "bench" => {
            let mut release = ReleasePolicy::default();
            if let Some(d) = a.get("intermediate-us").and_then(|s| s.parse().ok()) {
                release.intermediate_delay_us = d;
            }
            release.validate().unwrap_or_else(|e| die(format!("{e:?}")));
            let opts = BenchOptions {
                clients_per_tier: a.get("clients").and_then(|s| s.parse().ok()).unwrap_or(4),
                seconds: a.get("seconds").and_then(|s| s.parse().ok()).unwrap_or(30),
                mode: match a.get("mode").map(|s| s.as_str()) {
                    Some("federated" | "federated-remote") => SecurityMode::Federated,
                    _ => SecurityMode::TrustedRelay,
                },
                remote_members: a.get("mode").is_some_and(|m| m == "federated-remote"),
                release,
                state_dir: std::env::temp_dir().join(format!("shz-relay-bench-{}", std::process::id())),
                slow_client: a.get("slow-client").is_some_and(|v| v == "1"),
            };
            let receipt = run(opts).await.unwrap_or_else(|e| die(e));
            let json = serde_json::to_string_pretty(&receipt).unwrap();
            match a.get("out") {
                Some(p) => std::fs::write(p, &json).unwrap_or_else(|e| die(e)),
                None => println!("{json}"),
            }
        }
        _ => die("usage: shz-relay serve|member|keygen|subscribe|checkpoint|bench (see source header)"),
    }
}
