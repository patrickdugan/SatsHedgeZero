//! `shz-hftd` — SatsHedgeZero Sub-Millisecond HFT Gateway & Back-End Protocol Explorer Daemon.
#![forbid(unsafe_code)]

use std::{env, path::PathBuf, thread, time::Duration};

use shz_hftd::{HftServerConfig, spawn_hftd_server};

fn main() {
    let mut bind_addr =
        env::var("SHZ_HFTD_BIND").unwrap_or_else(|_| "127.0.0.1:8090".to_owned());
    let mut ui_dir =
        PathBuf::from(env::var("SHZ_UI_PUBLIC_DIR").unwrap_or_else(|_| "ui/public".to_owned()));
    let mut rollup_ms: u64 = 300_000;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" if i + 1 < args.len() => {
                bind_addr = args[i + 1].clone();
                i += 2;
            }
            "--ui-dir" if i + 1 < args.len() => {
                ui_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--rollup-ms" if i + 1 < args.len() => {
                rollup_ms = args[i + 1].parse().unwrap_or(300_000);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let handle = spawn_hftd_server(HftServerConfig {
        bind_addr,
        ui_public_dir: ui_dir,
        rollup_interval_ms: rollup_ms,
        enable_live_oracle: true,
        enable_auto_mm: true,
    })
    .expect("failed to bind shz-hftd listener");

    println!(
        "[shz-hftd] listening on http://{} (WS: ws://{}/v1/ws | Explorer: http://{}/explorer)",
        handle.local_addr, handle.local_addr, handle.local_addr
    );

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
