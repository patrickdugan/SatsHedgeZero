//! Atomic live progress `%` telemetry emitter (`rbzk-nova-progress-v1`) consumed by
//! `rbzk-prover-ui` ("ZK Rusto no Bitcoino Prover" desktop console).
//!
//! Writes `/tmp/shz-mnr05-live-progress.json` (plus `<artifacts_dir>/live_progress.json`) via
//! atomic `.tmp -> rename` and binds `(pid, start_ticks)` from `/proc/self/stat` so stale files
//! never appear as an active prover if a process exits unexpectedly.
#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub const DEFAULT_LIVE_PROGRESS_PATH: &str = "/tmp/shz-mnr05-live-progress.json";
pub const TOTAL_PIPELINE_STEPS: u32 = 20;

fn unix_now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn linux_start_ticks() -> Option<u64> {
    let raw = fs::read_to_string("/proc/self/stat").ok()?;
    let after = raw.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    fields.get(19)?.parse().ok()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NovaLiveProgressSnapshot {
    pub schema: &'static str,
    pub kind: &'static str,
    pub title: &'static str,
    pub network: &'static str,
    pub backend: &'static str,
    pub pid: u32,
    pub start_ticks: Option<u64>,
    pub started_at_unix: f64,
    pub updated_at_unix: f64,
    pub stage: String,
    pub phase: String,
    pub completed_steps: u32,
    pub total_steps: u32,
    pub fold_step: Option<u32>,
    pub fold_total: Option<u32>,
    pub progress_pct: f64,
    pub recent_lines: Vec<String>,
}

pub struct Mnr05ProgressReporter {
    primary_path: PathBuf,
    mirror_path: Option<PathBuf>,
    pid: u32,
    start_ticks: Option<u64>,
    started_at_unix: f64,
    recent_lines: Vec<String>,
}

impl Mnr05ProgressReporter {
    pub fn new(artifacts_dir: Option<&Path>) -> Self {
        let primary_path = std::env::var_os("RBZK_NOVA_PROGRESS_JSON")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LIVE_PROGRESS_PATH));
        let mirror_path = artifacts_dir.map(|d| d.join("live_progress.json"));
        Self {
            primary_path,
            mirror_path,
            pid: std::process::id(),
            start_ticks: linux_start_ticks(),
            started_at_unix: unix_now_f64(),
            recent_lines: Vec::with_capacity(12),
        }
    }

    pub fn emit(
        &mut self,
        stage: &str,
        phase: impl Into<String>,
        completed_steps: u32,
        fold_step: Option<u32>,
        fold_total: Option<u32>,
        progress_pct: f64,
    ) {
        let phase_str = phase.into();
        let pct = progress_pct.clamp(0.0, 100.0);
        let elapsed = (unix_now_f64() - self.started_at_unix).max(0.0);
        self.recent_lines
            .push(format!("[{elapsed:5.1}s | {pct:5.1}%] {phase_str}"));
        if self.recent_lines.len() > 10 {
            self.recent_lines.remove(0);
        }

        let snap = NovaLiveProgressSnapshot {
            schema: "rbzk-nova-progress-v1",
            kind: "mnr05",
            title: "SHZ-MNR-05 Batched BitVM3 & PTLC Proof",
            network: "SatsHedgeZero · Core 31.1 Regtest",
            backend: "Nova Spartan/IPA · CPU (0 GPU VRAM)",
            pid: self.pid,
            start_ticks: self.start_ticks,
            started_at_unix: self.started_at_unix,
            updated_at_unix: unix_now_f64(),
            stage: stage.to_owned(),
            phase: phase_str,
            completed_steps,
            total_steps: TOTAL_PIPELINE_STEPS,
            fold_step,
            fold_total,
            progress_pct: (pct * 10.0).round() / 10.0,
            recent_lines: self.recent_lines.clone(),
        };

        if let Ok(bytes) = serde_json::to_vec_pretty(&snap) {
            Self::write_atomic(&self.primary_path, &bytes);
            if let Some(ref m) = self.mirror_path {
                Self::write_atomic(m, &bytes);
            }
        }
    }

    fn write_atomic(target: &Path, bytes: &[u8]) {
        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let tmp = target.with_extension(format!("tmp.{}", std::process::id()));
        if fs::write(&tmp, bytes).is_ok() {
            let _ = fs::rename(&tmp, target);
        }
    }
}
