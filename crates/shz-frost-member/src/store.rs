//! Durable writes: temp file in the same directory, fsync, rename, fsync the directory
//! (`frost.SignerState._save`, `dlc_oracle._atomic_write`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::json::{PyErr, R};

fn os_err(e: std::io::Error) -> PyErr {
    PyErr::new("OSError", e.to_string())
}

pub fn atomic_write(path: &Path, prefix: &str, data: &[u8]) -> R<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut n = 0u32;
    let (tmp, mut f) = loop {
        let tmp = dir.join(format!("{prefix}{}{}", std::process::id(), hex8(crate::ec::rand32())));
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        match o.open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 8 => n += 1,
            Err(e) => return Err(os_err(e)),
        }
    };
    let res = (|| {
        f.write_all(data)?;
        f.flush()?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(os_err(e));
    }
    #[cfg(unix)]
    {
        let d = fs::File::open(dir).map_err(os_err)?;
        d.sync_all().map_err(os_err)?;
    }
    Ok(())
}

fn hex8(b: [u8; 32]) -> String {
    crate::json::hex(&b[..4])
}
