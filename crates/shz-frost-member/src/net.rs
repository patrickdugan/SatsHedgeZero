//! Minimal HTTP/1.1 client: HTTPS GET for the member's own price reading, plain POST for the
//! test-hook callbacks.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const MAX_BODY: usize = 1_000_000;

struct Url<'a> {
    https: bool,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url(url: &str) -> Result<Url<'_>, String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("unsupported url {url}"));
    };
    let (hostport, path) = match rest.find('/') {
        Some(p) => (&rest[..p], &rest[p..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "bad port".to_string())?),
        None => (hostport, if https { 443 } else { 80 }),
    };
    Ok(Url { https, host, port, path })
}

fn connect(u: &Url, timeout: Duration) -> Result<TcpStream, String> {
    let addrs = (u.host, u.port).to_socket_addrs().map_err(|e| format!("URLError: {e}"))?;
    let mut last = String::from("URLError: no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(timeout)).ok();
                s.set_write_timeout(Some(timeout)).ok();
                return Ok(s);
            }
            Err(e) => last = format!("URLError: {e}"),
        }
    }
    Err(last)
}

fn exchange<S: Read + Write>(mut s: S, req: &[u8]) -> Result<(u16, Vec<u8>), String> {
    s.write_all(req).map_err(|e| format!("OSError: {e}"))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BODY + 65_536 {
                    break;
                }
            }
            // Servers that close TLS without close_notify still delivered the whole body.
            Err(e) if !raw.is_empty() && matches!(e.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset) => break,
            Err(e) => return Err(format!("timeout: {e}")),
        }
    }
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("RemoteDisconnected: no header")?;
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let mut body = raw[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or("BadStatusLine")?;
    let mut chunked = false;
    let mut length: Option<usize> = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            } else if k == "content-length" {
                length = v.parse().ok();
            }
        }
    }
    if chunked {
        let mut out = Vec::new();
        let mut p = 0;
        loop {
            let le = body[p..].windows(2).position(|w| w == b"\r\n").ok_or("IncompleteRead")? + p;
            let size_txt = String::from_utf8_lossy(&body[p..le]).to_string();
            let size = usize::from_str_radix(size_txt.split(';').next().unwrap_or("").trim(), 16).map_err(|_| "IncompleteRead")?;
            p = le + 2;
            if size == 0 {
                break;
            }
            if p + size > body.len() {
                return Err("IncompleteRead".into());
            }
            out.extend_from_slice(&body[p..p + size]);
            p += size + 2;
        }
        body = out;
    } else if let Some(n) = length {
        if body.len() < n {
            return Err("IncompleteRead".into());
        }
        body.truncate(n);
    }
    body.truncate(MAX_BODY);
    Ok((status, body))
}

fn request(url: &str, method: &str, body: Option<&[u8]>, timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let u = parse_url(url)?;
    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: shz-public-relay/1\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        u.path, u.host
    );
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    if let Some(b) = body {
        bytes.extend_from_slice(b);
    }
    let tcp = connect(&u, timeout)?;
    if u.https {
        tls_exchange(u.host, tcp, &bytes)
    } else {
        exchange(tcp, &bytes)
    }
}

#[cfg(feature = "fetch")]
fn tls_exchange(host: &str, tcp: TcpStream, req: &[u8]) -> Result<(u16, Vec<u8>), String> {
    use std::sync::OnceLock;
    static CONNECTOR: OnceLock<Result<native_tls::TlsConnector, String>> = OnceLock::new();
    let c = CONNECTOR
        .get_or_init(|| native_tls::TlsConnector::new().map_err(|e| format!("SSLError: {e}")))
        .as_ref()
        .map_err(|e| e.clone())?;
    let s = c.connect(host, tcp).map_err(|e| format!("SSLError: {e}"))?;
    exchange(s, req)
}

#[cfg(not(feature = "fetch"))]
fn tls_exchange(_host: &str, _tcp: TcpStream, _req: &[u8]) -> Result<(u16, Vec<u8>), String> {
    Err("URLError: built without the fetch feature".into())
}

/// GET returning the body of a 2xx response (urllib raises HTTPError on >= 400).
pub fn get(url: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let (status, body) = request(url, "GET", None, timeout)?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTPError: {status}"));
    }
    Ok(body)
}

pub fn post(url: &str, body: &[u8], timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    request(url, "POST", Some(body), timeout)
}
