//! HTTP/1.0 server with the member handler's semantics (`BaseHTTPRequestHandler`, one request
//! per connection) and the F-11 limits of `public_relay.LimitedHTTPServer`: 256 connections,
//! 32 per address (a one-line 503 before any thread starts), 10 s per socket read or write.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::json::{self, J, PyErr, Style};
use crate::member::{MAX_BODY, Member, obj};

pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_CONNECTIONS_PER_IP: usize = 32;
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LINE: usize = 65_536;
const MAX_HEADERS: usize = 100;

#[derive(Default)]
struct Conns {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

pub fn serve(m: Arc<Member>, listener: TcpListener) {
    let conns = Arc::new(Mutex::new(Conns::default()));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let Ok(peer) = stream.peer_addr() else { continue };
        let ip = peer.ip();
        let full = {
            let mut c = conns.lock().unwrap();
            let full = c.total >= MAX_CONNECTIONS || c.per_ip.get(&ip).copied().unwrap_or(0) >= MAX_CONNECTIONS_PER_IP;
            if !full {
                c.total += 1;
                *c.per_ip.entry(ip).or_insert(0) += 1;
            }
            full
        };
        if full {
            stream.set_write_timeout(Some(Duration::from_secs(1))).ok();
            let _ = stream.write_all(b"HTTP/1.0 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.shutdown(std::net::Shutdown::Both);
            continue;
        }
        let (m, conns) = (m.clone(), conns.clone());
        std::thread::spawn(move || {
            let _ = handle(&m, stream);
            let mut c = conns.lock().unwrap();
            c.total -= 1;
            let n = c.per_ip.get(&ip).copied().unwrap_or(1) - 1;
            if n == 0 {
                c.per_ip.remove(&ip);
            } else {
                c.per_ip.insert(ip, n);
            }
        });
    }
}

fn phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        414 => "Request-URI Too Long",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        _ => "Error",
    }
}

fn http_date() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{}, {:02} {} {} {:02}:{:02}:{:02} GMT", WD[days.rem_euclid(7) as usize], d, MO[(mo - 1) as usize], y, rem / 3600, rem % 3600 / 60, rem % 60)
}

fn respond(s: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.0 {code} {}\r\nServer: shz-frost-member\r\nDate: {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
        phrase(code),
        http_date(),
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    s.write_all(&out)?;
    s.flush()
}

fn respond_json(s: &mut TcpStream, code: u16, j: &J) -> std::io::Result<()> {
    respond(s, code, "application/json", json::dumps(j, Style::Default).as_bytes())
}

fn send_error(s: &mut TcpStream, code: u16, msg: &str) -> std::io::Result<()> {
    let body = format!(
        "<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        <title>Error response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n        <p>Error code: {code}</p>\n        <p>Message: {msg}.</p>\n    </body>\n</html>\n"
    );
    respond(s, code, "text/html;charset=utf-8", body.as_bytes())
}

fn handle(m: &Member, mut s: TcpStream) -> std::io::Result<()> {
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_LINE * 2 {
            return send_error(&mut s, 431, "Line too long");
        }
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut body = buf[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    if request_line.len() > MAX_LINE {
        return send_error(&mut s, 414, "Request-URI Too Long");
    }
    let words: Vec<&str> = request_line.split_whitespace().collect();
    if words.len() != 3 || !words[2].starts_with("HTTP/") {
        return send_error(&mut s, 400, &format!("Bad request syntax ({})", json::py_repr_str(request_line)));
    }
    let method = words[0];
    let mut path = words[1].to_string();
    if path.starts_with("//") {
        path = format!("/{}", path.trim_start_matches('/'));
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    for l in lines {
        if headers.len() >= MAX_HEADERS {
            return send_error(&mut s, 431, "Too many headers");
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.to_ascii_lowercase(), v.trim_start_matches([' ', '\t']).to_string()));
        }
    }
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    match method {
        "GET" => {
            if path == "/healthz" {
                match m.healthz() {
                    Ok(h) => respond_json(&mut s, 200, &h),
                    Err(e) => respond_json(&mut s, 500, &obj(vec![("error", J::s(e.to_string()))])),
                }
            } else {
                respond_json(&mut s, 404, &obj(vec![("error", J::s("not found"))]))
            }
        }
        "POST" => {
            let (len, cl_err) = match header("content-length") {
                None => (0i128, None),
                Some(v) => match json::py_int_str(v) {
                    Ok(n) => (n.clamp(0, MAX_BODY), None),
                    Err(e) => (0, Some(PyErr::value(e.msg))),
                },
            };
            let len = len as usize;
            if cl_err.is_none() {
                while body.len() < len {
                    let n = s.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                body.truncate(len);
            } else {
                body.clear();
            }
            let (code, resp) = m.post(&path, &body, header(&crate::auth::HEADER.to_ascii_lowercase()), cl_err);
            respond_json(&mut s, code, &resp)
        }
        other => send_error(&mut s, 501, &format!("Unsupported method ({})", json::py_repr_str(other))),
    }
}
