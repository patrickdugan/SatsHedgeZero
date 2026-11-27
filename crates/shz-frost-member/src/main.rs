//! `shz-frost-member`: same command line as `frost_signer.py`.
//!
//!   shz-frost-member --share share.json --state DIR --listen 127.0.0.1:9101 --coord-auth-key KEY
//!   shz-frost-member keygen --t 3 --n 5 --out DIR     (trusted dealer)

use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::process::exit;
use std::sync::{Arc, Mutex};

use shz_frost_member::auth::{self, Verifier};
use shz_frost_member::frost::{OsRng, Rng, Share};
use shz_frost_member::json::{self, Style};
use shz_frost_member::member::{MAX_DEVIATION_BPS, Member, VIEW_MAX_AGE_S, VIEW_REFRESH_S};
use shz_frost_member::view::{self, SourceView, View};
use shz_frost_member::{keygen, server};

const PROG: &str = "shz-frost-member";

struct Spec {
    name: &'static str,
    takes_value: bool,
    metavar: &'static str,
}

fn usage(specs: &[Spec], sub: bool) -> String {
    let mut u = format!("usage: {PROG} [-h]");
    if sub {
        u.push_str(" cmd");
    }
    for s in specs {
        let item = if s.takes_value { format!("{} {}", s.name, s.metavar) } else { s.name.to_string() };
        let required = matches!(s.name, "--share" | "--state" | "--out");
        u.push_str(&if required { format!(" {item}") } else { format!(" [{item}]") });
    }
    u
}

fn fail(specs: &[Spec], sub: bool, msg: &str) -> ! {
    eprintln!("{}\n{PROG}: error: {msg}", usage(specs, sub));
    exit(2)
}

/// argparse-style parsing: `--opt value`, `--opt=value`, unique prefixes, `-h`.
fn parse(args: &[String], specs: &[Spec], required: &[&str], sub: bool) -> Vec<(&'static str, Option<String>)> {
    let mut out = Vec::new();
    let mut extra = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "-h" || a == "--help" {
            println!("{}", usage(specs, sub));
            exit(0);
        }
        if !a.starts_with("--") {
            extra.push(a.clone());
            i += 1;
            continue;
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (a.as_str(), None),
        };
        let exact = specs.iter().find(|s| s.name == name);
        let cands: Vec<&Spec> = if let Some(e) = exact { vec![e] } else { specs.iter().filter(|s| s.name.starts_with(name)).collect() };
        if cands.len() > 1 {
            let names: Vec<&str> = cands.iter().map(|s| s.name).collect();
            fail(specs, sub, &format!("ambiguous option: {name} could match {}", names.join(", ")));
        }
        let Some(spec) = cands.first() else {
            extra.push(a.clone());
            i += 1;
            continue;
        };
        if spec.takes_value {
            let v = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    match args.get(i) {
                        Some(v) if !v.starts_with("--") => v.clone(),
                        _ => fail(specs, sub, &format!("argument {}: expected one argument", spec.name)),
                    }
                }
            };
            out.push((spec.name, Some(v)));
        } else {
            if let Some(v) = inline {
                fail(specs, sub, &format!("argument {}: ignored explicit argument '{v}'", spec.name));
            }
            out.push((spec.name, None));
        }
        i += 1;
    }
    let missing: Vec<&str> = required.iter().copied().filter(|r| !out.iter().any(|(n, _)| n == r)).collect();
    if !missing.is_empty() {
        fail(specs, sub, &format!("the following arguments are required: {}", missing.join(", ")));
    }
    let allowed_extra = if sub { 1 } else { 0 };
    if extra.len() > allowed_extra {
        fail(specs, sub, &format!("unrecognized arguments: {}", extra[allowed_extra..].join(" ")));
    }
    out
}

fn last(opts: &[(&'static str, Option<String>)], name: &str) -> Option<String> {
    opts.iter().rev().find(|(n, _)| *n == name).and_then(|(_, v)| v.clone())
}

fn has(opts: &[(&'static str, Option<String>)], name: &str) -> bool {
    opts.iter().any(|(n, _)| *n == name)
}

fn int_arg(specs: &[Spec], name: &str, v: Option<String>, default: i128) -> i128 {
    match v {
        None => default,
        Some(s) => json::py_int_str(&s).unwrap_or_else(|_| fail(specs, false, &format!("argument {name}: invalid int value: '{s}'"))),
    }
}

fn float_arg(specs: &[Spec], name: &str, v: Option<String>, default: f64) -> f64 {
    match v {
        None => default,
        Some(s) => s.trim().parse::<f64>().unwrap_or_else(|_| fail(specs, false, &format!("argument {name}: invalid float value: '{s}'"))),
    }
}

fn die(msg: String) -> ! {
    eprintln!("{PROG}: {msg}");
    exit(1)
}

fn keygen_main(args: &[String]) {
    let specs = [
        Spec { name: "--t", takes_value: true, metavar: "T" },
        Spec { name: "--n", takes_value: true, metavar: "N" },
        Spec { name: "--out", takes_value: true, metavar: "OUT" },
    ];
    let o = parse(args, &specs, &["--out"], true);
    let t = int_arg(&specs, "--t", last(&o, "--t"), 3);
    let n = int_arg(&specs, "--n", last(&o, "--n"), 5);
    let out = last(&o, "--out").unwrap();
    let out = Path::new(&out);
    std::fs::create_dir_all(out).unwrap_or_else(|e| die(e.to_string()));
    let (group, shares) = keygen::keygen(t, n, &mut OsRng).unwrap_or_else(|e| die(format!("ValueError: {e}")));
    std::fs::write(out.join("group.json"), json::dumps(&group, Style::Indent1)).unwrap_or_else(|e| die(e.to_string()));
    for s in &shares {
        let idx = s.at("index").ok().and_then(|i| i.strict_int()).unwrap();
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(out.join(format!("share{idx}.json"))).unwrap_or_else(|e| die(e.to_string()));
        f.write_all(json::dumps(s, Style::Default).as_bytes()).unwrap_or_else(|e| die(e.to_string()));
    }
    println!("{}", group.at("group_pubkey").unwrap().as_str().unwrap());
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("keygen") {
        return keygen_main(&args);
    }
    #[allow(unused_mut)]
    let mut specs = vec![
        Spec { name: "--share", takes_value: true, metavar: "SHARE" },
        Spec { name: "--state", takes_value: true, metavar: "STATE" },
        Spec { name: "--listen", takes_value: true, metavar: "LISTEN" },
        Spec { name: "--max-deviation-bps", takes_value: true, metavar: "MAX_DEVIATION_BPS" },
        Spec { name: "--view-refresh-s", takes_value: true, metavar: "VIEW_REFRESH_S" },
        Spec { name: "--view-max-age-s", takes_value: true, metavar: "VIEW_MAX_AGE_S" },
        Spec { name: "--no-price-check", takes_value: false, metavar: "" },
        Spec { name: "--coord-auth-key", takes_value: true, metavar: "COORD_AUTH_KEY" },
        Spec { name: "--no-coord-auth", takes_value: false, metavar: "" },
    ];
    #[cfg(feature = "test-hooks")]
    specs.extend([
        Spec { name: "--test-hooks", takes_value: true, metavar: "URL" },
        Spec { name: "--test-view", takes_value: true, metavar: "static|none" },
        Spec { name: "--test-dlc-path", takes_value: true, metavar: "FILE" },
    ]);
    let o = parse(&args, &specs, &["--share", "--state"], false);
    let max_dev = int_arg(&specs, "--max-deviation-bps", last(&o, "--max-deviation-bps"), MAX_DEVIATION_BPS);
    let refresh = float_arg(&specs, "--view-refresh-s", last(&o, "--view-refresh-s"), VIEW_REFRESH_S);
    let max_age = float_arg(&specs, "--view-max-age-s", last(&o, "--view-max-age-s"), VIEW_MAX_AGE_S);
    let no_price = has(&o, "--no-price-check");
    let key_path = last(&o, "--coord-auth-key").filter(|k| !k.is_empty());
    let no_auth = has(&o, "--no-coord-auth");
    if key_path.is_some() == no_auth {
        fail(&specs, false, "give exactly one of --coord-auth-key or --no-coord-auth");
    }
    let share_path = last(&o, "--share").unwrap();
    let raw = std::fs::read(&share_path).unwrap_or_else(|e| die(format!("{share_path}: {e}")));
    let share_j = json::loads_bytes(&raw).unwrap_or_else(|e| die(format!("{share_path}: {e}")));
    let share = Share::from_json(&share_j).unwrap_or_else(|e| die(format!("{share_path}: {e}")));
    let mut view = if no_price {
        View::NoCheck
    } else {
        let offset = (share.index - 1) as f64 * refresh / share.signers as f64;
        let v = Arc::new(SourceView::new(refresh, offset));
        let r = v.clone();
        std::thread::spawn(move || r.run());
        View::Source(v)
    };
    #[cfg(not(feature = "test-hooks"))]
    let dlc_path: Option<String> = None;
    #[cfg(feature = "test-hooks")]
    let dlc_path = last(&o, "--test-dlc-path");
    #[cfg(feature = "test-hooks")]
    {
        match last(&o, "--test-view").as_deref() {
            Some("static") => view = View::Static(Mutex::new(Default::default())),
            Some("none") => view = View::Missing,
            Some(other) => fail(&specs, false, &format!("argument --test-view: invalid choice: '{other}'")),
            None => {}
        }
    }
    let _ = &mut view;
    let index = share.index;
    let gpk = share.group_pubkey.clone();
    let group_x = share.group_x.clone();
    let state = last(&o, "--state").unwrap();
    let rng: Arc<Mutex<Box<dyn Rng>>> = Arc::new(Mutex::new(Box::new(OsRng)));
    let mut m = Member::new(share, Path::new(&state), dlc_path.as_deref().map(Path::new), view, max_dev, max_age, rng, Box::new(view::now_us))
        .unwrap_or_else(|e| die(format!("{state}: {e}")));
    if let Some(k) = &key_path {
        let key = auth::read_key(k).unwrap_or_else(|e| die(format!("ValueError: {e}")));
        m.verifier = Some(Verifier::new(key, group_x, index as u32));
    }
    #[cfg(feature = "test-hooks")]
    if let Some(u) = last(&o, "--test-hooks") {
        *m.hooks.url.lock().unwrap() = Some(u);
    }
    let listen = last(&o, "--listen").unwrap_or_else(|| "127.0.0.1:9101".into());
    let (host, port) = listen.rsplit_once(':').unwrap_or_else(|| die(format!("bad --listen {listen}")));
    let port: u16 = port.parse().unwrap_or_else(|_| die(format!("bad --listen {listen}")));
    let listener = TcpListener::bind((host, port)).unwrap_or_else(|e| die(format!("{listen}: {e}")));
    println!(
        "frost member {index} group={gpk} listen={listen} price_check={} coord_auth={}",
        if no_price { "off" } else { "on" },
        if m.verifier.is_some() { "on" } else { "OFF" }
    );
    std::io::stdout().flush().ok();
    server::serve(Arc::new(m), listener);
}
