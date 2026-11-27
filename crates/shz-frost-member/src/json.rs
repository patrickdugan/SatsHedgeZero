//! JSON with Python `json` semantics.
//!
//! The member hashes coordinator-supplied JSON (`canonical(body)`, the announcement core) and
//! rewrites state files Python members wrote, so it needs Python's exact behaviour: object keys
//! keep first-insertion order with last-value-wins, integers are not floats (`1` vs `1.0`),
//! `NaN`/`Infinity` parse, and the encoder reproduces `json.dumps` byte for byte
//! (`ensure_ascii`, `repr(float)`, both separator styles, `sort_keys`, `indent=1`).

use std::cmp::Ordering;
use std::fmt;

/// A Python exception surfaced to the coordinator as `"{kind}: {msg}"`.
#[derive(Debug, Clone, PartialEq)]
pub struct PyErr {
    pub kind: &'static str,
    pub msg: String,
}

impl PyErr {
    pub fn value(msg: impl Into<String>) -> Self {
        PyErr { kind: "ValueError", msg: msg.into() }
    }
    pub fn type_(msg: impl Into<String>) -> Self {
        PyErr { kind: "TypeError", msg: msg.into() }
    }
    pub fn key(k: &str) -> Self {
        PyErr { kind: "KeyError", msg: py_repr_str(k) }
    }
    pub fn new(kind: &'static str, msg: impl Into<String>) -> Self {
        PyErr { kind, msg: msg.into() }
    }
}

impl fmt::Display for PyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

pub type R<T> = Result<T, PyErr>;

#[derive(Debug, Clone)]
pub enum J {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn obj() -> J {
        J::Obj(Vec::new())
    }
    pub fn s(v: impl Into<String>) -> J {
        J::Str(v.into())
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            J::Null => "NoneType",
            J::Bool(_) => "bool",
            J::Int(_) => "int",
            J::Float(_) => "float",
            J::Str(_) => "str",
            J::Arr(_) => "list",
            J::Obj(_) => "dict",
        }
    }
    /// `d.get(key)` for a dict (None when absent); AttributeError for other types.
    pub fn get(&self, key: &str) -> R<Option<&J>> {
        match self {
            J::Obj(v) => Ok(v.iter().find(|(k, _)| k == key).map(|(_, v)| v)),
            other => Err(PyErr::new("AttributeError", format!("'{}' object has no attribute 'get'", other.type_name()))),
        }
    }
    /// `d.get(key)` returning `J::Null` for an absent key.
    pub fn get_or_null(&self, key: &str) -> R<J> {
        Ok(self.get(key)?.cloned().unwrap_or(J::Null))
    }
    /// `d[key]`.
    pub fn at(&self, key: &str) -> R<&J> {
        match self {
            J::Obj(v) => v.iter().find(|(k, _)| k == key).map(|(_, v)| v).ok_or_else(|| PyErr::key(key)),
            J::Arr(_) => Err(PyErr::type_("list indices must be integers or slices, not str")),
            J::Str(_) => Err(PyErr::type_("string indices must be integers, not 'str'")),
            other => Err(PyErr::type_(format!("'{}' object is not subscriptable", other.type_name()))),
        }
    }
    pub fn at_mut(&mut self, key: &str) -> R<&mut J> {
        match self {
            J::Obj(v) => v.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v).ok_or_else(|| PyErr::key(key)),
            other => Err(PyErr::type_(format!("'{}' object is not subscriptable", other.type_name()))),
        }
    }
    pub fn idx(&self, i: usize) -> R<&J> {
        match self {
            J::Arr(v) => v.get(i).ok_or_else(|| PyErr::new("IndexError", "list index out of range")),
            J::Str(_) => Err(PyErr::type_("string index is not a JSON value")),
            other => Err(PyErr::type_(format!("'{}' object is not subscriptable", other.type_name()))),
        }
    }
    pub fn contains_key(&self, key: &str) -> bool {
        matches!(self, J::Obj(v) if v.iter().any(|(k, _)| k == key))
    }
    /// `d[key] = value`: replaces in place, or appends a new key.
    pub fn set(&mut self, key: &str, value: J) {
        if let J::Obj(v) = self {
            if let Some(slot) = v.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value;
            } else {
                v.push((key.to_string(), value));
            }
        }
    }
    /// `d.pop(key, None)`.
    pub fn pop(&mut self, key: &str) -> Option<J> {
        if let J::Obj(v) = self
            && let Some(p) = v.iter().position(|(k, _)| k == key)
        {
            return Some(v.remove(p).1);
        }
        None
    }
    pub fn as_str(&self) -> Option<&str> {
        if let J::Str(s) = self { Some(s) } else { None }
    }
    pub fn str_or(&self, what: &str) -> R<&str> {
        self.as_str().ok_or_else(|| PyErr::type_(format!("{what} must be str, not {}", self.type_name())))
    }
    /// `not x` for a container.
    pub fn is_empty(&self) -> R<bool> {
        Ok(self.len()? == 0)
    }
    /// `len(x)`.
    pub fn len(&self) -> R<usize> {
        match self {
            J::Arr(v) => Ok(v.len()),
            J::Obj(v) => Ok(v.len()),
            J::Str(s) => Ok(s.chars().count()),
            other => Err(PyErr::type_(format!("object of type '{}' has no len()", other.type_name()))),
        }
    }
    /// Iteration as in Python: list items, dict keys, string characters.
    pub fn iter_py(&self) -> R<Vec<J>> {
        match self {
            J::Arr(v) => Ok(v.clone()),
            J::Obj(v) => Ok(v.iter().map(|(k, _)| J::Str(k.clone())).collect()),
            J::Str(s) => Ok(s.chars().map(|c| J::Str(c.to_string())).collect()),
            other => Err(PyErr::type_(format!("'{}' object is not iterable", other.type_name()))),
        }
    }
    pub fn items(&self) -> R<&Vec<(String, J)>> {
        match self {
            J::Obj(v) => Ok(v),
            other => Err(PyErr::new("AttributeError", format!("'{}' object has no attribute 'items'", other.type_name()))),
        }
    }
    pub fn truthy(&self) -> bool {
        match self {
            J::Null => false,
            J::Bool(b) => *b,
            J::Int(i) => *i != 0,
            J::Float(f) => *f != 0.0,
            J::Str(s) => !s.is_empty(),
            J::Arr(v) => !v.is_empty(),
            J::Obj(v) => !v.is_empty(),
        }
    }
    /// `type(x) is int` (bool excluded).
    pub fn strict_int(&self) -> Option<i128> {
        if let J::Int(i) = self { Some(*i) } else { None }
    }
}

// ------------------------------------------------------------ numbers ----

#[derive(Debug, Clone, Copy)]
pub enum Num {
    I(i128),
    F(f64),
}

// `cmp`/`eq`/`sub` are Python's int/float semantics (partial, mixed types), not the std traits.
#[allow(clippy::should_implement_trait)]
impl Num {
    pub fn of(j: &J) -> Option<Num> {
        match j {
            J::Int(i) => Some(Num::I(*i)),
            J::Bool(b) => Some(Num::I(*b as i128)),
            J::Float(f) => Some(Num::F(*f)),
            _ => None,
        }
    }
    pub fn need(j: &J) -> R<Num> {
        Num::of(j).ok_or_else(|| PyErr::type_(format!("'{}' is not a number", j.type_name())))
    }
    /// Python's exact int/float comparison.
    pub fn cmp(self, o: Num) -> Option<Ordering> {
        match (self, o) {
            (Num::I(a), Num::I(b)) => Some(a.cmp(&b)),
            (Num::F(a), Num::F(b)) => a.partial_cmp(&b),
            (Num::I(a), Num::F(b)) => cmp_int_float(a, b),
            (Num::F(a), Num::I(b)) => cmp_int_float(b, a).map(Ordering::reverse),
        }
    }
    pub fn lt(self, o: Num) -> bool {
        self.cmp(o) == Some(Ordering::Less)
    }
    pub fn le(self, o: Num) -> bool {
        matches!(self.cmp(o), Some(Ordering::Less | Ordering::Equal))
    }
    pub fn eq(self, o: Num) -> bool {
        self.cmp(o) == Some(Ordering::Equal)
    }
    /// `a - b` with Python's int/float promotion.
    pub fn sub(self, o: Num) -> Num {
        match (self, o) {
            (Num::I(a), Num::I(b)) => Num::I(a - b),
            (a, b) => Num::F(a.f() - b.f()),
        }
    }
    fn f(self) -> f64 {
        match self {
            Num::I(i) => i as f64,
            Num::F(f) => f,
        }
    }
}

fn cmp_int_float(a: i128, b: f64) -> Option<Ordering> {
    if b.is_nan() {
        return None;
    }
    if b >= 1.7e38 {
        return Some(Ordering::Less);
    }
    if b <= -1.7e38 {
        return Some(Ordering::Greater);
    }
    let t = b.trunc();
    let ti = t as i128;
    match a.cmp(&ti) {
        Ordering::Equal => {
            let frac = b - t;
            Some(if frac > 0.0 { Ordering::Less } else if frac < 0.0 { Ordering::Greater } else { Ordering::Equal })
        }
        o => Some(o),
    }
}

/// Python `==` on JSON values.
pub fn py_eq(a: &J, b: &J) -> bool {
    if let (Some(x), Some(y)) = (Num::of(a), Num::of(b)) {
        return x.eq(y);
    }
    match (a, b) {
        (J::Null, J::Null) => true,
        (J::Str(x), J::Str(y)) => x == y,
        (J::Arr(x), J::Arr(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (J::Obj(x), J::Obj(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.iter().any(|(k2, v2)| k == k2 && py_eq(v, v2)))
        }
        _ => false,
    }
}

pub fn is_str(j: &J, s: &str) -> bool {
    matches!(j, J::Str(x) if x == s)
}

/// Python `int(x)` for JSON values.
pub fn py_int(j: &J) -> R<i128> {
    match j {
        J::Int(i) => Ok(*i),
        J::Bool(b) => Ok(*b as i128),
        J::Float(f) => {
            if f.is_nan() {
                Err(PyErr::value("cannot convert float NaN to integer"))
            } else if f.is_infinite() {
                Err(PyErr::new("OverflowError", "cannot convert float infinity to integer"))
            } else if f.abs() >= 1.7e38 {
                Err(PyErr::new("OverflowError", "integer out of range"))
            } else {
                Ok(f.trunc() as i128)
            }
        }
        J::Str(s) => py_int_str(s),
        J::Null => Err(PyErr::type_("int() argument must be a string, a bytes-like object or a real number, not 'NoneType'")),
        other => Err(PyErr::type_(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            other.type_name()
        ))),
    }
}

fn invalid_literal(s: &str, base: u32) -> PyErr {
    PyErr::value(format!("invalid literal for int() with base {base}: {}", py_repr_str(s)))
}

/// Digits of `int(s, base)`: whitespace strip, sign, optional `0x` (base 16), single underscores
/// between digits. Returns (negative, big-endian magnitude digits).
fn py_int_digits(s: &str, base: u32) -> R<(bool, Vec<u8>)> {
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let mut rest = t;
    let mut neg = false;
    if let Some(r) = rest.strip_prefix('-') {
        neg = true;
        rest = r;
    } else if let Some(r) = rest.strip_prefix('+') {
        rest = r;
    }
    // 0 = start, 1 = after a base prefix, 2 = after a digit, 3 = after an underscore.
    let mut prev = 0u8;
    if base == 16
        && let Some(r) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X"))
    {
        rest = r;
        prev = 1;
    }
    let mut digits = Vec::with_capacity(rest.len());
    for c in rest.chars() {
        if c == '_' {
            if prev != 1 && prev != 2 {
                return Err(invalid_literal(s, base));
            }
            prev = 3;
            continue;
        }
        let d = c.to_digit(base).ok_or_else(|| invalid_literal(s, base))?;
        digits.push(d as u8);
        prev = 2;
    }
    if prev != 2 {
        return Err(invalid_literal(s, base));
    }
    Ok((neg, digits))
}

/// Python `int(s)` (base 10) into i128.
pub fn py_int_str(s: &str) -> R<i128> {
    let (neg, digits) = py_int_digits(s, 10)?;
    let mut v: i128 = 0;
    for d in digits {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(d as i128))
            .ok_or_else(|| PyErr::new("OverflowError", "integer too large for this member"))?;
    }
    Ok(if neg { -v } else { v })
}

/// Python `int(s, 16)` as (negative, big-endian magnitude bytes), any length.
pub fn py_int_hex(s: &str) -> R<(bool, Vec<u8>)> {
    let (neg, digits) = py_int_digits(s, 16)?;
    let mut bytes = vec![0u8; digits.len().div_ceil(2)];
    let off = bytes.len() * 2 - digits.len();
    for (i, d) in digits.iter().enumerate() {
        let p = i + off;
        bytes[p / 2] |= if p % 2 == 0 { d << 4 } else { *d };
    }
    Ok((neg, bytes))
}

/// `bytes.fromhex(s)`: pairs of hex digits, ASCII whitespace allowed between pairs.
pub fn py_fromhex(s: &str) -> R<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    let hexval = |c: u8| (c as char).to_digit(16);
    while i < b.len() {
        if matches!(b[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            i += 1;
            continue;
        }
        let hi = hexval(b[i]);
        let lo = b.get(i + 1).and_then(|&c| hexval(c));
        match (hi, lo) {
            (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
            _ => {
                let pos = if hi.is_none() { i } else { i + 1 };
                return Err(PyErr::value(format!("non-hexadecimal number found in fromhex() arg at position {pos}")));
            }
        }
        i += 2;
    }
    Ok(out)
}

pub fn fromhex_j(j: &J) -> R<Vec<u8>> {
    match j {
        J::Str(s) => py_fromhex(s),
        other => Err(PyErr::type_(format!("fromhex() argument must be str, not {}", other.type_name()))),
    }
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn py_repr_str(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut o = String::new();
    o.push(q);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c == q => {
                o.push('\\');
                o.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => o.push_str(&format!("\\x{:02x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push(q);
    o
}

// ------------------------------------------------------------- parser ----

pub fn loads_bytes(raw: &[u8]) -> R<J> {
    let raw = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let s = std::str::from_utf8(raw).map_err(|e| PyErr::new("UnicodeDecodeError", format!("'utf-8' codec can't decode bytes: {e}")))?;
    loads(s)
}

pub fn loads(s: &str) -> R<J> {
    let mut p = Parser { s: s.as_bytes(), i: 0, src: s };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(p.err("Extra data"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    src: &'a str,
}

impl Parser<'_> {
    fn err(&self, what: &str) -> PyErr {
        let before = &self.src[..self.i.min(self.src.len())];
        let line = before.matches('\n').count() + 1;
        let col = before.rfind('\n').map(|p| before[p + 1..].chars().count()).unwrap_or(before.chars().count()) + 1;
        let ch = before.chars().count();
        PyErr::new("JSONDecodeError", format!("{what}: line {line} column {col} (char {ch})"))
    }
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn lit(&mut self, w: &str) -> bool {
        if self.s[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            true
        } else {
            false
        }
    }
    fn value(&mut self) -> R<J> {
        if self.i >= self.s.len() {
            return Err(self.err("Expecting value"));
        }
        match self.s[self.i] {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => {
                self.i += 1;
                Ok(J::Str(self.string()?))
            }
            b'n' | b't' | b'f' | b'N' | b'I' | b'-' => {
                for (w, v) in [("null", J::Null), ("true", J::Bool(true)), ("false", J::Bool(false)), ("NaN", J::Float(f64::NAN)), ("Infinity", J::Float(f64::INFINITY)), ("-Infinity", J::Float(f64::NEG_INFINITY))] {
                    if self.lit(w) {
                        return Ok(v);
                    }
                }
                if self.s[self.i] == b'-' { self.number() } else { Err(self.err("Expecting value")) }
            }
            b'0'..=b'9' => self.number(),
            _ => Err(self.err("Expecting value")),
        }
    }
    fn number(&mut self) -> R<J> {
        let start = self.i;
        let d = |p: &Self, k: usize| p.s.get(k).is_some_and(|c| c.is_ascii_digit());
        if self.s[self.i] == b'-' {
            self.i += 1;
        }
        if !d(self, self.i) {
            self.i = start;
            return Err(self.err("Expecting value"));
        }
        if self.s[self.i] == b'0' {
            self.i += 1;
        } else {
            while d(self, self.i) {
                self.i += 1;
            }
        }
        let mut float = false;
        if self.s.get(self.i) == Some(&b'.') && d(self, self.i + 1) {
            float = true;
            self.i += 1;
            while d(self, self.i) {
                self.i += 1;
            }
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            let mut k = self.i + 1;
            if matches!(self.s.get(k), Some(b'+' | b'-')) {
                k += 1;
            }
            if d(self, k) {
                float = true;
                self.i = k;
                while d(self, self.i) {
                    self.i += 1;
                }
            }
        }
        let text = &self.src[start..self.i];
        if float {
            Ok(J::Float(text.parse::<f64>().map_err(|_| self.err("Expecting value"))?))
        } else {
            text.parse::<i128>()
                .map(J::Int)
                .map_err(|_| PyErr::new("OverflowError", "integer too large for this member"))
        }
    }
    fn hex4(&mut self) -> R<u32> {
        let h = self.s.get(self.i..self.i + 4).ok_or_else(|| self.err("Invalid \\uXXXX escape"))?;
        let t = std::str::from_utf8(h).map_err(|_| self.err("Invalid \\uXXXX escape"))?;
        if !t.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(self.err("Invalid \\uXXXX escape"));
        }
        self.i += 4;
        Ok(u32::from_str_radix(t, 16).unwrap())
    }
    fn string(&mut self) -> R<String> {
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.s.len() && self.s[self.i] != b'"' && self.s[self.i] != b'\\' && self.s[self.i] >= 0x20 {
                self.i += 1;
            }
            out.push_str(&self.src[start..self.i]);
            if self.i >= self.s.len() {
                return Err(self.err("Unterminated string starting at"));
            }
            match self.s[self.i] {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let c = *self.s.get(self.i).ok_or_else(|| self.err("Unterminated string starting at"))?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&u) && self.s[self.i..].starts_with(b"\\u") {
                                let save = self.i;
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xdc00..0xe000).contains(&lo) {
                                    0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00)
                                } else {
                                    self.i = save;
                                    u
                                }
                            } else {
                                u
                            };
                            // Lone surrogates are valid in Python strings, not in Rust ones.
                            out.push(char::from_u32(cp).ok_or_else(|| self.err("Lone surrogate not supported by this member"))?);
                        }
                        _ => {
                            self.i -= 2;
                            return Err(self.err("Invalid \\escape"));
                        }
                    }
                }
                _ => return Err(self.err("Invalid control character at")),
            }
        }
    }
    fn array(&mut self) -> R<J> {
        self.i += 1;
        let mut v = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(J::Arr(v));
        }
        loop {
            self.ws();
            v.push(self.value()?);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(J::Arr(v));
                }
                _ => return Err(self.err("Expecting ',' delimiter")),
            }
        }
    }
    fn object(&mut self) -> R<J> {
        self.i += 1;
        let mut o = J::obj();
        self.ws();
        if self.s.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(o);
        }
        loop {
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return Err(self.err("Expecting property name enclosed in double quotes"));
            }
            self.i += 1;
            let k = self.string()?;
            self.ws();
            if self.s.get(self.i) != Some(&b':') {
                return Err(self.err("Expecting ':' delimiter"));
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            o.set(&k, v);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(o);
                }
                _ => return Err(self.err("Expecting ',' delimiter")),
            }
        }
    }
}

// ------------------------------------------------------------ encoder ----

#[derive(Clone, Copy)]
pub enum Style {
    /// `json.dumps(obj)`: `", "` and `": "`.
    Default,
    /// `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
    Canonical,
    /// `json.dumps(obj, indent=1)`.
    Indent1,
}

pub fn dumps(j: &J, style: Style) -> String {
    let mut o = String::new();
    enc(j, style, 0, &mut o);
    o
}

pub fn py_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let e = format!("{f:e}"); // shortest round-trip digits, e.g. "-1.2345e-5"
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let (neg, mant) = mant.strip_prefix('-').map(|m| (true, m)).unwrap_or((false, mant));
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if decpt > 16 || decpt <= -4 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let x = decpt - 1;
        out.push_str(&format!("e{}{:02}", if x < 0 { '-' } else { '+' }, x.abs()));
    } else if decpt <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-decpt) as usize));
        out.push_str(&digits);
    } else {
        let d = decpt as usize;
        if digits.len() <= d {
            out.push_str(&digits);
            out.push_str(&"0".repeat(d - digits.len()));
            out.push_str(".0");
        } else {
            out.push_str(&digits[..d]);
            out.push('.');
            out.push_str(&digits[d..]);
        }
    }
    out
}

fn enc_str(s: &str, o: &mut String) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            ' '..='~' => o.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    o.push_str(&format!("\\u{:04x}", u));
                }
            }
        }
    }
    o.push('"');
}

fn enc(j: &J, st: Style, depth: usize, o: &mut String) {
    let (item_sep, kv_sep) = match st {
        Style::Default => (", ", ": "),
        Style::Canonical => (",", ":"),
        Style::Indent1 => (",", ": "),
    };
    let nl = |o: &mut String, d: usize| {
        if let Style::Indent1 = st {
            o.push('\n');
            o.push_str(&" ".repeat(d));
        }
    };
    match j {
        J::Null => o.push_str("null"),
        J::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
        J::Int(i) => o.push_str(&i.to_string()),
        J::Float(f) => o.push_str(&py_float_repr(*f)),
        J::Str(s) => enc_str(s, o),
        J::Arr(v) => {
            if v.is_empty() {
                o.push_str("[]");
                return;
            }
            o.push('[');
            for (k, x) in v.iter().enumerate() {
                if k > 0 {
                    o.push_str(item_sep);
                }
                nl(o, depth + 1);
                enc(x, st, depth + 1, o);
            }
            nl(o, depth);
            o.push(']');
        }
        J::Obj(v) => {
            if v.is_empty() {
                o.push_str("{}");
                return;
            }
            let mut items: Vec<&(String, J)> = v.iter().collect();
            if let Style::Canonical = st {
                items.sort_by(|a, b| a.0.cmp(&b.0));
            }
            o.push('{');
            for (k, (key, x)) in items.into_iter().enumerate() {
                if k > 0 {
                    o.push_str(item_sep);
                }
                nl(o, depth + 1);
                enc_str(key, o);
                o.push_str(kv_sep);
                enc(x, st, depth + 1, o);
            }
            nl(o, depth);
            o.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python() {
        for (f, s) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (9999999999999998.0, "9999999999999998.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (123.456, "123.456"),
            (6543210987654.0, "6543210987654.0"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
        ] {
            assert_eq!(py_float_repr(f), s, "{f}");
        }
    }

    #[test]
    fn dumps_matches_python() {
        let j = loads(r#"{"b": [1, 2.5, "é😀", null], "a": {"y": true, "x": NaN}, "b": 3}"#).unwrap();
        assert_eq!(dumps(&j, Style::Default), r#"{"b": 3, "a": {"y": true, "x": NaN}}"#);
        assert_eq!(dumps(&j, Style::Canonical), r#"{"a":{"x":NaN,"y":true},"b":3}"#);
        let bs = '\\';
        let k = J::Arr(vec![J::Str(['\u{e9}', '\u{1f600}', '\u{7f}', '\u{1}'].iter().collect())]);
        let want = format!("[\"{bs}u00e9{bs}ud83d{bs}ude00{bs}u007f{bs}u0001\"]");
        assert_eq!(dumps(&k, Style::Default), want);
        assert_eq!(dumps(&loads(&want).unwrap(), Style::Default), want);
        assert_eq!(dumps(&loads(r#"{"a":[1,{"b":[]}],"c":{}}"#).unwrap(), Style::Indent1), "{\n \"a\": [\n  1,\n  {\n   \"b\": []\n  }\n ],\n \"c\": {}\n}");
    }

    #[test]
    fn python_int_rules() {
        assert_eq!(py_int_str(" +1_000 ").unwrap(), 1000);
        assert_eq!(py_int_str("007").unwrap(), 7);
        assert!(py_int_str("1__0").is_err());
        assert!(py_int_str("_1").is_err());
        assert!(py_int_str("1_").is_err());
        assert_eq!(py_int_hex("0x_ff").unwrap(), (false, vec![0xff]));
        assert_eq!(py_int_hex("-a_b").unwrap(), (true, vec![0xab]));
        assert_eq!(py_fromhex("ab cd\t0f").unwrap(), vec![0xab, 0xcd, 0x0f]);
        assert!(py_fromhex("a bcd").is_err());
        assert!(py_eq(&J::Int(1), &J::Float(1.0)) && py_eq(&J::Bool(true), &J::Int(1)));
        assert!(Num::I(5).lt(Num::F(5.5)) && !Num::F(f64::NAN).le(Num::I(0)));
    }
}
