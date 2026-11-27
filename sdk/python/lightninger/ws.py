"""JSON-RPC 2.0 over WebSocket for /agent/v1/ws (stdlib only: a minimal RFC 6455 client).

`Stream.call(method, params)` sends one request and waits for its reply; `subscribe()`
registers channels. Every notification carries a per-channel `seq`; when one arrives out of
order, or the server sends `gap`, the stream calls `resync` for that channel and hands the
handler either the replayed events or a snapshot, so a handler never silently misses state.
"""
import base64
import json
import os
import queue
import socket
import ssl
import struct
import threading
import urllib.parse


class WsClosed(Exception):
    pass


class _Ws:
    def __init__(self, url, timeout=10):
        u = urllib.parse.urlparse(url)
        port = u.port or (443 if u.scheme == "wss" else 80)
        s = socket.create_connection((u.hostname, port), timeout=timeout)
        if u.scheme == "wss":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {u.hostname}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1)
            if not chunk:
                raise WsClosed("handshake")
            head += chunk
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise WsClosed("handshake refused: " + head.split(b"\r\n", 1)[0].decode(errors="replace"))
        s.settimeout(None)
        self.s = s
        self.lock = threading.Lock()

    def _exact(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c:
                raise WsClosed("eof")
            b += c
        return b

    def send_text(self, text):
        data = text.encode()
        hdr = bytes([0x81])
        n = len(data)
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        with self.lock:
            self.s.sendall(hdr + mask + body)

    def _send_ctrl(self, op, payload=b""):
        mask = os.urandom(4)
        with self.lock:
            self.s.sendall(bytes([0x80 | op, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def recv_text(self):
        parts = []
        while True:
            b0, b1 = self._exact(2)
            op, fin, n = b0 & 0x0F, b0 & 0x80, b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._exact(8))[0]
            mask = self._exact(4) if b1 & 0x80 else None
            data = self._exact(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 0x8:
                raise WsClosed("closed by server")
            if op == 0x9:
                self._send_ctrl(0xA, data)
                continue
            if op == 0xA:
                continue
            parts.append(data)
            if fin:
                return b"".join(parts).decode()

    def close(self):
        try:
            self._send_ctrl(0x8)
            self.s.close()
        except OSError:
            pass


class RpcError(Exception):
    def __init__(self, err):
        data = err.get("data") or {}
        super().__init__(f"{data.get('code', err.get('code'))}: {err.get('message')}")
        self.code = data.get("code") or str(err.get("code"))
        self.rpc_code = err.get("code")
        self.details = data.get("details")


class Stream:
    def __init__(self, base_url="http://127.0.0.1:8095"):
        url = base_url.rstrip("/").replace("https://", "wss://").replace("http://", "ws://") + "/agent/v1/ws"
        self.ws = _Ws(url)
        self.next_id = 0
        self.waiting = {}
        self.handlers = {}
        self.seq = {}
        self.resyncs = 0
        self.hello = json.loads(self.ws.recv_text())
        self.alive = True
        threading.Thread(target=self._reader, daemon=True, name="lightninger-ws").start()

    def call(self, method, params=None, timeout=10):
        self.next_id += 1
        rid = self.next_id
        q = queue.Queue(1)
        self.waiting[rid] = q
        self.ws.send_text(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}))
        try:
            msg = q.get(timeout=timeout)
        finally:
            self.waiting.pop(rid, None)
        if "error" in msg:
            raise RpcError(msg["error"])
        return msg["result"]

    def subscribe(self, channels, handler):
        """`handler(channel, kind, payload)`: kind is "event" (payload = venue event),
        "replay" (list of {seq, data}) or "snapshot" (current state) after a resync."""
        for c in channels:
            self.handlers[c] = handler
        r = self.call("subscribe", {"channels": list(channels)})
        for c in r["channels"]:
            self.seq[c["channel"]] = c["seq"]
        return r

    def _resync(self, ch):
        self.resyncs += 1
        r = self.call("resync", {"channel": ch, "since": self.seq.get(ch, 0)})
        self.seq[ch] = r["seq"]
        h = self.handlers.get(ch)
        if h:
            if "replay" in r:
                h(ch, "replay", r["replay"])
            else:
                h(ch, "snapshot", r["snapshot"])

    def _on_note(self, m):
        method, p = m.get("method"), m.get("params") or {}
        if method == "subscription":
            ch, seq = p["channel"], p["seq"]
            last = self.seq.get(ch, 0)
            if seq <= last:
                return
            if seq != last + 1:
                threading.Thread(target=self._resync, args=(ch,), daemon=True).start()
                return
            self.seq[ch] = seq
            h = self.handlers.get(ch)
            if h:
                h(ch, "event", p["data"])
        elif method == "gap":
            for c in p.get("channels", []):
                threading.Thread(target=self._resync, args=(c["channel"],), daemon=True).start()

    def _reader(self):
        try:
            while True:
                m = json.loads(self.ws.recv_text())
                for x in m if isinstance(m, list) else [m]:
                    if "id" in x and x["id"] in self.waiting:
                        self.waiting[x["id"]].put(x)
                    elif "method" in x:
                        self._on_note(x)
        except (WsClosed, OSError, ValueError):
            self.alive = False

    def close(self):
        self.ws.close()
