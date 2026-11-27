"""REST client for the agent API v1 (stdlib only).

Every method of docs/agent-api/openapi.json is one call here. Errors come back as
`LightningerError` with the API's stable `code`; 429 responses are retried after the
server's `Retry-After`; writes carry an `Idempotency-Key` so a retried request returns the
first response instead of placing twice.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


class LightningerError(Exception):
    def __init__(self, status, code, message, details=None, retryable=False):
        super().__init__(f"{code}: {message}")
        self.status, self.code, self.message, self.details, self.retryable = status, code, message, details, retryable


class Client:
    def __init__(self, base_url="http://127.0.0.1:8095", timeout=10, max_retries=3):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate = {}

    # ------------------------------------------------------------ transport
    def request(self, method, path, params=None, body=None, idempotency_key=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "User-Agent": "lightninger-sdk-python/1"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    self._rate(r.headers)
                    return json.loads(r.read() or b"null")
            except urllib.error.HTTPError as e:
                self._rate(e.headers)
                raw = e.read()
                try:
                    err = json.loads(raw)["error"]
                except Exception:
                    err = {"code": "http", "message": raw.decode(errors="replace")[:200]}
                if e.code == 429 and attempt < self.max_retries:
                    time.sleep(max(float(e.headers.get("Retry-After") or 1), 0.05))
                    continue
                raise LightningerError(e.code, err.get("code"), err.get("message"), err.get("details"), err.get("retryable", False)) from None
        raise AssertionError("unreachable")

    def _rate(self, h):
        if h and h.get("X-RateLimit-Remaining") is not None:
            self.rate = {"limit": int(h.get("X-RateLimit-Limit", 0)), "remaining": int(h.get("X-RateLimit-Remaining", 0)),
                         "reset_s": float(h.get("X-RateLimit-Reset", 0))}

    def get(self, path, **params):
        return self.request("GET", path, params=params)

    def post(self, path, body, idempotent=True):
        return self.request("POST", path, body=body, idempotency_key=os.urandom(16).hex() if idempotent else None)

    # ---------------------------------------------------------------- reads
    def info(self):
        return self.get("/agent/v1/info")

    def time(self):
        return self.get("/agent/v1/time")

    def markets(self):
        return self.get("/agent/v1/markets")

    def book(self, instrument="perp", depth=25):
        return self.get("/agent/v1/book", instrument=instrument, depth=depth)

    def trades(self, instrument="perp", limit=100):
        return self.get("/agent/v1/trades", instrument=instrument, limit=limit)

    def mark(self):
        return self.get("/agent/v1/mark")

    def option_chain(self):
        return self.get("/agent/v1/options/chain")

    def account(self, owner):
        return self.get("/agent/v1/account", owner=owner)

    def grants(self, owner=None, agent=None):
        return self.get("/agent/v1/grants", owner=owner, agent=agent)

    def grant(self, grant_id):
        return self.get("/agent/v1/grant", id=grant_id)

    def orders(self, grant_id, limit=100):
        return self.get("/agent/v1/orders", grant=grant_id, limit=limit)

    def pending_acks(self, grant_id):
        return self.get("/agent/v1/acks", grant=grant_id)

    def intent_id(self, instrument, intent):
        return self.post("/agent/v1/intent-id", {"instrument": instrument, "intent": intent}, idempotent=False)["id"]

    # --------------------------------------------------------------- writes
    def grant_draft(self, owner, agent, instruments, limits, expires_in_s=86_400, label=""):
        return self.post("/agent/v1/grants/draft", {"owner": owner, "agent": agent, "instruments": instruments, "limits": limits,
                                                    "expires_in_s": expires_in_s, "label": label}, idempotent=False)

    def grant_create(self, grant, label=""):
        return self.post("/agent/v1/grants", {"grant": grant, "label": label})

    def grant_revoke(self, revocation):
        return self.post("/agent/v1/grants/revoke", {"revocation": revocation})

    def place(self, grant_id, instrument, intent, idempotency_key=None):
        return self.request("POST", "/agent/v1/orders", body={"grant": grant_id, "instrument": instrument, "intent": intent},
                            idempotency_key=idempotency_key or os.urandom(16).hex())

    def cancel(self, grant_id, instrument, intent):
        return self.post("/agent/v1/orders/cancel", {"grant": grant_id, "instrument": instrument, "intent": intent})

    def replace(self, grant_id, instrument, cancel, place):
        return self.post("/agent/v1/orders/replace", {"grant": grant_id, "instrument": instrument, "cancel": cancel, "place": place})

    def submit_acks(self, grant_id, items):
        return self.post("/agent/v1/acks", {"grant": grant_id, "items": items})
