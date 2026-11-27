"""lightninger command line: agent keys and owner grants.

  python -m lightninger keygen --out agent.key           # new agent key (file mode 0600), prints its public key
  python -m lightninger grant  --owner-key owner.key --agent <pubkey> --instruments perps,spot \\
         --max-order 100 --max-daily 1000 --max-open 10 --rate 30 --collar-bps 200 --hours 24 [--yes]
  python -m lightninger revoke --owner-key owner.key --grant <id>
  python -m lightninger show   --grant <id> | --owner <pubkey> | --agent <pubkey>

`grant` and `revoke` use the owner's trading key on this machine; the agent never needs it.
`grant` prints the consent text and asks before signing (unless --yes).
"""
import argparse
import json
import os
import sys

from .agent import create_grant, new_key, pubkey_hex, revoke_grant
from .client import Client, LightningerError


def read_key(path):
    return bytes.fromhex(open(path).read().strip())


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lightninger")
    ap.add_argument("--venue", default=os.environ.get("LIGHTNINGER_VENUE", "http://127.0.0.1:8095"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    g = sub.add_parser("grant")
    g.add_argument("--owner-key", required=True)
    g.add_argument("--agent", required=True)
    g.add_argument("--instruments", default="perps")
    g.add_argument("--max-order", type=int, required=True, help="USD notional per order")
    g.add_argument("--max-daily", type=int, required=True, help="USD notional per rolling 24 h")
    g.add_argument("--max-open", type=int, default=10)
    g.add_argument("--rate", type=int, default=30, help="orders per minute")
    g.add_argument("--collar-bps", type=int, default=200)
    g.add_argument("--hours", type=float, default=24)
    g.add_argument("--label", default="")
    g.add_argument("--yes", action="store_true")
    r = sub.add_parser("revoke")
    r.add_argument("--owner-key", required=True)
    r.add_argument("--grant", required=True)
    s = sub.add_parser("show")
    s.add_argument("--grant")
    s.add_argument("--owner")
    s.add_argument("--agent")
    a = ap.parse_args(argv)
    c = Client(a.venue)
    try:
        if a.cmd == "keygen":
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            sk = new_key()
            with os.fdopen(fd, "w") as f:
                f.write(sk.hex())
            print(json.dumps({"agent_pubkey": pubkey_hex(sk), "key_file": a.out}))
        elif a.cmd == "grant":
            limits = {"max_order_notional_usd": a.max_order, "max_daily_notional_usd": a.max_daily, "max_open_orders": a.max_open,
                      "max_orders_per_minute": a.rate, "collar_bps": a.collar_bps}

            def confirm(text):
                print(text)
                return a.yes or input("Sign this grant with the owner key? [y/N] ").strip().lower() == "y"

            v = create_grant(c, read_key(a.owner_key), a.agent, a.instruments.split(","), limits, int(a.hours * 3600), a.label, confirm)
            print(json.dumps({"grant": v["id"], "status": v["status"], "expires_us": v["grant"]["expires_us"]}))
        elif a.cmd == "revoke":
            print(json.dumps(revoke_grant(c, read_key(a.owner_key), a.grant)))
        elif a.cmd == "show":
            print(json.dumps(c.grant(a.grant) if a.grant else c.grants(owner=a.owner, agent=a.agent), indent=2))
    except LightningerError as e:
        print(json.dumps({"error": e.code, "message": e.message, "details": e.details}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
