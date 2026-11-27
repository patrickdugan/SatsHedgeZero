"""Independent integer model of the post-positions V3 clearing kernel.
No position settlement, authorization, digest, checked Rust bounds or production claim.
Inputs: unique outpoint keys in native BTreeMap sort order representation.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class Lane:
    key: tuple
    pnl: int
    released: int


def prorata(total, amounts):
    if any(a < 0 for a in amounts) or not 0 <= total <= sum(amounts):
        raise ValueError("invalid prorata input")
    base = sum(amounts)
    if not base:
        return [0] * len(amounts)
    out = [total * a // base for a in amounts]
    rest = total - sum(out)
    for i, a in enumerate(amounts):
        extra = min(rest, a - out[i])
        out[i] += extra
        rest -= extra
    if rest:
        raise AssertionError("remainder")
    return out


def clear(cash, fund, carry, claims, lanes):
    if min(fund, carry, *claims.values(), 0) < 0:
        raise ValueError("negative state")
    if len({r.key for r in lanes}) != len(lanes) or any(r.released < 0 for r in lanes):
        raise ValueError("invalid lanes")
    old_cash = cash
    claims = {k: v for k, v in claims.items() if v}
    report = []
    gains = []
    for lane in lanes:
        need = max(0, -lane.pnl)
        claim = claims.get(lane.key, 0)
        collected = min(need, lane.released)
        own = min(need - collected, claim)
        short = need - collected - own
        claims[lane.key] = claim - own
        report.append({"key": lane.key, "pnl": lane.pnl, "released": lane.released,
                       "claim_before": claim, "collected": collected, "own_claim_used": own,
                       "shortfall": short, "haircut": 0})
        gains.append(max(0, lane.pnl))
    cash += sum(r["collected"] for r in report)
    short = sum(r["shortfall"] for r in report)
    used = min(short, fund)
    fund -= used
    owed = short - used + carry
    keys = sorted(k for k, v in claims.items() if v)
    amounts = [claims[k] for k in keys] + gains
    haircut = min(owed, sum(amounts))
    cuts = prorata(haircut, amounts)
    carry = owed - haircut
    by_key = {r["key"]: r for r in report}
    outside = []
    for k, cut in zip(keys, cuts):
        claims[k] -= cut
        if k in by_key:
            by_key[k]["haircut"] += cut
        elif cut:
            outside.append((k, cut))
    for i, cut in enumerate(cuts[len(keys):]):
        gains[i] -= cut
        report[i]["haircut"] += cut
    dues = [claims.get(l.key, 0) + gain for l, gain in zip(lanes, gains)]
    paid = prorata(min(sum(dues), max(cash, 0)), dues)
    for row, due, payment in zip(report, dues, paid):
        claims[row["key"]] = due - payment
        row["claim_after"] = due - payment
        row["paid"] = payment
        row["net"] = payment - row["collected"]
    cash -= sum(paid)
    assert sum(r["net"] for r in report) + cash - old_cash == 0
    assert cash >= min(old_cash, 0)
    return {"cash": cash, "fund": fund, "carry": carry,
            "claims": {k: v for k, v in claims.items() if v},
            "rows": report, "claim_haircuts": outside, "fund_absorbed": used,
            "haircut": haircut, "shortfall": short}
