"""Independent Python port of the IntentV6 id encoding (docs/SHZ_VENUE_API.md) and BIP86 cross-check.
Run from repo root: python ui/venue/test/gen_vectors.py
The Rust server's POST /api/intent-id is the authority; confirm these ids against it."""
import struct, sys, os
from hashlib import sha256
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'ops', 'public-relay'))
import bip340


def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)


def intent_id(sc, router, tariff_version, exec_policy, i, ent=b'\0' * 32):
    action = {'post': 1, 'take': 2, 'cancel': 3}[i['action']]
    side = {'long': 1, 'short': 2}[i['side']]
    tier = {'standard': 0, 'intermediate': 1, 'premium': 2}[i['tier']]
    m = (bytes.fromhex(sc['network']) + u64(sc['epoch']) + bytes.fromhex(sc['policy'])
         + u32(router) + bytes.fromhex(i['channel']['txid']) + u32(i['channel']['vout']) + bytes.fromhex(i['owner'])
         + u64(i['sequence']) + u64(i['expires_us'])
         + bytes([action, side, tier])
         + u32(tariff_version) + ent + bytes.fromhex(exec_policy)
         + u64(i['quantity']) + u64(i['limit_usd']) + u32(i['leverage_bps'])
         + u32(i['max_fee_ppm']) + u64(i['max_fee_sats']) + u64(i['max_mark_age_us'])
         + bytes([1 if i['early_window_opt_in'] else 0]) + bytes.fromhex(i['cancel_target']))
    return bip340.tagged_hash('SHZ/HFT06/INTENT/V1', m).hex()


CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def polymod(v):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for x in v:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ x
        for k in range(5):
            if (top >> k) & 1: chk ^= gen[k]
    return chk
def convert(data, f, t):
    acc = bits = 0; out = []
    for v in data:
        acc = (acc << f) | v; bits += f
        while bits >= t:
            bits -= t; out.append((acc >> bits) & ((1 << t) - 1))
        acc &= (1 << bits) - 1
    if bits: out.append((acc << (t - bits)) & ((1 << t) - 1))
    return out
def p2tr(internal_x, hrp):
    pt = bip340._lift_x(int.from_bytes(internal_x, 'big'))
    t = int.from_bytes(bip340.tagged_hash('TapTweak', internal_x), 'big')
    q = bip340._add(pt, bip340._mul(bip340.G, t))
    qx = q[0].to_bytes(32, 'big')
    data = [1] + convert(qx, 8, 5)
    hx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    chk = polymod(hx + data + [0] * 6) ^ 0x2bc830a3
    cs = [(chk >> (5 * (5 - j))) & 31 for j in range(6)]
    return qx.hex(), hrp + '1' + ''.join(CHARSET[d] for d in data + cs)


if __name__ == '__main__':
    sc = {'network': '11' * 32, 'epoch': 7, 'policy': '22' * 32}
    owner = bip340.pubkey(bytes.fromhex('00' * 31 + '03')).hex()
    i = {'owner': owner, 'channel': {'txid': '33' * 32, 'vout': 1}, 'sequence': 1700000000123,
         'expires_us': 1700000060000000, 'action': 'post', 'side': 'long', 'tier': 'standard',
         'quantity': 1000, 'limit_usd': 95000, 'leverage_bps': 50000, 'max_fee_ppm': 500,
         'max_fee_sats': 100, 'max_mark_age_us': 5000000, 'early_window_opt_in': True,
         'cancel_target': '00' * 32}
    print('intent id (post/long/standard):', intent_id(sc, 3, 1, '44' * 32, i))
    i2 = dict(i, action='cancel', side='short', tier='premium', cancel_target='55' * 32, early_window_opt_in=False)
    print('intent id (cancel/short/premium):', intent_id(sc, 3, 1, '44' * 32, i2, bytes.fromhex('66' * 32)))
    ik = bytes.fromhex('cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115')
    print('bip86 mainnet:', p2tr(ik, 'bc'))
    print('bip86 testnet:', p2tr(ik, 'tb'))
    print('bip340 vec0 pubkey:', bip340.pubkey(bytes.fromhex('00' * 31 + '03')).hex().upper())
    print('bip340 vec0 sig:', bip340.sign(bytes(32), bytes.fromhex('00' * 31 + '03'), bytes(32)).hex().upper())
