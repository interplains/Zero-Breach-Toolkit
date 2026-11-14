"""Encrypt-only age (age-encryption.org/v1, X25519 recipients) and Ed25519 signing, in plain Python.

Used to seal an evidence package for a helper: only the holder of the helper's age key can open it, and the
manifest inside is signed with the sender's own Ed25519 key, because age alone does not say who sent a file.

This module can ENCRYPT and SIGN; it has no decryption of anything. Implemented from the public specifications
(RFC 7748 X25519, RFC 8439 ChaCha20-Poly1305, RFC 5869 HKDF, RFC 8032 Ed25519, the age v1 format) and checked
against their published test vectors. Pure Python: fine for reports and phone collections (a few MB/s); for very
large packages the `age` / `rage` programs are used when installed. Timing side channels are not a concern for a
one-off local encryption.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct

AG_CHUNK = 64 * 1024
_AG_P = 2 ** 255 - 19
_AG_MASK = 0xFFFFFFFF


class AgError(ValueError):
    pass


# --- X25519 (RFC 7748) ----------------------------------------------------------------------------------------------

def ag_x25519(scalar: bytes, u: bytes) -> bytes:
    if len(scalar) != 32 or len(u) != 32:
        raise AgError("X25519 needs 32-byte inputs")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    p = _AG_P
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3 = (da + cb) * (da + cb) % p
        z3 = x1 * (da - cb) * (da - cb) % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    out = x2 * pow(z2, p - 2, p) % p
    return out.to_bytes(32, "little")


AG_X25519_BASE = (9).to_bytes(32, "little")


# --- ChaCha20-Poly1305 (RFC 8439) ----------------------------------------------------------------------------------

def _ag_chacha_block(key_words, counter, nonce_words):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + key_words + [counter & _AG_MASK] + nonce_words
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = s
    m = _AG_MASK
    for _ in range(10):
        # column rounds
        x0 = (x0 + x4) & m; x12 ^= x0; x12 = ((x12 << 16) | (x12 >> 16)) & m           # noqa: E702
        x8 = (x8 + x12) & m; x4 ^= x8; x4 = ((x4 << 12) | (x4 >> 20)) & m             # noqa: E702
        x0 = (x0 + x4) & m; x12 ^= x0; x12 = ((x12 << 8) | (x12 >> 24)) & m           # noqa: E702
        x8 = (x8 + x12) & m; x4 ^= x8; x4 = ((x4 << 7) | (x4 >> 25)) & m              # noqa: E702
        x1 = (x1 + x5) & m; x13 ^= x1; x13 = ((x13 << 16) | (x13 >> 16)) & m          # noqa: E702
        x9 = (x9 + x13) & m; x5 ^= x9; x5 = ((x5 << 12) | (x5 >> 20)) & m             # noqa: E702
        x1 = (x1 + x5) & m; x13 ^= x1; x13 = ((x13 << 8) | (x13 >> 24)) & m           # noqa: E702
        x9 = (x9 + x13) & m; x5 ^= x9; x5 = ((x5 << 7) | (x5 >> 25)) & m              # noqa: E702
        x2 = (x2 + x6) & m; x14 ^= x2; x14 = ((x14 << 16) | (x14 >> 16)) & m          # noqa: E702
        x10 = (x10 + x14) & m; x6 ^= x10; x6 = ((x6 << 12) | (x6 >> 20)) & m          # noqa: E702
        x2 = (x2 + x6) & m; x14 ^= x2; x14 = ((x14 << 8) | (x14 >> 24)) & m           # noqa: E702
        x10 = (x10 + x14) & m; x6 ^= x10; x6 = ((x6 << 7) | (x6 >> 25)) & m           # noqa: E702
        x3 = (x3 + x7) & m; x15 ^= x3; x15 = ((x15 << 16) | (x15 >> 16)) & m          # noqa: E702
        x11 = (x11 + x15) & m; x7 ^= x11; x7 = ((x7 << 12) | (x7 >> 20)) & m          # noqa: E702
        x3 = (x3 + x7) & m; x15 ^= x3; x15 = ((x15 << 8) | (x15 >> 24)) & m           # noqa: E702
        x11 = (x11 + x15) & m; x7 ^= x11; x7 = ((x7 << 7) | (x7 >> 25)) & m           # noqa: E702
        # diagonal rounds
        x0 = (x0 + x5) & m; x15 ^= x0; x15 = ((x15 << 16) | (x15 >> 16)) & m          # noqa: E702
        x10 = (x10 + x15) & m; x5 ^= x10; x5 = ((x5 << 12) | (x5 >> 20)) & m          # noqa: E702
        x0 = (x0 + x5) & m; x15 ^= x0; x15 = ((x15 << 8) | (x15 >> 24)) & m           # noqa: E702
        x10 = (x10 + x15) & m; x5 ^= x10; x5 = ((x5 << 7) | (x5 >> 25)) & m           # noqa: E702
        x1 = (x1 + x6) & m; x12 ^= x1; x12 = ((x12 << 16) | (x12 >> 16)) & m          # noqa: E702
        x11 = (x11 + x12) & m; x6 ^= x11; x6 = ((x6 << 12) | (x6 >> 20)) & m          # noqa: E702
        x1 = (x1 + x6) & m; x12 ^= x1; x12 = ((x12 << 8) | (x12 >> 24)) & m           # noqa: E702
        x11 = (x11 + x12) & m; x6 ^= x11; x6 = ((x6 << 7) | (x6 >> 25)) & m           # noqa: E702
        x2 = (x2 + x7) & m; x13 ^= x2; x13 = ((x13 << 16) | (x13 >> 16)) & m          # noqa: E702
        x8 = (x8 + x13) & m; x7 ^= x8; x7 = ((x7 << 12) | (x7 >> 20)) & m             # noqa: E702
        x2 = (x2 + x7) & m; x13 ^= x2; x13 = ((x13 << 8) | (x13 >> 24)) & m           # noqa: E702
        x8 = (x8 + x13) & m; x7 ^= x8; x7 = ((x7 << 7) | (x7 >> 25)) & m              # noqa: E702
        x3 = (x3 + x4) & m; x14 ^= x3; x14 = ((x14 << 16) | (x14 >> 16)) & m          # noqa: E702
        x9 = (x9 + x14) & m; x4 ^= x9; x4 = ((x4 << 12) | (x4 >> 20)) & m             # noqa: E702
        x3 = (x3 + x4) & m; x14 ^= x3; x14 = ((x14 << 8) | (x14 >> 24)) & m           # noqa: E702
        x9 = (x9 + x14) & m; x4 ^= x9; x4 = ((x4 << 7) | (x4 >> 25)) & m              # noqa: E702
    out = (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)
    return struct.pack("<16I", *[(a + b) & m for a, b in zip(out, s)])


_AG_LANES: dict = {}


def _ag_lanes(n):
    """(ones in every 64-bit lane, lane index in every lane, 32-bit mask in every lane) for n lanes."""
    got = _AG_LANES.get(n)
    if got is None:
        ones = int.from_bytes(b"\x01\x00\x00\x00\x00\x00\x00\x00" * n, "little")
        index = int.from_bytes(b"".join(i.to_bytes(8, "little") for i in range(n)), "little")
        got = _AG_LANES[n] = (ones, index, ones * _AG_MASK)
        if len(_AG_LANES) > 8:
            _AG_LANES.pop(next(iter(_AG_LANES)))
    return got


def _ag_chacha_many(key_words, counter, nonce_words, n):
    """n consecutive ChaCha20 blocks at once: each state word holds all n blocks in 64-bit lanes (32-bit value plus
    32 guard bits), so additions and rotations never spill into a neighbouring block once masked."""
    ones, index, M = _ag_lanes(n)
    s = [c * ones for c in (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)] + [k * ones for k in key_words] + \
        [counter * ones + index] + [w * ones for w in nonce_words]
    x = list(s)

    def qr(a, b, c, d):
        xa, xb, xc, xd = x[a], x[b], x[c], x[d]
        xa = (xa + xb) & M; xd ^= xa; xd = ((xd << 16) | (xd >> 16)) & M              # noqa: E702
        xc = (xc + xd) & M; xb ^= xc; xb = ((xb << 12) | (xb >> 20)) & M              # noqa: E702
        xa = (xa + xb) & M; xd ^= xa; xd = ((xd << 8) | (xd >> 24)) & M               # noqa: E702
        xc = (xc + xd) & M; xb ^= xc; xb = ((xb << 7) | (xb >> 25)) & M               # noqa: E702
        x[a], x[b], x[c], x[d] = xa, xb, xc, xd
    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)          # noqa: E702
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)          # noqa: E702
    out = bytearray(64 * n)
    for j in range(16):
        lane = ((x[j] + s[j]) & M).to_bytes(8 * n, "little")
        for k in range(4):
            out[4 * j + k::64] = lane[k::8]
    return bytes(out)


def ag_chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 keystream XOR (RFC 8439 section 2.4)."""
    kw = list(struct.unpack("<8I", key))
    nw = list(struct.unpack("<3I", nonce))
    blocks = (len(data) + 63) // 64
    if blocks == 0:
        return b""
    if blocks < 4:
        stream = b"".join(_ag_chacha_block(kw, counter + i, nw) for i in range(blocks))
    else:
        stream = _ag_chacha_many(kw, counter, nw, blocks)
    stream = stream[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


def _ag_poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        acc = (acc + int.from_bytes(block + b"\x01", "little")) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def ag_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """ChaCha20-Poly1305 encryption: ciphertext followed by the 16-byte tag."""
    otk = _ag_chacha_block(list(struct.unpack("<8I", key)), 0, list(struct.unpack("<3I", nonce)))[:32]
    ct = ag_chacha20(key, 1, nonce, plaintext)

    def pad(b):
        return b"\x00" * (-len(b) % 16)
    mac_data = aad + pad(aad) + ct + pad(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct + _ag_poly1305(otk, mac_data)


# --- HKDF-SHA256 (RFC 5869) ----------------------------------------------------------------------------------------

def ag_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


# --- age recipients (bech32) ---------------------------------------------------------------------------------------

_AG_BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _ag_polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def ag_parse_recipient(text: str) -> bytes:
    """The 32-byte X25519 public key from an `age1...` recipient. Refuses secret keys and typos."""
    s = (text or "").strip()
    if s.upper().startswith("AGE-SECRET-KEY-"):
        raise AgError("that is a SECRET key - never share it. Ask your helper for their public key, which starts "
                      "with age1")
    if s.startswith("ssh-"):
        raise AgError("SSH keys are not accepted (they reveal which key a file is for); ask your helper for an age "
                      "public key, which starts with age1")
    low = s.lower()
    if low != s and s.upper() != s:
        raise AgError("the key mixes capital and small letters - copy it again exactly")
    if not low.startswith("age1") or len(low) < 10:
        raise AgError("an age public key starts with age1")
    hrp, data = low[:3], low[4:]
    if any(c not in _AG_BECH for c in data):
        raise AgError("the key contains a character an age key cannot have - copy it again exactly")
    values = [_AG_BECH.index(c) for c in data]
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _ag_polymod(hrp_exp + values) != 1:
        raise AgError("the key has a typo (its check digits do not match) - copy it again exactly")
    acc, bits, out = 0, 0, bytearray()
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc & ((1 << bits) - 1)):
        raise AgError("the key is malformed")
    if len(out) != 32:
        raise AgError("the key is the wrong length for an age X25519 key")
    return bytes(out)


def ag_encode_recipient(public: bytes) -> str:
    """age1... string for a 32-byte X25519 public key (used by tests and to show keys back)."""
    acc, bits, values = 0, 0, []
    for b in public:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    hrp_exp = [ord(c) >> 5 for c in "age"] + [0] + [ord(c) & 31 for c in "age"]
    poly = _ag_polymod(hrp_exp + values + [0] * 6) ^ 1
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return "age1" + "".join(_AG_BECH[v] for v in values + checksum)


# --- age v1 encryption ---------------------------------------------------------------------------------------------

def _ag_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def ag_header(recipients, file_key: bytes, rand=os.urandom) -> bytes:
    """The age v1 header (with MAC) wrapping file_key to each X25519 recipient."""
    lines = [b"age-encryption.org/v1"]
    for public in recipients:
        eph = rand(32)
        eph_pub = ag_x25519(eph, AG_X25519_BASE)
        shared = ag_x25519(eph, public)
        if shared == b"\x00" * 32:
            raise AgError("that public key is not usable")
        wrap = ag_hkdf(shared, eph_pub + public, b"age-encryption.org/v1/X25519")
        body = _ag_b64(ag_seal(wrap, b"\x00" * 12, file_key))
        lines.append(("-> X25519 " + _ag_b64(eph_pub)).encode("ascii"))
        for i in range(0, len(body), 64):
            lines.append(body[i:i + 64].encode("ascii"))
        if len(body) % 64 == 0:
            lines.append(b"")
    head = b"\n".join(lines) + b"\n---"
    mac = hmac.new(ag_hkdf(file_key, b"", b"header"), head, hashlib.sha256).digest()
    return head + b" " + _ag_b64(mac).encode("ascii") + b"\n"


class AgWriter:
    """File-like object: plaintext written in, age v1 ciphertext written to `out`. No seek, so zipfile streams."""

    def __init__(self, out, recipients, rand=os.urandom):
        self._out = out
        file_key = rand(16)
        out.write(ag_header(recipients, file_key, rand))
        nonce = rand(16)
        out.write(nonce)
        self._key = ag_hkdf(file_key, nonce, b"payload")
        self._buf = bytearray()
        self._counter = 0
        self._written = 0
        self.closed = False

    def write(self, data) -> int:
        if self.closed:
            raise ValueError("write to a closed age stream")
        self._buf += data
        self._written += len(data)
        while len(self._buf) > AG_CHUNK:
            self._emit(bytes(self._buf[:AG_CHUNK]), last=False)
            del self._buf[:AG_CHUNK]
        return len(data)

    def _emit(self, chunk, last):
        nonce = self._counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")
        self._out.write(ag_seal(self._key, nonce, chunk))
        self._counter += 1

    def tell(self) -> int:
        return self._written

    def flush(self):
        self._out.flush()

    def close(self):
        if not self.closed:
            self._emit(bytes(self._buf), last=True)
            self._buf = bytearray()
            self.closed = True
            self._out.flush()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def ag_encrypt(plaintext: bytes, recipients, rand=os.urandom) -> bytes:
    import io
    out = io.BytesIO()
    w = AgWriter(out, recipients, rand)
    w.write(plaintext)
    w.close()
    return out.getvalue()


# --- Ed25519 (RFC 8032) --------------------------------------------------------------------------------------------

_ED_Q = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _AG_P - 2, _AG_P) % _AG_P
_ED_I = pow(2, (_AG_P - 1) // 4, _AG_P)


def _ed_recover_x(y, sign):
    p = _AG_P
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * _ED_I % p
    if (x * x - x2) % p:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_ED_GY = 4 * pow(5, _AG_P - 2, _AG_P) % _AG_P
_ED_GX = _ed_recover_x(_ED_GY, 0)
_ED_G = (_ED_GX, _ED_GY, 1, _ED_GX * _ED_GY % _AG_P)


def _ed_add(P, Q):
    p = _AG_P
    a = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    b = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    c = 2 * P[3] * Q[3] * _ED_D % p
    d = 2 * P[2] * Q[2] % p
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def _ed_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_equal(P, Q):
    p = _AG_P
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _ed_compress(P):
    zinv = pow(P[2], _AG_P - 2, _AG_P)
    x, y = P[0] * zinv % _AG_P, P[1] * zinv % _AG_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _AG_P)


def _ed_expand(seed):
    if len(seed) != 32:
        raise AgError("an Ed25519 seed is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed_public(seed: bytes) -> bytes:
    a, _prefix = _ed_expand(seed)
    return _ed_compress(_ed_mul(a, _ED_G))


def ed_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _ed_expand(seed)
    public = _ed_compress(_ed_mul(a, _ED_G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _ED_Q
    rs = _ed_compress(_ed_mul(r, _ED_G))
    h = int.from_bytes(hashlib.sha512(rs + public + msg).digest(), "little") % _ED_Q
    return rs + ((r + h * a) % _ED_Q).to_bytes(32, "little")


def ed_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _ed_decompress(public), _ed_decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _ED_Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _ED_Q
    return _ed_equal(_ed_mul(s, _ED_G), _ed_add(R, _ed_mul(h, A)))


def ag_safety_number(public: bytes) -> str:
    """Six groups of five digits identifying a public key, to read aloud and compare (like Signal's)."""
    digest = hashlib.sha256(b"zero-breach sender key\x00" + public).digest()
    groups = [str(int.from_bytes(digest[i * 5:i * 5 + 5], "big") % 100000).zfill(5) for i in range(6)]
    return " ".join(groups)
