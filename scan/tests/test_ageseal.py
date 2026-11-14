"""The encrypt-only age and Ed25519 code against published test vectors, and against an independent
implementation (the `cryptography` package, used here in the tests only - never by the toolkit)."""
import base64
import hashlib
import hmac
import os

import pytest

from zbtriage import ageseal as ag


def test_x25519_rfc7748_vectors():
    out = ag.ag_x25519(bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                       bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
    assert out.hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    assert ag.ag_x25519(alice, ag.AG_X25519_BASE).hex() == \
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"


def test_chacha20_poly1305_rfc8439_vector():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")
    sealed = ag.ag_seal(key, nonce, pt, aad)
    assert sealed[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2"
    assert sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691"


def test_ed25519_rfc8032_test1():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = ag.ed_public(seed)
    assert pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = ag.ed_sign(seed, b"")
    assert sig.hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b4"
                         "6bd25bf5f0595bbe24655141438e7a100b")
    assert ag.ed_verify(pub, b"", sig)
    assert not ag.ed_verify(pub, b"x", sig)
    assert not ag.ed_verify(pub, b"", sig[:-1] + bytes([sig[-1] ^ 1]))


def test_recipient_round_trip_and_typo_detection():
    pub = os.urandom(32)
    text = ag.ag_encode_recipient(pub)
    assert text.startswith("age1") and len(text) == 62
    assert ag.ag_parse_recipient(text) == pub
    assert ag.ag_parse_recipient(text.upper()) == pub
    typo = text[:-3] + ("q" if text[-3] != "q" else "p") + text[-2:]
    with pytest.raises(ag.AgError, match="typo"):
        ag.ag_parse_recipient(typo)
    with pytest.raises(ag.AgError, match="SECRET"):
        ag.ag_parse_recipient("AGE-SECRET-KEY-1QQQQ")
    with pytest.raises(ag.AgError, match="SSH"):
        ag.ag_parse_recipient("ssh-ed25519 AAAA")


def test_known_age_recipient_from_the_spec_parses():
    # The X25519 recipient published in the age README / spec examples.
    assert len(ag.ag_parse_recipient("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")) == 32


# --- independent check: decrypt our output with the cryptography package -----------------------------------------

crypto = pytest.importorskip("cryptography")


def _age_decrypt(blob, identity):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization

    def hkdf(ikm, salt, info):
        return HKDF(hashes.SHA256(), 32, salt or None, info).derive(ikm)

    def unb64(s):
        return base64.b64decode(s + "=" * (-len(s) % 4))
    end = blob.index(b"\n---") + 4
    head = blob[:end]
    mac_line_end = blob.index(b"\n", end)
    mac = unb64(blob[end + 1:mac_line_end].decode())
    lines = head.decode().split("\n")
    assert lines[0] == "age-encryption.org/v1"
    priv = X25519PrivateKey.from_private_bytes(identity)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    file_key = None
    i = 1
    while lines[i].startswith("-> "):
        args = lines[i].split()
        body = ""
        i += 1
        while True:
            body += lines[i]
            i += 1
            if len(lines[i - 1]) < 64:
                break
        assert args[1] == "X25519"
        eph = unb64(args[2])
        shared = priv.exchange(X25519PublicKey.from_public_bytes(eph))
        wrap = hkdf(shared, eph + pub, b"age-encryption.org/v1/X25519")
        file_key = ChaCha20Poly1305(wrap).decrypt(b"\x00" * 12, unb64(body), None)
    assert hmac.compare_digest(hmac.new(hkdf(file_key, b"", b"header"), head, hashlib.sha256).digest(), mac)
    payload = blob[mac_line_end + 1:]
    nonce, payload = payload[:16], payload[16:]
    key = ChaCha20Poly1305(hkdf(file_key, nonce, b"payload"))
    out, counter, size = b"", 0, ag.AG_CHUNK + 16
    while payload:
        chunk, payload = payload[:size], payload[size:]
        last = not payload
        out += key.decrypt(counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00"), chunk, None)
        counter += 1
    return out


@pytest.mark.parametrize("size", [0, 1, 1000, ag.AG_CHUNK, ag.AG_CHUNK + 1, 3 * ag.AG_CHUNK])
def test_age_output_decrypts_with_an_independent_implementation(size):
    identity = os.urandom(32)
    public = ag.ag_x25519(identity, ag.AG_X25519_BASE)
    data = os.urandom(size)
    assert _age_decrypt(ag.ag_encrypt(data, [public]), identity) == data


def test_x25519_and_aead_match_the_independent_implementation():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    a, b = os.urandom(32), os.urandom(32)
    pb = ag.ag_x25519(b, ag.AG_X25519_BASE)
    theirs = X25519PrivateKey.from_private_bytes(a).exchange(X25519PublicKey.from_public_bytes(pb))
    assert ag.ag_x25519(a, pb) == theirs
    key, nonce, msg, aad = os.urandom(32), os.urandom(12), os.urandom(777), os.urandom(13)
    assert ag.ag_seal(key, nonce, msg, aad) == ChaCha20Poly1305(key).encrypt(nonce, msg, aad)


def test_ed25519_matches_the_independent_implementation():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    seed, msg = os.urandom(32), os.urandom(300)
    k = Ed25519PrivateKey.from_private_bytes(seed)
    assert ag.ed_public(seed) == k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert ag.ed_sign(seed, msg) == k.sign(msg)


def test_safety_number_format():
    n = ag.ag_safety_number(b"\x01" * 32)
    assert len(n.split()) == 6 and all(len(g) == 5 and g.isdigit() for g in n.split())


@pytest.mark.parametrize("blocks", [4, 5, 17, 64, 1025])
def test_fast_keystream_equals_the_simple_block_function(blocks):
    import struct
    key, nonce = os.urandom(32), os.urandom(12)
    kw, nw = list(struct.unpack("<8I", key)), list(struct.unpack("<3I", nonce))
    simple = b"".join(ag._ag_chacha_block(kw, 7 + i, nw) for i in range(blocks))
    assert ag._ag_chacha_many(kw, 7, nw, blocks) == simple
