"""Password-based local backup reading. No password recovery or network use.

Android format: AOSP PerformAdbBackupTask / PasswordUtils format descriptions.
iOS: backup keybag TLV, RFC3394 wrapping, per-file CBC. Optional cryptography
is used for iOS and larger Android payloads; never installed automatically.
"""
import hashlib
import hmac
import struct
import sys

from .aes import aes_cbc_decrypt


def backup_cbc(key, data, iv=b"\0" * 16, unpad=False):
    if len(data) % 16 or len(iv) != 16:
        raise ValueError("invalid encrypted block length")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("encrypted data exceeds the pure-Python limit; install optional cryptography")
        return aes_cbc_decrypt(key, iv, data, unpad=unpad)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = decryptor.update(data) + decryptor.finalize()
    if unpad:
        n = out[-1] if out else 0
        if not 1 <= n <= 16 or out[-n:] != bytes([n]) * n:
            raise ValueError("invalid password or damaged encrypted backup")
        out = out[:-n]
    return out


def backup_android_decrypt(body, password):
    if not password:
        raise ValueError("encrypted SMS backup needs --backup-password")
    parts = body.split(b"\n", 5)
    if len(parts) != 6 or any(len(p) > 2048 for p in parts[:5]):
        raise ValueError("invalid encryption header")
    salt, checksum_salt, rounds, iv, wrapped, ciphertext = parts
    rounds = int(rounds)
    if not 1 <= rounds <= 1000000:
        raise ValueError("password derivation rounds outside the supported limit")
    salt, checksum_salt = bytes.fromhex(salt.decode()), bytes.fromhex(checksum_salt.decode())
    iv, wrapped = bytes.fromhex(iv.decode()), bytes.fromhex(wrapped.decode())
    if len(salt) != 64 or len(checksum_salt) != 64 or len(wrapped) > 256:
        raise ValueError("invalid encryption header")
    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, rounds, 32)
    blob = backup_cbc(key, wrapped, iv, True)
    fields, offset = [], 0
    for expected in (16, 32, 32):
        if offset >= len(blob) or blob[offset] != expected:
            raise ValueError("invalid password or master-key record")
        fields.append(blob[offset + 1:offset + 1 + expected])
        offset += 1 + expected
    if offset != len(blob):
        raise ValueError("invalid master-key record")
    data_iv, data_key, checksum = fields
    # Java's signed byte -> char conversion sign-extends before UTF-8 encoding.
    chars = "".join(chr(b if b < 128 else 0xff00 + b) for b in data_key)
    actual = hashlib.pbkdf2_hmac("sha1", chars.encode("utf-8"), checksum_salt, rounds, 32)
    if not hmac.compare_digest(actual, checksum):
        raise ValueError("invalid password or master-key checksum")
    return backup_cbc(data_key, ciphertext, data_iv, True)


def backup_ios_keys(blob, password):
    try:
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    except ImportError:
        # Most often it is installed, but for a different Python from the one
        # running the check: say which one, and give the command that fixes it.
        raise ValueError(
            "encrypted iPhone backups require optional cryptography, which is not installed for "
            "the Python running this check (Python {}.{}). Install it with the same command you "
            "start the check with, from the toolkit folder: python3 -m pip install "
            "--require-hashes -r requirements-backups.txt (on Windows: python -m pip ...)".format(
                sys.version_info[0], sys.version_info[1]))
    if not password:
        raise ValueError("encrypted iPhone backup needs --backup-password")
    if not isinstance(blob, bytes) or len(blob) > 1024 * 1024:
        raise ValueError("invalid backup keybag")
    header, groups, current, uuids, offset = {}, [], None, 0, 0
    while offset < len(blob):
        if offset + 8 > len(blob):
            raise ValueError("truncated keybag")
        tag, size = struct.unpack_from(">4sI", blob, offset)
        offset += 8
        if size > 4096 or offset + size > len(blob):
            raise ValueError("invalid keybag record")
        value = blob[offset:offset + size]
        offset += size
        if tag == b"UUID":
            uuids += 1
            if uuids > 65:
                raise ValueError("keybag class limit exceeded")
            if uuids > 1:
                current = {}
                groups.append(current)
        (header if current is None else current)[tag] = value
    def number(mapping, tag):
        raw = mapping.get(tag)
        if not isinstance(raw, bytes) or len(raw) != 4:
            raise ValueError("missing keybag number")
        return int.from_bytes(raw, "big")
    secret = password.encode("utf-8")
    for digest, salt_tag, count_tag in (("sha256", b"DPSL", b"DPIC"), ("sha1", b"SALT", b"ITER")):
        if salt_tag == b"DPSL" and salt_tag not in header:
            continue
        salt = header.get(salt_tag)
        count = number(header, count_tag)
        if not isinstance(salt, bytes) or not 1 <= len(salt) <= 128 or not 1 <= count <= 20000000:
            raise ValueError("unsupported keybag derivation parameters")
        secret = hashlib.pbkdf2_hmac(digest, secret, salt, count, 32)
    keys = {}
    for group in groups:
        if number(group, b"WRAP") == 2 and b"WPKY" in group:
            try:
                if len(group[b"WPKY"]) != 40:
                    continue
                keys[number(group, b"CLAS")] = aes_key_unwrap(secret, group[b"WPKY"])
            except Exception:
                continue
    if not keys:
        raise ValueError("incorrect password or unsupported/damaged keybag")
    return keys


def backup_ios_file_key(keys, wrapped):
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    if not isinstance(wrapped, bytes) or len(wrapped) != 44:
        raise ValueError("invalid wrapped backup file key")
    protection = int.from_bytes(wrapped[:4], "little")
    if protection not in keys:
        raise ValueError("file protection class could not be unlocked")
    try:
        return aes_key_unwrap(keys[protection], wrapped[4:])
    except Exception:
        raise ValueError("backup file key could not be verified")
