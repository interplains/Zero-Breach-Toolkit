"""The list of files inside a 7-Zip archive, read from its header - nothing is unpacked or run.

7-Zip compresses that list by default (an "encoded header"), so the one stream holding it is decompressed with the
standard library's LZMA - within strict size limits - and never any file's contents. With "encrypt file names"
(-mhe) the list itself is locked: that is reported, and is a reason for a closer look on its own.

Format: https://py7zr.readthedocs.io/en/latest/archive_format.html (7-Zip's 7zFormat.txt).
"""
import lzma
import struct

SZ_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
SZ_MAX_HEADER = 16 * 1024 * 1024        # the list of files, packed or unpacked
SZ_MAX_FILES = 100000

_K_END, _K_HEADER, _K_ARCHIVE_PROPS, _K_ADDITIONAL, _K_MAIN = 0x00, 0x01, 0x02, 0x03, 0x04
_K_FILES, _K_PACK, _K_UNPACK, _K_SUBSTREAMS, _K_SIZE, _K_CRC = 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A
_K_FOLDER, _K_UNPACK_SIZE, _K_NUM_UNPACK, _K_EMPTY_STREAM, _K_EMPTY_FILE = 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
_K_NAME, _K_ATTRIBUTES, _K_ENCODED_HEADER, _K_DUMMY = 0x11, 0x15, 0x17, 0x19

_ID_COPY, _ID_LZMA, _ID_LZMA2, _ID_AES = b"\x00", b"\x03\x01\x01", b"\x21", b"\x06\xf1\x07\x01"


class SzError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise SzError("the header ends early")
        self.pos += 1
        return self.data[self.pos - 1]

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise SzError("the header ends early")
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def number(self) -> int:
        """7-Zip's variable-length number: the leading 1-bits of the first byte say how many bytes follow."""
        first, mask, value = self.byte(), 0x80, 0
        for i in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * i))
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def bits(self, count: int):
        out, value, mask = [], 0, 0
        for _ in range(count):
            if not mask:
                value, mask = self.byte(), 0x80
            out.append(bool(value & mask))
            mask >>= 1
        return out

    def defined(self, count: int):
        all_defined = self.byte()
        return [True] * count if all_defined else self.bits(count)


def _limit(n: int, cap: int, what: str) -> int:
    if n > cap:
        raise SzError("too many {} ({:,})".format(what, n))
    return n


def _pack_info(r):
    r.number()                                          # where the packed streams start
    count = _limit(r.number(), 1000, "packed streams")
    sizes = []
    while True:
        kind = r.byte()
        if kind == _K_END:
            return sizes
        if kind == _K_SIZE:
            sizes = [r.number() for _ in range(count)]
        elif kind == _K_CRC:
            flags = r.defined(count)
            r.take(4 * sum(flags))
        else:
            raise SzError("unexpected item in the pack information")


def _streams_info(r):
    """[(coders, unpack sizes, crc known)] per folder, and the substream counts; the header stream is folder 0."""
    folders, packed = [], []
    while True:
        kind = r.byte()
        if kind == _K_END:
            return folders
        if kind == _K_PACK:
            packed = _pack_info(r)
        elif kind == _K_UNPACK:
            if r.byte() != _K_FOLDER:
                raise SzError("folders expected")
            count = _limit(r.number(), 100000, "folders")
            if r.byte() != 0:
                raise SzError("external folder data is not supported")
            for _ in range(count):
                coders, outs = [], 0
                for _ in range(_limit(r.number(), 64, "coders")):
                    flag = r.byte()
                    cid = r.take(flag & 0x0F)
                    n_in, n_out = (r.number(), r.number()) if flag & 0x10 else (1, 1)
                    props = r.take(r.number()) if flag & 0x20 else b""
                    coders.append((cid, props, n_in, n_out))
                    outs += n_out
                ins = sum(c[2] for c in coders)
                for _ in range(max(0, outs - 1)):
                    r.number(), r.number()              # bind pairs
                packed_streams = ins - max(0, outs - 1)
                if packed_streams > 1:
                    for _ in range(packed_streams):
                        r.number()
                folders.append({"coders": coders, "outs": outs, "sizes": [], "crc": False, "packed": packed})
            if r.byte() != _K_UNPACK_SIZE:
                raise SzError("unpack sizes expected")
            for f in folders:
                f["sizes"] = [r.number() for _ in range(f["outs"])]
            while True:
                kind2 = r.byte()
                if kind2 == _K_END:
                    break
                if kind2 == _K_CRC:
                    flags = r.defined(len(folders))
                    for f, has in zip(folders, flags):
                        f["crc"] = has
                    r.take(4 * sum(flags))
                else:
                    raise SzError("unexpected item in the unpack information")
        elif kind == _K_SUBSTREAMS:
            counts = [1] * len(folders)
            while True:
                kind2 = r.byte()
                if kind2 == _K_END:
                    break
                if kind2 == _K_NUM_UNPACK:
                    counts = [_limit(r.number(), SZ_MAX_FILES, "files") for _ in folders]
                elif kind2 == _K_SIZE:
                    for c in counts:
                        for _ in range(max(0, c - 1)):
                            r.number()
                elif kind2 == _K_CRC:
                    unknown = sum(c for f, c in zip(folders, counts) if not (c == 1 and f["crc"]))
                    flags = r.defined(unknown)
                    r.take(4 * sum(flags))
                else:
                    raise SzError("unexpected item in the substream information")
        else:
            raise SzError("unexpected item in the stream information")


def _decode_header(raw: bytes, folders) -> bytes:
    """Unpack the one stream that holds the (encoded) list of files."""
    if not folders or not folders[0]["coders"]:
        raise SzError("no stream for the list of files")
    folder = folders[0]
    if len(folder["coders"]) != 1:
        if any(c[0] == _ID_AES for c in folder["coders"]):
            raise SzError("encrypted")
        raise SzError("the list of files uses a filter chain this check does not unpack")
    cid, props, _i, _o = folder["coders"][0]
    size = folder["sizes"][0] if folder["sizes"] else 0
    packed = folder["packed"][0] if folder["packed"] else 0
    if size > SZ_MAX_HEADER or packed > SZ_MAX_HEADER:
        raise SzError("the list of files is too large to read")
    raw = raw[:packed]
    if cid == _ID_AES:
        raise SzError("encrypted")
    if cid == _ID_COPY:
        return raw[:size]
    if cid == _ID_LZMA and len(props) >= 5:
        d = props[0]
        lc, lp, pb = d % 9, (d // 9) % 5, d // 45
        dict_size = struct.unpack("<I", props[1:5])[0]
        filt = {"id": lzma.FILTER_LZMA1, "dict_size": max(4096, dict_size), "lc": lc, "lp": lp, "pb": pb}
    elif cid == _ID_LZMA2 and props:
        b = props[0] & 0x3F
        dict_size = 0xFFFFFFFF if b >= 40 else (2 | (b & 1)) << (b // 2 + 11)
        filt = {"id": lzma.FILTER_LZMA2, "dict_size": min(dict_size, 1 << 30)}
    else:
        raise SzError("the list of files uses a method this check does not unpack")
    try:
        out = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[filt]).decompress(raw, max_length=size)
    except lzma.LZMAError as exc:
        raise SzError("the list of files could not be unpacked ({})".format(exc))
    return out


def _files_info(r):
    count = _limit(r.number(), SZ_MAX_FILES, "files")
    names, empty_stream, empty_file, attrs = [], [], [], {}
    while True:
        kind = r.number()
        if kind == _K_END:
            break
        body = _Reader(r.take(_limit(r.number(), SZ_MAX_HEADER, "header bytes")))
        if kind == _K_NAME:
            if body.byte() != 0:
                raise SzError("external names are not supported")
            text = body.data[body.pos:].decode("utf-16-le", "replace")
            names = text.split("\x00")[:count]
        elif kind == _K_EMPTY_STREAM:
            empty_stream = body.bits(count)
        elif kind == _K_EMPTY_FILE:
            empty_file = body.bits(sum(empty_stream))
        elif kind == _K_ATTRIBUTES:
            flags = body.defined(count)
            if body.byte() == 0:
                for i, has in enumerate(flags):
                    if has:
                        attrs[i] = struct.unpack("<I", body.take(4))[0]
    out, e = [], 0
    for i, name in enumerate(names):
        is_dir = bool(attrs.get(i, 0) & 0x10)
        if i < len(empty_stream) and empty_stream[i]:
            if e < len(empty_file) and not empty_file[e] and i not in attrs:
                is_dir = True
            e += 1
        out.append((name.replace("\\", "/"), is_dir))
    return out


def sz_list(path: str):
    """{"files": [(name, is_folder)], "encrypted": bool, "problem": ""} for a 7-Zip archive."""
    result = {"files": [], "encrypted": False, "problem": ""}
    try:
        with open(path, "rb") as fh:
            start = fh.read(32)
            if start[:6] != SZ_SIGNATURE or len(start) < 32:
                raise SzError("not a 7-Zip archive")
            offset, size = struct.unpack_from("<QQ", start, 12)
            if size == 0:
                return result                           # an empty archive
            if size > SZ_MAX_HEADER:
                raise SzError("the list of files is too large to read")
            fh.seek(32 + offset)
            header = fh.read(size)
            if len(header) != size:
                raise SzError("the archive is cut short")
            r = _Reader(header)
            kind = r.byte()
            for _ in range(4):                          # an encoded header can itself be encoded
                if kind != _K_ENCODED_HEADER:
                    break
                pack_pos = _pack_position(header)
                folders = _streams_info(r)
                packed = folders[0]["packed"][0] if folders and folders[0]["packed"] else 0
                if packed > SZ_MAX_HEADER:
                    raise SzError("the list of files is too large to read")
                fh.seek(32 + pack_pos)                  # only the packed list itself is read, never the files
                header = _decode_header(fh.read(packed), folders)
                r = _Reader(header)
                kind = r.byte()
            if kind != _K_HEADER:
                raise SzError("no list of files")
            while True:
                kind = r.byte()
                if kind == _K_END:
                    break
                if kind == _K_ARCHIVE_PROPS:
                    while r.byte() != _K_END:
                        r.take(r.number())
                elif kind in (_K_ADDITIONAL, _K_MAIN):
                    for folder in _streams_info(r):
                        if any(c[0] == _ID_AES for c in folder["coders"]):
                            result["encrypted"] = True       # the files are password-protected
                elif kind == _K_FILES:
                    result["files"] = _files_info(r)
                else:
                    raise SzError("unexpected item in the header")
    except SzError as exc:
        if str(exc) == "encrypted":
            result["encrypted"] = True
        else:
            result["problem"] = str(exc)
    except (OSError, struct.error, IndexError, MemoryError) as exc:
        result["problem"] = "the list of files could not be read ({})".format(type(exc).__name__)
    return result


def _pack_position(header: bytes) -> int:
    """Where the packed stream of an encoded header starts (after the 32-byte signature header)."""
    r = _Reader(header)
    if r.byte() != _K_ENCODED_HEADER or r.byte() != _K_PACK:
        raise SzError("no pack information for the list of files")
    return r.number()
