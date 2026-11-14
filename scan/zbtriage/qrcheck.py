"""Check a QR code (--check-qr IMAGE): read it without following it, then check what it says.

A QR code is a link you cannot read. Someone photographs a screen, prints a sticker over a real one, or sends a
picture "to log in", and a person points a camera at it with no idea where it goes. The worst of them link a
messaging account to the attacker's device: one scan, and every message from then on is theirs too.

This decodes the code from an image file on this computer - nothing is scanned with a camera, nothing is opened,
nothing is contacted - and then hands what it says to the same check as "Check a link or message", so account-
linking addresses, look-alike names and known spyware links are all recognised.

The decoder is written here in plain Python: the QR standard's own grid, masking, error correction (Reed-Solomon
over GF(256)) and the four ways text is packed. It reads PNG, GIF, BMP and plain PPM/PGM with no other software
installed; for JPEG and HEIC a photo has to be saved as PNG first, and it says so.
"""
from __future__ import annotations

import os
import re
import struct
import zlib
from typing import Dict, List, Optional, Tuple

from .i18n import T
from .linkcheck import lc_para, lc_say, lc_shown

QR_KNOWN, QR_DANGER, QR_LOOK, QR_NOTHING = "known-threat", "dangerous", "worth-a-look", "nothing-known"
QR_MAX_BYTES = 64 * 1024 * 1024
QR_MAX_SIDE = 6000


class QrError(ValueError):
    pass


# --- pictures ------------------------------------------------------------------------------------------------

def qr_load_image(data: bytes) -> Tuple[int, int, List[List[int]]]:
    """(width, height, rows of 0-255 grey) from a picture this module can read by itself. A cut-short or damaged
    picture is "the picture is damaged", whatever low-level error its decoder ran into (a 6-byte GIF raised
    struct.error before this)."""
    import zlib
    try:
        return _qr_load_image(data)
    except QrError:
        raise
    except (struct.error, IndexError, KeyError, ValueError, ZeroDivisionError, EOFError, OverflowError,
            MemoryError, zlib.error):
        raise QrError(T("the picture is damaged"))


def _qr_load_image(data: bytes) -> Tuple[int, int, List[List[int]]]:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return _qr_png(data)
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return _qr_gif(data)
    if data[:2] == b"BM":
        return _qr_bmp(data)
    if data[:2] in (b"P5", b"P6", b"P4"):
        return _qr_pnm(data)
    if data[:3] == b"\xff\xd8\xff":
        raise QrError(T("that is a JPEG photo. Open it in any picture viewer and save it as PNG, then check that"))
    if data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1"):
        raise QrError(T("that is a HEIC photo (an iPhone picture). Save or export it as PNG, then check that"))
    raise QrError(T("that file is not a picture this check can read (PNG, GIF, BMP or PPM)"))


def _qr_grey(r, g, b) -> int:
    return (r * 299 + g * 587 + b * 114) // 1000


def _qr_png(data: bytes):
    pos, chunks, head = 8, [], None
    palette, transparency = b"", b""
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        if length > len(data):
            raise QrError(T("the picture is damaged"))
        body = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            head = struct.unpack(">IIBBBBB", body[:13])
        elif kind == b"PLTE":
            palette = body
        elif kind == b"tRNS":
            transparency = body
        elif kind == b"IDAT":
            chunks.append(body)
        elif kind == b"IEND":
            break
        pos += 12 + length
    if not head or not chunks:
        raise QrError(T("the picture could not be read"))
    width, height, depth, colour, compression, filtering, interlace = head
    if not (0 < width <= QR_MAX_SIDE and 0 < height <= QR_MAX_SIDE):
        raise QrError(T("the picture is {width}x{height}; the limit is {limit} on a side", width=width, height=height,
                        limit=QR_MAX_SIDE))
    if interlace:
        raise QrError(T("this picture is saved in an interlaced form the check cannot read; save it again as a "
                        "plain PNG"))
    if compression or filtering:
        raise QrError(T("the picture uses an unknown compression"))
    try:
        raw = zlib.decompress(b"".join(chunks))
    except zlib.error:
        raise QrError(T("the picture's data is damaged"))
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if channels is None or depth not in (1, 2, 4, 8, 16):
        raise QrError(T("the picture uses a colour format the check cannot read"))
    rows = _qr_unfilter(raw, width, height, channels, depth)
    out = []
    for row in rows:
        line = []
        for x in range(width):
            values = row[x * channels:(x + 1) * channels]
            if colour == 3:
                index = values[0]
                if palette and index * 3 + 2 < len(palette):
                    r, g, b = palette[index * 3:index * 3 + 3]
                else:
                    r = g = b = 0
                grey = _qr_grey(r, g, b)
                if transparency and index < len(transparency) and transparency[index] == 0:
                    grey = 255
            elif colour in (0, 4):
                grey = values[0]
                if colour == 4 and values[1] < 128:
                    grey = 255
            else:
                grey = _qr_grey(values[0], values[1], values[2])
                if colour == 6 and values[3] < 128:
                    grey = 255
            line.append(grey)
        out.append(line)
    return width, height, out


def _qr_unfilter(raw, width, height, channels, depth):
    """Undo PNG's per-row filters; every row comes back as one byte per channel per pixel."""
    bits = channels * depth
    stride = (width * bits + 7) // 8
    step = max(1, bits // 8)
    rows = []
    previous = bytearray(stride)
    pos = 0
    for _y in range(height):
        if pos + 1 + stride > len(raw):
            raise QrError(T("the picture's data is incomplete"))
        kind = raw[pos]
        line = bytearray(raw[pos + 1:pos + 1 + stride])
        pos += 1 + stride
        if kind == 1:
            for i in range(step, stride):
                line[i] = (line[i] + line[i - step]) & 0xFF
        elif kind == 2:
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 0xFF
        elif kind == 3:
            for i in range(stride):
                left = line[i - step] if i >= step else 0
                line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif kind == 4:
            for i in range(stride):
                a = line[i - step] if i >= step else 0
                b = previous[i]
                c = previous[i - step] if i >= step else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else (b if pb <= pc else c))) & 0xFF
        elif kind:
            raise QrError(T("the picture uses an unknown row filter"))
        previous = line
        rows.append(_qr_expand(line, width, channels, depth))
    return rows


def _qr_expand(line, width, channels, depth):
    if depth == 8:
        return line
    if depth == 16:
        return bytearray(line[i] for i in range(0, len(line), 2))
    out = bytearray()
    per_byte = 8 // depth
    top = (1 << depth) - 1
    for i in range(width * channels):
        byte = line[i // per_byte]
        shift = 8 - depth * (i % per_byte + 1)
        value = (byte >> shift) & top
        out.append(value * 255 // top if top else 0)
    return out


def _qr_bmp(data: bytes):
    if len(data) < 54:
        raise QrError(T("the picture is too short to be a BMP"))
    offset = struct.unpack_from("<I", data, 10)[0]
    header = struct.unpack_from("<IiiHH", data, 14)
    width, height, planes, depth = header[1], header[2], header[3], header[4]
    compression = struct.unpack_from("<I", data, 30)[0]
    if compression != 0 or planes != 1 or depth not in (1, 4, 8, 24, 32):
        raise QrError(T("this BMP uses a form the check cannot read; save it as PNG"))
    flip = height > 0
    height = abs(height)
    if not (0 < width <= QR_MAX_SIDE and 0 < height <= QR_MAX_SIDE):
        raise QrError(T("the picture is too large"))
    header_size = struct.unpack_from("<I", data, 14)[0]
    palette = data[14 + header_size:offset] if depth <= 8 else b""
    stride = ((width * depth + 31) // 32) * 4
    rows = []
    for y in range(height):
        start = offset + stride * y
        line = data[start:start + stride]
        if len(line) < stride:
            raise QrError(T("the picture's data is incomplete"))
        out = []
        for x in range(width):
            if depth == 24 or depth == 32:
                step = depth // 8
                b, g, r = line[x * step], line[x * step + 1], line[x * step + 2]
                out.append(_qr_grey(r, g, b))
            else:
                per_byte = 8 // depth
                byte = line[x // per_byte]
                shift = 8 - depth * (x % per_byte + 1)
                index = (byte >> shift) & ((1 << depth) - 1)
                if palette and index * 4 + 2 < len(palette):
                    b, g, r = palette[index * 4:index * 4 + 3]
                    out.append(_qr_grey(r, g, b))
                else:
                    out.append(0 if index else 255)
        rows.append(out)
    if flip:
        rows.reverse()
    return width, height, rows


def _qr_gif(data: bytes):
    width, height = struct.unpack_from("<HH", data, 6)
    flags = data[10]
    pos = 13
    table = b""
    if flags & 0x80:
        size = 3 * (2 ** ((flags & 7) + 1))
        table = data[pos:pos + size]
        pos += size
    while pos < len(data):
        block = data[pos]
        if block == 0x21:                                  # extension
            pos += 2
            while pos < len(data) and data[pos]:
                pos += data[pos] + 1
            pos += 1
            continue
        if block == 0x2C:                                  # image
            iw, ih = struct.unpack_from("<HH", data, pos + 5)
            local = data[pos + 9]
            pos += 10
            if local & 0x80:
                size = 3 * (2 ** ((local & 7) + 1))
                table = data[pos:pos + size]
                pos += size
            depth = data[pos]
            pos += 1
            stream = bytearray()
            while pos < len(data) and data[pos]:
                length = data[pos]
                stream += data[pos + 1:pos + 1 + length]
                pos += 1 + length
            indexes = _qr_lzw(bytes(stream), depth, iw * ih)
            if local & 0x40:
                # interlaced: the rows were stored in four passes, so put them back in order
                order = ([y for y in range(0, ih, 8)] + [y for y in range(4, ih, 8)]
                         + [y for y in range(2, ih, 4)] + [y for y in range(1, ih, 2)])
                reordered = [0] * (iw * ih)
                for stored, y in enumerate(order):
                    reordered[y * iw:(y + 1) * iw] = indexes[stored * iw:(stored + 1) * iw]
                indexes = reordered
            rows = []
            for y in range(ih):
                line = []
                for x in range(iw):
                    i = y * iw + x
                    index = indexes[i] if i < len(indexes) else 0
                    if table and index * 3 + 2 < len(table):
                        r, g, b = table[index * 3:index * 3 + 3]
                        line.append(_qr_grey(r, g, b))
                    else:
                        line.append(0 if index else 255)
                rows.append(line)
            return iw, ih, rows
        break
    raise QrError(T("no picture was found in that GIF"))


def _qr_lzw(data: bytes, depth: int, limit: int) -> List[int]:
    clear, end = 1 << depth, (1 << depth) + 1
    table = [[i] for i in range(clear)] + [[], []]
    out: List[int] = []
    size = depth + 1
    previous: Optional[List[int]] = None
    buffer = bits = 0
    for byte in data:
        buffer |= byte << bits
        bits += 8
        while bits >= size:
            code = buffer & ((1 << size) - 1)
            buffer >>= size
            bits -= size
            if code == clear:
                table = [[i] for i in range(clear)] + [[], []]
                size = depth + 1
                previous = None
                continue
            if code == end:
                return out[:limit]
            if code < len(table):
                entry = table[code]
            elif previous is not None:
                entry = previous + previous[:1]
            else:
                return out[:limit]
            out.extend(entry)
            if previous is not None:
                table.append(previous + entry[:1])
                if len(table) >= (1 << size) and size < 12:
                    size += 1
            previous = entry
            if len(out) >= limit:
                return out[:limit]
    return out[:limit]


def _qr_pnm(data: bytes):
    fields: List[bytes] = []
    pos = 2
    while len(fields) < (2 if data[:2] == b"P4" else 3):
        while pos < len(data) and data[pos:pos + 1].isspace():
            pos += 1
        if data[pos:pos + 1] == b"#":
            while pos < len(data) and data[pos] != 0x0A:
                pos += 1
            continue
        start = pos
        while pos < len(data) and not data[pos:pos + 1].isspace():
            pos += 1
        fields.append(data[start:pos])
    pos += 1
    width, height = int(fields[0]), int(fields[1])
    if not (0 < width <= QR_MAX_SIDE and 0 < height <= QR_MAX_SIDE):
        raise QrError(T("the picture is too large"))
    body = data[pos:]
    rows = []
    if data[:2] == b"P4":
        stride = (width + 7) // 8
        for y in range(height):
            line = body[y * stride:(y + 1) * stride]
            rows.append([(0 if (line[x // 8] >> (7 - x % 8)) & 1 else 255) if x // 8 < len(line) else 255
                         for x in range(width)])
        return width, height, rows
    channels = 3 if data[:2] == b"P6" else 1
    for y in range(height):
        line = body[y * width * channels:(y + 1) * width * channels]
        if channels == 1:
            rows.append(list(line) + [255] * (width - len(line)))
        else:
            rows.append([_qr_grey(line[x * 3], line[x * 3 + 1], line[x * 3 + 2]) if x * 3 + 2 < len(line) else 255
                         for x in range(width)])
    return width, height, rows


# --- finding the code in the picture --------------------------------------------------------------------------

def qr_to_black_white(rows, width, height) -> List[List[int]]:
    """1 for dark, 0 for light, using one threshold found from the picture itself."""
    counts = [0] * 256
    for row in rows:
        for value in row:
            counts[value] += 1
    total = sum(counts)
    if not total:
        raise QrError(T("the picture is empty"))
    # Otsu's method: the threshold that best separates dark from light.
    sum_all = sum(i * counts[i] for i in range(256))
    best, threshold, seen, weighted = -1.0, 128, 0, 0
    for t in range(256):
        seen += counts[t]
        if seen == 0 or seen == total:
            continue
        weighted += t * counts[t]
        dark_mean = weighted / seen
        light_mean = (sum_all - weighted) / (total - seen)
        score = seen * (total - seen) * (dark_mean - light_mean) ** 2
        if score > best:
            best, threshold = score, t
    return [[1 if value <= threshold else 0 for value in row] for row in rows]


def qr_grid(bits, width, height) -> Tuple[List[List[int]], int]:
    """(the code as a square of modules, how many modules a side) from a picture of one."""
    top, bottom, left, right = height, -1, width, -1
    for y in range(height):
        row = bits[y]
        if 1 in row:
            top = min(top, y)
            bottom = max(bottom, y)
            left = min(left, row.index(1))
            right = max(right, width - 1 - row[::-1].index(1))
    if bottom < 0 or right < left or bottom < top:
        raise QrError(T("no QR code was found in that picture (nothing dark in it)"))
    box_w, box_h = right - left + 1, bottom - top + 1
    if min(box_w, box_h) < 21:
        raise QrError(T("the code in that picture is too small to read; use a larger or sharper picture"))
    module = _qr_module_size(bits, top, left, box_w)
    for size in _qr_candidate_sizes(box_w, box_h, module):
        grid = _qr_sample(bits, top, left, box_w, box_h, size)
        if grid is not None and _qr_has_finders(grid, size):
            return grid, size
    raise QrError(T("that picture does not hold a QR code the check can line up. A straight-on, sharp picture of "
                    "the whole code, with a little white around it, reads best"))


def _qr_module_size(bits, top, left, box_w) -> int:
    """How many pixels one module is, from the top-left finder pattern's dark run."""
    row = bits[top]
    run = 0
    for x in range(left, min(left + box_w, len(row))):
        if row[x]:
            run += 1
        else:
            break
    return max(1, run // 7) if run >= 7 else 1


def _qr_candidate_sizes(box_w, box_h, module) -> List[int]:
    guesses = []
    for box in (box_w, box_h):
        guess = int(round(box / module)) if module else 0
        for delta in (0, 1, -1, 2, -2, 3, -3, 4, -4):
            size = guess + delta
            if size >= 21 and size <= 177 and (size - 17) % 4 == 0 and size not in guesses:
                guesses.append(size)
    for size in range(21, 178, 4):
        if size not in guesses:
            guesses.append(size)
    return guesses


def _qr_sample(bits, top, left, box_w, box_h, size) -> Optional[List[List[int]]]:
    grid = []
    for row in range(size):
        line = []
        for col in range(size):
            y = top + int((row + 0.5) * box_h / size)
            x = left + int((col + 0.5) * box_w / size)
            if not (0 <= y < len(bits) and 0 <= x < len(bits[0])):
                return None
            step_y, step_x = box_h // size, box_w // size
            if step_y < 4 or step_x < 4:
                # modules only a pixel or two across: the centre pixel is the only honest answer, because
                # looking at a neighbour would be looking at the next module
                line.append(bits[y][x])
            else:
                votes = points = 0
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        yy, xx = y + dy * (step_y // 4), x + dx * (step_x // 4)
                        if 0 <= yy < len(bits) and 0 <= xx < len(bits[0]):
                            votes += bits[yy][xx]
                            points += 1
                line.append(1 if points and votes * 2 > points else 0)
        grid.append(line)
    return grid


_QR_FINDER = [[1, 1, 1, 1, 1, 1, 1],
              [1, 0, 0, 0, 0, 0, 1],
              [1, 0, 1, 1, 1, 0, 1],
              [1, 0, 1, 1, 1, 0, 1],
              [1, 0, 1, 1, 1, 0, 1],
              [1, 0, 0, 0, 0, 0, 1],
              [1, 1, 1, 1, 1, 1, 1]]


def _qr_finder_score(grid, size, oy, ox) -> int:
    good = 0
    for y in range(7):
        for x in range(7):
            if oy + y < size and ox + x < size and grid[oy + y][ox + x] == _QR_FINDER[y][x]:
                good += 1
    return good


def _qr_has_finders(grid, size) -> bool:
    total = (_qr_finder_score(grid, size, 0, 0) + _qr_finder_score(grid, size, 0, size - 7)
             + _qr_finder_score(grid, size, size - 7, 0))
    return total >= 3 * 49 - 6


# --- reading the code ------------------------------------------------------------------------------------------

def _qr_function_map(size: int) -> List[List[int]]:
    """1 where a module is part of the code's structure rather than the message."""
    version = (size - 17) // 4
    taken = [[0] * size for _ in range(size)]

    def block(y0, x0, h, w):
        for y in range(y0, y0 + h):
            for x in range(x0, x0 + w):
                if 0 <= y < size and 0 <= x < size:
                    taken[y][x] = 1
    block(0, 0, 9, 9)
    block(0, size - 8, 9, 8)
    block(size - 8, 0, 8, 9)
    for i in range(size):
        taken[6][i] = 1
        taken[i][6] = 1
    for cy in _QR_ALIGN.get(version, []):
        for cx in _QR_ALIGN.get(version, []):
            if (cy, cx) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            block(cy - 2, cx - 2, 5, 5)
    if version >= 7:
        block(size - 11, 0, 3, 6)
        block(0, size - 11, 6, 3)
    return taken


_QR_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
             7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50], 11: [6, 30, 54],
             12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66], 15: [6, 26, 48, 70],
             16: [6, 26, 50, 74], 17: [6, 30, 54, 78], 18: [6, 30, 56, 82], 19: [6, 30, 58, 86],
             20: [6, 34, 62, 90], 21: [6, 28, 50, 72, 94], 22: [6, 26, 50, 74, 98],
             23: [6, 30, 54, 78, 102], 24: [6, 28, 54, 80, 106], 25: [6, 32, 58, 84, 110],
             26: [6, 30, 58, 86, 114], 27: [6, 34, 62, 90, 118], 28: [6, 26, 50, 74, 98, 122],
             29: [6, 30, 54, 78, 102, 126], 30: [6, 26, 52, 78, 104, 130], 31: [6, 30, 56, 82, 108, 134],
             32: [6, 34, 60, 86, 112, 138], 33: [6, 30, 58, 86, 114, 142], 34: [6, 34, 62, 90, 118, 146],
             35: [6, 30, 54, 78, 102, 126, 150], 36: [6, 24, 50, 76, 102, 128, 154],
             37: [6, 28, 54, 80, 106, 132, 158], 38: [6, 32, 58, 84, 110, 136, 162],
             39: [6, 26, 54, 82, 110, 138, 166], 40: [6, 30, 58, 86, 114, 142, 170]}

_QR_MASKS = (lambda y, x: (y + x) % 2 == 0,
             lambda y, x: y % 2 == 0,
             lambda y, x: x % 3 == 0,
             lambda y, x: (y + x) % 3 == 0,
             lambda y, x: (y // 2 + x // 3) % 2 == 0,
             lambda y, x: (y * x) % 2 + (y * x) % 3 == 0,
             lambda y, x: ((y * x) % 2 + (y * x) % 3) % 2 == 0,
             lambda y, x: ((y + x) % 2 + (y * x) % 3) % 2 == 0)

_QR_FORMAT_MASK = 0b101010000010010


def qr_read_format(grid, size) -> Tuple[int, int]:
    """(error-correction level, mask number) from the format information, repaired if need be."""
    first = [grid[8][x] for x in range(6)] + [grid[8][7], grid[8][8], grid[7][8]] + \
        [grid[y][8] for y in (5, 4, 3, 2, 1, 0)]
    second = [grid[size - 1 - i][8] for i in range(7)] + [grid[8][size - 8 + i] for i in range(8)]
    best = None
    for bits in (first, second):
        value = 0
        for bit in bits:
            value = (value << 1) | bit
        value ^= _QR_FORMAT_MASK
        for candidate in range(32):
            encoded = _qr_format_bits(candidate)
            distance = bin((value ^ encoded) & 0x7FFF).count("1")
            if best is None or distance < best[0]:
                best = (distance, candidate)
    if best is None or best[0] > 3:
        raise QrError(T("the code's format information could not be read"))
    candidate = best[1]
    return (candidate >> 3) & 3, candidate & 7


def _qr_format_bits(value: int) -> int:
    out = value << 10
    for _ in range(5):
        if out >> 10:
            top = out.bit_length() - 1
            if top >= 10:
                out ^= 0b10100110111 << (top - 10)
            else:
                break
        else:
            break
    return ((value << 10) | out) & 0x7FFF


def qr_bitstream(grid, size, mask) -> List[int]:
    taken = _qr_function_map(size)
    unmask = _QR_MASKS[mask]
    bits = []
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for x in (col, col - 1):
                if not taken[row][x]:
                    bit = grid[row][x]
                    if unmask(row, x):
                        bit ^= 1
                    bits.append(bit)
        col -= 2
        upward = not upward
    return bits


# --- error correction (Reed-Solomon over GF(256)) --------------------------------------------------------------

_GF_EXP = [1] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(1, 255):
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]
del _x, _i


def _gf_mul(a, b):
    return 0 if a == 0 or b == 0 else _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


def _gf_poly_mul(p, q):
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a:
            for j, b in enumerate(q):
                out[i + j] ^= _gf_mul(a, b)
    return out


def _gf_poly_eval(p, x):
    """p(x) with Horner's method; p is most-significant first."""
    y = 0
    for coefficient in p:
        y = _gf_mul(y, x) ^ coefficient
    return y


def _gf_poly_add(p, q):
    out = [0] * max(len(p), len(q))
    for i, c in enumerate(p):
        out[i + len(out) - len(p)] = c
    for i, c in enumerate(q):
        out[i + len(out) - len(q)] ^= c
    return out


def _gf_pow(x, power):
    return _GF_EXP[(_GF_LOG[x] * power) % 255] if x else 0


def _gf_inverse(x):
    if x == 0:
        raise ZeroDivisionError
    return _GF_EXP[255 - _GF_LOG[x]]


def _rs_locator(syndromes, ec_count):
    """The error-locator polynomial, by Berlekamp-Massey."""
    locator, previous = [1], [1]
    for i in range(ec_count):
        previous = previous + [0]
        delta = syndromes[i]
        for j in range(1, len(locator)):
            delta ^= _gf_mul(locator[len(locator) - 1 - j], syndromes[i - j])
        if delta != 0:
            if len(previous) > len(locator):
                scaled = [_gf_mul(c, delta) for c in previous]
                previous = [_gf_div(c, delta) for c in locator]
                locator = scaled
            locator = _gf_poly_add(locator, [_gf_mul(c, delta) for c in previous])
    while locator and locator[0] == 0:
        locator.pop(0)
    return locator


def _rs_positions(locator, length):
    """Where the errors are, by trying every position (Chien search)."""
    errors = len(locator) - 1
    found = []
    for i in range(length):
        if _gf_poly_eval(locator, _GF_EXP[(255 - i) % 255]) == 0:
            found.append(length - 1 - i)
    if len(found) != errors:
        raise QrError(T("too much of the code is damaged to repair"))
    return found


def _gf_solve(matrix, right):
    """Solve a small system in GF(256) by elimination. Returns None when it has no single answer."""
    size = len(right)
    rows = [list(matrix[i]) + [right[i]] for i in range(size)]
    for column in range(size):
        pivot = next((r for r in range(column, size) if rows[r][column]), None)
        if pivot is None:
            return None
        rows[column], rows[pivot] = rows[pivot], rows[column]
        inverse = _gf_inverse(rows[column][column])
        rows[column] = [_gf_mul(value, inverse) for value in rows[column]]
        for r in range(size):
            if r != column and rows[r][column]:
                factor = rows[r][column]
                rows[r] = [a ^ _gf_mul(factor, b) for a, b in zip(rows[r], rows[column])]
    return [rows[i][size] for i in range(size)]


def _rs_repair(block, syndromes, positions):
    """Put the right bytes back at the positions found.

    Each syndrome is the sum of every error's value times its position raised to that syndrome's number:
    S(k) = sum over errors of value * X^k. With the positions known, that is a small set of simultaneous
    equations in GF(256) - one per syndrome, one unknown per error - and solving it exactly is both simpler
    and easier to be sure of than the usual shortcut.
    """
    count = len(positions)
    locations = [_GF_EXP[(len(block) - 1 - position) % 255] for position in positions]
    matrix = [[_gf_pow(location, k) for location in locations] for k in range(count)]
    values = _gf_solve(matrix, syndromes[:count])
    if values is None:
        raise QrError(T("the code could not be repaired"))
    repaired = list(block)
    for position, value in zip(positions, values):
        repaired[position] ^= value
    return repaired


def qr_correct(block: List[int], ec_count: int) -> List[int]:
    """Repair one block and return its data bytes, or say it cannot be repaired.

    Reed-Solomon over GF(256): the syndromes say whether anything is wrong, Berlekamp-Massey finds where,
    Forney's formula says by how much. The result is checked again before it is trusted.
    """
    syndromes = [_gf_poly_eval(block, _GF_EXP[i]) for i in range(ec_count)]
    if not any(syndromes):
        return block[:len(block) - ec_count]
    locator = _rs_locator(syndromes, ec_count)
    if len(locator) - 1 > ec_count // 2:
        raise QrError(T("too much of the code is damaged to repair"))
    positions = _rs_positions(locator, len(block))
    repaired = _rs_repair(list(block), syndromes, positions)
    if any(_gf_poly_eval(repaired, _GF_EXP[i]) for i in range(ec_count)):
        raise QrError(T("the code could not be repaired"))
    return repaired[:len(repaired) - ec_count]


# how many error-correction bytes per block, and how the blocks are grouped, per version and level
_QR_EC = {}


def _qr_ec_table():
    """(ec per block, [(blocks, data bytes per block), ...]) for every version and level 1-40, L M Q H."""
    if _QR_EC:
        return _QR_EC
    rows = (
        # version: L, M, Q, H as (ec_per_block, group1_blocks, group1_data, group2_blocks, group2_data)
        (1, (7, 1, 19, 0, 0), (10, 1, 16, 0, 0), (13, 1, 13, 0, 0), (17, 1, 9, 0, 0)),
        (2, (10, 1, 34, 0, 0), (16, 1, 28, 0, 0), (22, 1, 22, 0, 0), (28, 1, 16, 0, 0)),
        (3, (15, 1, 55, 0, 0), (26, 1, 44, 0, 0), (18, 2, 17, 0, 0), (22, 2, 13, 0, 0)),
        (4, (20, 1, 80, 0, 0), (18, 2, 32, 0, 0), (26, 2, 24, 0, 0), (16, 4, 9, 0, 0)),
        (5, (26, 1, 108, 0, 0), (24, 2, 43, 0, 0), (18, 2, 15, 2, 16), (22, 2, 11, 2, 12)),
        (6, (18, 2, 68, 0, 0), (16, 4, 27, 0, 0), (24, 4, 19, 0, 0), (28, 4, 15, 0, 0)),
        (7, (20, 2, 78, 0, 0), (18, 4, 31, 0, 0), (18, 2, 14, 4, 15), (26, 4, 13, 1, 14)),
        (8, (24, 2, 97, 0, 0), (22, 2, 38, 2, 39), (22, 4, 18, 2, 19), (26, 4, 14, 2, 15)),
        (9, (30, 2, 116, 0, 0), (22, 3, 36, 2, 37), (20, 4, 16, 4, 17), (24, 4, 12, 4, 13)),
        (10, (18, 2, 68, 2, 69), (26, 4, 43, 1, 44), (24, 6, 19, 2, 20), (28, 6, 15, 2, 16)),
        (11, (20, 4, 81, 0, 0), (30, 1, 50, 4, 51), (28, 4, 22, 4, 23), (24, 3, 12, 8, 13)),
        (12, (24, 2, 92, 2, 93), (22, 6, 36, 2, 37), (26, 4, 20, 6, 21), (28, 7, 14, 4, 15)),
        (13, (26, 4, 107, 0, 0), (22, 8, 37, 1, 38), (24, 8, 20, 4, 21), (22, 12, 11, 4, 12)),
        (14, (30, 3, 115, 1, 116), (24, 4, 40, 5, 41), (20, 11, 16, 5, 17), (24, 11, 12, 5, 13)),
        (15, (22, 5, 87, 1, 88), (24, 5, 41, 5, 42), (30, 5, 24, 7, 25), (24, 11, 12, 7, 13)),
        (16, (24, 5, 98, 1, 99), (28, 7, 45, 3, 46), (24, 15, 19, 2, 20), (30, 3, 15, 13, 16)),
        (17, (28, 1, 107, 5, 108), (28, 10, 46, 1, 47), (28, 1, 22, 15, 23), (28, 2, 14, 17, 15)),
        (18, (30, 5, 120, 1, 121), (26, 9, 43, 4, 44), (26, 17, 22, 1, 23), (28, 2, 14, 19, 15)),
        (19, (28, 3, 113, 4, 114), (26, 3, 44, 11, 45), (26, 17, 21, 4, 22), (26, 9, 13, 16, 14)),
        (20, (28, 3, 107, 5, 108), (26, 3, 41, 13, 42), (30, 15, 24, 5, 25), (28, 15, 15, 10, 16)),
        (21, (28, 4, 116, 4, 117), (26, 17, 42, 0, 0), (28, 17, 22, 6, 23), (30, 19, 16, 6, 17)),
        (22, (28, 2, 111, 7, 112), (28, 17, 46, 0, 0), (30, 7, 24, 16, 25), (24, 34, 13, 0, 0)),
        (23, (30, 4, 121, 5, 122), (28, 4, 47, 14, 48), (30, 11, 24, 14, 25), (30, 16, 15, 14, 16)),
        (24, (30, 6, 117, 4, 118), (28, 6, 45, 14, 46), (30, 11, 24, 16, 25), (30, 30, 16, 2, 17)),
        (25, (26, 8, 106, 4, 107), (28, 8, 47, 13, 48), (30, 7, 24, 22, 25), (30, 22, 15, 13, 16)),
        (26, (28, 10, 114, 2, 115), (28, 19, 46, 4, 47), (28, 28, 22, 6, 23), (30, 33, 16, 4, 17)),
        (27, (30, 8, 122, 4, 123), (28, 22, 45, 3, 46), (30, 8, 23, 26, 24), (30, 12, 15, 28, 16)),
        (28, (30, 3, 117, 10, 118), (28, 3, 45, 23, 46), (30, 4, 24, 31, 25), (30, 11, 15, 31, 16)),
        (29, (30, 7, 116, 7, 117), (28, 21, 45, 7, 46), (30, 1, 23, 37, 24), (30, 19, 15, 26, 16)),
        (30, (30, 5, 115, 10, 116), (28, 19, 47, 10, 48), (30, 15, 24, 25, 25), (30, 23, 15, 25, 16)),
        (31, (30, 13, 115, 3, 116), (28, 2, 46, 29, 47), (30, 42, 24, 1, 25), (30, 23, 15, 28, 16)),
        (32, (30, 17, 115, 0, 0), (28, 10, 46, 23, 47), (30, 10, 24, 35, 25), (30, 19, 15, 35, 16)),
        (33, (30, 17, 115, 1, 116), (28, 14, 46, 21, 47), (30, 29, 24, 19, 25), (30, 11, 15, 46, 16)),
        (34, (30, 13, 115, 6, 116), (28, 14, 46, 23, 47), (30, 44, 24, 7, 25), (30, 59, 16, 1, 17)),
        (35, (30, 12, 121, 7, 122), (28, 12, 47, 26, 48), (30, 39, 24, 14, 25), (30, 22, 15, 41, 16)),
        (36, (30, 6, 121, 14, 122), (28, 6, 47, 34, 48), (30, 46, 24, 10, 25), (30, 2, 15, 64, 16)),
        (37, (30, 17, 122, 4, 123), (28, 29, 46, 14, 47), (30, 49, 24, 10, 25), (30, 24, 15, 46, 16)),
        (38, (30, 4, 122, 18, 123), (28, 13, 46, 32, 47), (30, 48, 24, 14, 25), (30, 42, 15, 32, 16)),
        (39, (30, 20, 117, 4, 118), (28, 40, 47, 7, 48), (30, 43, 24, 22, 25), (30, 10, 15, 67, 16)),
        (40, (30, 19, 118, 6, 119), (28, 18, 47, 31, 48), (30, 34, 24, 34, 25), (30, 20, 15, 61, 16)),
    )
    for row in rows:
        version = row[0]
        for level, (ec, b1, d1, b2, d2) in enumerate(row[1:]):
            groups = [(b1, d1)] + ([(b2, d2)] if b2 else [])
            _QR_EC[(version, level)] = (ec, groups)
    return _QR_EC


_QR_LEVEL_ORDER = {1: 0, 0: 1, 3: 2, 2: 3}       # the bits in the format information are L=01, M=00, Q=11, H=10
_QR_LEVEL_NAME = ("L", "M", "Q", "H")


def qr_data_bytes(bits, size, level) -> bytes:
    version = (size - 17) // 4
    ec_per_block, groups = _qr_ec_table()[(version, _QR_LEVEL_ORDER[level])]
    data_counts = []
    for blocks, data_per_block in groups:
        data_counts += [data_per_block] * blocks
    total_blocks = len(data_counts)
    whole = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        whole.append(byte)
    needed = sum(data_counts) + ec_per_block * total_blocks
    if len(whole) < needed:
        raise QrError(T("the code is incomplete"))
    whole = whole[:needed]
    data_blocks: List[List[int]] = [[] for _ in range(total_blocks)]
    ec_blocks: List[List[int]] = [[] for _ in range(total_blocks)]
    pos = 0
    for column in range(max(data_counts)):
        for index, count in enumerate(data_counts):
            if column < count:
                data_blocks[index].append(whole[pos])
                pos += 1
    for column in range(ec_per_block):
        for index in range(total_blocks):
            ec_blocks[index].append(whole[pos])
            pos += 1
    out = bytearray()
    for index in range(total_blocks):
        block = data_blocks[index] + ec_blocks[index]
        out += bytes(qr_correct(list(block), ec_per_block))
    return bytes(out)


_QR_ALPHANUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def qr_decode_text(data: bytes, size: int) -> str:
    version = (size - 17) // 4
    bits = []
    for byte in data:
        bits += [(byte >> i) & 1 for i in range(7, -1, -1)]
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(bits):
            raise QrError(T("the code's text ends unexpectedly"))
        value = 0
        for bit in bits[pos:pos + n]:
            value = (value << 1) | bit
        pos += n
        return value
    out = []
    while pos + 4 <= len(bits):
        mode = take(4)
        if mode == 0:
            break
        if mode == 1:                                           # numbers
            count = take(10 if version <= 9 else (12 if version <= 26 else 14))
            while count > 0:
                group = min(count, 3)
                value = take({3: 10, 2: 7, 1: 4}[group])
                out.append(str(value).zfill(group))
                count -= group
        elif mode == 2:                                         # letters and numbers
            count = take(9 if version <= 9 else (11 if version <= 26 else 13))
            while count > 0:
                if count >= 2:
                    value = take(11)
                    out.append(_QR_ALPHANUM[value // 45] + _QR_ALPHANUM[value % 45])
                    count -= 2
                else:
                    out.append(_QR_ALPHANUM[take(6)])
                    count -= 1
        elif mode == 4:                                         # bytes
            count = take(8 if version <= 9 else 16)
            raw = bytearray()
            for _ in range(count):
                raw.append(take(8))
            for encoding in ("utf-8", "shift_jis", "latin-1"):
                try:
                    out.append(raw.decode(encoding))
                    break
                except (UnicodeError, LookupError):
                    continue
        elif mode == 8:                                         # Japanese
            count = take(8 if version <= 9 else (10 if version <= 26 else 12))
            raw = bytearray()
            for _ in range(count):
                value = take(13)
                high, low = divmod(value, 0xC0)
                combined = (high << 8) | low
                combined += 0x8140 if combined < 0x1F00 else 0xC140
                raw += struct.pack(">H", combined)
            try:
                out.append(raw.decode("shift_jis"))
            except (UnicodeError, LookupError):
                out.append(raw.decode("latin-1"))
        elif mode == 7:                                         # a character set marker: skip it
            first = take(8)
            if first >= 0xC0:
                take(16)
            elif first >= 0x80:
                take(8)
        elif mode == 5:                                         # structured append marker
            take(16)
        else:
            break
    text = "".join(out)
    if not text.strip():
        raise QrError(T("the code was read but holds no text"))
    return text


def qr_read(data: bytes) -> Dict[str, object]:
    width, height, rows = qr_load_image(data)
    bits = qr_to_black_white(rows, width, height)
    tried = []
    for flipped in (False, True):
        grid_bits = [row[::-1] for row in bits] if flipped else bits
        for turn in range(4):
            try:
                grid, size = qr_grid(grid_bits, len(grid_bits[0]), len(grid_bits))
                level, mask = qr_read_format(grid, size)
                stream = qr_bitstream(grid, size, mask)
                text = qr_decode_text(qr_data_bytes(stream, size, level), size)
                return {"text": text, "modules": size, "version": (size - 17) // 4,
                        "level": _QR_LEVEL_NAME[_QR_LEVEL_ORDER[level]],
                        "picture": "{}x{}".format(width, height),
                        "turned": turn * 90, "mirrored": flipped}
            except (QrError, IndexError, KeyError, ValueError, ZeroDivisionError) as exc:
                tried.append(str(exc))
            grid_bits = [list(row) for row in zip(*grid_bits[::-1])]
    raise QrError(tried[0] if tried else T("no QR code was found in that picture"))


# --- what the code says ---------------------------------------------------------------------------------------

QR_HOW_TO = """  A QR code has to be in a picture file on this computer: take a screenshot, or save the picture
  someone sent you. PNG works best; a photo saved as JPEG or HEIC has to be saved as PNG first.
  Nothing is scanned with a camera, and the code is never followed."""


def qr_check(data: bytes, iocs=None) -> Dict[str, object]:
    """Read the code, then check what it says the same way a pasted link or message is checked."""
    from .linkcheck import lc_check_text
    code = qr_read(data)
    text = code["text"]
    link_result = lc_check_text(text, iocs)
    notes = []
    if code["turned"] or code["mirrored"]:
        if code["turned"] and code["mirrored"]:
            notes.append(lc_say("The code was turned {degrees} degrees and mirrored in the picture; it was lined up "
                                "before reading.", degrees=code["turned"]))
        elif code["turned"]:
            notes.append(lc_say("The code was turned {degrees} degrees in the picture; it was lined up before "
                                "reading.", degrees=code["turned"]))
        else:
            notes.append(lc_say("The code was mirrored in the picture; it was lined up before reading."))
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]{1,30}:", text.strip()) and "." not in text:
        notes.append(lc_say("This code is plain text, not an address: nothing to open."))
    return {"level": link_result["level"], "text": text, "code": code, "links": link_result, "notes": notes}


def qr_headline(result) -> str:
    from .linkcheck import lc_headline
    return lc_headline(result["links"])


from .safetext import safe_render  # noqa: E402


@safe_render
def qr_render(result) -> str:
    from .linkcheck import lc_render
    code = result["code"]
    lines = ["=" * 72, "  " + T("QR CODE CHECK") + "  -  " + T(qr_headline(result)),
             "  " + T("The code was read from the picture. Nothing was opened, visited or sent anywhere."), "=" * 72,
             "", "  " + T("The code says:"), "    " + result["text"][:1500], "",
             "  " + T("(read from a {picture} picture, {modules} modules across, version {version}, error "
                      "correction {level})", picture=code["picture"], modules=code["modules"],
                      version=code["version"], level=code["level"]), ""]
    for note in result["notes"]:
        lines.append("  " + T("note:") + " " + lc_shown(note))
    if result["notes"]:
        lines.append("")
    for line in lc_render(result["links"]).splitlines():
        if line.strip() and not line.startswith("="):
            lines.append(line)
    lines.append("")
    lines += lc_para(["A QR code is a link you cannot read before you follow it. The dangerous ones are printed on",
                      "stickers over real ones, or sent as a picture \"to sign in\" - and the worst link your messaging",
                      "account to someone else's device, so every message you get afterwards is theirs too."])
    return "\n".join(lines)


def qr_command(args, load_iocs, out=print) -> int:
    import json
    path = args.check_qr
    try:
        size = os.path.getsize(path)
        if size > QR_MAX_BYTES:
            out(T("That picture is {size} MB; the limit is 64 MB.", size="{:.1f}".format(size / 1e6)))
            return 1
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        out(T("That file could not be read: {why}", why=exc))
        return 1
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001
        out(T("(Indicator lists could not be loaded: {why}. Checking the text itself only.)", why=str(exc)[:160]))
        iocs = None
    try:
        result = qr_check(data, iocs)
    except QrError as exc:
        out("{}\n\n{}".format(exc, T(QR_HOW_TO)))
        return 1
    out(qr_render(result))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit qr code check"), fh, indent=2, ensure_ascii=False)
        out("\n" + T("Saved: {path}", path=args.json))
    from .linkcheck import LC_DANGER, LC_KNOWN, LC_LOOK
    return {LC_KNOWN: 3, LC_DANGER: 2, LC_LOOK: 1}.get(result["level"], 0)
