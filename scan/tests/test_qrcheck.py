"""The QR code reader and check. The decoder is tested against codes made by the independent `qrcode`
library where it is installed, and against hand-built pictures everywhere. Nothing may touch the network."""
import io
import os
import random
import socket
import struct
import zlib

import pytest

from zbtriage import qrcheck as qc
from zbtriage.iocs import Indicator, IocSet


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("reading a QR code must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


# --- pictures, built by hand ----------------------------------------------------------------------------------

def png_grey(rows) -> bytes:
    """A greyscale PNG from rows of 0-255."""
    height, width = len(rows), len(rows[0])
    raw = b"".join(b"\x00" + bytes(row) for row in rows)

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


def png_rgb(rows) -> bytes:
    height, width = len(rows), len(rows[0])
    raw = b"".join(b"\x00" + b"".join(bytes(pixel) for pixel in row) for row in rows)

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


def ppm(rows) -> bytes:
    head = "P5\n{} {}\n255\n".format(len(rows[0]), len(rows)).encode()
    return head + b"".join(bytes(row) for row in rows)


def test_pictures_are_read_and_turned_into_black_and_white():
    rows = [[255, 255, 10, 10], [255, 255, 10, 10], [10, 10, 255, 255], [10, 10, 255, 255]]
    for data in (png_grey(rows), ppm(rows)):
        width, height, got = qc.qr_load_image(data)
        assert (width, height) == (4, 4) and got[0][0] > 200 and got[0][2] < 50
        bits = qc.qr_to_black_white(got, width, height)
        assert bits[0] == [0, 0, 1, 1] and bits[2] == [1, 1, 0, 0]


def test_colour_pictures_become_grey():
    rows = [[(255, 255, 255), (0, 0, 0)], [(0, 0, 0), (255, 255, 255)]]
    width, height, got = qc.qr_load_image(png_rgb(rows))
    assert (width, height) == (2, 2) and got[0][0] == 255 and got[0][1] == 0


def test_photos_and_rubbish_say_what_to_do():
    with pytest.raises(qc.QrError, match="JPEG"):
        qc.qr_load_image(b"\xff\xd8\xff\xe0" + b"\x00" * 40)
    with pytest.raises(qc.QrError, match="HEIC"):
        qc.qr_load_image(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 40)
    with pytest.raises(qc.QrError, match="not a picture"):
        qc.qr_load_image(b"%PDF-1.7\n" + b"\x00" * 40)
    assert "PNG works best" in qc.QR_HOW_TO and "never followed" in qc.QR_HOW_TO


def test_a_picture_with_nothing_in_it_is_explained():
    with pytest.raises(qc.QrError, match="no QR code"):
        qc.qr_check(png_grey([[255] * 40 for _ in range(40)]))
    with pytest.raises(qc.QrError, match="too small"):
        qc.qr_check(png_grey([[0] * 10 for _ in range(10)]))


# --- the error correction, on its own -------------------------------------------------------------------------

def _encode(data, ec_count):
    generator = [1]
    for i in range(ec_count):
        generator = qc._gf_poly_mul(generator, [1, qc._GF_EXP[i]])
    out = list(data) + [0] * ec_count
    for i in range(len(data)):
        coefficient = out[i]
        if coefficient:
            for j in range(1, len(generator)):
                out[i + j] ^= qc._gf_mul(generator[j], coefficient)
    return list(data) + out[len(data):]


@pytest.mark.parametrize("ec_count", [7, 10, 17, 26, 30])
def test_damage_within_capacity_is_always_repaired(ec_count):
    random.seed(ec_count)
    for errors in range(0, ec_count // 2 + 1):
        for _ in range(12):
            data = [random.randrange(256) for _ in range(20)]
            block = _encode(data, ec_count)
            for where in random.sample(range(len(block)), errors):
                block[where] ^= random.randrange(1, 256)
            assert qc.qr_correct(list(block), ec_count) == data, \
                "{} errors with {} check bytes should be repairable".format(errors, ec_count)


@pytest.mark.parametrize("ec_count", [7, 10, 17, 26])
def test_damage_beyond_capacity_is_never_guessed_at(ec_count):
    """The dangerous failure would be inventing text. It must refuse instead."""
    random.seed(100 + ec_count)
    for _ in range(40):
        data = [random.randrange(256) for _ in range(20)]
        block = _encode(data, ec_count)
        for where in random.sample(range(len(block)), ec_count // 2 + 2):
            block[where] ^= random.randrange(1, 256)
        try:
            assert qc.qr_correct(list(block), ec_count) == data
        except qc.QrError:
            pass        # refusing is the right answer


def test_the_maths_helpers():
    assert qc._gf_mul(0, 5) == 0 and qc._gf_mul(1, 5) == 5
    assert qc._gf_div(qc._gf_mul(87, 131), 131) == 87
    assert qc._gf_inverse(qc._gf_mul(5, qc._gf_inverse(5))) == 1
    assert qc._gf_solve([[1, 0], [0, 1]], [7, 9]) == [7, 9]
    assert qc._gf_solve([[1, 1], [1, 1]], [1, 1]) is None       # no single answer


# --- against the independent library --------------------------------------------------------------------------

qrcode = pytest.importorskip("qrcode")


def make_png(text, level="M", box=6, border=4):
    levels = {"L": qrcode.constants.ERROR_CORRECT_L, "M": qrcode.constants.ERROR_CORRECT_M,
              "Q": qrcode.constants.ERROR_CORRECT_Q, "H": qrcode.constants.ERROR_CORRECT_H}
    image = qrcode.make(text, error_correction=levels[level], box_size=box, border=border)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.mark.parametrize("level", ["L", "M", "Q", "H"])
@pytest.mark.parametrize("text", [
    "https://example.org/a",
    "HELLO WORLD 123",
    "1234567890123456789",
    "sgnl://linkdevice?uuid=abc123&pub_key=Zm9vYmFy",
    "Café شكرا ümlaut",
    "x" * 250,
])
def test_codes_made_by_another_library_are_read_back_exactly(text, level):
    assert qc.qr_read(make_png(text, level))["text"] == text


@pytest.mark.parametrize("box,border", [(1, 4), (2, 4), (3, 1), (10, 0)])
def test_small_modules_and_a_missing_white_border(box, border):
    text = "https://example.org/verify?id=12345"
    assert qc.qr_read(make_png(text, "M", box=box, border=border))["text"] == text


def test_a_turned_or_mirrored_picture_is_lined_up():
    Image = pytest.importorskip("PIL.Image")
    text = "https://example.org/verify?id=12345"
    original = Image.open(io.BytesIO(make_png(text, "M"))).convert("L")
    for turn, change in ((90, lambda i: i.rotate(-90, expand=True)), (180, lambda i: i.rotate(180, expand=True)),
                         (270, lambda i: i.rotate(90, expand=True)),
                         (0, lambda i: i.transpose(Image.FLIP_LEFT_RIGHT))):
        buffer = io.BytesIO()
        change(original).save(buffer, format="PNG")
        got = qc.qr_read(buffer.getvalue())
        assert got["text"] == text
        del turn


def test_a_damaged_picture_is_still_read():
    Image = pytest.importorskip("PIL.Image")
    text = "https://example.org/verify?id=12345"
    image = Image.open(io.BytesIO(make_png(text, "H", box=6))).convert("L")
    pixels = image.load()
    random.seed(7)
    taken = qc._qr_function_map(37)
    free = [(r, c) for r in range(37) for c in range(37) if not taken[r][c]]
    random.shuffle(free)
    for row, col in free[:10]:
        x0, y0 = (4 + col) * 6, (4 + row) * 6
        value = 255 if pixels[x0 + 3, y0 + 3] < 128 else 0
        for dy in range(6):
            for dx in range(6):
                pixels[x0 + dx, y0 + dy] = value
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    assert qc.qr_read(buffer.getvalue())["text"] == text


def test_other_picture_formats_read_the_same_code():
    Image = pytest.importorskip("PIL.Image")
    text = "https://example.org/a"
    original = Image.open(io.BytesIO(make_png(text, "M"))).convert("L")
    for fmt, mode in (("GIF", "P"), ("BMP", "1"), ("PPM", "L"), ("BMP", "RGB")):
        buffer = io.BytesIO()
        original.convert(mode).save(buffer, format=fmt)
        assert qc.qr_read(buffer.getvalue())["text"] == text, fmt + "/" + mode


# --- what the code says ---------------------------------------------------------------------------------------

def test_a_device_linking_code_is_dangerous():
    result = qc.qr_check(make_png("sgnl://linkdevice?uuid=abc&pub_key=xyz"))
    assert result["level"] == "dangerous"
    text = qc.qr_render(result)
    assert "link a new device" in text and "Linked devices" in text
    assert "Nothing was opened" in text


def test_a_known_spyware_address_is_a_known_threat():
    iocs = IocSet([Indicator("bad.example", "infrastructure", "primary", "domain", "amnesty-test", "Pegasus")],
                  "t", 0)
    result = qc.qr_check(make_png("https://share.bad.example/x/7f"), iocs)
    assert result["level"] == "known-threat" and "Pegasus" in qc.qr_render(result)


def test_an_ordinary_code_is_not_alarming():
    result = qc.qr_check(make_png("https://www.bbc.co.uk/news"))
    assert result["level"] == "nothing-known"
    assert "https://www.bbc.co.uk/news" in qc.qr_render(result)


def test_plain_text_is_said_to_be_plain_text():
    result = qc.qr_check(make_png("TABLE 14"))
    assert any("plain text" in note for note in result["notes"])


def test_the_report_says_how_the_code_was_read():
    result = qc.qr_check(make_png("https://example.org/a", "Q"))
    text = qc.qr_render(result)
    assert "error correction Q" in text and "modules across" in text


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_checks_a_qr_code_and_does_not_scan(bundle, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    path = tmp_path / "code.png"
    path.write_bytes(make_png("https://example.org/a"))
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--check-qr", str(path)]) == 0
    assert "QR CODE CHECK" in capsys.readouterr().out


def test_a_missing_picture_is_refused():
    from zbtriage import cli
    with pytest.raises(SystemExit):
        cli._parse(["--check-qr", "no-such-picture.png"])
