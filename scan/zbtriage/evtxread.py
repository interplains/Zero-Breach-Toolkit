"""Read a Windows event log file (.evtx) in plain Python, on any operating system.

A helper given a Windows log can open it on Linux or a Mac with this; on Windows the toolkit asks Windows itself
instead, which is faster. Written from the published format: a 4 KB file header, then 64 KB chunks, each holding
records whose contents are "binary XML" - a compact form where element and attribute names are stored once per
chunk and most events reuse a template with the values filled in.

Only reads. A damaged or hostile file produces fewer events, never an exception out of ev_events(): every chunk
and record is bounded and checked, so one bad chunk does not cost the rest of the log.
"""
from __future__ import annotations

import datetime
import struct
from typing import Dict, Iterator, List, Optional, Tuple

EV_FILE_MAGIC = b"ElfFile\x00"
EV_CHUNK_MAGIC = b"ElfChnk\x00"
EV_RECORD_MAGIC = b"\x2a\x2a\x00\x00"
EV_CHUNK_SIZE = 0x10000
EV_MAX_RECORD = 2 * 1024 * 1024
EV_MAX_DEPTH = 24
EV_MAX_CHILDREN = 4096


class EvError(ValueError):
    pass


# binary-XML tokens
_T_EOF, _T_OPEN_START, _T_OPEN_START2, _T_CLOSE_START, _T_CLOSE_EMPTY = 0x00, 0x01, 0x41, 0x02, 0x03
_T_CLOSE, _T_VALUE, _T_VALUE2, _T_ATTR, _T_ATTR2 = 0x04, 0x05, 0x45, 0x06, 0x46
_T_CDATA, _T_CDATA2, _T_ENTITY, _T_ENTITY2, _T_PI_TARGET = 0x07, 0x47, 0x08, 0x48, 0x0A
_T_PI_DATA, _T_TEMPLATE, _T_NORMAL_SUB, _T_OPTIONAL_SUB = 0x0B, 0x0C, 0x0D, 0x0E
_T_FRAGMENT = 0x0F

_EV_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def ev_filetime(value: int) -> str:
    """A Windows FILETIME as an ISO date-time in UTC, or '' when out of range."""
    try:
        return (_EV_EPOCH + datetime.timedelta(microseconds=value // 10)).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def _ev_guid(raw: bytes) -> str:
    a, b, c = struct.unpack_from("<IHH", raw, 0)
    # Lower case, the spelling Windows' own XML uses.
    return "{{{:08x}-{:04x}-{:04x}-{}-{}}}".format(a, b, c, raw[8:10].hex(), raw[10:16].hex())


def _ev_sid(raw: bytes) -> str:
    if len(raw) < 8:
        return ""
    revision, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    parts = ["S", str(revision), str(authority)]
    for i in range(min(count, 15)):
        if 8 + 4 * i + 4 > len(raw):
            break
        parts.append(str(struct.unpack_from("<I", raw, 8 + 4 * i)[0]))
    return "-".join(parts)


def _ev_text(raw: bytes) -> str:
    return raw.decode("utf-16-le", "replace").rstrip("\x00")


def ev_value(vtype: int, raw: bytes):
    """One binary-XML value as text (lists become space-separated, like Windows' own XML)."""
    try:
        if vtype == 0x00:
            return ""
        if vtype == 0x01:
            return _ev_text(raw)
        if vtype == 0x02:
            return raw.split(b"\x00", 1)[0].decode("latin-1")
        if vtype == 0x03:
            return str(struct.unpack_from("<b", raw, 0)[0])
        if vtype == 0x04:
            return str(raw[0]) if raw else ""
        if vtype == 0x05:
            return str(struct.unpack_from("<h", raw, 0)[0])
        if vtype == 0x06:
            return str(struct.unpack_from("<H", raw, 0)[0])
        if vtype == 0x07:
            return str(struct.unpack_from("<i", raw, 0)[0])
        if vtype == 0x08:
            return str(struct.unpack_from("<I", raw, 0)[0])
        if vtype == 0x09:
            return str(struct.unpack_from("<q", raw, 0)[0])
        if vtype == 0x0A:
            return str(struct.unpack_from("<Q", raw, 0)[0])
        if vtype == 0x0B:
            return repr(struct.unpack_from("<f", raw, 0)[0])
        if vtype == 0x0C:
            return repr(struct.unpack_from("<d", raw, 0)[0])
        if vtype == 0x0D:
            return "true" if struct.unpack_from("<I", raw, 0)[0] else "false"
        if vtype == 0x0E:
            return raw.hex().upper()
        if vtype == 0x0F:
            return _ev_guid(raw)
        if vtype == 0x10:
            return str(int.from_bytes(raw[:8], "little"))
        if vtype == 0x11:
            return ev_filetime(struct.unpack_from("<Q", raw, 0)[0])
        if vtype == 0x12:
            return ev_filetime(struct.unpack_from("<Q", raw, 0)[0])
        if vtype == 0x13:
            return _ev_sid(raw)
        if vtype == 0x14:
            return "0x" + format(struct.unpack_from("<I", raw, 0)[0], "x")
        if vtype == 0x15:
            return "0x" + format(struct.unpack_from("<Q", raw, 0)[0], "x")
        if vtype == 0x21:
            return None                                   # a nested binary-XML document: handled by the caller
        if 0x81 <= vtype <= 0x8F or vtype in (0x9F, 0xAF, 0xB4, 0xB5, 0x94, 0x95):
            return _ev_array(vtype & 0x7F, raw)
        return raw.hex().upper()
    except (struct.error, IndexError, ValueError, UnicodeError):
        return ""


_EV_FIXED = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0A: 8, 0x0B: 4, 0x0C: 8,
             0x0D: 4, 0x0F: 16, 0x11: 8, 0x12: 8, 0x14: 4, 0x15: 8}


def _ev_array(base: int, raw: bytes):
    if base == 0x01:
        items = raw.decode("utf-16-le", "replace").split("\x00")
        while items and not items[-1]:
            items.pop()
        return _EvList(items)
    size = _EV_FIXED.get(base)
    if not size:
        return _EvList([raw.hex().upper()])
    return _EvList([str(ev_value(base, raw[i:i + size])) for i in range(0, len(raw) - size + 1, size)])


class _EvChunk:
    """One 64 KB chunk: its name table, its template cache and its records."""

    def __init__(self, data: bytes, offset: int):
        self.data = data
        self.base = offset
        self.names: Dict[int, str] = {}
        self.templates: Dict[int, dict] = {}

    def name_at(self, offset: int) -> str:
        got = self.names.get(offset)
        if got is not None:
            return got
        pos = self.base + offset
        if pos + 8 > len(self.data):
            raise EvError("name outside the chunk")
        count = struct.unpack_from("<H", self.data, pos + 6)[0]
        if count > 2048:
            raise EvError("name too long")
        text = self.data[pos + 8:pos + 8 + count * 2].decode("utf-16-le", "replace")
        self.names[offset] = text
        return text


def _ev_parse_name(chunk, pos, inline_ok=True) -> Tuple[str, int]:
    """(name, next position) for a name reference, which may carry the name inline the first time."""
    offset = struct.unpack_from("<I", chunk.data, pos)[0]
    pos += 4
    if inline_ok and offset == pos - chunk.base:
        count = struct.unpack_from("<H", chunk.data, chunk.base + offset + 6)[0]
        chunk.names[offset] = chunk.data[chunk.base + offset + 8:chunk.base + offset + 8 + count * 2].decode(
            "utf-16-le", "replace")
        pos = chunk.base + offset + 8 + count * 2 + 2
    return chunk.name_at(offset), pos


class _EvList:
    """An array value. Windows writes one element per item (the unnamed Data fields of a classic log), so the
    items are kept apart until then."""
    __slots__ = ("items",)

    def __init__(self, items):
        self.items = items

    def __str__(self):
        return " ".join(self.items)


class _EvDoc:
    """A whole binary-XML document used as one value (type 0x21), kept apart from a plain list of values."""
    __slots__ = ("nodes",)

    def __init__(self, nodes):
        self.nodes = nodes


class _EvNode:
    """One piece of a template's shape: an element, a placeholder, or a nested template instance."""
    __slots__ = ("name", "attrs", "kids", "text", "sub", "vals")

    def __init__(self, name):
        self.name = name
        self.attrs: List[Tuple[str, object]] = []
        self.kids: List[_EvNode] = []
        self.text: List[object] = []
        self.sub: Optional[Tuple[int, int]] = None     # (placeholder index, type)
        self.vals: Optional[list] = None               # a nested template instance's own values


def _ev_read_doc(chunk, pos: int, depth: int = 0) -> Tuple[List[_EvNode], int]:
    """Read a binary-XML fragment; returns (top-level nodes, position after it)."""
    if depth > EV_MAX_DEPTH:
        raise EvError("document nested too deeply")
    data = chunk.data
    nodes: List[_EvNode] = []
    stack: List[_EvNode] = []
    while pos < len(data):
        token = data[pos]
        kind = token & 0x0F
        if kind == _T_EOF:
            pos += 1
            break
        if token in (_T_FRAGMENT,):
            pos += 4                                                # version, flags
            continue
        if kind == (_T_OPEN_START & 0x0F):                          # 0x01 / 0x41 open start element
            has_attrs = bool(token & 0x40)
            pos += 1
            _dep = struct.unpack_from("<H", data, pos)[0]
            size = struct.unpack_from("<I", data, pos + 2)[0]
            end_of_element = pos + 2 + size
            pos += 6
            name, pos = _ev_parse_name(chunk, pos)
            node = _EvNode(name)
            if has_attrs:
                attr_size = struct.unpack_from("<I", data, pos)[0]
                pos += 4
                stop = pos + attr_size
                while pos < stop and len(node.attrs) < EV_MAX_CHILDREN:
                    atok = data[pos]
                    pos += 1
                    aname, pos = _ev_parse_name(chunk, pos)
                    value, pos = _ev_read_value(chunk, pos, depth)
                    node.attrs.append((aname, value))
                    if not (atok & 0x40):
                        break
                pos = stop
            if stack:
                stack[-1].kids.append(node)
            else:
                nodes.append(node)
            closer = data[pos]
            pos += 1
            if closer == _T_CLOSE_EMPTY:
                continue
            if closer != _T_CLOSE_START:
                raise EvError("element not closed properly")
            stack.append(node)
            del end_of_element
            continue
        if kind == _T_CLOSE:
            pos += 1
            if stack:
                stack.pop()
            continue
        if kind == (_T_VALUE & 0x0F):                               # 0x05 / 0x45 value text
            more = bool(token & 0x40)
            pos += 1
            vtype = data[pos]
            pos += 1
            pos -= 1
            text, pos = _ev_sized_value(chunk, pos)
            target = stack[-1] if stack else None
            if target is not None:
                target.text.append(text)
            del more
            continue
        if kind in (_T_ATTR & 0x0F,):                               # a stray attribute token
            pos += 1
            _n, pos = _ev_parse_name(chunk, pos)
            _v, pos = _ev_read_value(chunk, pos, depth)
            continue
        if kind in (_T_CDATA & 0x0F,):                              # 0x07 / 0x47 CDATA
            pos += 1
            count = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            text = data[pos:pos + count * 2].decode("utf-16-le", "replace")
            pos += count * 2
            if stack:
                stack[-1].text.append(text)
            continue
        if kind in (_T_ENTITY & 0x0F,):                             # entity reference
            pos += 1
            name, pos = _ev_parse_name(chunk, pos)
            if stack:
                stack[-1].text.append("&{};".format(name))
            continue
        if token in (_T_PI_TARGET, _T_PI_DATA):
            pos += 1
            if token == _T_PI_TARGET:
                _n, pos = _ev_parse_name(chunk, pos)
            else:
                count = struct.unpack_from("<H", data, pos)[0]
                pos += 2 + count * 2
            continue
        if kind in (_T_NORMAL_SUB, _T_OPTIONAL_SUB):                # template placeholder: token, index, type
            index, vtype = struct.unpack_from("<HB", data, pos + 1)
            pos += 4
            node = _EvNode("")
            node.sub = (index, vtype)
            if stack:
                stack[-1].text.append(node)
            else:
                nodes.append(node)
            continue
        if kind == _T_TEMPLATE:                                     # template instance
            node, pos = _ev_template(chunk, pos, depth)
            if stack:
                stack[-1].kids.append(node)
            else:
                nodes.append(node)
            continue
        raise EvError("unknown binary-XML token 0x{:02x}".format(token))
    return nodes, pos


def _ev_read_typed(chunk, vtype, pos):
    """A value whose length is implied by its type (inside a value token)."""
    data = chunk.data
    size = _EV_FIXED.get(vtype)
    if vtype == 0x13:                                               # SID
        count = data[pos + 1] if pos + 1 < len(data) else 0
        size = 8 + 4 * count
    elif vtype == 0x10:
        size = 16
    elif size is None:
        raise EvError("value type 0x{:02x} has no fixed size".format(vtype))
    raw = data[pos:pos + size]
    return ev_value(vtype, raw), pos + size


def _ev_sized_value(chunk, pos):
    """A value that carries its own length (inside a value token): text, bytes or a fixed-size type."""
    data = chunk.data
    vtype = data[pos]
    pos += 1
    if vtype == 0x01:
        count = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        return data[pos:pos + count * 2].decode("utf-16-le", "replace"), pos + count * 2
    if vtype == 0x02:
        count = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        return data[pos:pos + count].split(b"\x00", 1)[0].decode("latin-1"), pos + count
    if vtype == 0x0E:
        count = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        return data[pos:pos + count].hex().upper(), pos + count
    return _ev_read_typed(chunk, vtype, pos)


def _ev_read_value(chunk, pos, depth):
    """An attribute's value: a short run of value and placeholder tokens, joined into one piece of text."""
    data = chunk.data
    parts = []
    only_node = None
    for _ in range(64):
        token = data[pos] if pos < len(data) else 0
        kind = token & 0x0F
        if kind == (_T_VALUE & 0x0F):
            pos += 1
            text, pos = _ev_sized_value(chunk, pos)
            parts.append("" if text is None else str(text))
            continue
        if kind in (_T_NORMAL_SUB, _T_OPTIONAL_SUB):
            index, vtype = struct.unpack_from("<HB", data, pos + 1)
            pos += 4
            node = _EvNode("")
            node.sub = (index, vtype)
            if only_node is None and not parts:
                only_node = node
            else:
                only_node = None
                parts.append("")
            continue
        if kind in (_T_CDATA & 0x0F,):
            pos += 1
            count = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            parts.append(data[pos:pos + count * 2].decode("utf-16-le", "replace"))
            pos += count * 2
            continue
        if kind in (_T_ENTITY & 0x0F,):
            name, pos = _ev_parse_name(chunk, pos + 1)
            parts.append("&{};".format(name))
            continue
        break
    if only_node is not None:
        return only_node, pos
    return "".join(parts), pos


def _ev_template(chunk, pos, depth):
    """A template instance: the shared shape, plus this event's values.

    Layout (pos is at the 0x0c token): token, one unused byte, template id (4), offset of the definition in this
    chunk (4). The definition node itself starts FOUR bytes before that offset: unused (4), template id (4), a
    GUID (16), the length of the shape (4), then the shape. When the definition sits after the instance - the
    first event that uses it - this event's values follow the shape; otherwise they follow the instance header.
    """
    data = chunk.data
    token_at = pos - chunk.base
    _unused, _template_id, template_offset = struct.unpack_from("<BII", data, pos + 1)
    pos += 10
    head = chunk.base + template_offset - 4
    if not (0 <= template_offset - 4 and template_offset + 28 < EV_CHUNK_SIZE):
        raise EvError("template definition outside the chunk")
    cached = chunk.templates.get(template_offset)
    if cached is None:
        nodes, _end = _ev_read_doc(chunk, head + 0x1C, depth + 1)
        cached = chunk.templates[template_offset] = {"nodes": nodes}
    if template_offset > token_at:                                  # the shape is written here, before the values
        length = struct.unpack_from("<I", data, head + 0x18)[0]
        if length > EV_CHUNK_SIZE:
            raise EvError("template shape too long")
        pos = head + 0x1C + length
    count = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if count > EV_MAX_CHILDREN:
        raise EvError("too many template values")
    sizes = []
    for i in range(count):
        size, vtype = struct.unpack_from("<HH", data, pos + 4 * i)
        sizes.append((size, vtype & 0xFF))
    pos += 4 * count
    values = []
    for size, vtype in sizes:
        raw = data[pos:pos + size]
        pos += size
        if vtype == 0x21:                                           # a whole binary-XML document as a value
            try:
                sub = _EvChunk(chunk.data, chunk.base)
                sub.names = chunk.names
                inner, _e = _ev_read_doc(sub, pos - size, depth + 1)
                values.append(_EvDoc(inner))
            except (EvError, struct.error, IndexError):
                values.append("")
        else:
            values.append(ev_value(vtype, raw))
    root = _EvNode("")
    root.kids = cached["nodes"]
    root.vals = values
    return root, pos


def _ev_build(nodes, values, out, depth=0):
    """Turn a template's shape plus this event's values into plain dicts {name, attrs, text, kids}."""
    if depth > EV_MAX_DEPTH:
        return
    for kid in nodes[:EV_MAX_CHILDREN]:
        if kid.vals is not None:                       # a nested template instance: its own values, no element
            _ev_build(kid.kids, kid.vals, out, depth + 1)
            continue
        if kid.sub is not None:                        # a placeholder standing on its own
            value = values[kid.sub[0]] if kid.sub[0] < len(values) else ""
            if isinstance(value, _EvDoc):
                _ev_build(value.nodes, [], out, depth + 1)
            continue
        entry = {"name": kid.name, "attrs": {}, "text": "", "kids": []}
        for aname, avalue in kid.attrs:
            value = avalue
            if isinstance(value, _EvNode) and value.sub is not None:
                value = values[value.sub[0]] if value.sub[0] < len(values) else ""
            entry["attrs"][aname] = "" if value is None or isinstance(value, (_EvDoc, _EvNode)) else str(value)
        if len(kid.text) == 1 and isinstance(kid.text[0], _EvNode) and kid.text[0].sub is not None:
            one = values[kid.text[0].sub[0]] if kid.text[0].sub[0] < len(values) else ""
            if isinstance(one, _EvList):
                for item in one.items or [""]:
                    copy = {"name": kid.name, "attrs": dict(entry["attrs"]), "text": item, "kids": []}
                    _ev_build(kid.kids, values, copy["kids"], depth + 1)
                    out.append(copy)
                continue
        texts = []
        for item in kid.text:
            if isinstance(item, _EvNode) and item.sub is not None:
                value = values[item.sub[0]] if item.sub[0] < len(values) else ""
                if isinstance(value, _EvDoc):
                    _ev_build(value.nodes, [], entry["kids"], depth + 1)
                elif value is not None:
                    texts.append(str(value))
            elif not isinstance(item, (_EvNode, _EvDoc)):
                texts.append(str(item))
        entry["text"] = "".join(texts)
        _ev_build(kid.kids, values, entry["kids"], depth + 1)
        out.append(entry)


def _ev_flatten(record_nodes) -> dict:
    """An Event element as {Id, Time, Provider, Channel, Computer, Level, Data:{...}, Text}."""
    def walk(entries, path, found):
        for e in entries:
            name = e["name"]
            found.append((path + [name], e))
            walk(e["kids"], path + [name], found)
    found = []
    walk(record_nodes, [], found)
    event = {"Id": 0, "Time": "", "Provider": "", "Channel": "", "Computer": "", "Level": "", "Data": {},
             "RecordId": 0}
    texts = []
    counter = 0
    for path, e in found:
        tail = path[-1]
        # Header names (Provider, Level, Channel, Task...) are header fields only inside <System>. The
        # event's own data may use the same names - WMI-Activity's <Provider>SCM Event Provider</Provider>,
        # for one - and those are data: they must neither vanish nor overwrite the header.
        in_payload = "EventData" in path or "UserData" in path
        if in_payload or "System" not in path[:-1]:
            if tail == "Data" and in_payload:
                key = e["attrs"].get("Name") or "Data{}".format(counter)
                counter += 1
                event["Data"][key] = e["text"]
                if e["text"]:
                    texts.append(e["text"])
            elif tail not in ("Event", "System", "EventData", "UserData") and e["text"]:
                event["Data"].setdefault(tail, e["text"])
                texts.append(e["text"])
            continue
        if tail == "EventID":
            try:
                event["Id"] = int(e["text"] or e["attrs"].get("Qualifiers") or 0)
            except ValueError:
                pass
        elif tail == "EventRecordID":
            try:
                event["RecordId"] = int(e["text"])
            except (TypeError, ValueError):
                pass
        elif tail == "TimeCreated":
            event["Time"] = e["attrs"].get("SystemTime", "")
        elif tail == "Provider":
            event["Provider"] = e["attrs"].get("Name", "") or e["attrs"].get("Guid", "")
        elif tail in ("Channel", "Computer", "Level", "Task", "Opcode", "Keywords"):
            if e["text"]:
                event[tail] = e["text"]
        elif tail == "Execution":
            event["ProcessId"] = e["attrs"].get("ProcessID", "")
        elif tail == "Security":
            event["UserId"] = e["attrs"].get("UserID", "")
    event["Text"] = "\n".join(texts)
    return event


def ev_records(data: bytes) -> Iterator[dict]:
    """Every readable record in an .evtx file's bytes."""
    if len(data) < 4096 or data[:8] != EV_FILE_MAGIC:
        raise EvError("not a Windows event log file (.evtx)")
    seen = set()
    for base in range(4096, len(data) - 0x80, EV_CHUNK_SIZE):
        if data[base:base + 8] != EV_CHUNK_MAGIC:
            continue
        try:
            last_offset = struct.unpack_from("<I", data, base + 0x2C)[0]
        except struct.error:
            continue
        chunk = _EvChunk(data, base)
        pos = base + 0x200
        limit = min(base + EV_CHUNK_SIZE, len(data))
        guard = 0
        while pos + 24 <= limit and guard < 100000:
            guard += 1
            if data[pos:pos + 4] != EV_RECORD_MAGIC:
                break
            size, record_id, filetime = struct.unpack_from("<IQQ", data, pos + 4)
            if size < 24 or size > EV_MAX_RECORD or pos + size > limit:
                break
            if record_id not in seen:
                seen.add(record_id)
                try:
                    nodes, _end = _ev_read_doc(chunk, pos + 24)
                    entries: List[dict] = []
                    for node in nodes:
                        _ev_build([node], [], entries)
                    event = _ev_flatten(entries)
                    event["FileRecord"] = record_id
                    if not event.get("RecordId"):
                        event["RecordId"] = record_id
                    if not event["Time"]:
                        event["Time"] = ev_filetime(filetime)
                    yield event
                except (EvError, struct.error, IndexError, ValueError, UnicodeError, RecursionError):
                    pass
            pos += size
        del last_offset


def ev_events(path: str, limit: Optional[int] = None) -> List[dict]:
    """Read an .evtx file; the newest `limit` events when a limit is given."""
    with open(path, "rb") as fh:
        data = fh.read()
    out = []
    for event in ev_records(data):
        out.append(event)
    out.sort(key=lambda e: (e.get("Time") or "", e.get("RecordId") or 0))
    return out[-limit:] if limit else out
