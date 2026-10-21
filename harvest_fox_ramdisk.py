#!/usr/bin/env python3
import gzip, lzma, struct, subprocess, sys

MAGIC_VB = b"VNDRBOOT"
OFF_VER, OFF_PAGE, OFF_VRSIZE = 8, 12, 24
OFF_DTBSIZE, OFF_ENTNUM, OFF_ENTSIZE = 2100, 2116, 2120
E_SIZE, E_OFF, E_TYPE, E_NAME = 0, 4, 8, 12
TYPE_LABEL = {0: "NONE", 1: "PLATFORM", 2: "RECOVERY", 3: "DLKM"}


class HarvestError(Exception):
    pass


def align(x, p):
    return (x + p - 1) // p * p


def run_cli(cmd, blob):
    r = subprocess.run(cmd, input=blob, capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise HarvestError("decompressor failed: %s (rc=%d)" % (" ".join(cmd), r.returncode))
    return r.stdout


def try_decompress(blob):
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob), "gzip"
    if blob[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(blob), "xz"
    if blob[:3] == b"\x5d\x00\x00":
        return lzma.decompress(blob, format=lzma.FORMAT_ALONE), "lzma"
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        return run_cli(["zstd", "-d", "-q", "-"], blob), "zstd"
    if blob[:4] in (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"):
        return run_cli(["lz4", "-d", "-q", "-"], blob), "lz4"
    return blob, "raw"


def read_header(d):
    if d[:8] != MAGIC_VB:
        raise HarvestError("not a vendor_boot image (magic %r)" % d[:8])
    ver, page = struct.unpack_from("<II", d, OFF_VER)
    vr = struct.unpack_from("<I", d, OFF_VRSIZE)[0]
    dtb_size = struct.unpack_from("<I", d, OFF_DTBSIZE)[0]
    ent_num = struct.unpack_from("<I", d, OFF_ENTNUM)[0]
    ent_size = struct.unpack_from("<I", d, OFF_ENTSIZE)[0]
    if page < 512 or page > 65536:
        raise HarvestError("implausible page size %d" % page)
    if ver not in (3, 4):
        raise HarvestError("unsupported header version %d" % ver)
    return dict(ver=ver, page=page, vr=vr, dtb_size=dtb_size,
                ent_num=ent_num, ent_size=ent_size)


def parse_table_at(d, h, tbl_abs):
    if tbl_abs < h["page"]:
        return None
    if tbl_abs + h["ent_num"] * h["ent_size"] > len(d):
        return None
    entries = []
    prev_off = -1
    for i in range(h["ent_num"]):
        o = tbl_abs + i * h["ent_size"]
        e = d[o:o + h["ent_size"]]
        if len(e) < 44:
            return None
        sz, off, typ = struct.unpack_from("<III", e, 0)
        nm = e[E_NAME:E_NAME + 32].rstrip(b"\0")
        if not all(32 <= c < 127 for c in nm):
            return None
        if typ > 3 or sz <= 0:
            return None
        if off + sz > h["vr"] + h["page"]:
            return None
        if off < prev_off:
            return None
        prev_off = off
        entries.append(dict(name=nm.decode(), off=off, size=sz, type=typ))
    return entries if entries else None


def table_candidates(h):
    blob_base = h["page"]
    dtb_abs = align(blob_base + h["vr"], h["page"])
    return [align(dtb_abs + h["dtb_size"], h["page"]),
            align(blob_base + h["vr"], h["page"])]


def hexdump(d, off, n=64):
    rows = []
    for i in range(0, n, 16):
        chunk = d[off + i:off + i + 16]
        if not chunk:
            break
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        rows.append("    %08x  %-47s  %s" % (off + i, chunk.hex(" "), txt))
    return "\n".join(rows)


def read_entries(d, h):
    cands = table_candidates(h)
    for tbl_abs in cands:
        entries = parse_table_at(d, h, tbl_abs)
        if entries:
            print("vendor_ramdisk_table located at 0x%x (standard position)" % tbl_abs)
            return entries
    step = max(h["page"], 512)
    pos = h["page"]
    while pos + h["ent_num"] * h["ent_size"] <= len(d):
        entries = parse_table_at(d, h, pos)
        if entries:
            print("vendor_ramdisk_table located at 0x%x (page scan)" % pos)
            return entries
        pos += step
    msg = ["vendor_ramdisk_table unreadable (is this really a built vendor_boot?)",
           "header: ver=%d page=%d vr=%d dtb_size=%d ent_num=%d ent_size=%d file=%d"
           % (h["ver"], h["page"], h["vr"], h["dtb_size"], h["ent_num"],
              h["ent_size"], len(d))]
    for c in cands:
        msg.append("bytes at candidate table offset 0x%x:" % c)
        msg.append(hexdump(d, c))
    raise HarvestError("\n".join(msg))


def cpio_names(raw):
    names, off, guard = set(), 0, 0
    while off + 110 <= len(raw) and guard < 200000:
        guard += 1
        if raw[off:off + 6] not in (b"070701", b"070702"):
            nxt = raw.find(b"070701", off + 1, off + 2064)
            if nxt < 0:
                break
            off = nxt
            continue
        fsz = int(raw[off + 54:off + 62], 16)
        nsz = int(raw[off + 94:off + 102], 16)
        if nsz < 2 or nsz > 4096:
            break
        nm = raw[off + 110:off + 110 + nsz - 1].decode(errors="replace")
        if nm != "TRAILER!!!":
            names.add(nm)
        nxt = off + 110 + nsz
        nxt += (-nxt) % 4
        nxt += fsz + (-fsz) % 4
        off = nxt
    return names


def union_from_entries(d, h):
    entries = read_entries(d, h)
    print("vendor_ramdisk fragments=%d" % len(entries))
    out = bytearray()
    for e in entries:
        blob = d[h["page"] + e["off"]:h["page"] + e["off"] + e["size"]]
        raw, how = try_decompress(blob)
        out += raw
        print("  %-10s type=%d (%s) %10d B -> %10d B via %s"
              % (e["name"] or "(default)", e["type"], TYPE_LABEL.get(e["type"], "?"),
                 e["size"], len(raw), how))
    return out


def union_single_stream(d, h):
    print("ent_num=0 (table-less stream) -> harvesting the whole vendor_ramdisk region as one blob")
    out = bytearray()
    raw, how = try_decompress(d[h["page"]:h["page"] + h["vr"]])
    out += raw
    print("  %-10s %-10s %10d B -> %10d B via %s"
          % ("(stream)", "", h["vr"], len(raw), how))
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(args) < 2:
        print("usage: python3 harvest_fox_ramdisk.py <built_vendor_boot.img> <out.cpio>")
        return 2
    src, dst = args[0], args[1]
    with open(src, "rb") as f:
        d = f.read()
    h = read_header(d)
    print("vendor_boot v%d page=%d vr=%d dtb=%d ent_num=%d ent_size=%d file=%d"
          % (h["ver"], h["page"], h["vr"], h["dtb_size"], h["ent_num"],
             h["ent_size"], len(d)))
    if h["ver"] == 4 and h["ent_num"] > 0:
        out = union_from_entries(d, h)
    else:
        out = union_single_stream(d, h)
    names = cpio_names(bytes(out))
    if "system/bin/recovery" not in names:
        sample = ", ".join(sorted(names)[:8]) or "(no cpio records parsed)"
        raise HarvestError("harvested cpio lacks system/bin/recovery — not an OrangeFox rootfs (sample names: %s)" % sample)
    with open(dst, "wb") as f:
        f.write(bytes(out))
    fox = sum(1 for n in names if "fox" in n.lower())
    print("harvested: %d files, %d bytes -> %s (fox_files=%d)"
          % (len(names), len(out), dst, fox))
    print("HARVEST OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarvestError as ex:
        print("HARVEST FAIL: %s" % ex)
        sys.exit(1)
    except Exception as ex:
        print("HARVEST FAIL (unexpected): %r" % ex)
        sys.exit(1)
