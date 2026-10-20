from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import lzma
import shutil
import struct
import subprocess
import sys
import time

SCRIPT = "hybrid_assembler.py v2"

MAGIC_VB = b"VNDRBOOT"
MAGIC_DTB = b"\xd0\x0d\xfe\xed"
HDR_V4_SIZE = 2128

OFF_VER, OFF_PAGE, OFF_KADDR, OFF_RDADDR, OFF_VRSIZE = 8, 12, 16, 20, 24
OFF_TAGS, OFF_NAME, OFF_HDRSIZE, OFF_DTBSIZE, OFF_DTBADDR = 2076, 2080, 2096, 2100, 2104
OFF_TBLSIZE, OFF_ENTNUM, OFF_ENTSIZE, OFF_BOOTCFG = 2112, 2116, 2120, 2124

E_SIZE, E_OFF, E_TYPE, E_NAME, E_BOARD = 0, 4, 8, 12, 44
MIN_ENT_SIZE = 44

TYPE_NONE, TYPE_PLATFORM, TYPE_RECOVERY, TYPE_DLKM = 0, 1, 2, 3
TYPE_LABEL = {0: "NONE", 1: "PLATFORM", 2: "RECOVERY", 3: "DLKM"}

MAGIC_GZ = b"\x1f\x8b"
MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
MAGIC_XZ = b"\xfd7zXZ\x00"
MAGIC_LZ4 = b"\x04\x22\x4d\x18"

class AsmError(Exception):
    pass

def align(x: int, p: int) -> int:
    return (x + p - 1) // p * p

def fmt(n: int) -> str:
    return format(n, ",")

def mib(n: float) -> str:
    return "%.2f MiB" % (n / 1048576.0)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sniff(blob: bytes) -> str:
    if blob[:2] == MAGIC_GZ:
        return "gzip"
    if blob[:4] == MAGIC_ZSTD:
        return "zstd"
    if blob[:6] == MAGIC_XZ:
        return "xz"
    if blob[:4] == MAGIC_LZ4:
        return "lz4"
    if blob[:1] == b"\x5d" and blob[1:3] == b"\x00\x00":
        return "lzma"
    if blob[:6] in (b"070701", b"070702"):
        return "cpio-mentah"
    return "unknown"

def _run_cli(cmd, data: bytes, timeout: int = 600):
    try:
        r = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode == 0 and r.stdout:
        return r.stdout
    return None

def decompress_any(blob: bytes):
    pass
    kind = sniff(blob)
    if kind == "gzip":
        try:
            return gzip.decompress(blob), "gzip"
        except Exception:
            return None, "gzip-corrupt"
    if kind == "xz":
        try:
            return lzma.decompress(blob), "xz"
        except Exception:
            return None, "xz-corrupt"
    if kind == "lzma":
        try:
            return lzma.decompress(blob, format=lzma.FORMAT_ALONE), "lzma"
        except Exception:
            return None, "lzma-corrupt"
    if kind == "zstd":
        out = _run_cli(["zstd", "-d", "-q"], blob)
        if out is None and shutil.which("unzstd"):
            out = _run_cli(["unzstd", "-q"], blob)
        return (out, "zstd") if out is not None else (None, "zstd-unopenable")
    if kind == "lz4":
        out = _run_cli(["lz4", "-d", "-q"], blob)
        return (out, "lz4") if out is not None else (None, "lz4-unopenable")
    if kind == "cpio-mentah":
        return blob, "cpio-mentah"
    return None, kind

def _comp_gzip(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=9, mtime=0)

def _comp_xz(data: bytes) -> bytes:
    if shutil.which("xz"):
        out = _run_cli(["xz", "-T0", "-9", "--check=crc32", "-q"], data)
        if out is not None:
            return out
    return lzma.compress(data, format=lzma.FORMAT_XZ,
                         preset=9, check=lzma.CHECK_CRC32)

def _comp_lzma(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_ALONE, preset=9)

def _comp_zstd(data: bytes) -> bytes:
    out = _run_cli(["zstd", "-19", "-T0", "-q"], data)
    if out is None:
        raise AsmError("zstd failed (CLI present but compression errored)")
    return out

def codec_list() -> list:
    pass
    out = []
    if shutil.which("zstd"):
        out.append(("zstd", _comp_zstd))
    out.append(("xz", _comp_xz))
    out.append(("lzma", _comp_lzma))
    out.append(("gzip", _comp_gzip))
    return out

def parse_vb(data: bytes, label: str) -> dict:
    if len(data) < 2200:
        raise AsmError("%s: too small (%d B) for a vendor_boot" % (label, len(data)))
    if data[:8] != MAGIC_VB:
        raise AsmError("%s: magic %r is not VNDRBOOT (not an AOSP vendor_boot)" % (label, data[:8]))
    h = {"label": label, "file_size": len(data)}
    (h["ver"], h["page"], h["kaddr"], h["rdaddr"],
     h["vr_size"]) = struct.unpack_from("<5I", data, OFF_VER)
    if h["ver"] != 4:
        raise AsmError("%s: header_version=%d — this assembler handles v4 only" % (label, h["ver"]))
    h["hdr_size"] = struct.unpack_from("<I", data, OFF_HDRSIZE)[0]
    h["dtb_size"] = struct.unpack_from("<I", data, OFF_DTBSIZE)[0]
    h["dtb_addr"] = struct.unpack_from("<Q", data, OFF_DTBADDR)[0]
    h["tbl_size"], h["ent_num"], h["ent_size"], h["bootcfg"] = \
        struct.unpack_from("<IIII", data, OFF_TBLSIZE)
    if h["hdr_size"] != HDR_V4_SIZE:
        raise AsmError("%s: header_size=%d (expected %d) — unknown layout"
                       % (label, h["hdr_size"], HDR_V4_SIZE))
    if h["ent_size"] < MIN_ENT_SIZE:
        raise AsmError("%s: entry_size=%d too small (<%d)" % (label, h["ent_size"], MIN_ENT_SIZE))
    h["cmdline"] = data[28:28 + 2048].split(b"\x00")[0].decode("utf-8", "replace")
    h["board"] = data[OFF_NAME:OFF_NAME + 16].split(b"\x00")[0].decode("utf-8", "replace")

    page = h["page"]
    blob_base = page
    dtb_abs = align(blob_base + h["vr_size"], page)
    tbl_abs_std = align(dtb_abs + h["dtb_size"], page)   
    tbl_abs_alt = align(blob_base + h["vr_size"], page)  

    def read_table(off):
        ents = []
        if off < page or off + h["tbl_size"] > len(data):
            return None
        if h["ent_num"] == 0 or h["ent_num"] > 4096:
            return None
        for i in range(h["ent_num"]):
            a = off + i * h["ent_size"]
            raw = bytearray(data[a:a + h["ent_size"]])
            if len(raw) != h["ent_size"]:
                return None
            size, eoff, etype = struct.unpack_from("<III", raw, E_SIZE)
            nm = bytes(raw[E_NAME:E_NAME + 32]).split(b"\x00")[0].decode("utf-8", "replace")
            ents.append({"idx": i, "size": size, "off": eoff,
                         "type": etype, "name": nm, "raw": raw})
        return ents

    def plausible(ents):
        if not ents:
            return False
        for e in ents:
            if e["type"] > 3 or e["size"] <= 0:
                return False
            if e["off"] < 0 or e["off"] + e["size"] > h["vr_size"]:
                return False
            if e["name"] and not e["name"].isprintable():
                return False
        return True

    ents, mode = read_table(tbl_abs_std), "standar"
    if not plausible(ents) and tbl_abs_alt != tbl_abs_std:
        e2 = read_table(tbl_abs_alt)
        if plausible(e2):
            ents, mode = e2, "alternatif"
    if not plausible(ents):
        raise AsmError("%s: invalid vendor_ramdisk table (tbl=%d, num=%d, esize=%d)"
                       % (label, h["tbl_size"], h["ent_num"], h["ent_size"]))
    if h["tbl_size"] != h["ent_num"] * h["ent_size"]:
        _warn("%s: tbl_size=%d != ent_num*ent_size=%d (continuing with the table values)"
              % (label, h["tbl_size"], h["ent_num"] * h["ent_size"]))

    for e in ents:
        b = data[blob_base + e["off"]: blob_base + e["off"] + e["size"]]
        if len(b) != e["size"]:
            raise AsmError("%s: entry[%d] blob '%s' out of file bounds" % (label, e["idx"], e["name"]))
        e["blob"] = b
        e["kompresi"] = sniff(b)
    h["entrieses"] = ents
    h["tbl_abs"] = tbl_abs_std if mode == "standar" else tbl_abs_alt
    h["tbl_mode"] = mode
    h["dtb"] = data[dtb_abs:dtb_abs + h["dtb_size"]] if h["dtb_size"] else b""
    bcfg_abs = align(h["tbl_abs"] + h["tbl_size"], page)
    h["bootcfg_bytes"] = data[bcfg_abs:bcfg_abs + h["bootcfg"]] if h["bootcfg"] else b""
    h["header_page"] = bytes(data[:page])
    h["avb"] = _avb_footer(data)
    return h

def _avb_footer(data: bytes):
    foot = data[-64:]
    if foot[:4] != b"AVBf":
        return None
    vmaj, vmin = struct.unpack_from(">II", foot, 4)
    orig, voff, vsz = struct.unpack_from(">QQQ", foot, 12)
    return {"vmaj": vmaj, "vmin": vmin, "orig_size": orig,
            "vbmeta_off": voff, "vbmeta_size": vsz}

def compute_layout(page, kept_end, fox_size, dtb_size, tbl_size, bootcfg_size):
    pass
    fox_off = align(kept_end, page)
    vr = fox_off + fox_size
    dtb_abs = align(page + vr, page)
    tbl_abs = align(dtb_abs + dtb_size, page)
    bcfg_abs = align(tbl_abs + tbl_size, page)
    return align(bcfg_abs + bootcfg_size, page), fox_off, vr

def patch_entry(raw: bytearray, size: int, off: int, etype=None, name=None, zero_board=False):
    struct.pack_into("<III", raw, E_SIZE, size, off, etype if etype is not None
                     else struct.unpack_from("<I", raw, E_TYPE)[0])
    if etype is not None:
        struct.pack_into("<I", raw, E_TYPE, etype)
    if name is not None:
        nb = name.encode()[:31]
        raw[E_NAME:E_NAME + 32] = nb + b"\x00" * (32 - len(nb))
    if zero_board:
        raw[E_BOARD:] = b"\x00" * (len(raw) - E_BOARD)
    return raw

def recompress_kept(kept, codec_name, comp_fn):
    pass
    new, cat, off = [], [], 0
    for e in kept:
        raw_content, how = decompress_any(e["blob"])
        entry = dict(e)
        if raw_content is None:
            cat.append("entry[%d] '%s' unopenable (%s) — kept as-is"
                       % (e["idx"], e["name"] or "?", how))
            nb = e["blob"]
        else:
            if raw_content[:6] not in (b"070701", b"070702"):
                i = raw_content.find(b"070701")
                if i > 0:
                    raw_content = raw_content[i:]
            nb = comp_fn(raw_content)
        raw = bytearray(e["raw"])
        patch_entry(raw, len(nb), off)
        entry["blob"], entry["raw"], entry["off"], entry["size"] = nb, raw, off, len(nb)
        entry["kompresi"] = sniff(nb)
        off += len(nb)
        new.append(entry)
    return new, cat

def verify(out: bytes, stock_img: dict, kept_orig: list, schema_mode: str,
               fox_raw_ent: bytes, fox_blob: bytes, cpio_orig: bytes):
    pass
    v = parse_vb(out, "output")
    note = []

    def chk(cond, msg):
        if not cond:
            raise AsmError("verification FAILED: " + msg)
        note.append("[OK] " + msg)

    chk(v["ver"] == stock_img["ver"] and v["page"] == stock_img["page"], "ver/page size identical to stock")
    for f in ("kaddr", "rdaddr", "cmdline", "board", "hdr_size", "dtb_size", "dtb_addr",
              "ent_size", "bootcfg"):
        chk(v[f] == stock_img[f], "header.%s kept (%s)" % (f, fmt(v[f]) if isinstance(v[f], int) else v[f]))
    chk(v["vr_size"] == max([e["off"] + e["size"] for e in v["entrieses"]] or [0]),
        "vr_size %s = end of the last blob" % fmt(v["vr_size"]))
    chk(v["ent_num"] == len(kept_orig) + 1, "ent_num=%d (stock kept + 1 Fox entry)" % v["ent_num"])

    for i, orig in enumerate(kept_orig):
        e = v["entrieses"][i]
        chk(e["type"] == orig["type"] and e["name"] == orig["name"],
            "entry[%d] '%s' %s kept (type+name)" % (i, orig["name"] or "?", TYPE_LABEL[orig["type"]]))
        if schema_mode == "as-is":
            chk(e["blob"] == orig["blob"], "entry[%d] blob byte-exact from stock (%s B)"
                % (i, fmt(orig["size"])))
        else:
            a_raw, _ = decompress_any(orig["blob"])
            b_raw, how = decompress_any(e["blob"])
            chk(a_raw is not None and a_raw == b_raw,
                "entry[%d] CONTENT identical to original stock (recompressed %s: %s -> %s B)"
                % (i, how, fmt(orig["size"]), fmt(e["size"])))
    fox = v["entrieses"][-1]
    chk(bytes(fox["raw"]) == bytes(fox_raw_ent), "Fox entry reuses stock RECOVERY entry bytes (with new size/offset)")
    chk(fox["type"] == TYPE_RECOVERY, "Fox entry is RECOVERY-typed (2) — loaded by the bootloader in recovery mode")
    chk(fox["blob"] == fox_blob, "Fox entry = fresh OrangeFox blob (%s B)" % fmt(len(fox_blob)))
    dec, how = decompress_any(fox["blob"])
    chk(dec == cpio_orig, "Fox blob decompressed back (%s) = original cpio %s B" % (how, fmt(len(cpio_orig))))
    chk(v["dtb"] == stock_img["dtb"], "DTB byte-exact from stock (%s B)" % fmt(stock_img["dtb_size"]))
    chk(v["bootcfg_bytes"] == stock_img["bootcfg_bytes"], "bootconfig kept (%s B)" % fmt(stock_img["bootcfg"]))
    chk(v["avb"] is None, "old AVB footer dropped (avbtool/pipeline will re-add it)")
    return v, note

_WARNINGS = []

def _warn(m):
    _WARNINGS.append(m)
    print("  [!] " + m)

def load_fragment(path):
    blob = open(path, "rb").read()
    kind = sniff(blob)
    raw, how = decompress_any(blob)
    if raw is None:
        raise AsmError("fragment %s unopenable (%s). For lz4/zstd in Termux: "
                       "pkg install lz4 zstd xz-utils" % (path, kind))
    if raw[:6] not in (b"070701", b"070702"):
        i = raw.find(b"070701", 0, 4096)
        if i < 0:
            raise AsmError("fragment %s is not a cpio archive (detection: %s). Provide a raw cpio "
                           "or .gz/.xz/.zst of the recovery ramdisk." % (path, how))
        raw = raw[i:]
    return raw, kind, how

def dump_entry(h):
    for e in h["entrieses"]:
        print("    [%d] %-18s %-8s %12s B  off=%-9d  isi=%s" %
              (e["idx"], e["name"] or "(no-name)", TYPE_LABEL.get(e["type"], "?"),
               fmt(e["size"]), e["off"], e["kompresi"]))

def main(argv=None):
    global _WARNINGS
    _WARNINGS = []
    ap = argparse.ArgumentParser(description=SCRIPT, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stock", required=True, help="STOCK vendor_boot (from OTA/fastboot ROM)")
    ap.add_argument("--fragment", required=True, help="ramdisk recovery OrangeFox: cpio / .gz / .xz / .zst / .lz4")
    ap.add_argument("--output", default="vendor_boot_hybrid.img", help="hybrid output file")
    ap.add_argument("--partition-size", type=lambda x: int(x, 0), default=None,
                    help="vendor_boot partition size (default: stock file size)")
    ap.add_argument("--avb-headroom", type=lambda x: int(x, 0), default=0,
                    help="reserve space for the avbtool AVB footer (e.g. 8192)")
    ap.add_argument("--codec", choices=["auto", "zstd", "xz", "lzma", "gzip"], default="auto",
                    help="force the Fox fragment codec (default: auto = first one that fits)")
    ap.add_argument("--recompress-stock", choices=["auto", "never", "force"], default="auto",
                    help="recompress kept stock blobs (default: auto)")
    ap.add_argument("--keep-stock-recovery", action="store_true",
                    help="do not replace the stock RECOVERY entry — Fox is added as a new entry")
    ap.add_argument("--entry-name", default=None,
                    help="Fox entry name (default: keep the stock name / 'recovery' when adding)")
    ap.add_argument("--pad-to-partition", action="store_true",
                    help="pad the output exactly to partition size (no AVB footer)")
    ap.add_argument("--report", default=None, help="write the JSON report")
    ap.add_argument("--dry-run", action="store_true", help="compute the budget only, write no files")
    args = ap.parse_args(argv)

    print("== %s — vendor_boot hybrid malachite ==" % SCRIPT)
    t0 = time.time()

    stock_data = open(args.stock, "rb").read()
    stock_img = parse_vb(stock_data, "stock")
    partition = args.partition_size or stock_img["file_size"]
    page = stock_img["page"]
    print("[+] stock: %s B | header v4 | page %d | vr_size %s B | %d entrieses x %d B (%s)"
          % (fmt(stock_img["file_size"]), page, fmt(stock_img["vr_size"]), stock_img["ent_num"],
             stock_img["ent_size"], stock_img["tbl_mode"]))
    if stock_img["ent_size"] != 108:
        _warn("stock entry_size = %d (not 108) — patching stays safe for the first 44 bytes of fields" % stock_img["ent_size"])
    if stock_img["avb"]:
        print("[i] stock AVBf footer: orig_size=%s B (will be dropped from the output)"
              % fmt(stock_img["avb"]["orig_size"]))
    dump_entry(stock_img)

    cpio_raw, kind_in, how_in = load_fragment(args.fragment)
    n_cpio = cpio_raw.count(b"070701")
    print("[+] OrangeFox recovery cpio: ~%d cpio headers, %s B (input %s -> opened as %s)"
          % (n_cpio, fmt(len(cpio_raw)), kind_in, how_in))

    if args.keep_stock_recovery:
        kept = [dict(e) for e in stock_img["entrieses"]]
        rec_stock = next((e for e in stock_img["entrieses"] if e["type"] == TYPE_RECOVERY), None)
        entry_mode = "tambah"
    else:
        kept = [dict(e) for e in stock_img["entrieses"] if e["type"] != TYPE_RECOVERY]
        rec_stock = next((e for e in stock_img["entrieses"] if e["type"] == TYPE_RECOVERY), None)
        entry_mode = "ganti"
        missing = [e for e in stock_img["entrieses"] if e["type"] == TYPE_RECOVERY]
        for e in missing:
            print("[+] stock RECOVERY blob '%s' (%s B, %s) REPLACED with the OrangeFox blob — other entrieses intact"
                  % (e["name"] or "?", fmt(e["size"]), e["kompresi"]))
        if rec_stock is None:
            _warn("stock has NO RECOVERY-type entry — OrangeFox is added as a new entry "
                  "(this composition stays valid: the bootloader loads PLATFORM/DLKM in normal mode, "
                  "+RECOVERY in recovery mode)")
    if not kept:
        _warn("no stock blobs kept — normal boot fully depends on the new entry content")

    kept_end = max([e["off"] + e["size"] for e in kept], default=0)
    tbl_size_new = (len(kept) + 1) * stock_img["ent_size"]

    codecs = codec_list()
    if args.codec != "auto":
        codecs = [c for c in codecs if c[0] == args.codec]
        if not codecs:
            raise AsmError("codec %s unavailable in this environment (zstd CLI missing?)" % args.codec)
    schema = []
    if args.recompress_stock in ("auto", "never"):
        schema += [("as-is", c) for c in codecs]
    if args.recompress_stock in ("auto", "force"):
        schema += [("stock-recomp", c) for c in codecs]
    if args.recompress_stock == "force":
        schema = [("stock-recomp", c) for c in codecs]

    candidates, chosen = [], None
    for mode_schema, (codec_name, comp_fn) in [(m, c) for m, c in schema]:
        fox_blob = comp_fn(cpio_raw)
        if mode_schema == "as-is":
            kept_cur, stock_codec, kept_end_cur = kept, None, kept_end
        else:
            kept_cur, cat = recompress_kept(kept, codec_name, comp_fn)
            stock_codec = codec_name
            kept_end_cur = max([e["off"] + e["size"] for e in kept_cur], default=0)
            for c in cat:
                _warn(c)
        total, fox_off, vr_new = compute_layout(page, kept_end_cur, len(fox_blob),
                                               stock_img["dtb_size"], tbl_size_new, stock_img["bootcfg"])
        load = total + args.avb_headroom <= partition
        candidates.append({"mode": mode_schema, "codec": codec_name, "fox": len(fox_blob),
                         "total": total, "muat": load})
        print("  [>] candidate %-10s %-6s : fox=%s  total=%s  %s" %
              ("[%s]" % mode_schema, codec_name, fmt(len(fox_blob)), fmt(total),
               "MUAT" if load else "does not fit (partition %s%s)" %
               (fmt(partition), " - headroom %s" % fmt(args.avb_headroom) if args.avb_headroom else "")))
        if load and chosen is None:
            chosen = {"mode": mode_schema, "codec": codec_name, "stock_codec": stock_codec,
                       "kept": kept_cur, "kept_end": kept_end_cur, "fox_blob": fox_blob,
                       "fox_off": fox_off, "vr": vr_new, "total": total}
            break
    if chosen is None:
        best = min(candidates, key=lambda k: k["total"]) if candidates else None
        msg = ["DOES NOT FIT: no codec combination fits partition %s B (AVB headroom %s B)."
                 % (fmt(partition), fmt(args.avb_headroom))]
        if best:
            msg.append("Smallest combination: %s/%s -> total %s B (overrun %s B)." %
                         (best["mode"], best["codec"], fmt(best["total"]), fmt(best["total"] + args.avb_headroom - partition)))
        msg.append("Suggestions: (1) shrink the OrangeFox rootfs (extra themes/res), (2) check the zstd CLI "
                     "is installed (best ratio + fast decompression), (3) use the correct partition.")
        raise AsmError(" ".join(msg))

    fox_blob = chosen["fox_blob"]
    fox_off = chosen["fox_off"]
    vr_new = chosen["vr"]
    kept_cur = chosen["kept"]
    tbl_size_new = (len(kept_cur) + 1) * stock_img["ent_size"]

    if entry_mode == "ganti" and rec_stock is not None:
        fox_raw_ent = bytearray(rec_stock["raw"])          
        patch_entry(fox_raw_ent, len(fox_blob), fox_off)  
    else:
        source = next((e for e in kept_cur if e["type"] == TYPE_PLATFORM), kept_cur[0] if kept_cur else rec_stock)
        fox_raw_ent = bytearray(source["raw"] if source is not None else
                                bytearray(stock_img["ent_size"]))
        if len(fox_raw_ent) < stock_img["ent_size"]:
            fox_raw_ent += b"\x00" * (stock_img["ent_size"] - len(fox_raw_ent))
        patch_entry(fox_raw_ent, len(fox_blob), fox_off, etype=TYPE_RECOVERY,
                    name=args.entry_name or "recovery", zero_board=True)

    hdr = bytearray(stock_img["header_page"])                  
    struct.pack_into("<I", hdr, OFF_VRSIZE, vr_new)
    struct.pack_into("<I", hdr, OFF_TBLSIZE, tbl_size_new)
    struct.pack_into("<I", hdr, OFF_ENTNUM, len(kept_cur) + 1)
    out = bytearray(hdr)
    region = bytearray(vr_new)
    for e in kept_cur:
        region[e["off"]:e["off"] + e["size"]] = e["blob"]
    region[fox_off:fox_off + len(fox_blob)] = fox_blob
    out += region
    out += b"\x00" * ((page - len(out) % page) % page)
    out += stock_img["dtb"]
    out += b"\x00" * ((page - len(out) % page) % page)
    out += b"".join(bytes(e["raw"]) for e in kept_cur) + bytes(fox_raw_ent)
    out += b"\x00" * ((page - len(out) % page) % page)
    out += stock_img["bootcfg_bytes"]
    out += b"\x00" * ((page - len(out) % page) % page)
    if args.pad_to_partition:
        if len(out) > partition:
            raise AsmError("pad-to-partition: content %s B > partition %s B" % (fmt(len(out)), fmt(partition)))
        out += b"\x00" * (partition - len(out))

    v, note = verify(bytes(out), stock_img, kept, chosen["mode"], fox_raw_ent,
                        fox_blob, cpio_raw)

    print("")
    print("[=] Fox fragment codec : %s (stock mode: %s%s)" %
          (chosen["codec"], chosen["mode"],
           ", stock blobs recompressed with %s" % chosen["stock_codec"] if chosen["stock_codec"] else ""))
    for k in note:
        print("  " + k)
    rest = partition - args.avb_headroom - chosen["total"]
    print("[=] total %s B of %s B partition — %s B free (AVB headroom %s B)"
          % (fmt(chosen["total"]), fmt(partition),
             fmt(max(rest, 0)), fmt(args.avb_headroom)))
    print("[i] normal boot: stock PLATFORM/DLKM blobs %s — untouched (byte-exact)" %
          ("byte-exact" if chosen["mode"] == "as-is" else "recompressed, same content"))
    print("[i] GKI kernel android15-6.6: RD_GZIP/RD_LZMA/RD_XZ/RD_LZ4/RD_ZSTD default y; "
          "the RECOVERY fragment loads only in recovery mode (decompression failure does not affect normal boot).")
    print("[i] if recovery fails to boot (rare): retry with --codec xz or --codec gzip "
          "(+ --recompress-stock force if space is needed).")
    print("[=] %s — %s B, sha256 %s" % (args.output, fmt(len(out)), sha256(bytes(out))[:32]))

    if not args.dry_run:
        with open(args.output, "wb") as f:
            f.write(out)
    if args.report:
        rep = {
            "tool": SCRIPT, "waktu": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stock": {"file": args.stock, "size": stock_img["file_size"], "vr_size": stock_img["vr_size"],
                     "entries": [{"name": e["name"], "type": e["type"], "size": e["size"],
                                "off": e["off"], "kompresi": e["kompresi"]} for e in stock_img["entrieses"]],
                     "avb": stock_img["avb"]},
            "fragment": {"file": args.fragment, "input": kind_in, "cpio_bytes": len(cpio_raw)},
            "dipilih": {"mode": chosen["mode"], "codec": chosen["codec"],
                        "stock_codec": chosen["stock_codec"], "fox_blob": len(fox_blob),
                        "total": chosen["total"], "sisa": rest},
            "kandidat": candidates,
            "output": {"file": None if args.dry_run else args.output,
                       "size": len(out), "sha256": sha256(bytes(out))},
            "peringatan": _WARNINGS,
        }
        with open(args.report, "w") as f:
            json.dump(rep, f, indent=2, ensure_ascii=False)
        print("[=] report: %s" % args.report)
    print("[=] finished in %.1f s" % (time.time() - t0))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except AsmError as ex:
        print("[X] " + str(ex), file=sys.stderr)
        sys.exit(1)
