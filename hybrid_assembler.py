#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hybrid_assembler.py v2 — Rakit vendor_boot HYBRID malachite
(Xiaomi Redmi Note 14 Pro 5G · HyperOS 2.0.208.0.VOOMIXM · Android 15 · GKI vendor_boot v4)

Prinsip (koreksi atas v1 yang gagal "fragment recovery terlalu besar utk 64 MiB"):
  1. Ramdisk NORMAL stok (entri PLATFORM/DLKM/NONE) dipertahankan BYTE-PERSIS di
     offset aslinya -> boot normal tidak tersentuh.
  2. BLOB entri RECOVERY stok (type-2) DIGANTI dengan ramdisk OrangeFox — entri
     dipakai ulang (jumlah entri tetap, byte entri custom 44..ent_size dipertahankan).
     Ini komposisi yang dibuktikan bootloader stok (recovery stok bekerja).
  3. Kompresi fragmen otomatis zstd-19 -> xz-9 -> lzma-9 -> gzip-9: ambil codec
     pertama yang MUAT di partisi. Kernel GKI android15-6.6 usr/Kconfig: RD_GZIP /
     RD_LZMA / RD_XZ / RD_LZO / RD_LZ4 / RD_ZSTD semua "default y", dan fragmen
     RECOVERY hanya dimuat saat boot recovery -> gagal dekompresi tidak menyentuh
     boot normal (mode gagal-aman).
  4. Kalau tetap tidak muat: blob stok yang dipertahankan ikut dikompres ulang
     (--recompress-stock auto|force). Anggaran per bagian dilaporkan + laporan JSON
     + verifikasi mandiri penuh.

Layout ground truth (mkbootimg.py lineage-23.0/AOSP main, tervalidasi lapangan):
  header v4 = 2128 B: vr_size@24 | cmdline@28 | tags@2076 | name@2080 |
  hdr_size@2096 | dtb_size@2100 | dtb_addr@2104 | tbl_size@2112 | ent_num@2116 |
  ent_size@2120 | bootcfg@2124. Region: header(page) -> blobs -> dtb -> tabel ->
  bootconfig. Entri = 108 B: size@0, offset@4 (rel. thd awal region blob),
  type@8, name32@12, board_id 16xu32@44. Footer AVBf = BIG-ENDIAN (dibuang di output).

Pemakaian (GitHub Actions maupun lokal/Termux):
  python3 hybrid_assembler.py \
      --stock    vendor_boot_stock.img \
      --fragment vendor_boot.img.recovery.cpio.gz \
      --output   OrangeFox-R12.0_0-Beta-vendor_boot.img \
      --partition-size 67108864 --avb-headroom 8192 \
      --report   assemble_report.json

  --codec zstd|xz|lzma|gzip   paksa codec (default: auto = codec pertama yang muat)
  --recompress-stock auto|never|force   (default auto: hanya bila perlu)
  --keep-stock-recovery       jangan ganti entri RECOVERY stok; Fox ditambah sebagai
                              entri type-2 baru (butuh ruang lebih besar)
  --dry-run                   hitung & lapangkan anggaran tanpa menulis output
Stdlib Python saja; opsi zstd memakai CLI `zstd` bila tersedia (runner GitHub sudah
memilikinya; Termux: pkg install zstd xz-utils lz4).
"""
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

# ---- offset field header vendor_boot v4 (little-endian) ----
OFF_VER, OFF_PAGE, OFF_KADDR, OFF_RDADDR, OFF_VRSIZE = 8, 12, 16, 20, 24
OFF_TAGS, OFF_NAME, OFF_HDRSIZE, OFF_DTBSIZE, OFF_DTBADDR = 2076, 2080, 2096, 2100, 2104
OFF_TBLSIZE, OFF_ENTNUM, OFF_ENTSIZE, OFF_BOOTCFG = 2112, 2116, 2120, 2124

# ---- offset field entri tabel (V4: 108 byte) ----
E_SIZE, E_OFF, E_TYPE, E_NAME, E_BOARD = 0, 4, 8, 12, 44
MIN_ENT_SIZE = 44

TYPE_NONE, TYPE_PLATFORM, TYPE_RECOVERY, TYPE_DLKM = 0, 1, 2, 3
TYPE_LABEL = {0: "NONE", 1: "PLATFORM", 2: "RECOVERY", 3: "DLKM"}

MAGIC_GZ = b"\x1f\x8b"
MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
MAGIC_XZ = b"\xfd7zXZ\x00"
MAGIC_LZ4 = b"\x04\x22\x4d\x18"


class AsmError(Exception):
    """Kesalahan fatal yang harus dilaporkan apa adanya ke user/CI."""


def align(x: int, p: int) -> int:
    return (x + p - 1) // p * p


def fmt(n: int) -> str:
    return format(n, ",")


def mib(n: float) -> str:
    return "%.2f MiB" % (n / 1048576.0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
#  Deteksi & dekompresi kontainer
# --------------------------------------------------------------------------- #
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
    return "tidak-dikenal"


def _run_cli(cmd, data: bytes, timeout: int = 600):
    try:
        r = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode == 0 and r.stdout:
        return r.stdout
    return None


def decompress_any(blob: bytes):
    """-> (raw | None, cara). Mendukung gzip/xz/lzma (stdlib) + zstd/lz4 (CLI)."""
    kind = sniff(blob)
    if kind == "gzip":
        try:
            return gzip.decompress(blob), "gzip"
        except Exception:
            return None, "gzip-rusak"
    if kind == "xz":
        try:
            return lzma.decompress(blob), "xz"
        except Exception:
            return None, "xz-rusak"
    if kind == "lzma":
        try:
            return lzma.decompress(blob, format=lzma.FORMAT_ALONE), "lzma"
        except Exception:
            return None, "lzma-rusak"
    if kind == "zstd":
        out = _run_cli(["zstd", "-d", "-q"], blob)
        if out is None and shutil.which("unzstd"):
            out = _run_cli(["unzstd", "-q"], blob)
        return (out, "zstd") if out is not None else (None, "zstd-tak-terbuka")
    if kind == "lz4":
        out = _run_cli(["lz4", "-d", "-q"], blob)
        return (out, "lz4") if out is not None else (None, "lz4-tak-terbuka")
    if kind == "cpio-mentah":
        return blob, "cpio-mentah"
    return None, kind


# --------------------------------------------------------------------------- #
#  Kompresor
# --------------------------------------------------------------------------- #
def _comp_gzip(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=9, mtime=0)


def _comp_xz(data: bytes) -> bytes:
    # Utamakan CLI xz multithread (jauh lebih cepat di CI; keluaran tetap .xz
    # standar yang bisa dibaca dekompresor kernel — multi-block didukung).
    if shutil.which("xz"):
        out = _run_cli(["xz", "-T0", "-9", "--check=crc32", "-q"], data)
        if out is not None:
            return out
    # Fallback stdlib: preset 9 (tanpa EXTREME — rasio beda <0,5%, waktu ~2x lebih cepat).
    return lzma.compress(data, format=lzma.FORMAT_XZ,
                         preset=9, check=lzma.CHECK_CRC32)


def _comp_lzma(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_ALONE, preset=9)


def _comp_zstd(data: bytes) -> bytes:
    out = _run_cli(["zstd", "-19", "-T0", "-q"], data)
    if out is None:
        raise AsmError("zstd gagal (CLI ada tetapi kompresi error)")
    return out


def codec_list() -> list:
    """Urutan preferensi: rasio & kecepatan dekompresi kernel."""
    out = []
    if shutil.which("zstd"):
        out.append(("zstd", _comp_zstd))
    out.append(("xz", _comp_xz))
    out.append(("lzma", _comp_lzma))
    out.append(("gzip", _comp_gzip))
    return out


# --------------------------------------------------------------------------- #
#  Parser vendor_boot v4
# --------------------------------------------------------------------------- #
def parse_vb(data: bytes, label: str) -> dict:
    if len(data) < 2200:
        raise AsmError("%s: terlalu kecil (%d B) untuk vendor_boot" % (label, len(data)))
    if data[:8] != MAGIC_VB:
        raise AsmError("%s: magic %r bukan VNDRBOOT (bukan vendor_boot AOSP)" % (label, data[:8]))
    h = {"label": label, "file_size": len(data)}
    (h["ver"], h["page"], h["kaddr"], h["rdaddr"],
     h["vr_size"]) = struct.unpack_from("<5I", data, OFF_VER)
    if h["ver"] != 4:
        raise AsmError("%s: header_version=%d — assembler ini hanya menangani v4" % (label, h["ver"]))
    h["hdr_size"] = struct.unpack_from("<I", data, OFF_HDRSIZE)[0]
    h["dtb_size"] = struct.unpack_from("<I", data, OFF_DTBSIZE)[0]
    h["dtb_addr"] = struct.unpack_from("<Q", data, OFF_DTBADDR)[0]
    h["tbl_size"], h["ent_num"], h["ent_size"], h["bootcfg"] = \
        struct.unpack_from("<IIII", data, OFF_TBLSIZE)
    if h["hdr_size"] != HDR_V4_SIZE:
        raise AsmError("%s: header_size=%d (diharapkan %d) — layout tidak dikenal"
                       % (label, h["hdr_size"], HDR_V4_SIZE))
    if h["ent_size"] < MIN_ENT_SIZE:
        raise AsmError("%s: entry_size=%d terlalu kecil (<%d)" % (label, h["ent_size"], MIN_ENT_SIZE))
    h["cmdline"] = data[28:28 + 2048].split(b"\x00")[0].decode("utf-8", "replace")
    h["board"] = data[OFF_NAME:OFF_NAME + 16].split(b"\x00")[0].decode("utf-8", "replace")

    page = h["page"]
    blob_base = page
    dtb_abs = align(blob_base + h["vr_size"], page)
    tbl_abs_std = align(dtb_abs + h["dtb_size"], page)   # resmi: blobs -> dtb -> tabel
    tbl_abs_alt = align(blob_base + h["vr_size"], page)  # varian: tabel langsung stlh blobs

    def baca_tabel(off):
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

    def masuk_akal(ents):
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

    ents, mode = baca_tabel(tbl_abs_std), "standar"
    if not masuk_akal(ents) and tbl_abs_alt != tbl_abs_std:
        e2 = baca_tabel(tbl_abs_alt)
        if masuk_akal(e2):
            ents, mode = e2, "alternatif"
    if not masuk_akal(ents):
        raise AsmError("%s: tabel vendor_ramdisk tidak valid (tbl=%d, num=%d, esize=%d)"
                       % (label, h["tbl_size"], h["ent_num"], h["ent_size"]))
    if h["tbl_size"] != h["ent_num"] * h["ent_size"]:
        _warn("%s: tbl_size=%d != ent_num*ent_size=%d (dilanjutkan dengan angka tabel)"
              % (label, h["tbl_size"], h["ent_num"] * h["ent_size"]))

    for e in ents:
        b = data[blob_base + e["off"]: blob_base + e["off"] + e["size"]]
        if len(b) != e["size"]:
            raise AsmError("%s: blob entri[%d] '%s' keluar batas file" % (label, e["idx"], e["name"]))
        e["blob"] = b
        e["kompresi"] = sniff(b)
    h["entries"] = ents
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


# --------------------------------------------------------------------------- #
#  Anggaran ukuran
# --------------------------------------------------------------------------- #
def hitung_layout(page, kept_end, fox_size, dtb_size, tbl_size, bootcfg_size):
    """-> (total, fox_off_rel, vr_size) untuk satu komposisi blob.
    total = panjang image final TERMASUK padding halaman terakhir (bootconfig
    ditulis ter-pad, persis perilaku mkbootimg write_padded_file)."""
    fox_off = align(kept_end, page)
    vr = fox_off + fox_size
    dtb_abs = align(page + vr, page)
    tbl_abs = align(dtb_abs + dtb_size, page)
    bcfg_abs = align(tbl_abs + tbl_size, page)
    return align(bcfg_abs + bootcfg_size, page), fox_off, vr


# --------------------------------------------------------------------------- #
#  Util entri
# --------------------------------------------------------------------------- #
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


def rekompress_kept(kept, codec_name, comp_fn):
    """Kembalikan (kept_baru, catatan). Blob didekompres lalu dikompres ulang;
    offset dihitung ulang berurutan tanpa jeda (gaya mkbootimg)."""
    baru, cat, off = [], [], 0
    for e in kept:
        raw_content, how = decompress_any(e["blob"])
        entry = dict(e)
        if raw_content is None:
            cat.append("entri[%d] '%s' tidak bisa dibuka (%s) — dipertahankan apa adanya"
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
        baru.append(entry)
    return baru, cat


# --------------------------------------------------------------------------- #
#  Verifikasi mandiri
# --------------------------------------------------------------------------- #
def verifikasi(out: bytes, stok: dict, kept_asli: list, skema_mode: str,
               fox_raw_ent: bytes, fox_blob: bytes, cpio_asli: bytes):
    """kept_asli = entri stok ASLI (sebelum rekompresi) utk pembanding isi."""
    v = parse_vb(out, "output")
    ket = []

    def cek(kondisi, pesan):
        if not kondisi:
            raise AsmError("verifikasi GAGAL: " + pesan)
        ket.append("[OK] " + pesan)

    cek(v["ver"] == stok["ver"] and v["page"] == stok["page"], "ver/page size sama dengan stok")
    for f in ("kaddr", "rdaddr", "cmdline", "board", "hdr_size", "dtb_size", "dtb_addr",
              "ent_size", "bootcfg"):
        cek(v[f] == stok[f], "header.%s dipertahankan (%s)" % (f, fmt(v[f]) if isinstance(v[f], int) else v[f]))
    cek(v["vr_size"] == max([e["off"] + e["size"] for e in v["entries"]] or [0]),
        "vr_size %s = ujung blob terakhir" % fmt(v["vr_size"]))
    cek(v["ent_num"] == len(kept_asli) + 1, "ent_num=%d (stok dipertahankan + 1 entri Fox)" % v["ent_num"])

    for i, asli in enumerate(kept_asli):
        e = v["entries"][i]
        cek(e["type"] == asli["type"] and e["name"] == asli["name"],
            "entri[%d] '%s' %s dipertahankan (tipe+nama)" % (i, asli["name"] or "?", TYPE_LABEL[asli["type"]]))
        if skema_mode == "as-is":
            cek(e["blob"] == asli["blob"], "entri[%d] blob byte-persis stok (%s B)"
                % (i, fmt(asli["size"])))
        else:
            a_raw, _ = decompress_any(asli["blob"])
            b_raw, how = decompress_any(e["blob"])
            cek(a_raw is not None and a_raw == b_raw,
                "entri[%d] ISI sama dgn stok asli (dikompres ulang %s: %s -> %s B)"
                % (i, how, fmt(asli["size"]), fmt(e["size"])))
    fox = v["entries"][-1]
    cek(bytes(fox["raw"]) == bytes(fox_raw_ent), "entri Fox memakai byte entri RECOVERY stok (dengan size/offset baru)")
    cek(fox["type"] == TYPE_RECOVERY, "entri Fox bertipe RECOVERY (2) — dimuat bootloader saat mode recovery")
    cek(fox["blob"] == fox_blob, "entri Fox = blob OrangeFox yang baru (%s B)" % fmt(len(fox_blob)))
    dec, how = decompress_any(fox["blob"])
    cek(dec == cpio_asli, "blob Fox didekompres balik (%s) = cpio asli %s B" % (how, fmt(len(cpio_asli))))
    cek(v["dtb"] == stok["dtb"], "DTB byte-persis stok (%s B)" % fmt(stok["dtb_size"]))
    cek(v["bootcfg_bytes"] == stok["bootcfg_bytes"], "bootconfig dipertahankan (%s B)" % fmt(stok["bootcfg"]))
    cek(v["avb"] is None, "footer AVB lama dibuang (tinggal avbtool/pipeline menambah ulang)")
    return v, ket


# --------------------------------------------------------------------------- #
#  Util kecil
# --------------------------------------------------------------------------- #
_WARNINGS = []


def _warn(m):
    _WARNINGS.append(m)
    print("  [!] " + m)


def muat_fragment(path):
    blob = open(path, "rb").read()
    kind = sniff(blob)
    raw, how = decompress_any(blob)
    if raw is None:
        raise AsmError("fragment %s tidak bisa dibuka (%s). Untuk lz4/zstd di Termux: "
                       "pkg install lz4 zstd xz-utils" % (path, kind))
    if raw[:6] not in (b"070701", b"070702"):
        i = raw.find(b"070701", 0, 4096)
        if i < 0:
            raise AsmError("fragment %s bukan arsip cpio (deteksi: %s). Kirim cpio mentah "
                           "atau .gz/.xz/.zst dari ramdisk recovery." % (path, how))
        raw = raw[i:]
    return raw, kind, how


def dump_entri(h):
    for e in h["entries"]:
        print("    [%d] %-18s %-8s %12s B  off=%-9d  isi=%s" %
              (e["idx"], e["name"] or "(tanpa-nama)", TYPE_LABEL.get(e["type"], "?"),
               fmt(e["size"]), e["off"], e["kompresi"]))


# --------------------------------------------------------------------------- #
#  Utama
# --------------------------------------------------------------------------- #
def main(argv=None):
    global _WARNINGS
    _WARNINGS = []
    ap = argparse.ArgumentParser(description=SCRIPT, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stock", required=True, help="vendor_boot STOK (dari OTA/fastboot ROM)")
    ap.add_argument("--fragment", required=True, help="ramdisk recovery OrangeFox: cpio / .gz / .xz / .zst / .lz4")
    ap.add_argument("--output", default="vendor_boot_hybrid.img", help="file output hybrid")
    ap.add_argument("--partition-size", type=lambda x: int(x, 0), default=None,
                    help="ukuran partisi vendor_boot (default: ukuran file stok)")
    ap.add_argument("--avb-headroom", type=lambda x: int(x, 0), default=0,
                    help="ruang cadangan utk footer AVB avbtool (mis. 8192)")
    ap.add_argument("--codec", choices=["auto", "zstd", "xz", "lzma", "gzip"], default="auto",
                    help="paksa codec fragmen Fox (default: auto = yang pertama muat)")
    ap.add_argument("--recompress-stock", choices=["auto", "never", "force"], default="auto",
                    help="kompres ulang blob stok yang dipertahankan (default auto)")
    ap.add_argument("--keep-stock-recovery", action="store_true",
                    help="jangan ganti entri RECOVERY stok — Fox ditambah sebagai entri baru")
    ap.add_argument("--entry-name", default=None,
                    help="nama entri Fox (default: pertahankan nama stok / 'recovery' bila menambah)")
    ap.add_argument("--pad-to-partition", action="store_true",
                    help="pad output persis sebesar partisi (tanpa footer AVB)")
    ap.add_argument("--report", default=None, help="tulis laporan JSON")
    ap.add_argument("--dry-run", action="store_true", help="hitung anggaran saja, tidak menulis file")
    args = ap.parse_args(argv)

    print("== %s — vendor_boot hybrid malachite ==" % SCRIPT)
    t0 = time.time()

    # ---------- 1. stok ----------
    stok_data = open(args.stock, "rb").read()
    stok = parse_vb(stok_data, "stok")
    partition = args.partition_size or stok["file_size"]
    page = stok["page"]
    print("[+] stok: %s B | header v4 | page %d | vr_size %s B | %d entri x %d B (%s)"
          % (fmt(stok["file_size"]), page, fmt(stok["vr_size"]), stok["ent_num"],
             stok["ent_size"], stok["tbl_mode"]))
    if stok["ent_size"] != 108:
        _warn("entry_size stok = %d (bukan 108) — patch tetap aman utk field 44 byte pertama" % stok["ent_size"])
    if stok["avb"]:
        print("[i] footer AVBf stok: orig_size=%s B (akan dibuang dari output)"
              % fmt(stok["avb"]["orig_size"]))
    dump_entri(stok)

    # ---------- 2. fragment recovery OrangeFox ----------
    cpio_raw, kind_in, how_in = muat_fragment(args.fragment)
    n_cpio = cpio_raw.count(b"070701")
    print("[+] cpio recovery OrangeFox: ~%d header cpio, %s B (input %s -> dibuka sbg %s)"
          % (n_cpio, fmt(len(cpio_raw)), kind_in, how_in))

    # ---------- 3. komposisi entri ----------
    if args.keep_stock_recovery:
        kept = [dict(e) for e in stok["entries"]]
        rec_stok = next((e for e in stok["entries"] if e["type"] == TYPE_RECOVERY), None)
        mode_entri = "tambah"
    else:
        kept = [dict(e) for e in stok["entries"] if e["type"] != TYPE_RECOVERY]
        rec_stok = next((e for e in stok["entries"] if e["type"] == TYPE_RECOVERY), None)
        mode_entri = "ganti"
        hilang = [e for e in stok["entries"] if e["type"] == TYPE_RECOVERY]
        for e in hilang:
            print("[+] blob RECOVERY stok '%s' (%s B, %s) DIGANTI blob OrangeFox — entri lain utuh"
                  % (e["name"] or "?", fmt(e["size"]), e["kompresi"]))
        if rec_stok is None:
            _warn("stok TIDAK punya entri bertipe RECOVERY — OrangeFox ditambah sebagai entri baru "
                  "(komposisi ini tetap valid: bootloader memuat PLATFORM/DLKM saat normal, "
                  "+RECOVERY saat recovery)")
    if not kept:
        _warn("tidak ada blob stok yang dipertahankan — boot normal akan bergantung penuh pada isi entri baru")

    kept_end = max([e["off"] + e["size"] for e in kept], default=0)
    tbl_size_new = (len(kept) + 1) * stok["ent_size"]

    # ---------- 4. pilih codec ----------
    codecs = codec_list()
    if args.codec != "auto":
        codecs = [c for c in codecs if c[0] == args.codec]
        if not codecs:
            raise AsmError("codec %s tidak tersedia di lingkungan ini (butuh CLI zstd?)" % args.codec)
    skema = []
    if args.recompress_stock in ("auto", "never"):
        skema += [("as-is", c) for c in codecs]
    if args.recompress_stock in ("auto", "force"):
        skema += [("stock-ikut", c) for c in codecs]
    if args.recompress_stock == "force":
        skema = [("stock-ikut", c) for c in codecs]

    kandidat, dipilih = [], None
    for mode_skema, (codec_name, comp_fn) in [(m, c) for m, c in skema]:
        fox_blob = comp_fn(cpio_raw)
        if mode_skema == "as-is":
            kept_cur, stock_codec, kept_end_cur = kept, None, kept_end
        else:
            kept_cur, cat = rekompress_kept(kept, codec_name, comp_fn)
            stock_codec = codec_name
            kept_end_cur = max([e["off"] + e["size"] for e in kept_cur], default=0)
            for c in cat:
                _warn(c)
        total, fox_off, vr_new = hitung_layout(page, kept_end_cur, len(fox_blob),
                                               stok["dtb_size"], tbl_size_new, stok["bootcfg"])
        muat = total + args.avb_headroom <= partition
        kandidat.append({"mode": mode_skema, "codec": codec_name, "fox": len(fox_blob),
                         "total": total, "muat": muat})
        print("  [>] kandidat %-10s %-6s : fox=%s  total=%s  %s" %
              ("[%s]" % mode_skema, codec_name, fmt(len(fox_blob)), fmt(total),
               "MUAT" if muat else "tidak muat (partisi %s%s)" %
               (fmt(partition), " - headroom %s" % fmt(args.avb_headroom) if args.avb_headroom else "")))
        if muat and dipilih is None:
            dipilih = {"mode": mode_skema, "codec": codec_name, "stock_codec": stock_codec,
                       "kept": kept_cur, "kept_end": kept_end_cur, "fox_blob": fox_blob,
                       "fox_off": fox_off, "vr": vr_new, "total": total}
            break
    if dipilih is None:
        best = min(kandidat, key=lambda k: k["total"]) if kandidat else None
        pesan = ["TIDAK MUAT: tidak ada kombinasi codec yang muat di partisi %s B (headroom AVB %s B)."
                 % (fmt(partition), fmt(args.avb_headroom))]
        if best:
            pesan.append("Kombinasi terkecil: %s/%s -> total %s B (kelebihan %s B)." %
                         (best["mode"], best["codec"], fmt(best["total"]), fmt(best["total"] + args.avb_headroom - partition)))
        pesan.append("Saran: (1) perkecil rootfs OrangeFox (tema/res tambahan), (2) cek CLI zstd "
                     "terpasang (rasio terbaik+dekompresi cepat), (3) gunakan partisi benar.")
        raise AsmError(" ".join(pesan))

    fox_blob = dipilih["fox_blob"]
    fox_off = dipilih["fox_off"]
    vr_new = dipilih["vr"]
    kept_cur = dipilih["kept"]
    tbl_size_new = (len(kept_cur) + 1) * stok["ent_size"]

    # ---------- 5. entri Fox ----------
    if mode_entri == "ganti" and rec_stok is not None:
        fox_raw_ent = bytearray(rec_stok["raw"])          # byte custom stok dipertahankan
        patch_entry(fox_raw_ent, len(fox_blob), fox_off)  # type & nama stok tetap
    else:
        sumber = next((e for e in kept_cur if e["type"] == TYPE_PLATFORM), kept_cur[0] if kept_cur else rec_stok)
        fox_raw_ent = bytearray(sumber["raw"] if sumber is not None else
                                bytearray(stok["ent_size"]))
        if len(fox_raw_ent) < stok["ent_size"]:
            fox_raw_ent += b"\x00" * (stok["ent_size"] - len(fox_raw_ent))
        patch_entry(fox_raw_ent, len(fox_blob), fox_off, etype=TYPE_RECOVERY,
                    name=args.entry_name or "recovery", zero_board=True)

    # ---------- 6. rakit ----------
    hdr = bytearray(stok["header_page"])                  # seluruh byte halaman header dipertahankan
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
    out += stok["dtb"]
    out += b"\x00" * ((page - len(out) % page) % page)
    out += b"".join(bytes(e["raw"]) for e in kept_cur) + bytes(fox_raw_ent)
    out += b"\x00" * ((page - len(out) % page) % page)
    out += stok["bootcfg_bytes"]
    out += b"\x00" * ((page - len(out) % page) % page)
    if args.pad_to_partition:
        if len(out) > partition:
            raise AsmError("pad-to-partition: isi %s B > partisi %s B" % (fmt(len(out)), fmt(partition)))
        out += b"\x00" * (partition - len(out))

    # ---------- 7. verifikasi mandiri ----------
    v, ket = verifikasi(bytes(out), stok, kept, dipilih["mode"], fox_raw_ent,
                        fox_blob, cpio_raw)

    # ---------- 8. laporan ----------
    print("")
    print("[=] codec fragmen Fox : %s (mode stok: %s%s)" %
          (dipilih["codec"], dipilih["mode"],
           ", blob stok ikut dikompres %s" % dipilih["stock_codec"] if dipilih["stock_codec"] else ""))
    for k in ket:
        print("  " + k)
    sisa = partition - args.avb_headroom - dipilih["total"]
    print("[=] total %s B dari %s B partisi — sisa %s B (headroom AVB %s B)"
          % (fmt(dipilih["total"]), fmt(partition),
             fmt(max(sisa, 0)), fmt(args.avb_headroom)))
    print("[i] boot normal: blob PLATFORM/DLKM stok %s — TIDAK tersentuh (byte-persis)" %
          ("byte-persis" if dipilih["mode"] == "as-is" else "dikompres ulang, isi sama"))
    print("[i] kernel GKI android15-6.6: RD_GZIP/RD_LZMA/RD_XZ/RD_LZ4/RD_ZSTD default y; "
          "fragmen RECOVERY hanya dimuat saat mode recovery (gagal dekompresi tidak memengaruhi boot normal).")
    print("[i] bila recovery gagal boot (langka): ulangi dgn --codec xz atau --codec gzip "
          "(+ --recompress-stock force bila perlu ruang).")
    print("[=] %s — %s B, sha256 %s" % (args.output, fmt(len(out)), sha256(bytes(out))[:32]))

    if not args.dry_run:
        with open(args.output, "wb") as f:
            f.write(out)
    if args.report:
        rep = {
            "tool": SCRIPT, "waktu": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stok": {"file": args.stock, "size": stok["file_size"], "vr_size": stok["vr_size"],
                     "entri": [{"name": e["name"], "type": e["type"], "size": e["size"],
                                "off": e["off"], "kompresi": e["kompresi"]} for e in stok["entries"]],
                     "avb": stok["avb"]},
            "fragment": {"file": args.fragment, "input": kind_in, "cpio_bytes": len(cpio_raw)},
            "dipilih": {"mode": dipilih["mode"], "codec": dipilih["codec"],
                        "stock_codec": dipilih["stock_codec"], "fox_blob": len(fox_blob),
                        "total": dipilih["total"], "sisa": sisa},
            "kandidat": kandidat,
            "output": {"file": None if args.dry_run else args.output,
                       "size": len(out), "sha256": sha256(bytes(out))},
            "peringatan": _WARNINGS,
        }
        with open(args.report, "w") as f:
            json.dump(rep, f, indent=2, ensure_ascii=False)
        print("[=] laporan: %s" % args.report)
    print("[=] selesai dalam %.1f s" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AsmError as ex:
        print("[X] " + str(ex), file=sys.stderr)
        sys.exit(1)
