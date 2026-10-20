#!/usr/bin/env python3
# ============================================================================
# fox_check_malachite.py v3.1 — Pemeriksa pra-flash vendor_boot.img OrangeFox
# Perangkat : Xiaomi Redmi Note 14 Pro 5G (malachite)
# Layout sesuai mkbootimg.py AOSP/LineageOS lineage-23.0 (ground truth):
#   cmdline 2048 | header_size @2096 | dtb @2100/2104 | tabel v4 @2112 (u32)
#   entri 108 byte: size, offset, type, name32, board_id64 | region page-align
#   footer AVB BIG-ENDIAN (bukan little-endian!)
# v3.1: blob kompresi xz / zstd / lzma kini ikut dibuka (hasil hybrid_assembler v2
#       yang menghemat partisi 64 MiB dengan codec modern) — xz/lzma via stdlib,
#       zstd via CLI (Termux: pkg install zstd).
# Desain ISI malachite (ground truth build/make/core/Makefile lineage-23.0):
#   tree memakai BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT=true -> build
#   system MENGGABUNGKAN rootfs recovery ke ramdisk PLATFORM (mkbootimg
#   menerima --vendor_ramdisk tunggal bertipe PLATFORM, tanpa fragment
#   RECOVERY terpisah). Tabel TANPA entri bertipe RECOVERY itu NORMAL di
#   sini; keberadaan recovery dibuktikan langsung dari ISI komponen.
# Pemakaian:
#   python fox_check_malachite.py                    (cari otomatis di Download)
#   python fox_check_malachite.py /path/vendor_boot.img
#   python fox_check_malachite.py /path/vendor_boot.img /path/vendor_boot_stok.img
# Keluar: [PASS]/[WARN]/[FAIL] per butir + ringkasan; exit code 0 = aman lanjut.
# ============================================================================
import glob, gzip, hashlib, os, struct, subprocess, sys, zipfile

DEV            = "malachite"
EXP_PAGE       = 4096        # BoardConfig.mk: BOARD_PAGE_SIZE
EXP_HDR_VER    = 4           # BoardConfig.mk: BOARD_BOOT_HEADER_VERSION
EXP_PART_SIZE  = 67108864    # BoardConfig.mk: BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE (64 MiB)
EXP_HDR_SIZE   = 2128        # VENDOR_BOOT_IMAGE_HEADER_V4_SIZE (mkbootimg.py)
EXP_CMDLINE    = "bootopt=64S3,32N2,64N2"
EXP_FIRMWARE   = "VOOMIXM"   # HyperOS 2.0.208.0.VOOMIXM
TYPE_NAME      = {0: "NONE", 1: "PLATFORM", 2: "RECOVERY", 3: "DLKM"}

PASS, FAIL, WARN = [], [], []
def pok(m):  PASS.append(m); print("  [PASS] " + m)
def bad(m):  FAIL.append(m); print("  [FAIL] " + m)
def warn(m): WARN.append(m); print("  [WARN] " + m)
def info(m): print("  [info] " + m)
def sect(n, t): print("\n== %s. %s ==" % (n, t))

# ---------------------------------------------------------------- utilitas --
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def find_image():
    dirs = [os.path.expanduser("~/storage/downloads"),
            "/storage/emulated/0/Download", "/sdcard/Download",
            os.getcwd(), os.path.expanduser("~")]
    hits = []
    for d in dirs:
        hits += glob.glob(os.path.join(d, "*vendor_boot*.img"))
        hits += glob.glob(os.path.join(d, "*vendor_boot*.zip"))
    return sorted(set(hits))

def extract_from_zip(zpath):
    out = os.path.splitext(zpath)[0] + "_extracted.img"
    with zipfile.ZipFile(zpath) as z:
        cands = [n for n in z.namelist()
                 if "vendor_boot" in n.lower() and n.lower().endswith(".img")]
        if not cands:
            raise SystemExit("FAIL-FAST: tidak ada vendor_boot*.img di dalam ZIP %s" % zpath)
        with open(out, "wb") as f:
            f.write(z.read(cands[0]))
    print("Diekstrak dari ZIP: %s -> %s" % (os.path.basename(zpath), out))
    return out

def getprop(key):
    try:
        r = subprocess.run(["getprop", key], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None

def part_size_sysfs():
    try:
        out = subprocess.run(["ls", "-l", "/dev/block/by-name/vendor_boot"],
                             capture_output=True, text=True, timeout=10).stdout
        if "->" in out:
            node = out.rsplit("->", 1)[1].strip().split()[-1]
            p = "/sys/class/block/%s/size" % os.path.basename(node)
            if os.path.exists(p):
                return int(open(p).read().strip()) * 512
    except Exception:
        pass
    return None

def page_align(x, page):
    return (x + page - 1) // page * page

# ------------------------------------------------------------- parsing CPIO --
def cpio_entries(raw):
    ent, off = [], 0
    while off + 110 <= len(raw):
        if raw[off:off + 6] != b"070701":
            break
        f = [int(raw[off + 6 + i * 8: off + 14 + i * 8], 16) for i in range(13)]
        namesize, size, mode = f[11], f[6], f[1]
        name = raw[off + 110: off + 110 + namesize - 1].decode(errors="replace")
        doff = (off + 110 + namesize + 3) & ~3
        ent.append((name, size, mode))
        if name == "TRAILER!!!":
            break
        off = (doff + size + 3) & ~3
    return ent

def scan_entry_blob(blob):
    # Buka satu komponen ramdisk dan periksa isinya secara LANGSUNG dari data
    # (bukti recovery dicari dari isi cpio, bukan dari label tipe di tabel).
    out = {"how": None, "raw": None, "opened": False, "nfiles": 0, "recbin": [],
           "initrc": False, "res": 0, "fox": False, "vg": False}
    raw, how = try_decompress(blob)
    out["how"] = how
    if raw is None:
        return out
    out["opened"] = True
    out["raw"] = raw
    ents = cpio_entries(raw)
    names = [n for n, s, m in ents if n != "TRAILER!!!"]
    out["nfiles"] = len(names)
    out["recbin"] = [n for n in names if n.endswith("/recovery") or n == "recovery"]
    out["initrc"] = any("init.recovery" in n for n in names)
    out["res"] = sum(1 for n in names if "/res/" in n)
    out["fox"] = b"OrangeFox" in raw
    out["vg"] = b"VikrieGunawan" in raw
    return out

def try_decompress(blob):
    try:
        return gzip.decompress(blob), "gzip"
    except Exception:
        pass
    if blob[:6] in (b"070701", b"070702"):
        return blob, "raw"
    if blob[:6] == b"\xfd7zXZ\x00":  # kontainer xz (dipakai hybrid_assembler)
        try:
            import lzma
            return lzma.decompress(blob), "xz"
        except Exception:
            return None, "xz-rusak"
    if blob[:1] == b"\x5d" and blob[1:3] == b"\x00\x00":  # lzma legacy (.lzma)
        try:
            import lzma
            return lzma.decompress(blob, format=lzma.FORMAT_ALONE), "lzma"
        except Exception:
            return None, "lzma-rusak"
    if blob[:4] == b"\x28\xb5\x2f\xfd":  # frame zstd (butuh CLI zstd)
        try:
            r = subprocess.run(["zstd", "-d", "-q"], input=blob,
                               capture_output=True, timeout=30)
            if r.returncode == 0:
                return r.stdout, "zstd"
        except Exception:
            pass
        return None, "zstd-frame"
    if blob[:4] == b"\x04\x22\x4d\x18":  # frame lz4
        try:
            r = subprocess.run(["lz4", "-d", "-q"], input=blob,
                               capture_output=True, timeout=30)
            if r.returncode == 0:
                return r.stdout, "lz4"
        except Exception:
            pass
        return None, "lz4-frame"
    return None, "tidak-dikenal"

# ------------------------------------------------------- parsing vendor_boot --
# Layout ground truth (mkbootimg.py lineage-23.0 / A16, little-endian):
#   magic8 | ver u32 | page u32 | kaddr | rdaddr | vr_size | cmdline[2048]
#   tags u32 | name[16] | header_size u32 | dtb_size u32 | dtb_addr u64
#   [v4] tbl_size u32 | num u32 | esize u32 | bootconfig u32   (= 2128 byte)
# Region: header(page) -> blobs(page) -> dtb(page) -> tabel(page) -> bootconfig
#   entri 108 byte: size u32, offset u32, type u32, name 32s, board_id 64s
def parse_vb(path):
    data = open(path, "rb").read()
    if len(data) < 2200:
        raise ValueError("file terlalu kecil (%d byte) untuk header vendor_boot" % len(data))
    h = {"size": len(data), "raw": data}
    h["magic"] = data[:8]
    (h["hdr_ver"], h["page"], h["kaddr"], h["rdaddr"],
     h["vr_size"]) = struct.unpack_from("<5I", data, 8)
    h["cmdline"] = data[28:28 + 2048].split(b"\x00")[0].decode(errors="replace")
    h["tags_addr"] = struct.unpack_from("<I", data, 2076)[0]
    h["name"] = data[2080:2096].split(b"\x00")[0].decode(errors="replace")
    h["hdr_size"] = struct.unpack_from("<I", data, 2096)[0]
    h["dtb_size"] = struct.unpack_from("<I", data, 2100)[0]
    h["dtb_addr"] = struct.unpack_from("<Q", data, 2104)[0]
    h["tbl_size"] = h["ent_num"] = h["ent_size"] = h["bootcfg"] = 0
    if h["hdr_ver"] >= 4:
        (h["tbl_size"], h["ent_num"],
         h["ent_size"], h["bootcfg"]) = struct.unpack_from("<IIII", data, 2112)
    page = h["page"]
    h["entries"] = []
    h["tbl_off"] = 0
    h["tbl_mode"] = "-"
    if h["hdr_ver"] >= 4 and h["ent_num"] > 0 and h["ent_size"] >= 44:
        blob_base = page
        tbl_primary = page + page_align(h["vr_size"], page)
        if h["dtb_size"]:
            tbl_primary += page_align(h["dtb_size"], page)

        def read_table(tbl_off):
            out = []
            for i in range(h["ent_num"]):
                e = tbl_off + i * h["ent_size"]
                rsize, roff, rtype = struct.unpack_from("<III", data, e)
                rname = data[e + 12:e + 44].split(b"\x00")[0].decode(errors="replace")
                out.append({"size": rsize, "off": roff, "type": rtype, "name": rname})
            return out

        def entries_sane(ents):
            if not ents:
                return False
            for e in ents:
                if e["type"] > 3 or e["size"] <= 0:
                    return False
                if e["off"] + e["size"] > h["vr_size"]:
                    return False
                if e["name"] and not e["name"].isprintable():
                    return False
            return True

        # Lokasi tabel: urutan resmi mkbootimg.py = blobs -> dtb -> tabel.
        # Kandidat alternatif: tabel langsung setelah blobs (antisipasi varian).
        h["tbl_off"], h["tbl_mode"] = tbl_primary, "standar"
        ents = read_table(tbl_primary)
        if not entries_sane(ents):
            alt = page + page_align(h["vr_size"], page)
            if alt != tbl_primary and entries_sane(read_table(alt)):
                h["tbl_off"], h["tbl_mode"] = alt, "alternatif"
                ents = read_table(alt)
        for e in ents:
            e["blob"] = data[blob_base + e["off"]: blob_base + e["off"] + e["size"]]
        h["entries"] = ents
    elif h["hdr_ver"] == 3:
        h["entries"].append({"size": h["vr_size"], "off": 0, "type": 1,
                             "name": "(v3-tunggal)",
                             "blob": data[page:page + h["vr_size"]]})
    # footer AVB — 64 byte terakhir, SEMUA field BIG-ENDIAN
    foot = data[-64:]
    h["avb"] = None
    if foot[:4] == b"AVBf":
        vmaj, vmin = struct.unpack_from(">II", foot, 4)
        orig, voff, vsz = struct.unpack_from(">QQQ", foot, 12)
        h["avb"] = {"vmaj": vmaj, "vmin": vmin, "orig_size": orig,
                    "vbmeta_off": voff, "vbmeta_size": vsz}
    return h

# --------------------------------------------------------------- pemeriksaan --
def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    path = args[0] if args else None
    stock = args[1] if len(args) > 1 else None
    if not path:
        hits = find_image()
        if not hits:
            raise SystemExit("vendor_boot.img tidak ditemukan. Salin dulu lalu jalankan:\n"
                             "  python fox_check_malachite.py /path/ke/vendor_boot.img")
        path = extract_from_zip(hits[0]) if hits[0].lower().endswith(".zip") else hits[0]
    elif path.lower().endswith(".zip"):
        path = extract_from_zip(path)

    print("Pemeriksa vendor_boot OrangeFox v3 — %s" % DEV)
    print("Target: %s" % path)

    try:
        h = parse_vb(path)
    except Exception as e:
        bad("HEADER tidak bisa dibaca: %s" % e)
        verdict(); sys.exit(1)

    # -- 1. identitas file
    sect(1, "IDENTITAS FILE")
    info("Ukuran: %d byte (%.2f MiB)" % (h["size"], h["size"] / 1048576.0))
    print("  [info] SHA-256: %s" % sha256(path))
    info("Bandingkan hash ini dengan file di PC (certutil -hashfile vendor_boot.img SHA256) "
         "untuk memastikan transfer tidak korup.")

    # -- 2. header
    sect(2, "HEADER VENDOR_BOOT")
    if h["magic"] == b"VNDRBOOT":
        pok("Magic VNDRBOOT valid — ini image vendor_boot Android")
    else:
        bad("Magic salah (%r) — BUKAN image vendor_boot; jangan flash!" % h["magic"])
    if h["hdr_ver"] == EXP_HDR_VER:
        pok("Header version = %d (sesuai tree malachite)" % h["hdr_ver"])
    else:
        bad("Header version = %d, seharusnya %d — struktur tidak cocok dengan tree" %
            (h["hdr_ver"], EXP_HDR_VER))
    if h["page"] == EXP_PAGE:
        pok("Page size = %d (sesuai BOARD_PAGE_SIZE)" % h["page"])
    else:
        bad("Page size = %d, seharusnya %d — image tidak akan bisa boot" %
            (h["page"], EXP_PAGE))
    if h["hdr_size"] == EXP_HDR_SIZE:
        pok("header_size = %d — layout v4 resmi mkbootimg AOSP (ground truth)" % h["hdr_size"])
    else:
        warn("header_size = %d (diharapkan %d) — kemungkinan header v3 atau format lain" %
             (h["hdr_size"], EXP_HDR_SIZE))
    info("Kernel: TIDAK ADA di vendor_boot (desain GKI). Kernel tetap dari boot.img stok — "
         "kompatibilitas kernel terjaga selama boot.img & dtbo tidak disentuh.")
    info("dtb_size = %d byte @0x%08x | nama board: %r" % (h["dtb_size"], h["dtb_addr"], h["name"]))
    if EXP_CMDLINE.split()[0] in h["cmdline"]:
        pok("Vendor cmdline berisi token pabrik '%s'" % EXP_CMDLINE.split()[0])
    else:
        warn("Vendor cmdline tidak berisi '%s' (isinya: %r)" %
             (EXP_CMDLINE.split()[0], h["cmdline"][:80]))
    if h["vr_size"] <= 0:
        bad("vendor_ramdisk_size = 0 — ramdisk kosong, image pasti gagal boot")

    # -- 3. tabel vendor_ramdisk + pemindaian isi tiap komponen
    sect(3, "TABEL VENDOR_RAMDISK (komponen di dalam image)")
    scans, rec2, rec_hits = [], [], []
    if h["hdr_ver"] < 4:
        warn("Header v3 tanpa tabel — komponen tidak bisa diurai per-detail")
    elif h["ent_num"] == 0:
        bad("Tabel vendor_ramdisk kosong (entry_num=0) — bootloader tidak memuat ramdisk apapun!")
    else:
        info("Tabel @0x%x (%s): %d entri, entry_size %d byte, bootconfig %d byte" %
             (h.get("tbl_off", 0), h.get("tbl_mode", "standar"),
              h["ent_num"], h["ent_size"], h["bootcfg"]))
        if h["ent_size"] != 108:
            warn("entry_size = %d (standar AOSP: 108) — layout tidak baku" % h["ent_size"])
        for e in h["entries"]:
            nm = TYPE_NAME.get(e["type"], "?%d" % e["type"])
            sc = scan_entry_blob(e["blob"])
            sc["entry"] = e
            scans.append(sc)
            if sc["raw"] is None:
                ket = "tidak bisa dibuka (%s)" % sc["how"]
            elif sc["recbin"]:
                ket = "RECOVERY DITEMUKAN: %s" % ", ".join(sc["recbin"][:2])
            else:
                ket = "%d file, tanpa binary recovery" % sc["nfiles"]
            info("- %-24s tipe=%-8s ukuran=%-9d isi: %s" %
                 (e["name"] or "(tanpa nama)", nm, e["size"], ket))
            if not sc["recbin"]:
                sc["raw"] = None  # hemat memori: raw hanya disimpan untuk komponen recovery
        rec_hits = [s for s in scans if s["recbin"]]
        rec2 = [s for s in rec_hits if s["entry"]["type"] == 2]
        if rec2:
            pok("Komponen RECOVERY ada (%d byte) dan berisi binary recovery — ramdisk recovery tertanam" %
                rec2[0]["entry"]["size"])
        elif rec_hits:
            e0 = rec_hits[0]["entry"]
            if e0["type"] in (1, 3):
                pok("Recovery tertanam DI DALAM komponen %s ('%s', %d byte) — DESAIN ASLI tree malachite" %
                    (TYPE_NAME.get(e0["type"]), e0["name"] or "(tanpa nama)", e0["size"]))
                info("Tree malachite memakai BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT=true: build system "
                     "menggabungkan rootfs recovery ke ramdisk PLATFORM, bukan fragment RECOVERY terpisah "
                     "(ground truth: build/make/core/Makefile lineage-23.0, merge TARGET_RECOVERY_ROOT_OUT). "
                     "Bootloader memuat komponen PLATFORM di SEMUA mode boot — recovery tetap termuat. "
                     "Tidak adanya entri bertipe RECOVERY itu NORMAL untuk image ini.")
            else:
                warn("Binary recovery hanya ada di komponen bertipe NONE — bootloader tidak menjamin memuatnya")
        elif any(not s["opened"] for s in scans):
            unop = ", ".join(sorted(set(s["how"] for s in scans if not s["opened"])))
            warn("Binary recovery belum bisa dibuktikan: ada komponen yang tidak terbuka (%s) — "
                 "jalankan: pkg install lz4 zstd lalu ulangi pemeriksaan" % unop)
        else:
            bad("Binary 'recovery' TIDAK ditemukan di komponen manapun — image tidak akan bisa boot ke recovery!")
        endmax = max([e["off"] + e["size"] for e in h["entries"]] or [0])
        if endmax == h["vr_size"]:
            pok("Cakupan entri (%d) = vendor_ramdisk_size — struktur konsisten" % endmax)
        elif rec_hits or any(s["nfiles"] > 0 for s in scans):
            warn("Cakupan entri (%d) != vendor_ramdisk_size (%d) — isi komponen terbaca normal, "
                 "selisih kemungkinan hanya pembulatan halaman — bukan penghalang" % (endmax, h["vr_size"]))
        else:
            bad("Cakupan entri (%d) != vendor_ramdisk_size (%d) — struktur rusak" %
                (endmax, h["vr_size"]))

    # -- 4. isi ramdisk recovery
    sect(4, "ISI RAMDISK RECOVERY (bukti OrangeFox tertanam)")
    target = rec2[0] if rec2 else (rec_hits[0] if rec_hits else None)
    if target is None:
        info("Dilewati (tidak ada komponen yang berisi recovery)")
    elif target["raw"] is None:
        warn("Komponen recovery terkompresi %s — buka manual dengan: pkg install lz4 lalu ulangi" % target["how"])
    else:
        raw = target["raw"]
        ents = cpio_entries(raw)
        info("cpio (%s): %d file" % (target["how"], len(ents)))
        names = [n for n, s, m in ents if n != "TRAILER!!!"]
        recbin = [n for n in names if n.endswith("/recovery") or n == "recovery"]
        if recbin:
            pok("Binary recovery ada: %s" % ", ".join(recbin[:3]))
        else:
            bad("Tidak menemukan binary 'recovery' di ramdisk")
        if any("init.recovery" in n for n in names):
            pok("init.recovery*.rc ada (skrip boot recovery)")
        else:
            warn("init.recovery*.rc tidak terlihat")
        info("File res/ (tema/gambar UI): %d" % target["res"])
        if b"OrangeFox" in raw:
            pok("String 'OrangeFox' ditemukan — build benar OrangeFox, bukan TWRP murni")
        else:
            warn("String 'OrangeFox' tidak ditemukan di ramdisk (aneh untuk build ini)")
        if b"VikrieGunawan" in raw:
            pok("Maintainer 'VikrieGunawan' tertanam di binary")
        else:
            info("Maintainer tidak terbaca (boleh diabaikan)")

    # -- 5. AVB / vbmeta (BIG-ENDIAN)
    sect(5, "FOOTER AVB / VBMETA (big-endian)")
    if h["avb"]:
        a = h["avb"]
        sane = (0 < a["orig_size"] <= h["size"]
                and 0 < a["vbmeta_off"] <= h["size"]
                and a["vbmeta_off"] + a["vbmeta_size"] <= h["size"])
        if sane:
            pok("Footer AVBf v%d.%d valid (orig_size=%d, vbmeta@%d)" %
                (a["vmaj"], a["vmin"], a["orig_size"], a["vbmeta_off"]))
            vb = h["raw"][a["vbmeta_off"]:a["vbmeta_off"] + a["vbmeta_size"]]
            if vb[:4] == b"AVB0":
                pok("Blob vbmeta AVB0 valid")
                if b"vendor_boot" in vb[:4096]:
                    pok("Deskriptor hash untuk partisi 'vendor_boot' ada")
                else:
                    warn("Nama partisi 'vendor_boot' tidak terlihat di vbmeta")
                algo = struct.unpack_from(">I", vb, 28)[0] if len(vb) >= 32 else -1
                info("Algorithm type AVB: %d (0=tanpa tanda tangan; bootloader terbuka tetap boot)" % algo)
            else:
                warn("vbmeta_offset tidak menunjuk blob AVB0")
        else:
            warn("Footer AVBf ada tetapi field di luar batas file — "
                 "tidak fatal di bootloader terbuka; hexdump: %s" % h["raw"][-64:].hex()[:96])
    else:
        warn("Tidak ada footer AVB — wajar di-bootloader terbuka, tapi tidak standar untuk build GKI")

    # -- 6. kecocokan partisi
    sect(6, "KECOCOKAN PARTISI HP")
    if h["size"] <= EXP_PART_SIZE:
        pok("Ukuran image %.2f MiB <= partisi vendor_boot 64 MiB (67108864 byte)" %
            (h["size"] / 1048576.0))
    else:
        bad("Image %.2f MiB MELEBIHI partisi 64 MiB — flash bisa gagal/menulis melenceng!" %
            (h["size"] / 1048576.0))
    if h["size"] == EXP_PART_SIZE:
        info("Ukuran persis 64 MiB = normal: avbtool mem-pad image ke ukuran partisi.")
    real = part_size_sysfs()
    if real:
        if real == EXP_PART_SIZE:
            pok("Partisi vendor_boot HP terbaca: %d byte = sama dengan nilai tree" % real)
        else:
            warn("Partisi vendor_boot HP terbaca: %d byte (tree: %d) — pastikan ini benar-benar malachite" % (real, EXP_PART_SIZE))
    else:
        info("Ukuran partisi tidak bisa dibaca tanpa root — dipakai nilai tree 67108864")

    # -- 7. kondisi HP
    sect(7, "KONDISI HP (getprop)")
    dev = getprop("ro.product.device")
    if dev is None:
        warn("getprop tidak tersedia — bagian ini dilewati")
    else:
        if dev == DEV:
            pok("Perangkat = %s (cocok)" % dev)
        else:
            bad("Perangkat = %s — BUKAN %s! Nilai patokan tidak berlaku, jangan flash!" % (dev, DEV))
        rel = getprop("ro.build.version.release") or "?"
        inc = getprop("ro.build.version.incremental") or "?"
        info("Android %s | firmware: %s" % (rel, inc))
        if EXP_FIRMWARE not in inc:
            warn("Firmware bukan %s (target build) — recovery tetap bisa dicoba, tapi dekripsi data belum tentu" % EXP_FIRMWARE)
        locked = getprop("ro.boot.flash.locked")
        vbs = getprop("ro.boot.verifiedbootstate")
        if locked == "0":
            pok("Bootloader TERBUKA (flash.locked=0)")
        elif locked == "1" and vbs == "green":
            warn("flash.locked=1 & verifiedbootstate=green — BISA JADI hasil spoof (UBL nyata). "
                 "Nilai userspace tidak bisa dipercaya; verifikasi dari PC: fastboot getvar unlocked "
                 "(harus 'yes'). Flash hanya ditolak bila bootloader benar-benar terkunci.")
        elif locked == "1":
            warn("flash.locked=1 — jika UBL-nya dispoof abaikan; jika tidak, flash akan ditolak.")
        else:
            info("Status bootloader tidak terbaca (%r)" % locked)
        info("verifiedbootstate = %s | Slot aktif: %r | kernel berjalan: %s" %
             (vbs, getprop("ro.boot.slot_suffix"),
              subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()))
        info("vendor_boot TIDAK menyentuh kernel — boot.img, dtbo, vbmeta, super tidak diubah saat flash vendor_boot saja")

    # -- 8. pembanding stok
    if stock:
        sect(8, "PEMBANDING VENDOR_BOOT STOK")
        try:
            s = parse_vb(stock)
            print("  [info] Stok: SHA-256 %s" % sha256(stock))
            if s["magic"] != b"VNDRBOOT":
                bad("File stok bukan vendor_boot")
            else:
                same = (s["hdr_ver"] == h["hdr_ver"] and s["page"] == h["page"])
                if same:
                    pok("Header version & page size STOK = HASIL BUILD (%d / %d) — kompatibel" %
                        (h["hdr_ver"], h["page"]))
                else:
                    bad("Header/page stok (%d/%d) BEDA dengan hasil build (%d/%d) — JANGAN flash!" %
                        (s["hdr_ver"], s["page"], h["hdr_ver"], h["page"]))
                info("Simpan vendor_boot stok ini sebagai cadangan rollback: "
                     "fastboot flash vendor_boot vendor_boot_stok.img")
        except Exception as e:
            warn("Stok tidak bisa dianalisa: %s" % e)

    verdict()

def verdict():
    print("\n" + "=" * 64)
    print("RINGKASAN: PASS=%d  WARN=%d  FAIL=%d" % (len(PASS), len(WARN), len(FAIL)))
    if FAIL:
        print("KEPUTUSAN: JANGAN FLASH DULU — selesaikan dulu butir FAIL di atas.")
        print("Kirim output ini ke assistant untuk dianalisa.")
    else:
        print("KEPUTUSAN: STRUKTUR IMAGE SEHAT — aman lanjut ke tahap flash.")
        print("Wajib siapkan: vendor_boot.img STOK (dari fastboot ROM 2.0.208.0.VOOMIXM)")
        print("Rollback satu perintah: fastboot flash vendor_boot vendor_boot_stok.img")
    print("=" * 64)
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print("Kesalahan tak terduga: %r" % e)
        sys.exit(1)
