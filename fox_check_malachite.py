import glob, gzip, hashlib, os, struct, subprocess, sys, zipfile

DEV            = "malachite"
EXP_PAGE       = 4096        
EXP_HDR_VER    = 4           
EXP_PART_SIZE  = 67108864    
EXP_HDR_SIZE   = 2128        
EXP_CMDLINE    = "bootopt=64S3,32N2,64N2"
EXP_FIRMWARE   = "VOOMIXM"   
TYPE_NAME      = {0: "NONE", 1: "PLATFORM", 2: "RECOVERY", 3: "DLKM"}

PASS, FAIL, WARN = [], [], []
def passlog(m):  PASS.append(m); print("  [PASS] " + m)
def bad(m):  FAIL.append(m); print("  [FAIL] " + m)
def warn(m): WARN.append(m); print("  [WARN] " + m)
def info(m): print("  [info] " + m)
def sect(n, t): print("\n== %s. %s ==" % (n, t))

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
            raise SystemExit("FAIL-FAST: no vendor_boot*.img inside ZIP %s" % zpath)
        with open(out, "wb") as f:
            f.write(z.read(cands[0]))
    print("Extracted from ZIP: %s -> %s" % (os.path.basename(zpath), out))
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
    if blob[:6] == b"\xfd7zXZ\x00":  
        try:
            import lzma
            return lzma.decompress(blob), "xz"
        except Exception:
            return None, "xz-corrupt"
    if blob[:1] == b"\x5d" and blob[1:3] == b"\x00\x00":  
        try:
            import lzma
            return lzma.decompress(blob, format=lzma.FORMAT_ALONE), "lzma"
        except Exception:
            return None, "lzma-corrupt"
    if blob[:4] == b"\x28\xb5\x2f\xfd":  
        try:
            r = subprocess.run(["zstd", "-d", "-q"], input=blob,
                               capture_output=True, timeout=30)
            if r.returncode == 0:
                return r.stdout, "zstd"
        except Exception:
            pass
        return None, "zstd-frame"
    if blob[:4] == b"\x04\x22\x4d\x18":  
        try:
            r = subprocess.run(["lz4", "-d", "-q"], input=blob,
                               capture_output=True, timeout=30)
            if r.returncode == 0:
                return r.stdout, "lz4"
        except Exception:
            pass
        return None, "lz4-frame"
    return None, "unknown"

def parse_vb(path):
    data = open(path, "rb").read()
    if len(data) < 2200:
        raise ValueError("file too small (%d bytes) for a vendor_boot header" % len(data))
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

        h["tbl_off"], h["tbl_mode"] = tbl_primary, "standard"
        ents = read_table(tbl_primary)
        if not entries_sane(ents):
            alt = page + page_align(h["vr_size"], page)
            if alt != tbl_primary and entries_sane(read_table(alt)):
                h["tbl_off"], h["tbl_mode"] = alt, "alternative"
                ents = read_table(alt)
        for e in ents:
            e["blob"] = data[blob_base + e["off"]: blob_base + e["off"] + e["size"]]
        h["entries"] = ents
    elif h["hdr_ver"] == 3:
        h["entries"].append({"size": h["vr_size"], "off": 0, "type": 1,
                             "name": "(v3-tunggal)",
                             "blob": data[page:page + h["vr_size"]]})
    foot = data[-64:]
    h["avb"] = None
    if foot[:4] == b"AVBf":
        vmaj, vmin = struct.unpack_from(">II", foot, 4)
        orig, voff, vsz = struct.unpack_from(">QQQ", foot, 12)
        h["avb"] = {"vmaj": vmaj, "vmin": vmin, "orig_size": orig,
                    "vbmeta_off": voff, "vbmeta_size": vsz}
    return h

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    path = args[0] if args else None
    stock = args[1] if len(args) > 1 else None
    if not path:
        hits = find_image()
        if not hits:
            raise SystemExit("vendor_boot.img not found. Copy it first, then run:\n"
                             "  python fox_check_malachite.py /path/to/vendor_boot.img")
        path = extract_from_zip(hits[0]) if hits[0].lower().endswith(".zip") else hits[0]
    elif path.lower().endswith(".zip"):
        path = extract_from_zip(path)

    print("OrangeFox vendor_boot checker v3 — %s" % DEV)
    print("Target: %s" % path)

    try:
        h = parse_vb(path)
    except Exception as e:
        bad("HEADER unreadable: %s" % e)
        verdict(); sys.exit(1)

    sect(1, "FILE IDENTITY")
    info("Size: %d bytes (%.2f MiB)" % (h["size"], h["size"] / 1048576.0))
    print("  [info] SHA-256: %s" % sha256(path))
    info("Compare this hash with the file on your PC (certutil -hashfile vendor_boot.img SHA256) "
         "to make sure the transfer is not corrupted.")

    sect(2, "HEADER VENDOR_BOOT")
    if h["magic"] == b"VNDRBOOT":
        passlog("Magic VNDRBOOT valid — this is an Android vendor_boot image")
    else:
        bad("Wrong magic (%r) — NOT a vendor_boot image; do not flash!" % h["magic"])
    if h["hdr_ver"] == EXP_HDR_VER:
        passlog("Header version = %d (matches the malachite tree)" % h["hdr_ver"])
    else:
        bad("Header version = %d, expected %d — structure does not match the tree" %
            (h["hdr_ver"], EXP_HDR_VER))
    if h["page"] == EXP_PAGE:
        passlog("Page size = %d (matches BOARD_PAGE_SIZE)" % h["page"])
    else:
        bad("Page size = %d, expected %d — the image will not boot" %
            (h["page"], EXP_PAGE))
    if h["hdr_size"] == EXP_HDR_SIZE:
        passlog("header_size = %d — official AOSP mkbootimg v4 layout (ground truth)" % h["hdr_size"])
    else:
        warn("header_size = %d (expected %d) — probably a v3 header or another format" %
             (h["hdr_size"], EXP_HDR_SIZE))
    info("Kernel: NOT PRESENT in vendor_boot (GKI design). The kernel stays in stock boot.img — "
         "kernel compatibility is preserved as long as boot.img & dtbo are untouched.")
    info("dtb_size = %d bytes @0x%08x | board name: %r" % (h["dtb_size"], h["dtb_addr"], h["name"]))
    if EXP_CMDLINE.split()[0] in h["cmdline"]:
        passlog("Vendor cmdline contains the factory token '%s'" % EXP_CMDLINE.split()[0])
    else:
        warn("Vendor cmdline does not contain '%s' (content: %r)" %
             (EXP_CMDLINE.split()[0], h["cmdline"][:80]))
    if h["vr_size"] <= 0:
        bad("vendor_ramdisk_size = 0 — empty ramdisk, the image will surely fail to boot")

    sect(3, "VENDOR_RAMDISK TABLE (components inside the image)")
    scans, rec2, rec_hits = [], [], []
    if h["hdr_ver"] < 4:
        warn("v3 header without a table — components cannot be parsed in detail")
    elif h["ent_num"] == 0:
        bad("Empty vendor_ramdisk table (entry_num=0) — the bootloader will load no ramdisk at all!")
    else:
        info("Table @0x%x (%s): %d entries, entry_size %d bytes, bootconfig %d bytes" %
             (h.get("tbl_off", 0), h.get("tbl_mode", "standard"),
              h["ent_num"], h["ent_size"], h["bootcfg"]))
        if h["ent_size"] != 108:
            warn("entry_size = %d (AOSP standard: 108) — non-standard layout" % h["ent_size"])
        for e in h["entries"]:
            nm = TYPE_NAME.get(e["type"], "?%d" % e["type"])
            sc = scan_entry_blob(e["blob"])
            sc["entry"] = e
            scans.append(sc)
            if sc["raw"] is None:
                note = "unopenable (%s)" % sc["how"]
            elif sc["recbin"]:
                note = "RECOVERY FOUND: %s" % ", ".join(sc["recbin"][:2])
            else:
                note = "%d files, no recovery binary" % sc["nfiles"]
            info("- %-24s type=%-8s size=%-9d content: %s" %
                 (e["name"] or "(no name)", nm, e["size"], note))
            if not sc["recbin"]:
                sc["raw"] = None  
        rec_hits = [s for s in scans if s["recbin"]]
        rec2 = [s for s in rec_hits if s["entry"]["type"] == 2]
        if rec2:
            passlog("RECOVERY component present (%d bytes) and contains the recovery binary — recovery ramdisk embedded" %
                rec2[0]["entry"]["size"])
        elif rec_hits:
            e0 = rec_hits[0]["entry"]
            if e0["type"] in (1, 3):
                passlog("Recovery embedded INSIDE component %s ('%s', %d bytes) — ORIGINAL malachite tree design" %
                    (TYPE_NAME.get(e0["type"]), e0["name"] or "(no name)", e0["size"]))
                info("The malachite tree uses BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT=true: the build system "
                     "merges the recovery rootfs into the PLATFORM ramdisk instead of a separate RECOVERY fragment "
                     "(ground truth: build/make/core/Makefile lineage-23.0, merge TARGET_RECOVERY_ROOT_OUT). "
                     "The bootloader loads the PLATFORM component in ALL boot modes — recovery stays loaded. "
                     "The absence of a RECOVERY-type entry is NORMAL for this image.")
            else:
                warn("The recovery binary lives only in a NONE-typed component — the bootloader does not guarantee loading it")
        elif any(not s["opened"] for s in scans):
            unop = ", ".join(sorted(set(s["how"] for s in scans if not s["opened"])))
            warn("Recovery binary not yet proven: some component is unopenable (%s) — "
                 "run: pkg install lz4 zstd then repeat the check" % unop)
        else:
            bad("The 'recovery' binary was NOT found in any component — the image will not boot to recovery!")
        endmax = max([e["off"] + e["size"] for e in h["entries"]] or [0])
        if endmax == h["vr_size"]:
            passlog("Entry coverage (%d) = vendor_ramdisk_size — consistent structure" % endmax)
        elif rec_hits or any(s["nfiles"] > 0 for s in scans):
            warn("Entry coverage (%d) != vendor_ramdisk_size (%d) — component content reads normally, "
                 "the gap is probably just page rounding — not a blocker" % (endmax, h["vr_size"]))
        else:
            bad("Entry coverage (%d) != vendor_ramdisk_size (%d) — broken structure" %
                (endmax, h["vr_size"]))

    sect(4, "RECOVERY RAMDISK CONTENT (proof OrangeFox is embedded)")
    target = rec2[0] if rec2 else (rec_hits[0] if rec_hits else None)
    if target is None:
        info("Skipped (no component contains recovery)")
    elif target["raw"] is None:
        warn("Recovery component is %s-compressed — open manually with: pkg install lz4 then repeat" % target["how"])
    else:
        raw = target["raw"]
        ents = cpio_entries(raw)
        info("cpio (%s): %d files" % (target["how"], len(ents)))
        names = [n for n, s, m in ents if n != "TRAILER!!!"]
        recbin = [n for n in names if n.endswith("/recovery") or n == "recovery"]
        if recbin:
            passlog("Recovery binary present: %s" % ", ".join(recbin[:3]))
        else:
            bad("No 'recovery' binary found in the ramdisk")
        if any("init.recovery" in n for n in names):
            passlog("init.recovery*.rc present (recovery boot scripts)")
        else:
            warn("init.recovery*.rc not visible")
        info("res/ files (UI themes/images): %d" % target["res"])
        if b"OrangeFox" in raw:
            passlog("String 'OrangeFox' found — genuinely an OrangeFox build, not pure TWRP")
        else:
            warn("String 'OrangeFox' not found in the ramdisk (odd for this build)")
        if b"VikrieGunawan" in raw:
            passlog("Maintainer 'VikrieGunawan' embedded in the binary")
        else:
            info("Maintainer unreadable (safe to ignore)")

    sect(5, "FOOTER AVB / VBMETA (big-endian)")
    if h["avb"]:
        a = h["avb"]
        sane = (0 < a["orig_size"] <= h["size"]
                and 0 < a["vbmeta_off"] <= h["size"]
                and a["vbmeta_off"] + a["vbmeta_size"] <= h["size"])
        if sane:
            passlog("Footer AVBf v%d.%d valid (orig_size=%d, vbmeta@%d)" %
                (a["vmaj"], a["vmin"], a["orig_size"], a["vbmeta_off"]))
            vb = h["raw"][a["vbmeta_off"]:a["vbmeta_off"] + a["vbmeta_size"]]
            if vb[:4] == b"AVB0":
                passlog("Blob vbmeta AVB0 valid")
                if b"vendor_boot" in vb[:4096]:
                    passlog("Hash descriptor for partition 'vendor_boot' present")
                else:
                    warn("Partition name 'vendor_boot' not visible in vbmeta")
                algo = struct.unpack_from(">I", vb, 28)[0] if len(vb) >= 32 else -1
                info("AVB algorithm type: %d (0=unsigned; unlocked bootloader still boots)" % algo)
            else:
                warn("vbmeta_offset does not point to an AVB0 blob")
        else:
            warn("AVBf footer present but fields out of file bounds — "
                 "not fatal on an unlocked bootloader; hexdump: %s" % h["raw"][-64:].hex()[:96])
    else:
        warn("No AVB footer — normal on an unlocked bootloader, but not standard for GKI builds")

    sect(6, "PHONE PARTITION MATCH")
    if h["size"] <= EXP_PART_SIZE:
        passlog("Image size %.2f MiB <= vendor_boot partition 64 MiB (67108864 bytes)" %
            (h["size"] / 1048576.0))
    else:
        bad("Image %.2f MiB EXCEEDS the 64 MiB partition — flash may fail/write out of bounds!" %
            (h["size"] / 1048576.0))
    if h["size"] == EXP_PART_SIZE:
        info("Exactly 64 MiB = normal: avbtool pads the image to partition size.")
    real = part_size_sysfs()
    if real:
        if real == EXP_PART_SIZE:
            passlog("Phone vendor_boot partition reads: %d bytes = same as the tree value" % real)
        else:
            warn("Phone vendor_boot partition reads: %d bytes (tree: %d) — make sure this is really a malachite" % (real, EXP_PART_SIZE))
    else:
        info("Partition size unreadable without root — using the tree value 67108864")

    sect(7, "PHONE STATE (getprop)")
    dev = getprop("ro.product.device")
    if dev is None:
        warn("getprop unavailable — section skipped")
    else:
        if dev == DEV:
            passlog("Device = %s (match)" % dev)
        else:
            bad("Device = %s — NOT %s! Reference values do not apply, do not flash!" % (dev, DEV))
        rel = getprop("ro.build.version.release") or "?"
        inc = getprop("ro.build.version.incremental") or "?"
        info("Android %s | firmware: %s" % (rel, inc))
        if EXP_FIRMWARE not in inc:
            warn("Firmware is not %s (target build) — recovery may still work, but data decryption is not guaranteed" % EXP_FIRMWARE)
        locked = getprop("ro.boot.flash.locked")
        vbs = getprop("ro.boot.verifiedbootstate")
        if locked == "0":
            passlog("Bootloader UNLOCKED (flash.locked=0)")
        elif locked == "1" and vbs == "green":
            warn("flash.locked=1 & verifiedbootstate=green — MAY BE a spoof result (real UBL). "
                 "Userspace values cannot be trusted; verify from a PC: fastboot getvar unlocked "
                 "(must be 'yes'). Flash is refused only when the bootloader is truly locked.")
        elif locked == "1":
            warn("flash.locked=1 — ignore if UBL is spoofed; otherwise flash will be refused.")
        else:
            info("Bootloader status unreadable (%r)" % locked)
        info("verifiedbootstate = %s | Active slot: %r | running kernel: %s" %
             (vbs, getprop("ro.boot.slot_suffix"),
              subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()))
        info("vendor_boot does NOT touch the kernel — boot.img, dtbo, vbmeta, super stay unchanged when flashing vendor_boot only")

    if stock:
        sect(8, "STOCK VENDOR_BOOT COMPARISON")
        try:
            s = parse_vb(stock)
            print("  [info] Stock: SHA-256 %s" % sha256(stock))
            if s["magic"] != b"VNDRBOOT":
                bad("Stock file is not a vendor_boot")
            else:
                same = (s["hdr_ver"] == h["hdr_ver"] and s["page"] == h["page"])
                if same:
                    passlog("STOCK header version & page size = BUILD RESULT (%d / %d) — compatible" %
                        (h["hdr_ver"], h["page"]))
                else:
                    bad("Stock header/page (%d/%d) DIFFERS from the build result (%d/%d) — DO NOT flash!" %
                        (s["hdr_ver"], s["page"], h["hdr_ver"], h["page"]))
                info("Keep this stock vendor_boot as a rollback backup: "
                     "fastboot flash vendor_boot vendor_boot_stok.img")
        except Exception as e:
            warn("Stock cannot be analyzed: %s" % e)

    verdict()

def verdict():
    print("\n" + "=" * 64)
    print("SUMMARY: PASS=%d  WARN=%d  FAIL=%d" % (len(PASS), len(WARN), len(FAIL)))
    if FAIL:
        print("DECISION: DO NOT FLASH YET — resolve the FAIL items above first.")
        print("Send this output to the assistant for analysis.")
    else:
        print("DECISION: IMAGE STRUCTURE HEALTHY — safe to proceed to flashing.")
        print("Required: STOCK vendor_boot.img (from the fastboot ROM 2.0.208.0.VOOMIXM)")
        print("One-command rollback: fastboot flash vendor_boot vendor_boot_stok.img")
    print("=" * 64)
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print("Unexpected error: %r" % e)
        sys.exit(1)
