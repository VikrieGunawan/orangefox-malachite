import hashlib, io, lzma, bz2, gzip, os, pickle, struct, sys, time, urllib.request
import concurrent.futures as cf

UA    = {"User-Agent": "fetch-stock-vb/1.0 (malachite pipeline)"}
CHUNK = 1 << 20          
RETRY = 3

def http_size(url):
    req = urllib.request.Request(url, headers={**UA, "Range": "bytes=0-0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        cr = r.headers.get("Content-Range", "")
        if not cr.startswith("bytes "):
            raise RuntimeError("server does not support HTTP Range (empty Content-Range)")
        return int(cr.split("/")[1])

def http_get(url, start, end, timeout=300):  
    hdr = {**UA, "Range": "bytes=%d-%d" % (start, end)}
    last = None
    for attempt in range(RETRY):
        try:
            req = urllib.request.Request(url, headers=hdr)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            if len(data) != end - start + 1:
                raise RuntimeError("truncated range: requested %d got %d" %
                                   (end - start + 1, len(data)))
            return data
        except Exception as e:
            last = e
            time.sleep(2 + attempt * 4)
    raise RuntimeError("GET range [%d,%d] failed after %d attempts: %s" %
                       (start, end, RETRY, last))

def download_parallel(url, ranges, workers=16, chunk=4 << 20):
    pass
    total = sum(e - s + 1 for s, e in ranges)
    tasks = []
    for s0, e0 in ranges:
        s = s0
        while s <= e0:
            t0e = min(s + chunk - 1, e0)
            tasks.append((s, t0e))
            s = t0e + 1
    results = {}
    downloaded = [0]
    def fetch_task(t):
        s0, e0 = t
        data = http_get(url, s0, e0)
        downloaded[0] += len(data)
        print("\r[+]   %5.1f / %.1f MB (%d connections)" %
              (downloaded[0] / 1e6, total / 1e6, workers), end="", flush=True)
        return s0, data
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for s0, data in ex.map(fetch_task, tasks):
            results[s0] = data
    print()
    output = []
    for s0, e0 in ranges:
        buf = bytearray(e0 - s0 + 1)
        p = s0
        while p <= e0:
            d = results.pop(p)
            buf[p - s0: p - s0 + len(d)] = d
            p += len(d)
        output.append((s0, bytes(buf)))
    return output

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

def zip_entries(url, size):
    pass
    tail = http_get(url, max(0, size - 65536), size - 1)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise RuntimeError("ZIP EOCD not found — file is not a complete ZIP?")
    eocd   = tail[i:i + 22]
    cd_sz  = u32(eocd, 12)
    cd_off = u32(eocd, 16)
    n_tot  = u16(eocd, 10)
    if cd_off == 0xFFFFFFFF or n_tot == 0xFFFF:            
        j = tail.rfind(b"PK\x06\x07")
        if j < 0:
            raise RuntimeError("ZIP64 locator not found")
        z64 = http_get(url, u64(tail, j + 8), u64(tail, j + 8) + 55)
        n_tot, cd_sz, cd_off = u64(z64, 32), u64(z64, 40), u64(z64, 48)
    ents, off = [], cd_off
    cd_end = cd_off + cd_sz
    while off < cd_end:
        hdr = http_get(url, off, off + 45)
        if hdr[:4] != b"PK\x01\x02":
            break
        method = u16(hdr, 10)
        csize  = u32(hdr, 20)
        ucsz   = u32(hdr, 24)
        nlen   = u16(hdr, 28)
        elen   = u16(hdr, 30)
        clen   = u16(hdr, 32)
        lho    = u32(hdr, 42)
        name   = http_get(url, off + 46, off + 46 + nlen + elen - 1)
        entry_name   = name[:nlen].decode("utf-8", "replace")
        extra  = name[nlen:]
        e, method2, csize2, ucsz2, lho2 = 0, method, csize, ucsz, lho
        while e + 4 <= len(extra):
            eid, esz = u16(extra, e), u16(extra, e + 2)
            if eid == 0x0001:
                p = e + 4
                if ucsz  == 0xFFFFFFFF: ucsz2  = u64(extra, p); p += 8
                if csize == 0xFFFFFFFF: csize2 = u64(extra, p); p += 8
                if lho   == 0xFFFFFFFF: lho2   = u64(extra, p); p += 8
                break
            e += 4 + esz
        lh   = http_get(url, lho2, lho2 + 29)
        if lh[:4] != b"PK\x03\x04":
            raise RuntimeError("local header %s corrupt" % entry_name)
        data0 = lho2 + 30 + u16(lh, 26) + u16(lh, 28)
        ents.append((entry_name, method2, data0, ucsz2))
        off += 46 + nlen + elen + clen
    return ents

def rd_varint(b, i):
    r = s = 0
    while True:
        c = b[i]; i += 1
        r |= (c & 0x7F) << s
        if not c & 0x80:
            return r, i
        s += 7
        if s > 70:
            raise ValueError("implausible varint")

def pb_fields(b):
    i = 0
    while i < len(b):
        tag, i = rd_varint(b, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = rd_varint(b, i)
        elif wt == 1:
            v, i = b[i:i + 8], i + 8
        elif wt == 5:
            v, i = b[i:i + 4], i + 4
        elif wt == 2:
            ln, i = rd_varint(b, i)
            v, i = b[i:i + ln], i + ln
        elif wt == 3:
            depth, start = 1, i
            while i < len(b) and depth:
                t2, i = rd_varint(b, i)
                f2, w2 = t2 >> 3, t2 & 7
                if w2 == 0:
                    _, i = rd_varint(b, i)
                elif w2 == 1:
                    i += 8
                elif w2 == 5:
                    i += 4
                elif w2 == 2:
                    ln, i = rd_varint(b, i)
                    i += ln
                elif w2 == 3:
                    depth += 1
                elif w2 == 4:
                    if f2 == fn:
                        depth -= 1
                    else:
                        raise ValueError("mismatched end-group")
                else:
                    raise ValueError("wiretype %d inside group" % w2)
            v = b[start:i]
        else:
            raise ValueError("wiretype %d not supported" % wt)
        yield fn, wt, v

OP_NAME = {0: "REPLACE", 1: "REPLACE_BZ", 2: "MOVE", 3: "BSDIFF", 4: "SOURCE_COPY",
           5: "SOURCE_BSDIFF", 6: "ZERO", 7: "DISCARD", 8: "REPLACE_XZ",
           9: "PUFFDIFF", 10: "BROTLI_BZ"}
NEED_SRC = {2, 3, 4, 5, 9}

def parse_extentinfo(b):
    exts = []
    for fn, wt, v in pb_fields(b):
        if fn == 1 and wt == 2:
            sb = nb = 0
            for f2, w2, v2 in pb_fields(v):
                if f2 == 1 and w2 == 0: sb = v2
                elif f2 == 2 and w2 == 0: nb = v2
            exts.append((sb, nb))
    return exts

def parse_op(b):
    d = {"off": 0, "typ": 0, "len": 0, "dst": None}
    for fn, wt, v in pb_fields(b):
        if fn == 1 and wt == 0: d["typ"] = v
        elif fn == 2 and wt == 0: d["off"] = v
        elif fn == 3 and wt == 0: d["len"] = v
        elif fn == 6 and wt == 2: d["dst"] = parse_extentinfo(v)
    return d

def parse_manifest(m):
    block, parts = 4096, {}
    for fn, wt, v in pb_fields(m):
        if fn == 3 and wt == 0:
            block = v
        elif fn == 13 and wt == 2:                       
            name, newsize, ops = None, 0, []
            for f2, w2, v2 in pb_fields(v):
                if f2 == 1 and w2 == 2:
                    name = v2.decode()
                elif f2 == 7 and w2 == 2:                
                    for f3, w3, v3 in pb_fields(v2):
                        if f3 == 1 and w3 == 0:
                            newsize = v3
                elif f2 == 8 and w2 == 2:                
                    ops.append(parse_op(v2))
            if name:
                parts[name] = {"size": newsize, "ops": ops}
    return block, parts

def decomp(typ, blob):
    if typ == 0:  return blob                              
    if typ == 1:  return bz2.decompress(blob)              
    if typ == 8:  return lzma.decompress(blob)             
    if typ == 10:                                          
        try:
            import brotli
        except ImportError:
            print("FATAL: op BROTLI_BZ requires the brotli module — run: pip install brotli")
            sys.exit(2)
        return brotli.decompress(blob)
    raise RuntimeError("codec op %s not supported" % OP_NAME.get(typ, typ))

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    want = ["vendor_boot"]
    for i, a in enumerate(sys.argv):
        if a == "--partitions" and i + 1 < len(sys.argv):
            want = [x.strip() for x in sys.argv[i + 1].split(",") if x.strip()]
    if not args:
        raise SystemExit("usage: python3 fetch_stock_vb.py <url_ota_zip> [output.img] "
                         "[--partitions vendor_boot,...]")
    url, out = args[0], (args[1] if len(args) > 1 else "vendor_boot.img")

    t0 = time.time()
    size = http_size(url)
    print("[+] OTA: %s (%.2f GB)" % (url.split("/")[-1], size / 1e9))

    ents = zip_entries(url, size)
    pay = next((e for e in ents if e[0] == "payload.bin"), None)
    if not pay:
        raise SystemExit("FATAL: payload.bin not found in ZIP (%d entries)" % len(ents))
    entry_name, method, data0, ucsz = pay
    if method != 0:
        raise SystemExit("FATAL: payload.bin is compressed (method=%d) — per-byte range "
                         "is not possible on this OTA." % method)
    print("[+] payload.bin: STORED @%d (%.2f GB) — range mode OK" % (data0, ucsz / 1e9))

    head = http_get(url, data0, data0 + 23)
    if head[:4] != b"CrAU":
        raise SystemExit("FATAL: magic payload %r != CrAU" % head[:4])
    ver32 = struct.unpack_from(">I", head, 4)[0]
    if ver32 >= 1:                                       
        ver  = ver32
        msz  = struct.unpack_from(">Q", head, 8)[0]
        sigs = struct.unpack_from(">I", head, 16)[0]
    else:                                                
        ver  = struct.unpack_from(">Q", head, 4)[0]
        msz  = struct.unpack_from(">Q", head, 12)[0]
        sigs = struct.unpack_from(">I", head, 20)[0]
    if ver < 2:
        raise SystemExit("FATAL: payload version %d not supported (need >= 2)" % ver)
    base = data0 + 24 + msz + sigs
    man = http_get(url, data0 + 24, data0 + 24 + msz - 1)
    block, parts = parse_manifest(man)
    print("[+] manifest: %d bytes, block_size %d, partitions: %s" %
          (msz, block, ", ".join(sorted(parts))))

    results = {}
    for wname in want:
        p = parts.get(wname)
        if not p:
            raise SystemExit("FATAL: partition %r not found in manifest (%s)" %
                             (wname, ", ".join(sorted(parts))))
        newsize, ops = p["size"], p["ops"]
        print("[+] %s: %d bytes, %d ops" % (wname, newsize, len(ops)))
        if any(o["typ"] in NEED_SRC for o in ops):
            raise SystemExit("FATAL: %s uses delta ops requiring source partition %s — "
                             "only full OTA is supported." %
                             (wname, sorted({OP_NAME[o['typ']] for o in ops
                                             if o['typ'] in NEED_SRC})))
        need = [(o["off"], o["off"] + o["len"] - 1) for o in ops
                if o["typ"] in (0, 1, 8, 10)]
        need.sort()
        merged = []
        for s0, e0 in need:                                
            if merged and s0 - merged[-1][1] <= 2 << 20:
                merged[-1][1] = max(merged[-1][1], e0)
            else:
                merged.append([s0, e0])
        print("[+] downloading %d ranges (%.1f MB total — not the whole OTA)" %
              (len(merged), sum(e - s + 1 for s, e in merged) / 1e6))
        cache = out + ".blobs.cache"
        blobs = None
        if os.path.exists(cache):
            try:
                with open(cache, "rb") as f:
                    blobs = pickle.load(f)
                print("[+] using download cache: %s" % cache)
            except Exception:
                blobs = None
        if blobs is None:
            blobs = [(s0 - base, d) for s0, d in download_parallel(url,
                     [(base + s0, base + e0) for s0, e0 in merged])]
            try:
                with open(cache, "wb") as f:
                    pickle.dump(blobs, f)
            except Exception:
                pass
        def fetch_blob(off, ln):
            for s0, data in blobs:
                if s0 <= off and off + ln <= s0 + len(data):
                    return data[off - s0: off - s0 + ln]
            raise RuntimeError("range %d+%d not covered by the download" % (off, ln))
        outbuf = bytearray(newsize)
        cur, dl = 0, 0
        for idx, o in enumerate(ops):
            t = o["typ"]
            if t in (6, 7):                                
                if not o["dst"]:
                    print("[!] op %d %s without dst_extents — skipped" %
                          (idx, OP_NAME.get(t, t)))
                continue                                   
            blob = fetch_blob(o["off"], o["len"])
            data = decomp(t, blob)
            dl += len(blob)
            if o["dst"]:
                pos = 0
                for sb, nb in o["dst"]:
                    n = min(nb * block, newsize - sb * block)
                    if n <= 0:
                        continue
                    outbuf[sb * block: sb * block + n] = \
                        data[pos: pos + n].ljust(n, b"\x00")
                    pos += nb * block
            else:
                n = min(len(data), newsize - cur)
                outbuf[cur: cur + n] = data[:n]
                cur += len(data)
        if cur and cur != newsize:
            print("[!] wrote %d bytes, partition %d bytes — remainder stays zero" % (cur, newsize))
        h = hashlib.sha256(bytes(outbuf)).hexdigest()
        with open(out, "wb") as f:
            f.write(outbuf)
        results[wname] = (out, len(outbuf), h)
        print("[+] %s -> %s | %d bytes | SHA-256 %s" % (wname, out, len(outbuf), h))
        print("[+] effective download: %.1f MB in %.1f s" %
              (dl / 1e6, time.time() - t0))
    print("DONE: %s" % ", ".join("%s=%s" % (k, v[0]) for k, v in results.items()))

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print("FAILED: %r" % e)
        sys.exit(1)
