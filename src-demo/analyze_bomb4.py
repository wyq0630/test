#!/usr/bin/env python3
"""analyze_bomb4.py —— 从字符串池 @1,827,792 还原完整真实 AndroidManifest

结构已破解：
  root@0 (size=N)
   ├ fake chunk @8          size=1,827,784     <- 1.8MB 假块（hex 文本填充）
   ├ STRING_POOL @1,827,792 size=370,399,808   <- 真池！345MB 'a' 填充包在里面
   ├ fake chunk @372,227,600 size=1,858,412
   ├ fake chunk @374,086,012 size=52,428,800   <- 正好 50MB
   └ 真 XML 元素 @426,514,812 ..
"""
import sys, zipfile, struct, hashlib

u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
L = 76

z = zipfile.ZipFile(sys.argv[1] if len(sys.argv) > 1 else "samples/bomb-entry.zip")
with z.open("AndroidManifest.xml") as f:
    D = f.read()
N = len(D)

POOL = 1_827_792
print("=" * L)
print("  zipbomb -> 真实 AndroidManifest 还原")
print("=" * L)
print(f"  数据 {N:,} B   sha256 {hashlib.sha256(D).hexdigest()}")

# ── string pool ──
t, hs, sz = u16(D, POOL), u16(D, POOL+2), u32(D, POOL+4)
sc, stc, fl, ss, sst = (u32(D, POOL+8), u32(D, POOL+12), u32(D, POOL+16),
                        u32(D, POOL+20), u32(D, POOL+24))
print(f"\n  STRING_POOL @{POOL:,}")
print(f"    type=0x{t:04x} headerSize={hs} size={sz:,}  ({sz/1048576:.1f} MB)")
print(f"    stringCount={sc:,}  styleCount={stc:,}")
print(f"    flags=0x{fl:x} ({'UTF-8' if fl&0x100 else 'UTF-16LE'})")
print(f"    stringsStart={ss:,}  stylesStart={sst:,}")
print(f"    --> 池声明 {sz/1048576:.1f} MB，实际字符串只占开头，其余是填充")

utf8 = bool(fl & 0x100)
base = POOL + ss
idx = POOL + hs
strs = []
for i in range(sc):
    try:
        so = u32(D, idx + i*4)
    except Exception:
        break
    p = base + so
    if utf8:
        ln = D[p]
        if ln & 0x80:
            ln = ((ln & 0x7f) << 8) | D[p+1]; p += 2
        else:
            p += 1
        strs.append(D[p:p+ln].decode("utf-8", "replace"))
    else:
        ln = u16(D, p)
        if ln & 0x8000:
            ln = ((ln & 0x7fff) << 16) | u16(D, p+2); p += 4
        else:
            p += 2
        strs.append(D[p:p+ln*2].decode("utf-16-le", "replace").split("\x00")[0])

print(f"\n  ── {len(strs)} 条字符串 ──")
for i, s in enumerate(strs):
    print(f"    [{i:>4}] {s}")

# ── XML 元素 ──
print(f"\n  ── 还原的 XML ──")
o = 0
for cand in (426_514_812, 426_514_820):
    if u16(D, cand) in (0x0100, 0x0180, 0x0102, 0x0101, 0x017e, 0x017f, 0x0105, 0x0103):
        o = cand
        break
if not o:
    o = 426_514_812

depth = 0
cnt = 0
while o + 8 <= N and cnt < 5000:
    t, hz, cz = u16(D, o), u16(D, o+2), u32(D, o+4)
    if not (8 <= hz <= 64 and cz >= 8 and o + cz <= N):
        o += 1
        continue
    if t == 0x0100:      # START_ELEMENT
        ns, nm = u32(D, o+16), u32(D, o+20)
        an, asz, ac = u16(D, o+28), u16(D, o+30), u16(D, o+32)
        at = []
        for k in range(ac):
            ao = o + 36 + k*asz
            a_ns, a_nm, a_raw = u32(D, ao), u32(D, ao+4), u32(D, ao+8)
            a_typ, a_data = D[ao+15], u32(D, ao+16)
            key = strs[a_nm] if a_nm < len(strs) else f"#{a_nm}"
            if a_raw:
                val = strs[a_raw] if a_raw < len(strs) else f"#{a_raw}"
            elif a_typ == 0x03:
                val = strs[a_data] if a_data < len(strs) else f"@{a_data}"
            elif a_typ == 0x12:
                val = "true" if a_data else "false"
            elif a_typ == 0x10:
                val = str(struct.unpack("<i", struct.pack("<I", a_data))[0])
            elif a_typ == 0x11:
                val = f"0x{a_data:08x}"
            else:
                val = f"0x{a_data:x}"
            if a_ns:
                nsn = strs[a_ns] if a_ns < len(strs) else "?"
                key = f"{nsn}:{key}"
            at.append(f"{key}=\"{val}\"")
        nmv = strs[nm] if nm < len(strs) else f"#{nm}"
        print("  " + "  " * depth + f"<{nmv}"
              + (" " + " ".join(at) if at else "") + ">")
        depth += 1
    elif t == 0x0101:    # END_ELEMENT
        depth = max(0, depth - 1)
        nm = u32(D, o+20)
        nmv = strs[nm] if nm < len(strs) else f"#{nm}"
        print("  " + "  " * depth + f"</{nmv}>")
    cnt += 1
    o += cz

print("\n" + "=" * L)
