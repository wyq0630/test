#!/usr/bin/env python3
"""analyze_bomb3.py —— 定位并还原 zipbomb 里的真实 AndroidManifest

思路修正：不猜结构，直接**搜真实字符串**（UTF-16LE 的 "android.permission"）
来pinpoint真 string pool，再回溯找它的 chunk 头。
"""
import sys, zipfile, struct, hashlib

u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
L = 76

path = sys.argv[1] if len(sys.argv) > 1 else "samples/bomb-entry.zip"
z = zipfile.ZipFile(path)
with z.open("AndroidManifest.xml") as f:
    D = f.read()
N = len(D)
mv = memoryview(D)

print("=" * L)
print("  zipbomb 深挖 v3")
print("=" * L)
print(f"  {N:,} B   sha256 {hashlib.sha256(D).hexdigest()[:32]}...")

def hr(t=""):
    print("-" * L + (f"  {t}" if t else ""))

# ── 1. chunk 链（修正：从 offset 8 起）──
hr("1. chunk 链（解析器路径）")
print(f"  根: type=0x{u16(D,0):04x} hdrSz={u16(D,2)} size={u32(D,4):,}")
o, hop, total = u16(D, 2), 0, 0
while o + 8 <= N and hop < 200:
    t, hs, sz = u16(D, o), u16(D, o+2), u32(D, o+4)
    bad = not (8 <= hs <= 8192) or sz < hs or o + sz > N
    print(f"  {hop:>3} @{o:>13,} type=0x{t:04x} hdr={hs:<5} size={sz:>13,}"
          + ("   <- 断裂" if bad else ""))
    if bad or hop >= 12:
        if not bad:
            print("  ... (链继续，略)")
        break
    o += sz
    hop += 1
hr()

# ── 2. 搜真实字符串定位 ──
hr("2. 搜真实 AXML 字符串（三种编码都试）")
targets = {
    "android.permission (UTF-16LE)": "android.permission".encode("utf-16-le"),
    "android.permission (UTF-8)":    b"android.permission",
    "manifest (UTF-16LE)":           "manifest".encode("utf-16-le"),
    "manifest (UTF-8)":              b"manifest",
}
hits = {}
for name, pat in targets.items():
    offs = []
    start = 0
    while len(offs) < 5:
        i = D.find(pat, start)
        if i < 0:
            break
        offs.append(i)
        start = i + 1
    hits[name] = offs
    print(f"  {name:<34} 命中 {len(offs)} 处"
          + (f"  首处 @{offs[0]:,}" if offs else ""))
    for x in offs[:3]:
        print(f"      @{x:,}   (距末尾 {N-x:,} B)")
hr()

# ── 3. 若有命中，回溯找回 chunk 头 ──
best = None
for k in ("android.permission (UTF-16LE)", "manifest (UTF-16LE)"):
    if hits.get(k):
        best = hits[k][0]
        break
if best is None and hits.get("manifest (UTF-8)"):
    best = hits["manifest (UTF-8)"][0]

if best is not None:
    hr(f"3. 从 @{best:,} 向上回溯 chunk 头")
    for back in range(0, 4096):
        p = best - back
        if p < 0:
            break
        if u16(D, p) == 0x0001:          # STRING_POOL
            hs, sz = u16(D, p+2), u32(D, p+4)
            sc, stc = u32(D, p+8), u32(D, p+12)
            fl, ss = u32(D, p+16), u32(D, p+20)
            if 28 <= hs <= 512 and sz > hs and 0 < sc < 50000 and p + sz <= N:
                print(f"  [OK] 找到 STRING_POOL @{p:,}")
                print(f"       hdrSize={hs} size={sz:,} count={sc:,} styleCount={stc:,}")
                print(f"       flags=0x{fl:x} ({'UTF-8' if fl&0x100 else 'UTF-16'}) stringsStart={ss:,}")
                # 再向上找 RES_XML 根
                for rb in range(0, 1 << 20):
                    q = p - rb
                    if q < 0:
                        break
                    if u16(D, q) == 0x0003 and u16(D, q+2) == 8 and u32(D, q+4) == N:
                        print(f"       上级 RES_XML 根 @{q:,}（与文件头同为 size={N:,}）")
                        break
                # 解析字符串
                base, idx = p + ss, p + hs
                utf8 = bool(fl & 0x100)
                strs = []
                for i in range(sc):
                    try:
                        so = u32(D, idx + i*4)
                    except Exception:
                        break
                    q2 = base + so
                    if utf8:
                        ln = D[q2]
                        if ln & 0x80:
                            ln = ((ln & 0x7f) << 8) | D[q2+1]; q2 += 2
                        else:
                            q2 += 1
                        strs.append(D[q2:q2+ln].decode("utf-8", "replace"))
                    else:
                        ln = u16(D, q2)
                        if ln & 0x8000:
                            ln = ((ln & 0x7fff) << 16) | u16(D, q2+2); q2 += 4
                        else:
                            q2 += 2
                        strs.append(D[q2:q2+ln*2].decode("utf-16-le", "replace").split("\x00")[0])
                print(f"       --- {len(strs)} 条字符串 ---")
                for i, s in enumerate(strs):
                    if s:
                        print(f"       [{i:>4}] {s[:104]}")
                # 元素
                print(f"       --- XML 元素 ---")
                o2, cnt = p + sz, 0
                while o2 + 8 <= N and cnt < 3000:
                    t, hz, cz = u16(D, o2), u16(D, o2+2), u32(D, o2+4)
                    if not (8 <= hz <= 64 and cz >= 8 and o2 + cz <= N):
                        o2 += 1
                        continue
                    if t == 0x0100:
                        nm = u32(D, o2+20)
                        an, asz, ac = u16(D, o2+28), u16(D, o2+30), u16(D, o2+32)
                        at = []
                        for k in range(ac):
                            ao = o2 + 36 + k*asz
                            a_nm, a_raw, a_typ, a_data = (u32(D, ao+4), u32(D, ao+8),
                                                          D[ao+15], u32(D, ao+16))
                            key = strs[a_nm] if a_nm < len(strs) else "?"
                            if a_raw:
                                val = strs[a_raw] if a_raw < len(strs) else "?"
                            elif a_typ == 0x03:
                                val = strs[a_data] if a_data < len(strs) else f"@{a_data}"
                            elif a_typ == 0x12:
                                val = "true" if a_data else "false"
                            elif a_typ == 0x10:
                                val = str(struct.unpack("<i", struct.pack("<I", a_data))[0])
                            else:
                                val = f"0x{a_data:x}"
                            at.append(f"{key}={val}")
                        print(f"       <{strs[nm] if nm<len(strs) else '?'}"
                              + (f" {' '.join(at)}" if at else "") + ">")
                    elif t == 0x0101:
                        nm = u32(D, o2+20)
                        print(f"       </{strs[nm] if nm<len(strs) else '?'}>")
                    cnt += 1
                    o2 += cz
                break
    else:
        print("  未回溯到合法 STRING_POOL")
hr()

# ── 4. 边界 hex dump ──
hr("4. 关键位置 hex dump")
for nm, off in (("文件头", 0), ("根头后 (8)", 8),
                ("填充切换 A", 10_664_074), ("填充切换 B", 373_242_590),
                ("末尾 256B", N - 256)):
    print(f"  {nm} @{off:,}:")
    print(f"    {D[off:off+64].hex()}")
    print(f"    {D[off:off+64]!r}")
hr()

# ── 5. 分区 1 的内容（0x00 区里的文本）──
hr("5. 第一段 (0..10.6MB) 的文本内容")
seg = D[16:16+512]
print(f"  raw: {seg[:64]!r}")
try:
    print(f"  utf-16le: {seg.decode('utf-16-le', 'replace')[:200]!r}")
except Exception as e:
    print("  decode fail", e)
print()
seg2 = D[100_000:100_000+256]
print(f"  @100000 raw: {seg2[:64]!r}")
try:
    print(f"  utf-16le: {seg2.decode('utf-16-le','replace')[:120]!r}")
except Exception as e:
    print("  decode fail", e)
hr()
print("  结束")
print("=" * L)
