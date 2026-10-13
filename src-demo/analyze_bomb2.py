#!/usr/bin/env python3
"""analyze_bomb2.py —— 深挖 zipbomb 结构

核心问题：Android 的 ResXMLTree 只按 chunk 的 size 字段前进。
所以填充必须藏在「一串假 chunk」里，让解析器顺着 size 跳过去。
本脚本走这条 chunk 链，还原真实结构。
"""
import sys, zipfile, struct, hashlib, collections

u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

TYPES = {0x0001: "STRING_POOL", 0x0002: "TABLE", 0x0003: "XML",
         0x0100: "START_ELEMENT", 0x0101: "END_ELEMENT", 0x0102: "CDATA",
         0x0103: "RESOURCE_MAP", 0x0180: "START_NAMESPACE"}
L = 74
def hr(t=""): print("─" * L + (f"  {t}" if t else ""))

path = sys.argv[1] if len(sys.argv) > 1 else "samples/bomb-entry.zip"
z = zipfile.ZipFile(path)
info = z.getinfo("AndroidManifest.xml")
with z.open("AndroidManifest.xml") as f:
    D = f.read()
N = len(D)

print("═" * L)
print("  zipbomb 深挖报告 v2")
print("═" * L)
print(f"  解压后 {N:,} B   压缩后 {info.compress_size:,} B   比 {N/info.compress_size:.1f}")
print(f"  sha256 {hashlib.sha256(D).hexdigest()}")
hr()

# ══ 1. chunk 链：从 offset 8 顺着 size 走 ══
print("  [1] chunk 链（解析器的真实路径）")
print("      根头: type=0x%04x headerSize=%d size=%s" % (u16(D,0), u16(D,2), f"{u32(D,4):,}"))
print()
print(f"      {'#':>3} {'offset':>14} {'type':>8} {'headerSize':>11} {'size':>14}  说明")
o = u16(D, 0)  # =8，从根头之后开始
hop = 0
while o + 8 <= N and hop < 60:
    t, hs, sz = u16(D, o), u16(D, o+2), u32(D, o+4)
    name = TYPES.get(t, f"未知0x{t:04x}")
    note = ""
    if not (8 <= hs <= 4096) or sz < hs or o + sz > N:
        note = "  <- 非法，链在此断裂"
    print(f"      {hop:>3} {o:>14,} {name:>8} {hs:>11} {sz:>14,} {note}")
    if note:
        break
    # 只跟随「非真实解析」的大块，直到接近末尾
    if o + sz >= N - 65536:
        print(f"      --> 落到尾部区域 (剩余 {N-(o+sz):,} B)")
    o += sz
    hop += 1
hr()

# ══ 2. 填充的分区（按字节构成找不同区域）══
print("  [2] 填充分区（按局部字节特征切分）")
def profile(off, n=8192):
    s = D[off:off+n]
    c = collections.Counter(s)
    return c.most_common(1)[0]

step = max(1, N // 40)
prev = None
start = 0
for off in range(0, N, step):
    b, _ = profile(off)
    if prev is None:
        prev, start = b, 0
    elif b != prev:
        seg = f"{start:>12,} .. {off:>12,}  ({(off-start)/1048576:>7.2f} MB)"
        print(f"      {seg}   主导字节 0x{prev:02x} {chr(prev) if 32<=prev<127 else '·'}")
        prev, start = b, off
seg = f"{start:>12,} .. {N:>12,}  ({(N-start)/1048576:>7.2f} MB)"
print(f"      {seg}   主导字节 0x{prev:02x} {chr(prev) if 32<=prev<127 else '·'}")
hr()

# ══ 3. 找真实 AXML：从尾部扫一个合法 string pool ══
print("  [3] 尾部真实 AXML 定位")
tail_start = max(0, N - 2 * 1024 * 1024)
cands = []
o = tail_start
while o + 28 < N:
    if u16(D, o) == 0x0001:
        hs, sz = u16(D, o+2), u32(D, o+4)
        sc, stc = u32(D, o+8), u32(D, o+12)
        if 28 <= hs <= 512 and sz > hs and o + sz <= N and 0 < sc < 20000:
            cands.append((o, hs, sz, sc, stc, u32(D, o+16), u32(D, o+20)))
            o += sz
            continue
    o += 1
print(f"      找到 {len(cands)} 个候选 string pool:")
for (off, hs, sz, sc, stc, fl, ss) in cands[:6]:
    print(f"        @{off:,}  hdr={hs} size={sz:,} count={sc:,} style={stc:,} "
          f"{'UTF-8' if fl & 0x100 else 'UTF-16'} stringsStart={ss:,}")
hr()

# ══ 4. 解析真实 string pool + XML 元素 ══
def read_pool(off, hs, sc, ss, utf8):
    base = off + ss
    idx = off + hs
    out = []
    for i in range(sc):
        try:
            so = u32(D, idx + i * 4)
        except Exception:
            break
        p = base + so
        if utf8:
            ln = D[p]
            if ln & 0x80:
                ln = ((ln & 0x7f) << 8) | D[p+1]; p += 2
            else:
                p += 1
            out.append(D[p:p+ln].decode("utf-8", "replace"))
        else:
            ln = u16(D, p)
            if ln & 0x8000:
                ln = ((ln & 0x7fff) << 16) | u16(D, p+2); p += 4
            else:
                p += 2
            out.append(D[p:p+ln*2].decode("utf-16-le", "replace").split("\x00")[0])
    return out

if cands:
    off, hs, sz, sc, stc, fl, ss = max(cands, key=lambda c: c[3])
    strs = read_pool(off, hs, sc, ss, bool(fl & 0x100))
    print(f"  [4] 真实字符串池（@{off:,}，{len(strs)} 条）")
    for i, s in enumerate(strs):
        if s:
            print(f"      [{i:>4}] {s[:110]}")
    hr()

    # 元素解析：从该 pool 之后开始走
    print("  [5] 解析真实 XML 元素")
    o = off + sz
    cnt = 0
    while o + 8 <= N and cnt < 400:
        t, hsz, csz = u16(D, o), u16(D, o+2), u32(D, o+4)
        if not (8 <= hsz <= 64 and 8 <= csz and o + csz <= N):
            o += 1
            continue
        if t == 0x0100:      # START_ELEMENT
            ns = u32(D, o+16); nm = u32(D, o+20)
            an = u16(D, o+28); asz = u16(D, o+30); ac = u16(D, o+32)
            s_ns = strs[ns] if ns < len(strs) else "?"
            s_nm = strs[nm] if nm < len(strs) else "?"
            attrs = []
            for k in range(ac):
                ao = o + 36 + k * asz
                a_ns = u32(D, ao); a_nm = u32(D, ao+4); a_raw = u32(D, ao+8)
                a_typ = D[ao+15]
                a_data = u32(D, ao+16)
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
                    val = f"0x{a_data:x}(type{a_typ})"
                attrs.append(f"{key}={val}")
            print(f"      <{s_nm}{(' ' + ' '.join(attrs)) if attrs else ''}>")
        elif t == 0x0101:
            nm = u32(D, o+20)
            print(f"      </{strs[nm] if nm < len(strs) else '?'}>")
        cnt += 1
        o += csz
hr()
print("  报告结束")
print("═" * L)
