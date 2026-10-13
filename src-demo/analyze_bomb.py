#!/usr/bin/env python3
"""analyze_bomb.py —— 在 CI（16GB 内存）里完整解压并解剖 zipbomb 的 AndroidManifest.xml

本机（Termux）内存/磁盘吃紧，这里直接把 426MB 全解进内存分析。
用法: analyze_bomb.py <zip路径>
"""
import sys, zipfile, struct, collections, binascii

CHUNK = {
    0x0001: "RES_STRING_POOL", 0x0002: "RES_TABLE", 0x0003: "RES_XML",
    0x0180: "RES_XML_START_NS", 0x0100: "RES_XML_START_ELEMENT",
    0x0101: "RES_XML_END_ELEMENT", 0x0102: "RES_XML_CDATA",
    0x0103: "RES_XML_RESOURCE_MAP", 0x0104: "RES_XML_LAST",
}
u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

path = sys.argv[1] if len(sys.argv) > 1 else "bomb-entry.zip"
z = zipfile.ZipFile(path)
info = z.getinfo("AndroidManifest.xml")

print("═" * 70)
print("  zipbomb AndroidManifest.xml 解剖报告")
print("═" * 70)
print(f"  zip 文件      : {path}")
print(f"  条目          : {info.filename}")
print(f"  压缩后        : {info.compress_size:,} B")
print(f"  解压后        : {info.file_size:,} B  ({info.file_size/1048576:.1f} MB)")
print(f"  压缩比        : {info.file_size/info.compress_size:.1f} : 1")
print(f"  compress_type : {info.compress_type} (8=deflate)")
print()

# ── 全量解进内存 ──
print("  [1] 解压中 ...")
with z.open("AndroidManifest.xml") as f:
    data = f.read()
print(f"      解出 {len(data):,} B")
import hashlib
print(f"      解压后 sha256: {hashlib.sha256(data).hexdigest()}")
print()

# ── 找最小周期 ──
print("  [2] 周期分析（这决定了为什么能压到 214:1）")
probe_at = len(data) // 4
win = 4096
probe = data[probe_at:probe_at + win]
periods = [p for p in range(1, 1024) if probe[:win - p] == probe[p:]]
if periods:
    p = periods[0]
    print(f"      在 offset {probe_at:,} 处发现最小周期: {p} 字节")
    print(f"      周期内容 (hex): {data[probe_at:probe_at+p].hex()}")
    try:
        print(f"      周期内容 (utf-16le): {data[probe_at:probe_at+p].decode('utf-16-le')!r}")
    except Exception:
        pass
    # 全文件是否全程周期？找出非周期区间
    print(f"      检查全程周期性 ...")
    ok_head = data[:win] == data[p:p + win]
    tail = len(data) - win
    ok_tail = data[tail:tail + win] == data[tail - p:tail - p + win]
    print(f"        开头一致: {ok_head}    结尾一致: {ok_tail}")
    # 二分找第一处不周期的地方
    lo, hi = 0, len(data) - win
    def periodic_at(x):
        return data[x:x + win] == data[x + p:x + p + win]
    if not periodic_at(0):
        firstbad = 0
    else:
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if periodic_at(mid):
                lo = mid
            else:
                hi = mid - 1
        firstbad = lo + 1
    print(f"        首处非周期位置: offset {firstbad:,}  ({firstbad/1048576:.2f} MB)")
    if firstbad < len(data):
        print(f"        该处内容: {data[firstbad:firstbad+64].hex()}")
    # 反过来找最后一处非周期
    lo, hi = 0, len(data) - 2 * win
    while lo < hi:
        mid = (lo + hi) // 2
        if periodic_at(len(data) - win - mid - 1):
            hi = mid
        else:
            lo = mid + 1
    print(f"        末处非周期位置: offset ~{len(data) - win - lo:,}")
else:
    print("      未在探测点发现 ≤1024 的周期")
print()

# ── 字节分布 ──
print("  [3] 全局字节分布（看是否单一字符填充）")
cnt = collections.Counter(data)
total = len(data)
for byte, n in cnt.most_common(10):
    ch = chr(byte) if 32 <= byte < 127 else "·"
    print(f"      0x{byte:02x} {ch!r:>4}: {n:>12,}  {n/total*100:6.2f}%")
print()

# ── chunk 结构 ──
print("  [4] AXML chunk 结构")
print(f"      root: type=0x{u16(data,0):04x} headerSize={u16(data,2)} size={u32(data,4):,}")
# 从 offset 8 的两个指针跳
for nm, off in (("stringPool", u32(data, 8)), ("resourceMap", u32(data, 12))):
    if 0 < off < len(data) - 8:
        print(f"      data[{off:,}] 声明为 {nm}: type=0x{u16(data,off):04x} "
              f"headerSize={u16(data,off+2)} size={u32(data,off+4):,}")
print()

# ── 找真正的 XML 元素区（trailer）──
print("  [5] 尾部真实内容扫描（找 RES_XML_START_ELEMENT / END）")
# 从后往前找合法 chunk
found = []
o = len(data) - 4
scan_from = max(0, len(data) - 4 * 1024 * 1024)   # 扫尾部 4MB
o = scan_from
while o < len(data) - 8:
    t = u16(data, o)
    if t in CHUNK:
        hs, sz = u16(data, o + 2), u32(data, o + 4)
        if 8 <= hs <= 512 and sz >= hs and o + sz <= len(data):
            found.append((o, t, hs, sz))
            o += sz
            continue
    o += 1
print(f"      尾部 4MB 内识别到 {len(found)} 个 chunk:")
for (off, t, hs, sz) in found[:25]:
    print(f"        @{off:>12,}  {CHUNK.get(t,'?'):<22} hdr={hs:<4} size={sz:,}")
if len(found) > 25:
    print(f"        ... 另有 {len(found)-25} 个")
print()

# ── 如果尾部有 string pool，把字符串 dump 出来 ──
for (off, t, hs, sz) in found:
    if t == 0x0001 and sz < 4 * 1024 * 1024:
        sc, stc = u32(data, off + 8), u32(data, off + 12)
        flags, sstart = u32(data, off + 16), u32(data, off + 20)
        utf8 = bool(flags & 0x100)
        print(f"  [6] 字符串池 @{off:,}: count={sc:,} styleCount={stc:,} "
              f"{'UTF-8' if utf8 else 'UTF-16'}  stringsStart={sstart:,}")
        if sc and sc < 100000 and sstart > 0:
            base = off + sstart
            idx = off + hs
            strs = []
            try:
                for i in range(min(sc, 400)):
                    so = u32(data, idx + i * 4)
                    p = base + so
                    if utf8:
                        ln = data[p]
                        if ln & 0x80:
                            ln = ((ln & 0x7f) << 8) | data[p + 1]; p += 2
                        else:
                            p += 1
                        strs.append(data[p:p + ln].decode("utf-8", "replace"))
                    else:
                        ln = u16(data, p)
                        if ln & 0x8000:
                            ln = ((ln & 0x7fff) << 16) | u16(data, p + 2); p += 4
                        else:
                            p += 2
                        s = data[p:p + ln * 2].decode("utf-16-le", "replace")
                        s = s.split("\x00")[0]
                        strs.append(s)
                print(f"        前 {len(strs)} 条字符串（去空后）:")
                shown = 0
                for s in strs:
                    if s and shown < 80:
                        print(f"          {s[:100]}")
                        shown += 1
                print(f"        （共取 {len(strs)} 条，显示 {shown} 条非空）")
            except Exception as e:
                print(f"        解析失败: {e}")
        break
print()
print("═" * 70)
print("  报告结束")
print("═" * 70)
