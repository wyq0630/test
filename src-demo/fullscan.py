#!/usr/bin/env python3
"""fullscan.py —— 全量扫描 Android 样本（在 CI 上跑，手机干不动的活）

流程：
  A. 全量目录 APK 所有条目（分类 + 压缩比 + 异常检测）
  B. 全量 dump AndroidManifest（含 zipbomb 情形）
  C. 反编译全部 dex（jadx）-> 全量扫描 Java 源码
  D. 全量二进制字符串提取（所有 .so / .bin / 未知类型）
  E. 汇总 IOC（URL / IP / 域名 / 邮箱 / 密钥 / Base64 块）
  F. 输出多个 artifact 报告
"""
import os, sys, zipfile, struct, re, json, subprocess, shutil, hashlib, collections

APK = sys.argv[1] if len(sys.argv) > 1 else "samples/sample.apk"
OUT = "out"
os.makedirs(OUT, exist_ok=True)
R = []                      # 报告行


def w(s=""):
    print(s, flush=True)
    R.append(s)


def hr(t=""):
    w("─" * 78 + (f"  {t}" if t else ""))


u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

# ══════════════════════════════════════════════════════════════════
w("=" * 78)
w("  全量扫描报告")
w("=" * 78)
w(f"  样本: {APK}")
sz = os.path.getsize(APK)
w(f"  大小: {sz:,} B ({sz/1048576:.2f} MB)")
w(f"  sha256: {hashlib.sha256(open(APK,'rb').read()).hexdigest()}")
hr()

z = zipfile.ZipFile(APK)
E = z.infolist()

# ══ A. 全量条目 ══
w("A. 全量条目分析")
w(f"  条目总数: {len(E)}")
w(f"  压缩总大小: {sum(e.compress_size for e in E):,} B")
w(f"  解压总大小: {sum(e.file_size for e in E):,} B")
w(f"  整体压缩比: {sum(e.file_size for e in E)/max(1,sum(e.compress_size for e in E)):.1f}")
w()
# 按扩展名分类
ext_c = collections.Counter()
ext_sz = collections.Counter()
for e in E:
    x = os.path.splitext(e.filename)[1].lower() or "(无扩展名)"
    ext_c[x] += 1
    ext_sz[x] += e.file_size
w(f"  {'扩展名':<16} {'数量':>6} {'解压后':>16}")
for x, n in ext_c.most_common(20):
    w(f"  {x:<16} {n:>6} {ext_sz[x]:>16,}")
w()
# 异常检测：高压缩比
w("  [异常] 压缩比 > 50 的条目（zipbomb 嫌疑）:")
bombs = [e for e in E if e.compress_size > 0 and e.file_size / e.compress_size > 50]
for e in sorted(bombs, key=lambda x: -x.file_size)[:20]:
    r = e.file_size / e.compress_size
    w(f"    {e.filename:<40} {e.compress_size:>12,} -> {e.file_size:>13,}  比 {r:>8.1f}")
if not bombs:
    w("    (无)")
w()
# 异常检测：文件名
w("  [异常] 可疑文件名（长随机串 / 无意义层级）:")
susp = [e for e in E if re.search(r"(^|/)[a-z]{8,}/[a-z]{8,}/[a-z]{8,}\.", e.filename)
        or re.search(r"/[a-z]{10,}\.(png|xml|9\.png)$", e.filename)]
w(f"    疑似混淆路径: {len(susp)} 个")
for e in susp[:8]:
    w(f"      {e.filename}")
hr()

# ══ B. AndroidManifest 全量 ══
w("B. AndroidManifest 全量 dump")
try:
    mi = z.getinfo("AndroidManifest.xml")
    w(f"  压缩 {mi.compress_size:,} -> 解压 {mi.file_size:,}  ({mi.file_size/1048576:.1f} MB)")
    with z.open("AndroidManifest.xml") as f:
        mf = f.read()
    open(os.path.join(OUT, "AndroidManifest.raw"), "wb").write(mf)
    w(f"  已存 out/AndroidManifest.raw  sha256={hashlib.sha256(mf).hexdigest()[:32]}...")

    if mi.file_size > 16 * 1024 * 1024:
        w("  [WARN] 超大 manifest -> 走 zipbomb 分析路径")
        # 找真 string pool：搜 manifest 字符串
        hit = mf.find("manifest".encode("utf-16-le"))
        pool = -1
        for back in range(0, 20000):
            p = hit - back if hit >= 0 else -1
            if p < 0:
                break
            if u16(mf, p) == 0x0001:
                hs, ssz = u16(mf, p + 2), u32(mf, p + 4)
                sc = u32(mf, p + 8)
                if 28 <= hs <= 512 and ssz > hs and 0 < sc < 100000: pool = p; break
        if pool >= 0:
            hs, ssz = u16(mf, pool + 2), u32(mf, pool + 4)
            sc, ss = u32(mf, pool + 8), u32(mf, pool + 20)
            fl = u32(mf, pool + 16)
            w(f"  真实 STRING_POOL @{pool:,}  size={ssz:,}  count={sc}  stringsStart={ss}  flags=0x{fl:x}")
            utf8 = bool(fl & 0x100)
            base, idx = pool + ss, pool + hs
            # 只读字符串数据区（300KB 足够，跳过巨串）
            data = mf[base: base + 512 * 1024]
            strs = []
            for i in range(sc):
                so = u32(mf, idx + i * 4)
                p = so
                try:
                    if utf8:
                        ln = data[p]
                        if ln & 0x80: ln = ((ln & 0x7f) << 8) | data[p+1]; p += 2
                        else: p += 1
                        strs.append(data[p:p+ln].decode("utf-8", "replace"))
                    else:
                        ln = u16(data, p)
                        if ln & 0x8000: ln = ((ln & 0x7fff) << 16) | u16(data, p+2); p += 4
                        else: p += 2
                        strs.append(data[p:p+ln*2].decode("utf-16-le", "replace").split("\x00")[0])
                except Exception:
                    strs.append(f"<超出已读区 offset={so}>")
            # 修掉超长的（bomb 本体）
            fixed = []
            for s in strs:
                if len(s) > 4096 and len(set(s)) <= 4:
                    fixed.append(f"<BOMB {len(s):,} B 周期填充 {s[:8]!r}...>")
                else:
                    fixed.append(s)
            open(os.path.join(OUT, "manifest-strings.txt"), "w", encoding="utf-8").write(
                "\n".join(f"[{i:>4}] {s}" for i, s in enumerate(fixed)))
            w(f"  {len(strs)} 条字符串 -> out/manifest-strings.txt")
            w("  ── 权限 ──")
            for i, s in enumerate(fixed):
                if s.startswith("android.permission."):
                    w(f"    {s}")
            w("  ── 组件 ──")
            for i, s in enumerate(fixed):
                if re.match(r"^\.internal\.|^me\.handy\.news\.lite\.[A-Z]", s):
                    w(f"    {s}")
        else:
            w("  未找到 string pool")
except KeyError:
    w("  无 AndroidManifest.xml")
hr()

# ══ C. 反编译 dex ══
w("C. 全量反编译 + 代码扫描")
dexes = [e.filename for e in E if e.filename.endswith(".dex")]
w(f"  dex 文件: {len(dexes)} 个  合计 {sum(z.getinfo(d).file_size for d in dexes):,} B")
os.makedirs("dex", exist_ok=True)
for d in dexes:
    with z.open(d) as f, open(os.path.join("dex", os.path.basename(d)), "wb") as o:
        shutil.copyfileobj(f, o)
w("  已解出到 dex/")

# 装 jadx
if not shutil.which("jadx"):
    w("  下载 jadx ...")
    subprocess.run("curl -sSL -o /tmp/jadx.zip "
                   "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip",
                   shell=True, check=False)
    subprocess.run("unzip -q -o /tmp/jadx.zip -d /tmp/jadx && chmod +x /tmp/jadx/bin/jadx",
                   shell=True, check=False)
    os.environ["PATH"] = "/tmp/jadx/bin:" + os.environ["PATH"]
w(f"  jadx: {shutil.which('jadx')}")
for d in sorted(os.listdir("dex")):
    if not d.endswith(".dex"):
        continue
    tgt = "src-" + d
    w(f"  反编译 {d} ...")
    subprocess.run(f"timeout 1800 jadx -d {tgt} --no-res -q dex/{d}",
                   shell=True, check=False)
    n = sum(1 for _, _, fs in os.walk(tgt) for f in fs if f.endswith(".java"))
    w(f"    -> {tgt}  {n} 个 java")
hr()

# ══ D. 全量字符串提取（非 dex 条目）══
w("D. 全量二进制字符串提取")
TEXT_EXT = {".xml", ".json", ".txt", ".html", ".js", ".css", ".properties", ".cfg", ".ini"}
strings_all = []
bins = 0
for e in E:
    if e.filename.endswith(".dex") or e.filename == "AndroidManifest.xml":
        continue
    if e.file_size > 24 * 1024 * 1024:
        continue
    ext = os.path.splitext(e.filename)[1].lower()
    if ext in TEXT_EXT:
        continue
    try:
        with z.open(e.filename) as f:
            b = f.read()
        bins += 1
        for m in re.finditer(rb"[\x20-\x7e]{6,}", b):
            strings_all.append((e.filename, m.group().decode("ascii", "replace")))
    except Exception:
        pass
w(f"  扫了 {bins} 个二进制条目，提取 {len(strings_all):,} 条字符串")
open(os.path.join(OUT, "bin-strings.txt"), "w", encoding="utf-8").write(
    "\n".join(f"{f}\t{s}" for f, s in strings_all))
hr()

# ══ E. IOC 汇总 ══
w("E. IOC 汇总")
RE_URL = re.compile(r"https?://[^\s\"'<>\\)\]]{6,200}", re.I)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOM = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                    r"(?:com|net|org|cn|top|xyz|info|biz|io|me|ru|su|link|site|club|online|shop|app|cc|tk)\b", re.I)
RE_MAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")
RE_B64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
ALLOW = re.compile(r"(?i)(schemas\.android\.com|w3\.org|apache\.org|json\.org|"
                   r"example\.com|googleapis\.com|gstatic\.com|github\.com|"
                   r"kotlinlang\.org|jetbrains\.com|android\.com|google\.com|"
                   r"xml\.org|sun\.com|oracle\.com|slf4j\.org|bouncycastle\.org)")

# 收集所有文本源
corpus = []
for f, s in strings_all:
    corpus.append(s)
# 加 manifest 与 java
mf_str = os.path.join(OUT, "manifest-strings.txt")
if os.path.exists(mf_str):
    corpus += open(mf_str, encoding="utf-8").read().split("\n")
for root, _, fs in os.walk("."):
    for f in fs:
        if f.endswith(".java"):
            try:
                corpus += open(os.path.join(root, f), encoding="utf-8",
                               errors="replace").read().split("\n")
            except Exception:
                pass
w(f"  语料: {len(corpus):,} 行")
big = "\n".join(corpus)

urls = {u for u in RE_URL.findall(big) if not ALLOW.search(u)}
ips = {i for i in RE_IP.findall(big) if not i.startswith(("0.", "127.", "255."))}
doms = {d.lower() for d in RE_DOM.findall(big) if not ALLOW.search(d)}
mails = {m for m in RE_MAIL.findall(big) if not ALLOW.search(m)}
b64s = {b for b in RE_B64.findall(big)}

w(f"\n  URL ({len(urls)}):")
for u in sorted(urls)[:60]:
    w(f"    {u}")
if len(urls) > 60:
    w(f"    ... 另有 {len(urls)-60}")
w(f"\n  IPv4 ({len(ips)}):")
for i in sorted(ips):
    w(f"    {i}")
w(f"\n  域名 ({len(doms)}):")
for d in sorted(doms)[:80]:
    w(f"    {d}")
if len(doms) > 80:
    w(f"    ... 另有 {len(doms)-80}")
w(f"\n  邮箱 ({len(mails)}):")
for m in sorted(mails)[:30]:
    w(f"    {m}")
w(f"\n  疑似 Base64/密钥块 ({len(b64s)}):")
for b in sorted(b64s, key=len, reverse=True)[:15]:
    w(f"    [{len(b):>5}] {b[:100]}")

open(os.path.join(OUT, "ioc.json"), "w", encoding="utf-8").write(json.dumps({
    "urls": sorted(urls), "ips": sorted(ips), "domains": sorted(doms),
    "emails": sorted(mails), "b64_sample": sorted(b64s, key=len, reverse=True)[:200],
}, ensure_ascii=False, indent=1))
hr()
w("  结束")
w("=" * 78)

open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8").write("\n".join(R))
