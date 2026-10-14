#!/usr/bin/env python3
"""handwrite.py —— 字体渲染 A4 手写风格页面（300dpi）

与 Inko 的差别（本质）:
  字体排版：同一个字每次长得一样（这是字体的定义）
  笔迹推理：同一个字每次都不同（AI 生成）
  -> 所以本脚本靠「每字随机扰动」补偿：旋转 / 位移 / 缩放 / 基线漂移 / 墨色深浅

产物性质：字体渲染（typesetting），同「Word 里选草书字体」，不涉及 AI 生成标识。

用法:
  handwrite.py --font F.ttf --text c.txt --out out [--pages N] [--sample]
"""
import argparse, os, random
import numpy as np
from PIL import Image, ImageDraw, ImageFont

DPI = 300
MM = DPI / 25.4
mm = lambda v: int(round(v * MM))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--font", required=True)
    ap.add_argument("--text", required=True)
    ap.add_argument("--out", default="out")
    ap.add_argument("--size-mm", type=float, default=8.2)
    ap.add_argument("--line-mm", type=float, default=11.5)
    ap.add_argument("--pitch-mm", type=float, default=9.6, help="字距（格子宽）")
    ap.add_argument("--top-mm", type=float, default=35.4)
    ap.add_argument("--side-mm", type=float, default=13.0)
    ap.add_argument("--bottom-mm", type=float, default=13.0)
    ap.add_argument("--rot", type=float, default=2.2, help="每字最大旋转角(度)")
    ap.add_argument("--jit", type=float, default=2.0, help="每字最大位移(px)")
    ap.add_argument("--scale", type=float, default=0.055, help="每字缩放幅度")
    ap.add_argument("--drift", type=float, default=1.2, help="每行左缘抖动(mm)")
    ap.add_argument("--ink", type=float, default=0.10, help="墨色深浅变化幅度")
    ap.add_argument("--pages", type=int, default=0, help="只出前 N 页（0=全部）")
    ap.add_argument("--seed", type=int, default=20261014)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    nprng = np.random.default_rng(a.seed)

    os.makedirs(a.out, exist_ok=True)
    W, H = mm(210), mm(297)
    top, side, bottom = mm(a.top_mm), mm(a.side_mm), mm(a.bottom_mm)
    line_h, pitch, fsize = mm(a.line_mm), mm(a.pitch_mm), mm(a.size_mm)
    drift_px = mm(a.drift_mm)

    font = ImageFont.truetype(a.font, fsize)
    fname = os.path.basename(a.font)

    src = open(a.text, encoding="utf-8").read().split("\n")
    per_line = max(1, (W - 2 * side) // pitch)
    lines = []
    for l in src:
        s = l.rstrip()
        if not s:
            lines.append("")
            continue
        for i in range(0, len(s), per_line):
            lines.append(s[i:i + per_line])
    lpp = max(1, (H - top - bottom) // line_h)
    npx = (len(lines) + lpp - 1) // lpp
    if a.pages:
        npx = min(npx, a.pages)

    print(f"  字体 {fname}  页 {W}x{H}@{DPI}dpi")
    print(f"  字号{a.size_mm} 行距{a.line_mm} 字距{a.pitch_mm} | 每行{per_line}字 每页{lpp}行")
    print(f"  扰动: 旋转±{a.rot}° 位移±{a.jit}px 缩放±{a.scale*100:.0f}% 抖动±{a.drift}mm")
    print(f"  出 {npx} 页")

    # 字符缓存（同字不同扰动 -> 每次重新画）
    def glyph(ch):
        pad = fsize
        box = int(fsize * 2.6)
        t = Image.new("RGBA", (box, box), (0, 0, 0, 0))
        d = ImageDraw.Draw(t)
        alpha = int(255 * (1.0 - rng.uniform(0, a.ink)))
        d.text((pad, pad), ch, font=font, fill=(18, 18, 24, alpha))
        # 旋转
        ang = rng.uniform(-a.rot, a.rot)
        t = t.rotate(ang, resample=Image.BICUBIC, expand=False)
        # 缩放
        s = 1.0 + rng.uniform(-a.scale, a.scale)
        nw, nh = max(1, int(box * s)), max(1, int(box * s))
        t = t.resize((nw, nh), Image.LANCZOS)
        bb = t.getbbox()
        return t.crop(bb) if bb else None

    pages, nchar = [], 0
    for pi in range(npx):
        page = Image.new("RGB", (W, H), (255, 255, 255))
        chunk = lines[pi * lpp:(pi + 1) * lpp]
        for li, text in enumerate(chunk):
            if not text:
                continue
            base_y = top + li * line_h
            x = side + rng.uniform(0, drift_px)
            # 整行轻微倾斜（模拟手写行不水平）
            row_tilt = rng.uniform(-0.5, 0.5)
            for ci, ch in enumerate(text):
                if ch.strip():
                    g = glyph(ch)
                    if g:
                        dy = base_y + rng.uniform(-a.jit, a.jit) + ci * pitch * (row_tilt / 100.0)
                        dx = x + rng.uniform(-a.jit, a.jit)
                        page.paste(g, (int(dx), int(dy)), g)
                        nchar += 1
                x += pitch
        pages.append(page)
        print(f"    页 {pi+1}")

    pdf = os.path.join(a.out, f"handwrite.pdf")
    pages[0].save(pdf, "PDF", resolution=DPI, save_all=True, append_images=pages[1:])
    for i, p in enumerate(pages, 1):
        p.save(os.path.join(a.out, f"page-{i}.png"))

    arr = np.asarray(pages[0].convert("L"))
    intr = (arr[:top] < 200).sum()
    print(f"  [OK] {pdf}  {len(pages)} 页 {nchar} 字")
    print(f"  顶部{a.top_mm}mm 内墨迹: {intr} px -> 应为 0")


if __name__ == "__main__":
    main()
