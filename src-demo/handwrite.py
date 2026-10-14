#!/usr/bin/env python3
"""handwrite.py —— 用字体把纯文本渲染成 A4 手写风格页面（300dpi）

与 Inko 的区别（重要）:
  Inko = 笔迹推理，产物属「AI 生成合成内容」-> 必须带 AI 标识（法定）
  本脚本 = 字体排版（typesetting）-> 与「Word 里选草书字体」同类，不涉及 AI 标识

用法:
  handwrite.py --font FONT.ttf --text content.txt --out out_dir
               [--size-mm 8.5] [--line-mm 12] [--top-mm 35.4]
               [--side-mm 14] [--bottom-mm 14] [--jitter 1.2] [--seed 42]
"""
import argparse, os, random, sys
from PIL import Image, ImageDraw, ImageFont

DPI = 300
MM = DPI / 25.4


def mm2px(v):
    return int(round(v * MM))


def render_glyph(ch, font, jitter_deg, jitter_px, rng):
    """把一个字符渲染成 RGBA 小图，带轻微旋转/位移"""
    tmp = Image.new("RGBA", (font.size * 3, font.size * 3), (0, 0, 0, 0))
    d = ImageDraw.Draw(tmp)
    d.text((font.size, font.size), ch, font=font, fill=(20, 20, 25, 255))
    if jitter_deg:
        tmp = tmp.rotate(rng.uniform(-jitter_deg, jitter_deg),
                         resample=Image.BICUBIC, expand=False)
    bb = tmp.getbbox()
    if not bb:
        return None
    return tmp.crop(bb)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--font", required=True)
    ap.add_argument("--text", required=True)
    ap.add_argument("--out", default="out")
    ap.add_argument("--size-mm", type=float, default=8.5)
    ap.add_argument("--line-mm", type=float, default=12.0)
    ap.add_argument("--top-mm", type=float, default=35.4)
    ap.add_argument("--side-mm", type=float, default=14.0)
    ap.add_argument("--bottom-mm", type=float, default=14.0)
    ap.add_argument("--jitter", type=float, default=1.2, help="每字最大旋转角度")
    ap.add_argument("--drift-mm", type=float, default=0.8, help="每行起始左边界抖动")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    rng = random.Random(a.seed)

    os.makedirs(a.out, exist_ok=True)
    W, H = mm2px(210), mm2px(297)
    top = mm2px(a.top_mm)
    side = mm2px(a.side_mm)
    bottom = mm2px(a.bottom_mm)
    line_h = mm2px(a.line_mm)
    fsize = mm2px(a.size_mm)
    drift = mm2px(a.drift_mm)

    font = ImageFont.truetype(a.font, fsize)
    adv_px = fsize  # 等宽推进（稿纸风格）

    lines = [l for l in open(a.text, encoding="utf-8").read().split("\n")]

    # ── 折行（按字数，等宽）──
    per_line = max(1, (W - 2 * side) // adv_px)
    wrapped = []
    for l in lines:
        s = l.rstrip()
        if not s:
            wrapped.append("")
            continue
        for i in range(0, len(s), per_line):
            wrapped.append(s[i:i + per_line])
    lines_per_page = max(1, (H - top - bottom) // line_h)

    print(f"  页 {W}x{H}px  @{DPI}dpi (A4 210x297mm)")
    print(f"  字号 {a.size_mm}mm  行距 {a.line_mm}mm  每行 {per_line} 字  每页 {lines_per_page} 行")
    print(f"  顶部留白 {a.top_mm}mm  左右 {a.side_mm}mm  下 {a.bottom_mm}mm")
    print(f"  正文 {len(wrapped)} 行 -> {(len(wrapped)+lines_per_page-1)//lines_per_page} 页")

    pages = []
    total_chars = 0
    for pi, start in enumerate(range(0, len(wrapped), lines_per_page)):
        chunk = wrapped[start:start + lines_per_page]
        page = Image.new("RGB", (W, H), (255, 255, 255))
        for li, text in enumerate(chunk):
            if not text:
                continue
            y = top + li * line_h
            # 行基线漂移（让左缘不笔直）
            x = side + rng.uniform(0, drift)
            for ch in text:
                if ch.strip():
                    g = render_glyph(ch, font, a.jitter, 0, rng)
                    if g:
                        gy = y + rng.uniform(-1.5, 1.5)
                        gx = x + rng.uniform(-1.0, 1.0)
                        page.paste(g, (int(gx), int(gy)), g)
                        total_chars += 1
                x += adv_px
        pages.append(page)
        print(f"    页 {pi+1}  {len(chunk)} 行")

    pdf = os.path.join(a.out, "handwrite.pdf")
    pages[0].save(pdf, "PDF", resolution=DPI, save_all=True, append_images=pages[1:])
    for i, p in enumerate(pages, 1):
        p.save(os.path.join(a.out, f"page-{i}.png"))
    print(f"  [OK] {pdf}  {len(pages)} 页  {total_chars} 字")
    # 顶部留白自检
    import numpy as np
    arr = np.asarray(pages[0].convert("L"))
    print(f"  顶部 {a.top_mm}mm 内墨迹像素: {(arr[:top] < 200).sum()}  -> 应为 0")


if __name__ == "__main__":
    main()
