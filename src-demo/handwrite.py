#!/usr/bin/env python3
"""handwrite.py —— 字体渲染 A4 手写页（300dpi）

与 Inko 的本质差别:
  字体排版：同一个字每次都一样（字体的定义）
  Inko   ：同一个字每次都不同（笔迹推理）
  -> 本脚本靠「多维度扰动」逼近手写观感：
     旋转 / 位移 / 缩放 / 墨色深浅 / 笔画粗细 / 局部形变 / 基线漂移 / 行倾斜

产物性质：字体渲染（typesetting），同「Word 里选草书字体」，不涉及 AI 生成标识。
"""
import argparse, os, random
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter

DPI = 300
MM = DPI / 25.4
mm = lambda v: int(round(v * MM))


def make_glyph(ch, font, size, rng, cfg):
    """把单字渲染成 RGBA，并施加全部扰动"""
    pad = size
    box = int(size * 3.0)
    t = Image.new("RGBA", (box, box), (0, 0, 0, 0))
    d = ImageDraw.Draw(t)

    # 1) 墨色深浅（真人写字力道不一）
    shade = 1.0 - rng.uniform(0, cfg["ink"])
    v = int(20 + rng.uniform(-8, 30))          # 色相微偏（冷/暖）
    alpha = int(255 * shade)
    d.text((pad, pad), ch, font=font, fill=(v, v, min(255, v + 6), alpha))

    # 2) 笔画粗细（用 MaxFilter 模拟下笔重）
    if rng.random() < cfg["bold_p"]:
        t = t.filter(ImageFilter.MaxFilter(3))

    # 3) 局部形变（手抖 / 写歪）——在纵向做非均匀缩放
    if rng.random() < cfg["warp_p"]:
        bbox = t.getbbox()
        if bbox:
            sub = t.crop(bbox)
            w0, h0 = sub.size
            # 纵向随机拉伸 + 轻微错切
            ky = rng.uniform(-cfg["shear"], cfg["shear"])
            sub = sub.transform(
                (w0, h0), Image.AFFINE,
                (1, ky, -ky * h0 / 2, 0, 1 + rng.uniform(-0.08, 0.08), 0),
                resample=Image.BICUBIC)
            t = Image.new("RGBA", (box, box), (0, 0, 0, 0))
            t.paste(sub, (bbox[0], bbox[1]), sub)

    # 4) 旋转
    ang = rng.uniform(-cfg["rot"], cfg["rot"])
    t = t.rotate(ang, resample=Image.BICUBIC, expand=False)

    # 5) 缩放（大小不一）
    s = 1.0 + rng.uniform(-cfg["scale"], cfg["scale"])
    t = t.resize((max(1, int(box * s)), max(1, int(box * s))), Image.LANCZOS)

    bb = t.getbbox()
    return t.crop(bb) if bb else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--font", required=True)
    ap.add_argument("--text", required=True)
    ap.add_argument("--out", default="out")
    ap.add_argument("--size-mm", type=float, default=8.6)
    ap.add_argument("--line-mm", type=float, default=11.6)
    ap.add_argument("--pitch-mm", type=float, default=8.8)
    ap.add_argument("--top-mm", type=float, default=35.4)
    ap.add_argument("--side-mm", type=float, default=13.0)
    ap.add_argument("--bottom-mm", type=float, default=13.0)
    # ── 扰动强度 ──
    ap.add_argument("--level", choices=["normal", "strong"], default="strong")
    ap.add_argument("--pages", type=int, default=0)
    ap.add_argument("--seed", type=int, default=20261014)
    a = ap.parse_args()

    cfg = dict(
        normal=dict(rot=2.2, jit=2.0, scale=0.06, drift=1.2, ink=0.12,
                    shear=0.03, bold_p=0.06, warp_p=0.10, tilt=0.5),
        strong=dict(rot=4.5, jit=5.0, scale=0.11, drift=2.6, ink=0.28,
                    shear=0.07, bold_p=0.14, warp_p=0.35, tilt=1.4),
    )[a.level]

    rng = random.Random(a.seed)
    os.makedirs(a.out, exist_ok=True)
    W, H = mm(210), mm(297)
    top, side, bottom = mm(a.top_mm), mm(a.side_mm), mm(a.bottom_mm)
    line_h, pitch, fsize = mm(a.line_mm), mm(a.pitch_mm), mm(a.size_mm)
    drift_px = mm(cfg["drift"])

    font = ImageFont.truetype(a.font, fsize)
    print(f"  字体 {os.path.basename(a.font)}  扰动档位 {a.level}")
    print(f"  rot±{cfg['rot']}° jit±{cfg['jit']}px scale±{cfg['scale']*100:.0f}% "
          f"ink±{cfg['ink']*100:.0f}% warp{cfg['warp_p']*100:.0f}% 行倾±{cfg['tilt']}°")

    src = open(a.text, encoding="utf-8").read().split("\n")
    per_line = max(1, (W - 2 * side) // pitch)
    lines = []
    for l in src:
        s = l.rstrip()
        if not s:
            lines.append(""); continue
        for i in range(0, len(s), per_line):
            lines.append(s[i:i + per_line])
    # [KEY] 顶部占位符要留白：strong 档位抖动大（旋转+位移+缩放），
    # 首行基线若正好等于 top，字形上沿会压进占位符（实测侵入 1.7mm）。
    # -> 首行基线额外下沉一个"抖动余量"（约半个字高）。
    guard = int(fsize * 0.55)
    top_draw = top + guard
    lpp = max(1, (H - top_draw - bottom) // line_h)
    npx = (len(lines) + lpp - 1) // lpp
    if a.pages:
        npx = min(npx, a.pages)
    print(f"  每行{per_line}字 每页{lpp}行 -> 出 {npx} 页")

    pages, nchar = [], 0
    for pi in range(npx):
        page = Image.new("RGB", (W, H), (255, 255, 255))
        for li, text in enumerate(lines[pi * lpp:(pi + 1) * lpp]):
            if not text:
                continue
            base_y = top_draw + li * line_h
            x = side + rng.uniform(0, drift_px)
            tilt = rng.uniform(-cfg["tilt"], cfg["tilt"])   # 整行倾斜
            for ci, ch in enumerate(text):
                if ch.strip():
                    g = make_glyph(ch, font, fsize, rng, cfg)
                    if g:
                        dy = base_y + rng.uniform(-cfg["jit"], cfg["jit"]) + ci * pitch * (tilt / 100.0)
                        dx = x + rng.uniform(-cfg["jit"], cfg["jit"])
                        page.paste(g, (int(dx), int(dy)), g)
                        nchar += 1
                x += pitch
        pages.append(page)
        print(f"    页 {pi+1}")

    pdf = os.path.join(a.out, "handwrite.pdf")
    pages[0].save(pdf, "PDF", resolution=DPI, save_all=True, append_images=pages[1:])
    for i, p in enumerate(pages, 1):
        p.save(os.path.join(a.out, f"page-{i}.png"))
    arr = np.asarray(pages[0].convert("L"))
    print(f"  [OK] {pdf}  {len(pages)} 页 {nchar} 字")
    print(f"  顶部占位符区（0..{a.top_mm}mm）内墨迹: {(arr[:top] < 200).sum()} px  -> 应为 0")


if __name__ == "__main__":
    main()
