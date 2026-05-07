/**
 * generate-og-png.js - Creates FinOwl og:image (1200x630)
 *
 * Strategy:
 *   1. Try to fetch the REALISTIC owl from R2 → convert to PNG → embed as base64 in SVG
 *   2. If R2 unreachable (sandbox) → use icon-512.svg as the owl
 *   3. Render SVG via @resvg/resvg-js (high quality, installed on Render)
 *   4. Pure-JS fallback if resvg unavailable
 *
 * Design: Dark navy bg | Realistic owl logo (240x240) | "FinOwl" brand name
 *         NO tagline, NO feature pills, NO price
 *
 * Run: node generate-og-png.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');

const OUT_PATH = path.join(__dirname, 'public', 'icons', 'og-image.png');
const CACHED_OWL = path.join(__dirname, 'public', 'icons', 'owl-for-og.png');

// R2 URL for the CORRECT realistic owl (in gold circle, matching site header)
const OWL_R2_URL = 'https://pub-629428d185ca4960a0a73c850d32294b.r2.dev/company_65779/images/8f41bd9a-1865-481f-9bc7-3041e0b2390a.jpeg';

// ── Step 1: Fetch + process owl image ────────────────────────────────────────

async function fetchOwlImage() {
  try {
    const fetch = require('node-fetch');

    console.log('Fetching realistic owl from R2...');
    const res = await fetch(OWL_R2_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const buf = await res.buffer();
    const contentType = res.headers.get('content-type') || 'image/jpeg';
    console.log(`  Downloaded ${buf.length} bytes (${contentType}) from R2`);

    // Cache locally for debugging
    fs.writeFileSync(CACHED_OWL, buf);
    console.log(`  Cached owl image → ${buf.length} bytes`);

    // Return raw buffer + mime type — no sharp needed, SVG <image> handles JPEG natively
    return { buffer: buf, contentType };
  } catch (e) {
    console.log(`  R2 fetch failed (sandbox/offline): ${e.message}`);
    return null;
  }
}

// ── Step 2: Build SVG template ────────────────────────────────────────────────

function buildSVG(owlData) {
  // Build the <image> element for the owl
  let owlEl;
  if (owlData) {
    // Embed the fetched image as base64 data URI (JPEG or PNG — SVG handles both)
    const mime = owlData.contentType.includes('png') ? 'image/png' : 'image/jpeg';
    const base64 = owlData.buffer.toString('base64');
    owlEl = `<image href="data:${mime};base64,${base64}" width="240" height="240" x="60" y="195" preserveAspectRatio="xMidYMid slice"/>`;
  } else {
    // Fallback: use icon-512.svg geometry embedded inline
    const iconSvg = fs.readFileSync(path.join(__dirname, 'public', 'icons', 'icon-512.svg'), 'utf8');
    const innerSvg = iconSvg
      .replace(/<svg[^>]*>/, '')
      .replace(/<\/svg>/, '')
      .replace(/<title>[^<]*<\/title>/g, '')
      .replace(/<desc>[^<]*<\/desc>/g, '');

    const logoScale = 240 / 512;
    const tx = 60, ty = 195;
    owlEl = `<g transform="translate(${tx}, ${ty}) scale(${logoScale})">${innerSvg}</g>`;
  }

  // 1200×630 card design: dark navy bg | realistic owl | "FinOwl" brand name
  // NO tagline, NO feature pills, NO price — just logo + brand name
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <radialGradient id="bgGrad" cx="50%" cy="50%" r="70%">
      <stop offset="0%" stop-color="#22223e"/>
      <stop offset="100%" stop-color="#1a1a2e"/>
    </radialGradient>
    <radialGradient id="logoGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#d4920b" stop-opacity="0.3"/>
      <stop offset="100%" stop-color="#d4920b" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <!-- Background -->
  <rect width="1200" height="630" fill="url(#bgGrad)"/>

  <!-- Subtle grid lines -->
  ${Array.from({ length: 16 }, (_, i) => `<line x1="${i * 80}" y1="0" x2="${i * 80}" y2="630" stroke="#ffffff" stroke-width="0.4" stroke-opacity="0.04"/>`).join('\n  ')}
  ${Array.from({ length: 9 }, (_, i) => `<line x1="0" y1="${i * 80}" x2="1200" y2="${i * 80}" stroke="#ffffff" stroke-width="0.4" stroke-opacity="0.04"/>`).join('\n  ')}

  <!-- Left accent bar -->
  <rect x="0" y="0" width="6" height="630" fill="#d4920b"/>

  <!-- Logo glow -->
  <ellipse cx="180" cy="315" rx="170" ry="170" fill="url(#logoGlow)"/>

  <!-- Owl logo (240x240, left-aligned) -->
  ${owlEl}

  <!-- Separator line (vertical) -->
  <line x1="340" y1="175" x2="340" y2="455" stroke="#d4920b" stroke-width="1.5" stroke-opacity="0.4"/>

  <!-- Brand name: FinOwl -->
  <text x="370" y="295"
        font-family="'Helvetica Neue', Helvetica, Arial, sans-serif"
        font-weight="800"
        font-size="96"
        fill="#ffffff"
        letter-spacing="-2">FinOwl</text>

  <!-- Subtle divider -->
  <line x1="370" y1="330" x2="820" y2="330" stroke="#d4920b" stroke-width="1" stroke-opacity="0.35"/>

  <!-- Bottom bar -->
  <rect x="0" y="580" width="1200" height="50" fill="#0a0f1a"/>
  <text x="600" y="612" text-anchor="middle"
        font-family="'Helvetica Neue', Helvetica, Arial, sans-serif"
        font-size="18" fill="#d4920b" letter-spacing="2">FINOWL.CO.UK</text>
</svg>`;

  return svg;
}

// ── Strategy A: resvg (high quality) ─────────────────────────────────────────

async function tryResvg(owlData) {
  try {
    const { Resvg } = require('@resvg/resvg-js');

    const svg = buildSVG(owlData);
    const resvg = new Resvg(svg, {
      fitTo: { mode: 'width', value: 1200 },
      font: { loadSystemFonts: true },
    });
    const png = resvg.render().asPng();
    fs.writeFileSync(OUT_PATH, png);
    console.log('✅ OG PNG saved (via resvg):', OUT_PATH);
    console.log('   Size:', png.length, 'bytes (' + (png.length / 1024).toFixed(1) + ' KB)');
    return true;
  } catch (e) {
    console.log('ℹ️  @resvg/resvg-js not available:', e.message);
    return false;
  }
}

// ── Strategy B: Pure-JS fallback (no deps) ──────────────────────────────────

function purJsFallback() {
  const zlib = require('zlib');

  function crc32(buf) {
    let c = 0xffffffff;
    const table = [];
    for (let n = 0; n < 256; n++) {
      let cc = n;
      for (let k = 0; k < 8; k++) cc = cc & 1 ? 0xedb88320 ^ (cc >>> 1) : cc >>> 1;
      table[n] = cc >>> 0;
    }
    for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  function createChunk(type, data) {
    const typeB = Buffer.from(type, 'ascii');
    const lenB = Buffer.allocUnsafe(4);
    lenB.writeUInt32BE(data.length);
    const crcB = Buffer.allocUnsafe(4);
    crcB.writeUInt32BE(crc32(Buffer.concat([typeB, data])));
    return Buffer.concat([lenB, typeB, data, crcB]);
  }

  function createPNG(width, height, rgba) {
    const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
    const ihdr = Buffer.allocUnsafe(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
    const rawRows = Buffer.allocUnsafe(height * (1 + width * 4));
    for (let y = 0; y < height; y++) {
      rawRows[y * (1 + width * 4)] = 0;
      for (let x = 0; x < width; x++) {
        const srcIdx = (y * width + x) * 4;
        const dstIdx = y * (1 + width * 4) + 1 + x * 4;
        rawRows[dstIdx] = rgba[srcIdx];
        rawRows[dstIdx + 1] = rgba[srcIdx + 1];
        rawRows[dstIdx + 2] = rgba[srcIdx + 2];
        rawRows[dstIdx + 3] = rgba[srcIdx + 3];
      }
    }
    const idat = zlib.deflateSync(rawRows, { level: 6 });
    return Buffer.concat([sig, createChunk('IHDR', ihdr), createChunk('IDAT', idat), createChunk('IEND', Buffer.alloc(0))]);
  }

  class Canvas {
    constructor(w, h) {
      this.w = w; this.h = h;
      this.pixels = Buffer.alloc(w * h * 4, 0);
    }

    _blend(i, r, g, b, a) {
      if (a >= 255) {
        this.pixels[i] = r; this.pixels[i + 1] = g; this.pixels[i + 2] = b; this.pixels[i + 3] = 255;
      } else if (a > 0) {
        const alpha = a / 255;
        const inv = 1 - alpha;
        this.pixels[i] = Math.round(r * alpha + this.pixels[i] * inv);
        this.pixels[i + 1] = Math.round(g * alpha + this.pixels[i + 1] * inv);
        this.pixels[i + 2] = Math.round(b * alpha + this.pixels[i + 2] * inv);
        this.pixels[i + 3] = 255;
      }
    }

    setPixel(x, y, r, g, b, a = 255) {
      x = Math.floor(x); y = Math.floor(y);
      if (x < 0 || x >= this.w || y < 0 || y >= this.h) return;
      this._blend((y * this.w + x) * 4, r, g, b, a);
    }

    fillRect(x1, y1, w, h, r, g, b, a = 255) {
      for (let dy = 0; dy < h; dy++)
        for (let dx = 0; dx < w; dx++)
          this.setPixel(x1 + dx, y1 + dy, r, g, b, a);
    }

    fillCircleAA(cx, cy, rad, r, g, b, a = 255) {
      const r2 = rad * rad;
      const minY = Math.max(0, Math.floor(cy - rad - 1));
      const maxY = Math.min(this.h - 1, Math.ceil(cy + rad + 1));
      const minX = Math.max(0, Math.floor(cx - rad - 1));
      const maxX = Math.min(this.w - 1, Math.ceil(cx + rad + 1));
      for (let py = minY; py <= maxY; py++) {
        for (let px = minX; px <= maxX; px++) {
          const dx = px - cx, dy = py - cy;
          const dist2 = dx * dx + dy * dy;
          if (dist2 <= r2) {
            const edge = rad - Math.sqrt(dist2);
            const alpha2 = edge < 1 ? Math.round(edge * a) : a;
            this.setPixel(px, py, r, g, b, alpha2);
          }
        }
      }
    }

    fillTriangle(x1, y1, x2, y2, x3, y3, r, g, b, a = 255) {
      const minX = Math.max(0, Math.floor(Math.min(x1, x2, x3)));
      const maxX = Math.min(this.w - 1, Math.ceil(Math.max(x1, x2, x3)));
      const minY = Math.max(0, Math.floor(Math.min(y1, y2, y3)));
      const maxY = Math.min(this.h - 1, Math.ceil(Math.max(y1, y2, y3)));
      for (let py = minY; py <= maxY; py++) {
        for (let px = minX; px <= maxX; px++) {
          const d1 = (px - x1) * (y2 - y1) - (py - y1) * (x2 - x1);
          const d2 = (px - x2) * (y3 - y2) - (py - y2) * (x2 - x3);
          const d3 = (px - x3) * (y1 - y3) - (py - y3) * (x3 - x1);
          if ((d1 >= 0 && d2 >= 0 && d3 >= 0) || (d1 <= 0 && d2 <= 0 && d3 <= 0))
            this.setPixel(px, py, r, g, b, a);
        }
      }
    }
  }

  // Minimal pixel font (8x10 per char)
  const FONT8 = {
    'F': [0b11111000, 0b10000000, 0b11100000, 0b10000000, 0b10000000],
    'I': [0b11100000, 0b01000000, 0b01000000, 0b01000000, 0b11100000],
    'N': [0b10001000, 0b11001000, 0b10101000, 0b10011000, 0b10001000],
    'O': [0b01110000, 0b10001000, 0b10001000, 0b10001000, 0b01110000],
    'W': [0b10001000, 0b10001000, 0b10101000, 0b10101000, 0b01010000],
    'L': [0b10000000, 0b10000000, 0b10000000, 0b10000000, 0b11111000],
    'A': [0b01110000, 0b10001000, 0b11111000, 0b10001000, 0b10001000],
    'K': [0b10001000, 0b10010000, 0b11100000, 0b10010000, 0b10001000],
    'U': [0b10001000, 0b10001000, 0b10001000, 0b10001000, 0b01110000],
    'C': [0b01110000, 0b10001000, 0b10000000, 0b10001000, 0b01110000],
    'E': [0b11111000, 0b10000000, 0b11110000, 0b10000000, 0b11111000],
    'R': [0b11110000, 0b10001000, 0b11110000, 0b10010000, 0b10001000],
    'S': [0b01110000, 0b10000000, 0b01110000, 0b00001000, 0b11110000],
    'Y': [0b10001000, 0b01010000, 0b00100000, 0b00100000, 0b00100000],
    'D': [0b11100000, 0b10010000, 0b10001000, 0b10010000, 0b11100000],
    'B': [0b11110000, 0b10001000, 0b11110000, 0b10001000, 0b11110000],
    'G': [0b01110000, 0b10000000, 0b10111000, 0b10001000, 0b01110000],
    'H': [0b10001000, 0b10001000, 0b11111000, 0b10001000, 0b10001000],
    'J': [0b00111000, 0b00010000, 0b00010000, 0b10010000, 0b01100000],
    'M': [0b10001000, 0b11011000, 0b10101000, 0b10001000, 0b10001000],
    'P': [0b11110000, 0b10001000, 0b11110000, 0b10000000, 0b10000000],
    'Q': [0b01110000, 0b10001000, 0b10101000, 0b10011000, 0b01111000],
    'T': [0b11111000, 0b00100000, 0b00100000, 0b00100000, 0b00100000],
    'V': [0b10001000, 0b10001000, 0b10001000, 0b01010000, 0b00100000],
    'X': [0b10001000, 0b01010000, 0b00100000, 0b01010000, 0b10001000],
    'Z': [0b11111000, 0b00010000, 0b00100000, 0b01000000, 0b11111000],
    '0': [0b01110000, 0b10011000, 0b10101000, 0b11001000, 0b01110000],
    '1': [0b01100000, 0b00100000, 0b00100000, 0b00100000, 0b01110000],
    '2': [0b11110000, 0b00001000, 0b01110000, 0b10000000, 0b11111000],
    '3': [0b11110000, 0b00001000, 0b01110000, 0b00001000, 0b11110000],
    '4': [0b10001000, 0b10001000, 0b11111000, 0b00001000, 0b00001000],
    '5': [0b11111000, 0b10000000, 0b11110000, 0b00001000, 0b11110000],
    '6': [0b01110000, 0b10000000, 0b11110000, 0b10001000, 0b01110000],
    '7': [0b11111000, 0b00001000, 0b00010000, 0b00100000, 0b00100000],
    '8': [0b01110000, 0b10001000, 0b01110000, 0b10001000, 0b01110000],
    '9': [0b01110000, 0b10001000, 0b01111000, 0b00001000, 0b01110000],
    ' ': [0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000],
    '.': [0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b01000000],
    '/': [0b00001000, 0b00010000, 0b00100000, 0b01000000, 0b10000000],
    '£': [0b01110000, 0b10001000, 0b11100000, 0b10000000, 0b11111000],
    '-': [0b00000000, 0b00000000, 0b11111000, 0b00000000, 0b00000000],
    ':': [0b01000000, 0b00000000, 0b01000000, 0b00000000, 0b01000000],
  };

  function drawText(cv, text, x, y, scale, r, g, b, a = 255) {
    let cx = x;
    for (const ch of text.toUpperCase()) {
      const rows = FONT8[ch] || FONT8[' '];
      for (let row = 0; row < 5; row++) {
        const byte = rows[row];
        for (let col = 0; col < 8; col++) {
          if (byte & (0x80 >> col)) {
            cv.fillRect(cx + col * scale, y + row * scale, scale, scale, r, g, b, a);
          }
        }
      }
      cx += (8 + 2) * scale;
    }
    return cx;
  }

  function textWidth(text, scale) {
    return text.length * (8 + 2) * scale;
  }

  // ── Render ──────────────────────────────────────────────────────────────────
  const W = 1200, H = 630;
  const cv = new Canvas(W, H);

  // Background radial gradient
  for (let py = 0; py < H; py++) {
    for (let px = 0; px < W; px++) {
      const dx = (px - W / 2) / (W / 2);
      const dy = (py - H / 2) / (H / 2);
      const t = Math.min(1, Math.sqrt(dx * dx + dy * dy));
      const bgR = Math.round(0x22 + (0x1a - 0x22) * t);
      const bgG = Math.round(0x22 + (0x1a - 0x22) * t);
      const bgB = Math.round(0x3e + (0x2e - 0x3e) * t);
      cv.pixels[(py * W + px) * 4] = bgR;
      cv.pixels[(py * W + px) * 4 + 1] = bgG;
      cv.pixels[(py * W + px) * 4 + 2] = bgB;
      cv.pixels[(py * W + px) * 4 + 3] = 255;
    }
  }

  // Subtle grid
  for (let x = 0; x < W; x += 80) cv.fillRect(x, 0, 1, H, 0x40, 0x40, 0x70, 12);
  for (let y = 0; y < H; y += 80) cv.fillRect(0, y, W, 1, 0x40, 0x40, 0x70, 12);

  // Left accent bar
  cv.fillRect(0, 0, 6, H, 0xd4, 0x92, 0x0b);

  // ── Owl logo at left (geometric, from icon-512.svg geometry) ─────────────────
  // Scale icon-512.svg geometry to fit in 240x240, centered at (180, 315)
  const S = 240 / 512;
  const OX = 180, OY = 315;
  const off = (v) => v * S;
  const mx = (x) => OX + (x - 256) * S;
  const my = (y) => OY + (y - 256) * S;

  cv.fillCircleAA(OX, OY, off(256), 0xd4, 0x92, 0x0b);
  cv.fillCircleAA(mx(256), my(268), off(198), 0x0a, 0x0f, 0x1a);
  cv.fillCircleAA(mx(178), my(236), off(76), 0xd4, 0x92, 0x0b);
  cv.fillCircleAA(mx(178), my(236), off(48), 0x0a, 0x0f, 0x1a);
  cv.fillCircleAA(mx(158), my(216), off(14), 0xff, 0xff, 0xff, 153);
  cv.fillCircleAA(mx(334), my(236), off(76), 0xd4, 0x92, 0x0b);
  cv.fillCircleAA(mx(334), my(236), off(48), 0x0a, 0x0f, 0x1a);
  cv.fillCircleAA(mx(314), my(216), off(14), 0xff, 0xff, 0xff, 153);
  cv.fillTriangle(mx(256), my(290), mx(236), my(322), mx(276), my(322), 0xf5, 0xdf, 0xa3);
  cv.fillTriangle(mx(135), my(135), mx(156), my(193), mx(104), my(176), 0xd4, 0x92, 0x0b);
  cv.fillTriangle(mx(377), my(135), mx(356), my(193), mx(408), my(176), 0xd4, 0x92, 0x0b);

  // Vertical separator
  cv.fillRect(338, 175, 2, 280, 0xd4, 0x92, 0x0b, 60);

  // Brand name "FinOwl" (scale=9)
  const BRAND = 'FINOWL';
  const BRAND_SCALE = 9;
  const brandX = 368;
  const brandY = 210;
  drawText(cv, BRAND, brandX + 2, brandY + 2, BRAND_SCALE, 0x10, 0x10, 0x25);
  drawText(cv, BRAND, brandX, brandY, BRAND_SCALE, 0xff, 0xff, 0xff);

  // Subtle divider line
  cv.fillRect(brandX, brandY + 116, 450, 1, 0xd4, 0x92, 0x0b, 80);

  // Bottom bar
  cv.fillRect(0, H - 50, W, 50, 0x0a, 0x0f, 0x1a);
  const domain = 'FINOWL.CO.UK';
  const domainW = textWidth(domain, 2);
  drawText(cv, domain, Math.round(W / 2 - domainW / 2), H - 36, 2, 0xd4, 0x92, 0x0b);

  // Encode & save
  const png = createPNG(W, H, cv.pixels);
  fs.writeFileSync(OUT_PATH, png);
  console.log('✅ OG PNG saved (pure-JS fallback):', OUT_PATH);
  console.log('   Size:', png.length, 'bytes (' + (png.length / 1024).toFixed(1) + ' KB)');
}

// ── Run ───────────────────────────────────────────────────────────────────────

async function main() {
  // Step 1: Fetch owl from R2 (works on Render; fails silently in sandbox)
  const owlData = await fetchOwlImage();

  // Step 2: Try resvg first, fall back to pure-JS
  if (!await tryResvg(owlData)) {
    purJsFallback();
  }
}

main().catch((e) => {
  console.error('generate-og-png error:', e.message);
  process.exit(1);
});