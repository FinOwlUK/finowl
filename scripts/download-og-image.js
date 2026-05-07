/**
 * download-og-image.js
 *
 * Downloads the pre-made og:image from R2 and saves it to public/icons/og-image.png.
 * Runs during Render build (network available). Fails silently if unreachable — the
 * existing file (if any) is kept as fallback.
 *
 * Source image: user-provided JPEG (1200×630)
 */

'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const SOURCE_URL =
  'https://pub-629428d185ca4960a0a73c850d32294b.r2.dev/company_65779/images/dcd264a5-683a-478f-b929-e6c98089ad86.jpeg';

const OUTPUT_PATH = path.join(__dirname, '..', 'public', 'icons', 'og-image.png');

function download(url, dest, redirects = 0) {
  if (redirects > 5) {
    throw new Error('Too many redirects');
  }

  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    proto
      .get(url, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
          const location = res.headers.location;
          res.resume();
          return download(location, dest, redirects + 1).then(resolve).catch(reject);
        }

        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        }

        // Ensure output directory exists
        fs.mkdirSync(path.dirname(dest), { recursive: true });

        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on('finish', () => {
          file.close();
          const size = fs.statSync(dest).size;
          console.log(`[og-image] Downloaded ${size} bytes → ${dest}`);
          resolve();
        });
        file.on('error', (err) => {
          fs.unlink(dest, () => {});
          reject(err);
        });
      })
      .on('error', reject);
  });
}

download(SOURCE_URL, OUTPUT_PATH)
  .then(() => {
    console.log('[og-image] Done.');
  })
  .catch((err) => {
    console.error('[og-image] WARNING: Could not download og:image:', err.message);
    console.error('[og-image] Build will continue with existing file (if any).');
    // Non-fatal — don't exit(1)
  });
