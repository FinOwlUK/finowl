/**
 * FinOwl Source Maps Upload Script
 *
 * Run after each production deploy to upload source maps to Sentry so
 * server.js stack traces show meaningful file names and line numbers.
 *
 * Prerequisites:
 *   1. Install @sentry/cli:
 *        npm install --save-dev @sentry/cli
 *
 *   2. Authenticate (one-time):
 *        npx sentry-cli auth
 *      Or set SENTRY_AUTH_TOKEN env var from your Sentry account settings.
 *
 *   3. Set these env vars (or pass them inline):
 *        SENTRY_DSN          — e.g. https://...@sentry.io/PROJECT_ID
 *        SENTRY_ORG          — Sentry organisation slug (e.g. "finowl")
 *        SENTRY_PROJECT      — Sentry project slug (e.g. "finowl")
 *        SENTRY_AUTH_TOKEN   — Optional if already authenticated
 *
 * Usage:
 *   SENTRY_DSN=https://...@sentry.io/123 \
     SENTRY_ORG=finowl \
     SENTRY_PROJECT=finowl \
 *   node scripts/upload-sourcemaps.js
 *
 * CI/CD (GitHub Actions — run as a step after deploy):
 *   - name: Upload source maps to Sentry
 *     run: node scripts/upload-sourcemaps.js
 *     env:
 *       SENTRY_DSN: ${{ secrets.SENTRY_DSN }}
 *       SENTRY_ORG: finowl
 *       SENTRY_PROJECT: finowl
 *       SENTRY_AUTH_TOKEN: ${{ secrets.SENTRY_AUTH_TOKEN }}
 */

const { spawnSync } = require('child_process');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');

function run(cmd, args, opts = {}) {
  const full = [cmd, ...args];
  console.log('[Sourcemaps] Running:', full.join(' '));
  const result = spawnSync(cmd, args, {
    cwd: rootDir,
    stdio: 'inherit',
    ...opts,
  });
  return result;
}

const missing = [];
if (!process.env.SENTRY_DSN) missing.push('SENTRY_DSN');
if (!process.env.SENTRY_ORG) missing.push('SENTRY_ORG');
if (!process.env.SENTRY_PROJECT) missing.push('SENTRY_PROJECT');

if (missing.length > 0) {
  console.warn('[Sourcemaps] Missing required env vars — skipping:', missing.join(', '));
  console.warn('         Set SENTRY_DSN, SENTRY_ORG, SENTRY_PROJECT to upload source maps.');
  process.exit(0);
}

// Step 1: Tell Sentry CLI where the source files are (inject sourcemap refs into JS bundle)
// For a plain Node.js app, we inject the refs so stack traces include sourcemap URLs
console.log('[Sourcemaps] Step 1: Injecting sourcemap references into server.js...');
run('npx', [
  'sentry-cli', 'sourcemaps', 'inject',
  '--org', process.env.SENTRY_ORG,
  '--project', process.env.SENTRY_PROJECT,
  rootDir,
]);

// Step 2: Upload the original source files as a release artifact
console.log('[Sourcemaps] Step 2: Uploading original source files to Sentry...');
const uploadResult = run('npx', [
  'sentry-cli', 'sourcemaps', 'upload',
  '--org', process.env.SENTRY_ORG,
  '--project', process.env.SENTRY_PROJECT,
  '--release', process.env.SENTRY_PROJECT,
  '--url-prefix', '~/',
  rootDir,
]);

console.log('[Sourcemaps] Done. Stack traces in Sentry should now show server.js file/line refs.');
console.log('[Sourcemaps] Note: For full inline source maps, also run:');
console.log('  node --enable-source-maps server.js');
console.log('  (add --enable-source-maps to the startCommand in render.yaml)');