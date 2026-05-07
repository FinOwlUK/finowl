/**
 * FinOwl CDN Worker
 *
 * Cloudflare Worker acting as a CDN proxy for static assets.
 * Caches at 300+ global edge locations for fast delivery worldwide.
 *
 * Deploy: wrangler deploy cdn-worker.js
 * Docs:  https://developers.cloudflare.com/workers/
 */

const ORIGIN = 'https://finowl.co.uk';

// Static asset paths to CDN-cache (fingerprint-based, safe to cache long-term)
const IMMUTABLE_PATTERNS = [
  '/icons/',
  '/favicon',
  '.svg',
  '.png',
  '.jpg',
  '.jpeg',
  '.webp',
  '.avif',
  '.woff2',
  '.woff',
  '.ttf',
  '.otf',
  '.ico',
];

// PWA assets — cache for 1 hour (version via filename change)
const PWA_PATTERNS = [
  '/sw.js',
  '/manifest.json',
  '/pwa-install.js',
];

// Cache TTLs
const IMMUTABLE_TTL = 60 * 60 * 24 * 365; // 1 year (immutable)
const PWA_TTL = 60 * 60;                    // 1 hour
const DEFAULT_TTL = 60 * 60;                // 1 hour fallback

function getTTL(urlPath) {
  for (const pattern of IMMUTABLE_PATTERNS) {
    if (urlPath.includes(pattern) || urlPath.endsWith(pattern)) {
      return IMMUTABLE_TTL;
    }
  }
  for (const pattern of PWA_PATTERNS) {
    if (urlPath.endsWith(pattern)) {
      return PWA_TTL;
    }
  }
  return DEFAULT_TTL;
}

function shouldCDNCache(urlPath) {
  // Only cache static asset paths, not HTML pages or API routes
  const skipPaths = ['/api/', '/app', '/dashboard', '/login', '/signup',
                     '/reset-password', '/terms', '/privacy', '/cookies',
                     '/security', '/accept'];
  for (const skip of skipPaths) {
    if (urlPath.startsWith(skip)) return false;
  }
  return true;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Only handle requests to the CDN domain (cdn.finowl.co.uk)
    // If running on finowl.co.uk itself, handle all static asset paths
    const cdnHost = 'cdn.finowl.co.uk';
    const isCDNRequest = url.hostname === cdnHost;

    // Skip non-GET requests
    if (request.method !== 'GET') {
      return fetch(request);
    }

    // Only CDN-cache static asset paths
    if (!shouldCDNCache(url.pathname)) {
      // Proxy HTML/API requests directly to origin
      return fetch(request);
    }

    const cache = caches.default;
    const cacheKey = request;

    // Try cache first
    let response = await cache.match(cacheKey);
    if (response) {
      // Add CDN header for debugging
      response = new Response(response.body, response);
      response.headers.set('X-CDN', 'HIT');
      response.headers.set('X-CDN-Worker', 'FinOwl-CDN');
      return response;
    }

    // Fetch from origin
    const originUrl = `${ORIGIN}${url.pathname}${url.search}`;
    response = await fetch(originUrl, {
      headers: {
        ...Object.fromEntries(request.headers),
        'Host': 'finowl.co.uk',
      },
    });

    if (!response.ok && response.status !== 200) {
      return response;
    }

    const ttl = getTTL(url.pathname);

    // Create a new response we can modify
    response = new Response(response.body, response);

    // Set CDN cache headers
    response.headers.set('Cache-Control', `public, max-age=${ttl}`);
    response.headers.set('X-CDN', 'MISS');
    response.headers.set('X-CDN-Worker', 'FinOwl-CDN');
    response.headers.set('X-CDN-Edge', 'Cloudflare-Worker');

    // Allow cross-origin sharing for fonts/icons
    if (url.pathname.endsWith('.woff2') || url.pathname.endsWith('.woff') ||
        url.pathname.endsWith('.ttf') || url.pathname.endsWith('.svg') ||
        url.pathname.includes('/icons/')) {
      response.headers.set('Access-Control-Allow-Origin', '*');
      response.headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
    }

    // Clone response before caching (body can only be consumed once)
    ctx.waitUntil(cache.put(cacheKey, response.clone()));

    return response;
  },
};