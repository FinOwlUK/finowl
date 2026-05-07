/**
 * FinOwl Service Worker
 * Provides offline shell caching for the FinOwl PWA
 * Cache strategy:
 *   - Static assets (icons, manifest, fonts): Cache-first (fast, rarely change)
 *   - HTML pages: Network-first with cache fallback (fresh content when online)
 *   - External CDN scripts: Stale-while-revalidate (freshness preferred)
 *
 * CDN improvements (this task):
 *   - Comprehensive asset caching across all PWA assets
 *   - Pre-caching og-image for social sharing performance
 *   - Extended cache coverage for fonts and CDN resources
 */

const CACHE_NAME = 'finowl-shell-v6';
const RUNTIME_CACHE = 'finowl-runtime-v6';

// App shell: core pages and assets that must work offline
// CDN benefit: browser caches these once → instant loads on repeat visits
const SHELL_URLS = [
  // Core HTML pages
  '/',
  '/index.html',
  '/login.html',
  '/signup.html',
  '/reset-password.html',
  '/dashboard.html',
  '/security.html',
  '/terms.html',
  '/privacy.html',
  '/cookies.html',
  '/accept.html',
  // PWA assets
  '/manifest.json',
  '/pwa-install.js',
  '/sw.js',
  // Icons
  '/icons/icon-192.svg',
  '/icons/icon-512.svg',
  '/icons/icon-maskable.svg',
  // Social preview (CDN-cached for fast OG image loads)
  '/icons/og-image.png',
];

// ─── INSTALL ────────────────────────────────────────────────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[SW] Caching app shell');
        return Promise.allSettled(
          SHELL_URLS.map((url) =>
            cache.add(url).catch((err) => {
              console.warn(`[SW] Failed to cache: ${url}`, err);
            })
          )
        );
      })
      .then(() => {
        console.log('[SW] App shell cached');
        // Skip waiting so the new SW activates immediately
        return self.skipWaiting();
      })
  );
});

// ─── ACTIVATE ────────────────────────────────────────────────────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((cacheNames) =>
        Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME && name !== RUNTIME_CACHE)
            .map((name) => {
              console.log(`[SW] Deleting old cache: ${name}`);
              return caches.delete(name);
            })
        )
      )
      .then(() => {
        console.log('[SW] Activated v6');
        // Take control of all clients immediately
        return self.clients.claim();
      })
  );
});

// ─── FETCH ─────────────────────────────────────────────────────────────────
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Only handle GET requests from the same origin
  if (request.method !== 'GET' || url.origin !== location.origin) {
    return;
  }

  // Skip non-http(s) requests (chrome-extension, blob, data, etc.)
  if (!url.protocol.startsWith('http')) {
    return;
  }

  // Skip API and print routes — let them go straight to the server
  // (export downloads, print pages, and data endpoints should never be cached)
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/print/')) {
    return;
  }

  // Google Fonts: cache-first (fonts rarely change, want fast offline loads)
  if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
    event.respondWith(cacheFirst(request));
    return;
  }

  // External CDN scripts (Chart.js etc.): stale-while-revalidate
  if (url.hostname === 'cdn.jsdelivr.net' || url.hostname === 'cdnjs.cloudflare.com') {
    event.respondWith(staleWhileRevalidate(request));
    return;
  }

  // App shell HTML pages: network-first with cache fallback
  if (request.destination === 'document' || request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(networkFirst(request));
    return;
  }

  // Static assets (icons, manifest): cache-first
  if (
    request.destination === 'image' ||
    request.destination === 'script' ||
    request.destination === 'style' ||
    url.pathname.endsWith('.json')
  ) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // Default: network-first
  event.respondWith(networkFirst(request));
});

// ─── CACHE STRATEGIES ───────────────────────────────────────────────────────

/**
 * Cache-first: check cache first, fall back to network, cache the response.
 * Good for: static assets, icons, fonts
 */
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) {
    return cached;
  }

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    console.warn(`[SW] Network failed for ${request.url}:`, err);
    // Return a basic offline response for images/icons if available
    return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
  }
}

/**
 * Network-first: try network first, fall back to cache if offline.
 * Good for: HTML pages, dynamic content
 */
async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    console.log(`[SW] Network failed, serving from cache: ${request.url}`);
    const cached = await caches.match(request);
    if (cached) {
      return cached;
    }

    // Return the offline fallback page for HTML navigations
    if (request.destination === 'document') {
      const offlinePage = await caches.match('/index.html');
      if (offlinePage) {
        return offlinePage;
      }
    }

    return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
  }
}

/**
 * Stale-while-revalidate: serve from cache immediately, update cache in background.
 * Good for: CDN scripts where stale is OK but freshness preferred
 */
async function staleWhileRevalidate(request) {
  const cache = await caches.open(RUNTIME_CACHE);
  const cached = await cache.match(request);

  const fetchPromise = fetch(request)
    .then((response) => {
      if (response.ok) {
        cache.put(request, response.clone());
      }
      return response;
    })
    .catch(() => null);

  return cached || fetchPromise;
}