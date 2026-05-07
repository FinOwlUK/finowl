/**
 * FinOwl Client-Side Error Tracking (legacy async fallback)
 *
 * NOTE: dashboard.html uses a synchronous inline Sentry init in <head> instead
 * of this file.  That approach is required to catch parse-time JS errors in
 * subsequent script blocks (April 22-27 incident).
 *
 * This file is kept for any other HTML pages that reference it and cannot
 * use the inline DSN injection approach.  It fetches the DSN from
 * /sentry-client-config and initialises @sentry/browser via the UMD CDN
 * bundle.  Parse-time errors in the page's own script blocks will NOT be
 * captured because this loads asynchronously — use the inline approach for
 * critical pages.
 */

(function () {
  'use strict';

  // Bail out if Sentry was already initialised by the inline approach
  if (window.__SENTRY_INIT__) return;

  fetch('/sentry-client-config')
    .then(function (r) { return r.json(); })
    .then(function (config) {
      if (!config.dsn) {
        // SENTRY_DSN not configured — browser error tracking disabled
        return;
      }
      loadAndInit(config);
    })
    .catch(function () {
      // Network or parse error — silently skip client tracking
    });

  function loadAndInit(config) {
    // Load @sentry/browser UMD bundle from CDN (sets window.Sentry)
    var script = document.createElement('script');
    script.src = 'https://browser.sentry-cdn.com/8.47.0/bundle.min.js';
    script.crossOrigin = 'anonymous';
    script.onload = function () { init(config); };
    document.head.appendChild(script);
  }

  function init(config) {
    if (!window.Sentry) return;
    var isProd = config.environment === 'production';
    var sampleRate = isProd ? 0.10 : 1.0;

    Sentry.init({
      dsn: config.dsn,
      environment: config.environment,
      tracesSampleRate: sampleRate,
    });

    // Catch synchronous errors (note: parse-time errors in existing script blocks
    // fired before this ran won't be captured here)
    window.addEventListener('error', function (ev) {
      if (ev.target && ev.target !== window && (ev.target.src || ev.target.href)) return;
      Sentry.captureException(ev.error || new Error(ev.message || 'Unknown error'), {
        tags: { type: 'window-error' },
      });
    });

    // Catch unhandled promise rejections
    window.addEventListener('unhandledrejection', function (ev) {
      Sentry.captureException(
        ev.reason instanceof Error ? ev.reason : new Error(String(ev.reason)),
        { tags: { type: 'unhandledrejection' } }
      );
    });

    window.__SENTRY_INIT__ = true;
  }
})();
