/**
 * FinOwl PWA Install Handler
 * Manages "Add to Home Screen" prompt across iOS Safari, Android Chrome, and desktop browsers.
 *
 * Detection logic:
 *  - iOS Safari (iPhone/iPad): show custom banner with step-by-step instructions
 *  - Android Chrome / Desktop Chrome/Edge: listen for beforeinstallprompt event, show native prompt
 *  - Already installed (standalone mode): hide the banner entirely
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'finowl_pwa_dismissed';
  const INSTALLED_KEY = 'finowl_pwa_installed';

  let deferredPrompt = null;
  let bannerEl = null;

  // ─── UTILS ──────────────────────────────────────────────────────────────────

  function isIOS() {
    return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
  }

  function isInStandaloneMode() {
    return (
      window.matchMedia('(display-mode: standalone)').matches ||
      window.navigator.standalone === true
    );
  }

  function isDismissed() {
    return localStorage.getItem(STORAGE_KEY) === 'true';
  }

  function isInstalled() {
    return localStorage.getItem(INSTALLED_KEY) === 'true';
  }

  function dismissBanner() {
    localStorage.setItem(STORAGE_KEY, 'true');
    if (bannerEl) {
      bannerEl.classList.add('pwa-banner--hidden');
      setTimeout(() => {
        if (bannerEl && bannerEl.parentNode) {
          bannerEl.parentNode.removeChild(bannerEl);
        }
        bannerEl = null;
      }, 400);
    }
  }

  function markInstalled() {
    localStorage.setItem(INSTALLED_KEY, 'true');
    dismissBanner();
  }

  // ─── BANNER CREATION ─────────────────────────────────────────────────────

  function createBanner(installAction) {
    if (bannerEl) return;

    const isIOSDevice = isIOS();

    bannerEl = document.createElement('div');
    bannerEl.id = 'pwa-install-banner';
    bannerEl.className = 'pwa-banner';
    bannerEl.setAttribute('role', 'complementary');
    bannerEl.setAttribute('aria-label', 'Install FinOwl app');

    if (isIOSDevice) {
      bannerEl.innerHTML = `
        <div class="pwa-banner__inner">
          <div class="pwa-banner__icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
              <circle cx="16" cy="16" r="16" fill="#d4920b"/>
              <circle cx="16" cy="17" r="12" fill="#0a0f1a"/>
              <circle cx="11" cy="15" r="5" fill="#d4920b"/>
              <circle cx="11" cy="15" r="3" fill="#0a0f1a"/>
              <circle cx="21" cy="15" r="5" fill="#d4920b"/>
              <circle cx="21" cy="15" r="3" fill="#0a0f1a"/>
              <polygon points="16,19 14,22 18,22" fill="#f5dfa3"/>
            </svg>
          </div>
          <div class="pwa-banner__text">
            <strong>Install FinOwl</strong>
            <span class="pwa-banner__hint">Tap <span class="pwa-banner__action">⌘ Share</span> then <span class="pwa-banner__action">Add to Home Screen</span></span>
          </div>
          <button class="pwa-banner__close" aria-label="Dismiss install prompt" id="pwa-close-btn">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
              <line x1="3" y1="3" x2="13" y2="13" stroke="#fff" stroke-width="2" stroke-linecap="round"/>
              <line x1="13" y1="3" x2="3" y2="13" stroke="#fff" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </button>
        </div>
      `;
    } else {
      bannerEl.innerHTML = `
        <div class="pwa-banner__inner">
          <div class="pwa-banner__icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
              <circle cx="16" cy="16" r="16" fill="#d4920b"/>
              <circle cx="16" cy="17" r="12" fill="#0a0f1a"/>
              <circle cx="11" cy="15" r="5" fill="#d4920b"/>
              <circle cx="11" cy="15" r="3" fill="#0a0f1a"/>
              <circle cx="21" cy="15" r="5" fill="#d4920b"/>
              <circle cx="21" cy="15" r="3" fill="#0a0f1a"/>
              <polygon points="16,19 14,22 18,22" fill="#f5dfa3"/>
            </svg>
          </div>
          <div class="pwa-banner__text">
            <strong>Install FinOwl</strong>
            <span class="pwa-banner__hint">Get the app — faster, works offline</span>
          </div>
          <button class="pwa-banner__install" id="pwa-install-btn">Install</button>
          <button class="pwa-banner__close" aria-label="Dismiss install prompt">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
              <line x1="3" y1="3" x2="13" y2="13" stroke="#fff" stroke-width="2" stroke-linecap="round"/>
              <line x1="13" y1="3" x2="3" y2="13" stroke="#fff" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </button>
        </div>
      `;
    }

    // Inject styles into <head>
    injectStyles();

    // Append to body
    document.body.appendChild(bannerEl);

    // Attach events after a tick to ensure DOM is ready
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        bannerEl.classList.add('pwa-banner--visible');
      });
    });

    // Close button
    bannerEl.querySelector('.pwa-banner__close').addEventListener('click', dismissBanner);

    // Install button (Android / desktop)
    const installBtn = bannerEl.querySelector('#pwa-install-btn');
    if (installBtn && installAction) {
      installBtn.addEventListener('click', async () => {
        if (deferredPrompt) {
          deferredPrompt.prompt();
          const { outcome } = await deferredPrompt.userChoice;
          if (outcome === 'accepted') {
            markInstalled();
          } else {
            // User dismissed the native prompt — keep banner visible
            // so they can try again if they want
          }
          deferredPrompt = null;
        }
      });
    }
  }

  function injectStyles() {
    if (document.getElementById('pwa-banner-styles')) return;

    const style = document.createElement('style');
    style.id = 'pwa-banner-styles';
    style.textContent = `
      .pwa-banner {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        z-index: 99999;
        font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        background: #0a0f1a;
        border-top: 1px solid rgba(212, 146, 11, 0.3);
        transform: translateY(100%);
        transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1);
      }

      .pwa-banner--visible {
        transform: translateY(0);
      }

      .pwa-banner--hidden {
        transform: translateY(100%);
        opacity: 0;
      }

      .pwa-banner__inner {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.875rem 1rem;
        max-width: 960px;
        margin: 0 auto;
      }

      .pwa-banner__icon {
        flex-shrink: 0;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .pwa-banner__text {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 0.125rem;
        min-width: 0;
      }

      .pwa-banner__text strong {
        color: #ffffff;
        font-size: 0.9375rem;
        font-weight: 600;
        font-family: 'Space Grotesk', sans-serif;
        white-space: nowrap;
      }

      .pwa-banner__hint {
        color: rgba(255, 255, 255, 0.65);
        font-size: 0.8125rem;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .pwa-banner__action {
        background: rgba(212, 146, 11, 0.2);
        color: #d4920b;
        padding: 0.125rem 0.375rem;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
      }

      .pwa-banner__install {
        flex-shrink: 0;
        background: #d4920b;
        color: #0a0f1a;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-size: 0.875rem;
        font-weight: 700;
        font-family: 'Space Grotesk', sans-serif;
        cursor: pointer;
        transition: background 0.15s ease;
        white-space: nowrap;
      }

      .pwa-banner__install:hover {
        background: #e8a20d;
      }

      .pwa-banner__install:active {
        background: #c08a09;
      }

      .pwa-banner__close {
        flex-shrink: 0;
        background: transparent;
        border: none;
        cursor: pointer;
        padding: 0.25rem;
        opacity: 0.6;
        transition: opacity 0.15s ease;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 4px;
      }

      .pwa-banner__close:hover {
        opacity: 1;
      }

      @media (min-width: 480px) {
        .pwa-banner {
          bottom: 1.5rem;
          left: 1.5rem;
          right: auto;
          border-radius: 14px;
          border-top: none;
          max-width: 420px;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
        }

        .pwa-banner__inner {
          padding: 1rem 1.25rem;
        }
      }
    `;
    document.head.appendChild(style);
  }

  // ─── SERVICE WORKER REGISTRATION ──────────────────────────────────────────

  function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;

    navigator.serviceWorker
      .register('/sw.js')
      .then((registration) => {
        console.log('[PWA] Service worker registered:', registration.scope);
      })
      .catch((err) => {
        console.warn('[PWA] Service worker registration failed:', err);
      });
  }

  // ─── BOOTSTRAP ─────────────────────────────────────────────────────────────

  function init() {
    // Already in standalone mode (installed as PWA) — don't show the banner
    if (isInStandaloneMode()) {
      console.log('[PWA] App running in standalone mode — install banner suppressed');
      return;
    }

    // Already dismissed or already marked as installed
    if (isDismissed() || isInstalled()) {
      console.log('[PWA] Install banner suppressed (dismissed or installed)');
      return;
    }

    // Register the service worker immediately
    registerServiceWorker();

    // ── iOS Safari: use custom prompt ──
    if (isIOS()) {
      // iOS Safari doesn't fire beforeinstallprompt — show custom banner
      createBanner(null);
      return;
    }

    // ── Android / Desktop: native PWA install prompt ──
    window.addEventListener('beforeinstallprompt', (e) => {
      // Intercept the native prompt so we can show our own UI first
      e.preventDefault();
      deferredPrompt = e;
      createBanner(true);
    });

    // ── AppInstalled event: user added to home screen via native prompt ──
    window.addEventListener('appinstalled', () => {
      console.log('[PWA] App installed successfully');
      markInstalled();
    });
  }

  // Run after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();