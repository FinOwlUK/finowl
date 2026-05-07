/**
 * Sentry error monitoring for FinOwl Express server.
 * Import this file at the VERY TOP of server.js — before any other require().
 *
 * Env vars required:
 *   SENTRY_DSN   — Sentry DSN from sentry.io (get from https://sentry.io/organizations/finowl)
 *   NODE_ENV     — 'production' on Render, 'development' locally
 */

const IS_PROD = process.env.NODE_ENV === 'production';

// Sentry is null when SENTRY_DSN is not configured — callers MUST check .isEnabled
const noop = (req, res, next) => next();
const Sentry = {
  isEnabled: false,
  captureException: () => {},
  captureMessage: () => {},
  addBreadcrumb: () => {},
  getClient: () => null,
  requestHandler: () => noop,
  errorHandler: () => noop,
  Handlers: {
    requestHandler: () => noop,
    errorHandler: () => noop,
  },
};

if (process.env.SENTRY_DSN) {
  try {
    // eslint-disable-next-line unicorn/prefer-module
    const sentry = require('@sentry/node');

    sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: IS_PROD ? 'production' : 'development',
      // Performance monitoring: 10% sample rate (low-traffic app)
      tracesSampleRate: IS_PROD ? 0.10 : 1.0,
      // Only send errors in production (skip local noise)
      sendClientReports: false,
      // Include request body in error events for API debugging
      includeBody: true,
    });

    Sentry.isEnabled = true;
    Sentry.captureException = sentry.captureException.bind(sentry);
    Sentry.captureMessage = sentry.captureMessage.bind(sentry);
    Sentry.addBreadcrumb = sentry.addBreadcrumb.bind(sentry);
    Sentry.getClient = () => sentry;

    // @sentry/node v8: expressErrorHandler() is top-level; v7 used Handlers.errorHandler()
    // Support both APIs so the middleware wiring in server.js stays stable
    Sentry.Handlers = sentry.Handlers || {};
    if (typeof sentry.expressErrorHandler === 'function') {
      // v8+
      Sentry.errorHandler = () => sentry.expressErrorHandler();
      Sentry.requestHandler = () => noop; // v8 captures requests automatically via init()
    } else if (sentry.Handlers) {
      // v7 compat
      Sentry.requestHandler = () => sentry.Handlers.requestHandler();
      Sentry.errorHandler = () => sentry.Handlers.errorHandler();
    }

    console.log('[Sentry] Initialized — environment:', IS_PROD ? 'production' : 'development');
  } catch (err) {
    console.warn('[Sentry] Failed to initialize (@sentry/node not installed yet — will retry on next deploy):', err.message);
  }
} else {
  console.log('[Sentry] SENTRY_DSN not set — monitoring disabled');
}

module.exports = { Sentry };